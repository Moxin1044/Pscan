//! DNS 解析、TCP / UDP 端口扫描、主机发现与取消控制。
//!
//! 扫描以「有界并发 + 结果通道背压」的方式执行：任务用
//! [`futures::stream::for_each_concurrent`] 限量并发，结果通过
//! [`tokio::sync::mpsc`] 交给消费者，消费者跟不上时生产者自动暂停，
//! 因此内存占用与 `result_buffer` 同阶，而不是与目标总数同阶。
//!
//! 三种网络行为都在这里：
//!
//! - [`scan_to_channel_with_cancel`]：端口扫描（TCP connect / UDP）
//! - [`discover_hosts`]：主机存活发现（ICMP Echo + TCP connect 回退）
//! - [`resolve_targets`]：目标 DNS 解析（同名多地址全部展开）

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{StreamExt, stream};
use serde::Serialize;
use surge_ping::{Client as PingClient, Config as PingConfig, ICMP, PingIdentifier, PingSequence};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{sleep_until, timeout};
pub use tokio_util::sync::CancellationToken;

use crate::fingerprint::{self, Fingerprint};
use crate::tls::{self, TlsInfo};

/// 单次连接最多保留的 banner 字节数，防止恶意服务无限输出撑爆内存。
const MAX_BANNER_BYTES: usize = 2048;

/// 单次 `read` 的缓冲区大小。
const BANNER_CHUNK_BYTES: usize = 1024;

/// banner 缓冲区的初始容量，覆盖绝大多数欢迎信息。
const BANNER_INITIAL_CAPACITY: usize = 512;

/// 被动 banner 的最长等待时间；服务不主动说话时不值得久等。
const PASSIVE_WAIT: Duration = Duration::from_millis(180);

/// 主动探针的等待窗口：发完探针后最多等这么久，拿到数据立即返回。
const PROBE_WAIT: Duration = Duration::from_millis(250);

/// 目标预解析的最大并发数，避免一次性对 DNS 服务器发起上百个查询。
const RESOLVE_CONCURRENCY_MAX: usize = 64;

/// ICMP Echo 与通用 UDP 探针的载荷；对端日志里可据此识别扫描来源。
const PROBE_PAYLOAD: &[u8] = b"Pscan";

/// ICMP Echo 使用的序号；本工具每个目标只发一次探测。
const ICMP_SEQUENCE: u16 = 0;

/// DNS 查询探针：12 字节头 + 根域名 `QNAME` + `QTYPE=SOA`、`QCLASS=IN`。
const UDP_DNS_PROBE: &[u8] =
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01";

/// NTP Client 请求：48 字节，首字节 `LI=0 VN=3 Mode=3`（client mode）。
const UDP_NTP_PROBE: &[u8] = b"\x1b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// 主动 HTTP 探针模板；`Host` 与 `User-Agent` 用于让虚拟主机返回真实响应。
const HTTP_PROBE_TEMPLATE: &str = "HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Pscan/2\r\n\r\n";

/// SYN 扫描下 TCP 端口的判定状态。
///
/// connect 扫描只能得到「连上 / 没连上」，而半开扫描还能区分
/// 「响应 RST（关闭）」与「完全没有响应（被过滤或丢包）」。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpState {
    /// 收到 `SYN-ACK`。
    Open,
    /// 收到 `RST`。
    Closed,
    /// 超时无响应：可能被防火墙丢弃，也可能是链路丢包。
    Filtered,
}

/// 传输层协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// TCP（connect 扫描）。
    Tcp,
    /// UDP（无连接，需配合 [`UdpState`] 解读）。
    Udp,
}

/// UDP 的三种判定状态。
///
/// UDP 无连接且远端可能静默，因此无法像 TCP 那样二分「开 / 关」。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdpState {
    /// 收到目标应答。
    Open,
    /// 内核收到 ICMP Port Unreachable。
    Closed,
    /// 超时或无可判定响应：可能开放静默，也可能被过滤。
    OpenOrFiltered,
}

/// 端口扫描的运行时配置。
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// 最大并发网络操作数。
    pub concurrency: usize,
    /// 单次 connect / recv 的超时。
    pub connect_timeout: Duration,
    /// 每个已建立连接的指纹识别总预算。
    pub fingerprint_timeout: Duration,
    /// 是否启用 banner 读取与主动探针。
    pub service_detection: bool,
    /// 每秒任务启动上限；`None` 表示不限速。
    pub rate_limit: Option<u32>,
    /// 结果通道容量（背压上限）。
    pub result_buffer: usize,
    /// 传输层选择。
    pub transport: Transport,
    /// 是否使用 SYN 半开扫描（仅 TCP，仅 Unix）。
    ///
    /// 为 `true` 时会忽略 `service_detection`：半开扫描不建立连接，
    /// 没有 banner 可读。命令行在参数校验阶段已拒绝这种组合。
    pub syn: bool,
}

/// 单次端口扫描结果，逐条序列化为 JSONL。
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    /// 记录类型，固定为 `scan`，便于和多段输出区分。
    pub kind: &'static str,
    /// 用户输入的主机名或 IP 文本。
    pub host: String,
    /// 解析后的 IP 文本（IPv6 不带方括号）。
    pub ip: String,
    /// 端口号。
    pub port: u16,
    /// TCP 是否连通；UDP 下为「非 closed」。
    pub open: bool,
    /// 从发起到拿到结果的耗时（毫秒）。
    pub latency_ms: u64,
    /// 传输层协议。
    pub transport: Transport,
    /// UDP 状态，仅 UDP 结果有值。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_state: Option<UdpState>,
    /// SYN 扫描的 TCP 状态，仅 `--syn` 的结果有值。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_state: Option<TcpState>,
    /// 识别出的服务名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// 识别出的产品名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// 识别出的版本号。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// 原始 banner（已做控制字符清洗）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// 失败原因；`closed` 的 TCP 结果也会带 `Connection refused`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// 主机存活判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HostState {
    /// 收到确认响应。
    Alive,
    /// 探测期间没有确认响应；**不等于主机离线**。
    Unknown,
}

/// 单台主机的存活发现结果。
#[derive(Debug, Clone, Serialize)]
pub struct HostDiscoveryResult {
    /// 记录类型，固定为 `host`。
    pub kind: &'static str,
    /// 用户输入的主机名或 IP 文本。
    pub host: String,
    /// 解析后的 IP 文本。
    pub ip: String,
    /// 存活状态。
    pub state: HostState,
    /// 判定方法，如 `icmp`、`tcp/443`、`tcp/443-refused`、`no-response`。
    pub method: String,
    /// 耗时（毫秒）。
    pub latency_ms: u64,
}

/// 主机发现配置。
#[derive(Debug, Clone)]
pub struct HostDiscoveryConfig {
    /// 最大并发探测数。
    pub concurrency: usize,
    /// 单次 ICMP / TCP 探测的超时。
    pub timeout: Duration,
    /// ICMP 无响应时的 TCP 回退端口。
    pub tcp_ports: Vec<u16>,
    /// 是否启用 ICMP Echo（关闭时只做 TCP 回退）。
    pub icmp: bool,
}

/// 已解析的目标：保留原始输入与解析后的 IP。
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    /// 用户输入的原始文本。
    pub host: String,
    /// 解析后的 IP。
    pub ip: IpAddr,
}

/// 全局令牌桶限速器。
///
/// 所有任务共享一个 `next` 时刻：每次取号后把 `next` 前移一个间隔，
/// 从而把任务启动时间均匀摊开。`next` 用 [`Mutex`] 保护，只在取号时
/// 短暂持锁，不会覆盖真正的网络等待。
#[derive(Debug)]
pub(crate) struct RatePacer {
    /// 相邻两次任务启动的间隔。
    interval: Duration,
    /// 下一个允许启动的时刻。
    next: Mutex<tokio::time::Instant>,
}

impl RatePacer {
    /// 按每秒 `rate` 个任务构造限速器。
    ///
    /// # 参数
    ///
    /// * `rate` - 每秒允许启动的任务数，必须大于 0。
    ///
    /// # 返回
    ///
    /// * [`RatePacer`] - 首个任务可立即启动。
    ///
    /// # 异常
    ///
    /// `rate` 为 0 时 `1.0 / 0.0` 得到正无穷，间隔为 `Duration::MAX`，
    /// 因此调用方必须先过滤 `rate == 0`；本函数不做该检查。
    pub(crate) fn new(rate: u32) -> Self {
        Self {
            interval: Duration::from_secs_f64(1.0 / f64::from(rate)),
            next: Mutex::new(tokio::time::Instant::now()),
        }
    }

    /// 等待到本任务的允许启动时刻。
    ///
    /// # 参数
    ///
    /// * `cancel` - 取消令牌，取消时立即返回。
    ///
    /// # 返回
    ///
    /// * `true` - 已到号，可以启动任务。
    /// * `false` - 等待期间被取消，调用方应放弃该任务。
    pub(crate) async fn wait(&self, cancel: &CancellationToken) -> bool {
        let mut next = self.next.lock().await;
        let now = tokio::time::Instant::now();
        if *next > now {
            tokio::select! {
                _ = cancel.cancelled() => return false,
                _ = sleep_until(*next) => {}
            }
        }
        // 取号后立刻前移，保证后续任务不会挤在同一时刻。
        *next = std::cmp::max(*next, now) + self.interval;
        true
    }
}

/// 执行完整扫描并把所有结果收集到内存。
///
/// 适合库调用与测试；命令行路径应使用 [`scan_to_channel_with_cancel`]
/// 以流式消费结果，避免全量结果常驻内存。
///
/// # 参数
///
/// * `targets` - 目标表达式列表。
/// * `ports` - 端口列表。
/// * `config` - 扫描配置。
///
/// # 返回
///
/// * `Vec<ScanResult>` - 全部结果，顺序为完成顺序。
pub async fn scan(targets: &[String], ports: &[u16], config: &ScanConfig) -> Vec<ScanResult> {
    scan_with_cancel(targets, ports, config, CancellationToken::new()).await
}

/// 执行可取消的完整扫描并把所有结果收集到内存。
///
/// # 参数
///
/// * `targets` - 目标表达式列表。
/// * `ports` - 端口列表。
/// * `config` - 扫描配置。
/// * `cancel` - 取消令牌。
///
/// # 返回
///
/// * `Vec<ScanResult>` - 已完成的全部结果；被取消时只包含取消前完成的部分。
pub async fn scan_with_cancel(
    targets: &[String],
    ports: &[u16],
    config: &ScanConfig,
    cancel: CancellationToken,
) -> Vec<ScanResult> {
    let (sender, mut receiver) = mpsc::channel(config.result_buffer.max(1));
    let scan = scan_to_channel_with_cancel(targets, ports, config, sender, cancel);
    let collect = async move {
        let mut results = Vec::new();
        while let Some(batch) = receiver.recv().await {
            results.extend(batch);
        }
        results
    };
    let (_, results) = tokio::join!(scan, collect);
    results
}

/// 扫描并把结果写入通道（不可取消版本）。
///
/// # 参数
///
/// * `targets` / `ports` / `config` - 同 [`scan_to_channel_with_cancel`]。
/// * `sender` - 结果通道发送端。
pub async fn scan_to_channel(
    targets: &[String],
    ports: &[u16],
    config: &ScanConfig,
    sender: mpsc::Sender<Vec<ScanResult>>,
) {
    scan_to_channel_with_cancel(targets, ports, config, sender, CancellationToken::new()).await;
}

/// 扫描并把结果流式写入通道。
///
/// 函数在全部任务结束或取消后返回；返回时 `sender` 已被丢弃，
/// 因此消费者侧 `recv()` 会自然结束。
///
/// # 参数
///
/// * `targets` - 目标表达式列表；DNS 解析失败的目标会被跳过。
/// * `ports` - 端口列表。
/// * `config` - 扫描配置。
/// * `sender` - 结果通道发送端，容量即背压上限。
/// * `cancel` - 取消令牌；触发后不再下发新任务并在途任务尽快返回。
pub async fn scan_to_channel_with_cancel(
    targets: &[String],
    ports: &[u16],
    config: &ScanConfig,
    sender: mpsc::Sender<Vec<ScanResult>>,
    cancel: CancellationToken,
) {
    let (resolved, _failures) = resolve_targets(targets, config.connect_timeout, &cancel).await;
    #[cfg(unix)]
    if config.syn {
        crate::syn::scan_to_channel_with_cancel(resolved, ports, config, sender, cancel).await;
        return;
    }
    // 非 Unix 平台没有原始套接字；保守退回 connect 扫描，结果字段保持一致。
    scan_connect_resolved(resolved, ports, config, sender, cancel).await;
}

/// 对已解析目标执行 connect / UDP 扫描。
///
/// # 参数
///
/// * `resolved` - 已解析的目标列表。
/// * `ports` - 端口列表。
/// * `config` - 扫描配置。
/// * `sender` - 结果通道发送端。
/// * `cancel` - 取消令牌。
pub(crate) async fn scan_connect_resolved(
    resolved: Vec<ResolvedTarget>,
    ports: &[u16],
    config: &ScanConfig,
    sender: mpsc::Sender<Vec<ScanResult>>,
    cancel: CancellationToken,
) {
    let pacer = config
        .rate_limit
        .filter(|rate| *rate > 0)
        .map(RatePacer::new)
        .map(Arc::new);
    // `flat_map` 是惰性的：即使目标 × 端口达到百万级，也不会先构造完整任务表。
    let jobs = resolved.into_iter().flat_map(|target| {
        ports
            .iter()
            .copied()
            .map(move |port| (target.clone(), port))
    });

    stream::iter(jobs)
        .take_until(cancel.cancelled())
        .for_each_concurrent(config.concurrency.max(1), |(target, port)| {
            let sender = sender.clone();
            let pacer = pacer.clone();
            let cancel = cancel.clone();
            async move {
                if cancel.is_cancelled() {
                    return;
                }
                if let Some(pacer) = pacer
                    && !pacer.wait(&cancel).await
                {
                    return;
                }
                let result = match config.transport {
                    Transport::Tcp => scan_tcp(target, port, config, &cancel).await,
                    Transport::Udp => scan_udp(target, port, config, &cancel).await,
                };
                if let Some(result) = result {
                    // 消费者退出（写入失败）时发送会失败，此处静默丢弃即可。
                    let _ = sender.send(vec![result]).await;
                }
            }
        })
        .await;
    drop(sender);
}

/// 对目标列表做主机存活发现。
///
/// 优先 ICMP Echo；ICMP socket 不可用或无响应时，依次尝试
/// [`HostDiscoveryConfig::tcp_ports`] 的 TCP connect。连接成功或明确收到
/// `Connection refused` 都视为存活（后者说明主机在线且端口关闭）。
///
/// # 参数
///
/// * `targets` - 目标表达式列表。
/// * `config` - 发现配置。
/// * `cancel` - 取消令牌。
///
/// # 返回
///
/// * `Vec<HostDiscoveryResult>` - 每个 IP 一条结果，状态为
///   [`HostState::Alive`] 或 [`HostState::Unknown`]。
pub async fn discover_hosts(
    targets: &[String],
    config: &HostDiscoveryConfig,
    cancel: CancellationToken,
) -> Vec<HostDiscoveryResult> {
    let (resolved, _failures) = resolve_targets(targets, config.timeout, &cancel).await;
    let ping_v4 = config
        .icmp
        .then(|| PingClient::new(&PingConfig::default()).ok())
        .flatten()
        .map(Arc::new);
    let ping_v6 = config
        .icmp
        .then(|| PingClient::new(&PingConfig::builder().kind(ICMP::V6).build()).ok())
        .flatten()
        .map(Arc::new);

    stream::iter(resolved)
        .take_until(cancel.cancelled())
        .map(|target| {
            let cancel = cancel.clone();
            let ping_client = match target.ip {
                IpAddr::V4(_) => ping_v4.clone(),
                IpAddr::V6(_) => ping_v6.clone(),
            };
            async move { discover_one(target, config, ping_client, &cancel).await }
        })
        .buffer_unordered(config.concurrency.max(1))
        .filter_map(|result| async move { result })
        .collect()
        .await
}

/// 解析目标列表为 IP 地址。
///
/// IP 字面量直接使用；域名通过系统解析器查询，同名多地址（A + AAAA）
/// 全部展开并排序去重。
///
/// # 参数
///
/// * `targets` - 目标表达式列表。
/// * `resolve_timeout` - 单次 DNS 查询超时。
/// * `cancel` - 取消令牌。
///
/// # 返回
///
/// * `(Vec<ResolvedTarget>, Vec<(String, String)>)` - 左侧为成功解析的目标，
///   右侧为 `(主机名, 失败原因)` 列表，供调用方打印到 stderr 并决定退出码。
pub async fn resolve_targets(
    targets: &[String],
    resolve_timeout: Duration,
    cancel: &CancellationToken,
) -> (Vec<ResolvedTarget>, Vec<(String, String)>) {
    let concurrency = targets.len().clamp(1, RESOLVE_CONCURRENCY_MAX);
    type PerHostResult = (Vec<ResolvedTarget>, Option<(String, String)>);
    let per_host: Vec<PerHostResult> = stream::iter(targets.iter().cloned())
        .take_until(cancel.cancelled())
        .map(|host| {
            let cancel = cancel.clone();
            async move {
                if let Ok(ip) = host.parse::<IpAddr>() {
                    return (vec![ResolvedTarget { host, ip }], None);
                }
                // 端口 0 只是 `lookup_host` 的占位符，不会发起连接。
                let lookup = timeout(resolve_timeout, lookup_host((host.as_str(), 0)));
                let outcome = tokio::select! {
                    _ = cancel.cancelled() => return (Vec::new(), None),
                    result = lookup => result,
                };
                match outcome {
                    Ok(Ok(addresses)) => {
                        let mut ips = addresses.map(|address| address.ip()).collect::<Vec<_>>();
                        ips.sort_unstable();
                        ips.dedup();
                        if ips.is_empty() {
                            let host_for_error = host.clone();
                            return (
                                Vec::new(),
                                Some((host_for_error, "resolve returned no addresses".into())),
                            );
                        }
                        let resolved = ips
                            .into_iter()
                            .map(|ip| ResolvedTarget {
                                host: host.clone(),
                                ip,
                            })
                            .collect();
                        (resolved, None)
                    }
                    Ok(Err(error)) => (
                        Vec::new(),
                        Some((host.clone(), format!("resolve failed: {error}"))),
                    ),
                    Err(_) => (Vec::new(), Some((host.clone(), "resolve timed out".into()))),
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let mut resolved = Vec::new();
    let mut failures = Vec::new();
    for (targets, failure) in per_host {
        resolved.extend(targets);
        if let Some(failure) = failure {
            failures.push(failure);
        }
    }
    (resolved, failures)
}

/// 扫描单个 TCP 端口。
///
/// # 参数
///
/// * `target` - 已解析的目标。
/// * `port` - 端口号。
/// * `config` - 扫描配置。
/// * `cancel` - 取消令牌。
///
/// # 返回
///
/// * `Some(ScanResult)` - 连通或明确失败的结果。
/// * `None` - 等待期间被取消。
async fn scan_tcp(
    target: ResolvedTarget,
    port: u16,
    config: &ScanConfig,
    cancel: &CancellationToken,
) -> Option<ScanResult> {
    let started = Instant::now();
    let address = SocketAddr::new(target.ip, port);
    let connect = timeout(config.connect_timeout, TcpStream::connect(address));
    match tokio::select! {
        _ = cancel.cancelled() => return None,
        result = connect => result,
    } {
        Ok(Ok(mut socket)) => {
            let (fingerprint, banner) = if config.service_detection {
                tokio::select! {
                    _ = cancel.cancelled() => return None,
                    result = fingerprint_stream(&mut socket, &target.host, port, config.fingerprint_timeout) => result,
                }
            } else {
                (Fingerprint::default(), None)
            };
            Some(ScanResult {
                kind: "scan",
                host: target.host,
                ip: target.ip.to_string(),
                port,
                open: true,
                latency_ms: elapsed_millis(started),
                transport: Transport::Tcp,
                udp_state: None,
                tcp_state: None,
                service: fingerprint.service,
                product: fingerprint.product,
                version: fingerprint.version,
                banner,
                error: None,
            })
        }
        Ok(Err(error)) => Some(closed_tcp(target, port, started, error.to_string())),
        Err(_) => Some(closed_tcp(
            target,
            port,
            started,
            "connection timed out".into(),
        )),
    }
}

/// 扫描单个 UDP 端口。
///
/// 每个任务使用独立 socket，这样内核才能把 ICMP Port Unreachable 映射为
/// 该 socket 上的 `ConnectionRefused`，从而区分 `closed` 与 `open|filtered`。
/// 代价是每个端口多一次 `bind` / `connect` 系统调用。
///
/// # 参数
///
/// * `target` - 已解析的目标。
/// * `port` - 端口号。
/// * `config` - 扫描配置。
/// * `cancel` - 取消令牌。
///
/// # 返回
///
/// * `Some(ScanResult)` - 三种 UDP 状态之一；本地 socket 错误记为 `closed`。
/// * `None` - 等待期间被取消。
async fn scan_udp(
    target: ResolvedTarget,
    port: u16,
    config: &ScanConfig,
    cancel: &CancellationToken,
) -> Option<ScanResult> {
    let started = Instant::now();
    let bind_addr = match target.ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(error) => {
            return Some(udp_result(
                target,
                port,
                started,
                UdpState::Closed,
                None,
                Some(error.to_string()),
            ));
        }
    };
    if let Err(error) = socket.connect(SocketAddr::new(target.ip, port)).await {
        return Some(udp_result(
            target,
            port,
            started,
            UdpState::Closed,
            None,
            Some(error.to_string()),
        ));
    }
    let probe = udp_probe(port);
    if let Err(error) = socket.send(probe).await {
        return Some(udp_result(
            target,
            port,
            started,
            UdpState::Closed,
            None,
            Some(error.to_string()),
        ));
    }

    let mut buffer = [0_u8; MAX_BANNER_BYTES];
    let receive = timeout(config.connect_timeout, socket.recv(&mut buffer));
    match tokio::select! {
        _ = cancel.cancelled() => return None,
        result = receive => result,
    } {
        Ok(Ok(count)) => {
            let bytes = &buffer[..count];
            let banner = (!bytes.is_empty()).then(|| sanitize_banner(bytes));
            Some(udp_result(
                target,
                port,
                started,
                UdpState::Open,
                banner,
                None,
            ))
        }
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            Some(udp_result(
                target,
                port,
                started,
                UdpState::Closed,
                None,
                Some(error.to_string()),
            ))
        }
        Ok(Err(error)) => Some(udp_result(
            target,
            port,
            started,
            UdpState::OpenOrFiltered,
            None,
            Some(error.to_string()),
        )),
        Err(_) => Some(udp_result(
            target,
            port,
            started,
            UdpState::OpenOrFiltered,
            None,
            None,
        )),
    }
}

/// 对单台主机做存活探测。
///
/// # 参数
///
/// * `target` - 已解析的目标。
/// * `config` - 发现配置。
/// * `ping_client` - 对应地址族的 ICMP 客户端；`None` 表示 ICMP 不可用。
/// * `cancel` - 取消令牌。
///
/// # 返回
///
/// * `Some(HostDiscoveryResult)` - 存活或未知结果。
/// * `None` - 探测期间被取消。
async fn discover_one(
    target: ResolvedTarget,
    config: &HostDiscoveryConfig,
    ping_client: Option<Arc<PingClient>>,
    cancel: &CancellationToken,
) -> Option<HostDiscoveryResult> {
    let started = Instant::now();
    if let Some(client) = ping_client {
        let identifier = PingIdentifier(host_identifier(target.ip));
        let mut pinger = client.pinger(target.ip, identifier).await;
        pinger.timeout(config.timeout);
        let ping = pinger.ping(PingSequence(ICMP_SEQUENCE), PROBE_PAYLOAD);
        if let Ok((_packet, latency)) = tokio::select! {
            _ = cancel.cancelled() => return None,
            result = ping => result,
        } {
            return Some(HostDiscoveryResult {
                kind: "host",
                host: target.host,
                ip: target.ip.to_string(),
                state: HostState::Alive,
                method: "icmp".into(),
                latency_ms: duration_millis(latency),
            });
        }
    }

    for port in &config.tcp_ports {
        let connect = timeout(
            config.timeout,
            TcpStream::connect(SocketAddr::new(target.ip, *port)),
        );
        let result = tokio::select! {
            _ = cancel.cancelled() => return None,
            result = connect => result,
        };
        match result {
            Ok(Ok(_)) => {
                return Some(host_alive(target, started, format!("tcp/{port}")));
            }
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                // 明确拒绝说明主机在线，只是端口关闭。
                return Some(host_alive(target, started, format!("tcp/{port}-refused")));
            }
            _ => {}
        }
    }

    Some(HostDiscoveryResult {
        kind: "host",
        host: target.host,
        ip: target.ip.to_string(),
        state: HostState::Unknown,
        method: "no-response".into(),
        latency_ms: elapsed_millis(started),
    })
}

/// 在已建立的 TCP 连接上做服务指纹识别。
///
/// 策略按端口分流，避免把预算浪费在「对端根本不会说话」的场景上：
///
/// - **TLS 端口**：直接握手，采集版本 / 套件 / ALPN / 证书 CN，成功后
///   再补一次 `HEAD /`；握手失败说明并非 TLS，退回通用流程。
/// - **明文 HTTP 端口**：跳过被动等待，直接发 `HEAD /`。
/// - **其余端口**：先等 [`PASSIVE_WAIT`] 的被动 banner；识别不出时再用
///   [`PROBE_WAIT`] 的短窗口补一次 HTTP 探针。
///
/// 任何一次读取只要拿到数据就立即返回，不会等满整个预算。
///
/// # 参数
///
/// * `socket` - 已连通的 TCP 流。
/// * `host` - 原始主机名，用于 `Host:` 头与 TLS `SNI`。
/// * `port` - 目标端口。
/// * `fingerprint_timeout` - 本次识别的总预算。
///
/// # 返回
///
/// * `(Fingerprint, Option<String>)` - 指纹与清洗后的 banner。
async fn fingerprint_stream(
    socket: &mut TcpStream,
    host: &str,
    port: u16,
    fingerprint_timeout: Duration,
) -> (Fingerprint, Option<String>) {
    if fingerprint::is_tls_port(port) {
        if let Some(info) = tls::probe(
            socket,
            host,
            fingerprint_timeout,
            fingerprint::is_https_port(port),
        )
        .await
        {
            return tls_fingerprint(&info, port);
        }
        // 握手失败后连接里已经有半截 handshake 数据，继续探测没有意义；
        // 直接退回端口表，保证总耗时不超过 `fingerprint_timeout`。
        return (fingerprint::port_fallback(port), None);
    }

    let deadline = tokio::time::Instant::now() + fingerprint_timeout;
    let passive_wait = if fingerprint::is_http_port(port) {
        Duration::ZERO
    } else {
        PASSIVE_WAIT.min(fingerprint_timeout)
    };
    let mut banner = Vec::with_capacity(BANNER_INITIAL_CAPACITY);
    read_banner(socket, &mut banner, passive_wait).await;
    let mut result = fingerprint::identify(port, &banner);

    if !result.is_complete()
        && matches!(result.service.as_deref(), None | Some("http" | "https"))
        && let Some(probed) = probe_http(socket, host, &mut banner, deadline).await
    {
        result = probed;
    }

    if !result.is_identified() {
        result = fingerprint::port_fallback(port);
    }
    let banner = (!banner.is_empty()).then(|| sanitize_banner(&banner));
    (result, banner)
}

/// 补发一次明文 `HEAD /`，把响应头解析成指纹。
///
/// # 参数
///
/// * `socket` - 已连通的 TCP 流。
/// * `host` - 原始主机名，用于 `Host:` 头。
/// * `banner` - 累计缓冲区，探针响应会追加到这里。
/// * `deadline` - 本次识别的绝对截止时刻。
///
/// # 返回
///
/// * `Some(Fingerprint)` - 响应里确实出现了 `HTTP/` 状态行。
/// * `None` - 写入或读取失败、超时，或响应不是 HTTP。
async fn probe_http(
    socket: &mut TcpStream,
    host: &str,
    banner: &mut Vec<u8>,
    deadline: tokio::time::Instant,
) -> Option<Fingerprint> {
    let remaining = deadline.checked_duration_since(tokio::time::Instant::now())?;
    let wait = remaining.min(PROBE_WAIT);
    let request = HTTP_PROBE_TEMPLATE.replace("{host}", host);
    if timeout(wait, socket.write_all(request.as_bytes()))
        .await
        .ok()?
        .is_err()
    {
        return None;
    }

    let before = banner.len();
    read_banner(socket, banner, wait).await;
    if banner.len() == before {
        return None;
    }
    let text = String::from_utf8_lossy(banner);
    let offset = text.to_ascii_lowercase().find("http/")?;
    Some(fingerprint::identify_http(&text[offset..], false))
}

/// 把 TLS 采集结果映射为扫描指纹与 banner。
///
/// 优先采用握手后 HTTP 响应里的产品 / 版本（如 `nginx 1.25.3`）；没有
/// HTTP 响应时退回端口表给出的服务名，版本取协商出的 TLS 版本。
///
/// # 参数
///
/// * `info` - TLS 握手采集结果。
/// * `port` - 目标端口，用于端口表回退。
///
/// # 返回
///
/// * `(Fingerprint, Option<String>)` - 指纹与单行 TLS 摘要。
fn tls_fingerprint(info: &TlsInfo, port: u16) -> (Fingerprint, Option<String>) {
    let http = info.http.clone().filter(|found| found.product.is_some());
    let service = http
        .as_ref()
        .and_then(|found| found.service.clone())
        .or_else(|| fingerprint::service_for_port(port).map(str::to_string))
        .or_else(|| Some("tls".to_string()));
    let product = http.as_ref().and_then(|found| found.product.clone());
    let version = http
        .as_ref()
        .and_then(|found| found.version.clone())
        .or_else(|| info.version.clone());
    let summary = info.summary();
    let banner = (!summary.is_empty()).then(|| sanitize_banner(summary.as_bytes()));
    (
        Fingerprint {
            service,
            product,
            version,
        },
        banner,
    )
}

/// 读取一次 banner，受等待时间与全局上限双重约束。
///
/// # 参数
///
/// * `socket` - TCP 流。
/// * `banner` - 累计缓冲区；达到 [`MAX_BANNER_BYTES`] 后不再追加。
/// * `wait` - 本次读取的最长等待时间。
async fn read_banner(socket: &mut TcpStream, banner: &mut Vec<u8>, wait: Duration) {
    if banner.len() >= MAX_BANNER_BYTES || wait.is_zero() {
        return;
    }
    let mut buffer = [0_u8; BANNER_CHUNK_BYTES];
    if let Ok(Ok(count)) = timeout(wait, socket.read(&mut buffer)).await {
        banner.extend_from_slice(&buffer[..count.min(MAX_BANNER_BYTES - banner.len())]);
    }
}

/// 选择 UDP 探针载荷。
///
/// # 参数
///
/// * `port` - 目标端口。
///
/// # 返回
///
/// * `&'static [u8]` - 53 用最小 DNS 查询，123 用 NTP client 请求，
///   其余端口用通用 [`PROBE_PAYLOAD`]。
fn udp_probe(port: u16) -> &'static [u8] {
    match port {
        53 => UDP_DNS_PROBE,
        123 => UDP_NTP_PROBE,
        _ => PROBE_PAYLOAD,
    }
}

/// 组装 UDP 扫描结果。
///
/// # 参数
///
/// * `target` - 目标。
/// * `port` - 端口。
/// * `started` - 任务开始时刻。
/// * `state` - UDP 状态。
/// * `banner` - 清洗后的响应文本。
/// * `error` - 错误描述。
///
/// # 返回
///
/// * [`ScanResult`] - `service` 取自端口表。
fn udp_result(
    target: ResolvedTarget,
    port: u16,
    started: Instant,
    state: UdpState,
    banner: Option<String>,
    error: Option<String>,
) -> ScanResult {
    let service = fingerprint::service_for_port(port).map(str::to_owned);
    ScanResult {
        kind: "scan",
        host: target.host,
        ip: target.ip.to_string(),
        port,
        open: state != UdpState::Closed,
        latency_ms: elapsed_millis(started),
        transport: Transport::Udp,
        udp_state: Some(state),
        tcp_state: None,
        service,
        product: None,
        version: None,
        banner,
        error,
    }
}

/// 组装 TCP 失败结果。
///
/// # 参数
///
/// * `target` - 目标。
/// * `port` - 端口。
/// * `started` - 任务开始时刻。
/// * `error` - 失败原因文本。
///
/// # 返回
///
/// * [`ScanResult`] - `open = false`，指纹字段为空。
fn closed_tcp(target: ResolvedTarget, port: u16, started: Instant, error: String) -> ScanResult {
    ScanResult {
        kind: "scan",
        host: target.host,
        ip: target.ip.to_string(),
        port,
        open: false,
        latency_ms: elapsed_millis(started),
        transport: Transport::Tcp,
        udp_state: None,
        tcp_state: None,
        service: None,
        product: None,
        version: None,
        banner: None,
        error: Some(error),
    }
}

/// 组装「主机存活」结果。
///
/// # 参数
///
/// * `target` - 目标。
/// * `started` - 发现开始时刻。
/// * `method` - 判定方法文本。
///
/// # 返回
///
/// * [`HostDiscoveryResult`] - 状态固定为 [`HostState::Alive`]。
fn host_alive(target: ResolvedTarget, started: Instant, method: String) -> HostDiscoveryResult {
    HostDiscoveryResult {
        kind: "host",
        host: target.host,
        ip: target.ip.to_string(),
        state: HostState::Alive,
        method,
        latency_ms: elapsed_millis(started),
    }
}

/// 由 IP 派生 ICMP 标识符。
///
/// 把地址各段折叠成一个 `u16`。注意这是**弱哈希**：不同 IP 可能得到相同
/// 值（如 `10.0.1.0` 与 `10.0.0.1`），因此不能把它当作唯一键使用。
///
/// # 参数
///
/// * `ip` - 目标地址。
///
/// # 返回
///
/// * `u16` - 用于 `PingIdentifier` 的稳定值。
fn host_identifier(ip: IpAddr) -> u16 {
    match ip {
        IpAddr::V4(ip) => ip
            .octets()
            .into_iter()
            .fold(0_u16, |acc, byte| acc.wrapping_add(u16::from(byte))),
        IpAddr::V6(ip) => ip.segments().into_iter().fold(0_u16, u16::wrapping_add),
    }
}

/// 清洗 banner：控制字符替换为空格，连续空白折叠成单个空格。
///
/// 目的是让不可信的服务输出在终端里安全可读，避免 ANSI 转义序列注入。
///
/// # 参数
///
/// * `bytes` - 原始响应字节。
///
/// # 返回
///
/// * `String` - 单行化、去控制字符后的文本。
fn sanitize_banner(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|character| {
            // 只保留制表符，其余控制字符（含 ESC）一律降级为空格。
            if character.is_control() && !matches!(character, '\t') {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// 把 `Duration` 转为毫秒并饱和到 `u64`。
///
/// # 参数
///
/// * `duration` - 待转换的时长。
///
/// # 返回
///
/// * `u64` - 毫秒数，超过 `u64::MAX` 时截断。
fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

/// 计算自 `started` 起经过的毫秒数。
///
/// # 参数
///
/// * `started` - 起始时刻。
///
/// # 返回
///
/// * `u64` - 经过的毫秒数。
pub(crate) fn elapsed_millis(started: Instant) -> u64 {
    duration_millis(started.elapsed())
}
