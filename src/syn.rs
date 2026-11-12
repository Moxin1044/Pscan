//! 基于原始套接字的 TCP SYN 扫描（半开扫描）。
//!
//! 与 connect 扫描的区别：只发 SYN，不完成三次握手，因此不会在目标上留下
//! 完整连接记录，单探针开销也更低。代价是需要创建原始套接字，通常要 root
//! 或 `CAP_NET_RAW`：
//!
//! ```bash
//! sudo setcap cap_net_raw+ep ./pscan
//! ```
//!
//! 判定规则：
//!
//! - 收到 `SYN-ACK` → `open`，本端内核随后会回 `RST` 终止这个半开连接；
//! - 收到 `RST` → `closed`；
//! - 超时无响应 → `filtered`（可能被防火墙丢弃，也可能是链路丢包）。
//!
//! 仅支持 IPv4 目标；IPv6 目标会自动退回 connect 扫描，结果字段一致，
//! 只是速度慢一些。
//!
//! # 实现要点
//!
//! 扫描主循环是**阻塞**实现，整体放在 [`tokio::task::spawn_blocking`] 里：
//!
//! - 发送端用 `sendmmsg`（Linux）一次提交一批报文，非 Linux 平台退化为逐包
//!   `sendto`；
//! - 接收端用独立的阻塞线程 + `recvmmsg` 批量收包，把解析结果成批交给主循环；
//! - 在途探针直接用「端口号下标」的定长数组表示，避免每探针一次哈希；
//! - TCP 校验和按伪首部预计算值 + 变化字段增量求出，不再整包重算；
//! - 时钟按毫秒粒度每轮取一次，不为每个探针单独取时。

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc as async_mpsc;
pub use tokio_util::sync::CancellationToken;

use crate::fingerprint;
use crate::scanner::{ResolvedTarget, ScanResult, TcpState, Transport, scan_connect_resolved};

/// 一个完整 SYN 报文（20 字节 IP 首部 + 20 字节 TCP 首部）的长度。
const SYN_PACKET_LEN: usize = 40;

/// IPv4 首部长度。
const IP_HEADER_LEN: usize = 20;

/// 不含选项的 TCP 首部长度。
const TCP_HEADER_LEN: usize = 20;

/// TCP `SYN` 标志位。
const TCP_FLAG_SYN: u8 = 0x02;

/// TCP `RST` 标志位。
const TCP_FLAG_RST: u8 = 0x04;

/// TCP `ACK` 标志位。
const TCP_FLAG_ACK: u8 = 0x10;

/// `SYN | ACK` 组合，用于判断握手应答。
const TCP_FLAGS_SYN_ACK: u8 = TCP_FLAG_SYN | TCP_FLAG_ACK;

/// 探针的 TTL；1 跳以内的目标都能收到，也避免探针在广域网上跑太远。
const SYN_TTL: u8 = 64;

/// 探针声明的接收窗口；值本身不影响判定。
const SYN_WINDOW: u16 = 65535;

/// IP 标识字段。扫描关心的是端口而不是分片重组，固定值可以让首部校验和
/// 在整场扫描中只算一次。
const IP_ID: u16 = 0x1234;

/// 每批提交的报文数：`sendmmsg` 一次系统调用能带走的最大包数。
///
/// 256 是在「一次系统调用摊薄到每个包的开销」与「单批构造耗时」之间的
/// 折中；再大时单批构造的 CPU 时间会盖过系统调用省下来的部分。
const SEND_BATCH: usize = 256;

/// 接收线程每批读取的报文数。
const RECV_BATCH: usize = 64;

/// 接收缓冲区中单个报文的最大长度，覆盖常见以太网 MTU 与 IP 选项。
const MAX_PACKET_BYTES: usize = 2048;

/// 接收线程与主循环之间结果队列的容量（以「批」为单位）。
const REPLY_CHANNEL_CAPACITY: usize = 1024;

/// 接收套接字缓冲区大小；高并发扫描时内核会一次性堆很多 SYN-ACK。
const RECV_SOCKET_BUFFER: i32 = 16 * 1024 * 1024;

/// 接收线程单次阻塞的上限：足够短以及时响应取消，又避免空转。
const RECV_POLL_MILLIS: i32 = 1;

/// 主循环在无事可做时最长的阻塞时间；用于定期检查取消标志。
const WAIT_SLICE_MILLIS: u64 = 50;

/// 源端口范围的起点。
const SOURCE_PORT_MIN: u16 = 40_000;

/// 源端口范围的宽度。
const SOURCE_PORT_SPAN: u16 = 20_000;

/// 发送缓冲满时的重试间隔。
const SEND_RETRY_DELAY: Duration = Duration::from_millis(1);

/// 发送失败的最大重试次数。
const SEND_RETRIES: usize = 3;

/// 端口号的取值上限（`u16::MAX`），用作探针数组长度。
const PORT_COUNT: usize = u16::MAX as usize + 1;

/// 内核送来的 TCP 报文（已从 IP / TCP 首部解出判定所需的字段）。
#[derive(Debug, Clone, Copy)]
struct TcpReply {
    /// 报文的目的地址，即本机地址。
    dst: Ipv4Addr,
    /// 报文源端口，即被扫描的目标端口。
    source_port: u16,
    /// 报文目的端口，即本机伪装的源端口。
    dest_port: u16,
    /// TCP 确认号；`SYN-ACK` 下等于我方序号 + 1。
    ack: u32,
    /// TCP 标志位。
    flags: u8,
}

/// 在途探针的状态。
///
/// 按端口号下标存放；`sequence == 0` 表示该端口当前没有在途探针。
#[derive(Debug, Clone, Copy, Default)]
struct ProbeState {
    /// 我方发出的 TCP 序号，用于校验 `SYN-ACK` 的确认号。
    sequence: u32,
    /// 探测开始时刻（相对本次目标扫描起点的毫秒数）。
    started_ms: u64,
    /// 超时时刻（相对本次目标扫描起点的毫秒数）。
    deadline_ms: u64,
}

/// 检查当前进程是否有权限发起 SYN 扫描。
///
/// 通过真实创建一个原始套接字判断，避免用 `geteuid() == 0` 误判
/// （带 `CAP_NET_RAW` 的非 root 进程同样可以扫描）。
///
/// # 返回
///
/// * `Ok(())` - 可以创建原始套接字。
/// * `Err(String)` - 权限不足或平台不支持，内容可直接展示给用户。
pub fn preflight() -> Result<(), String> {
    open_raw_socket()
        .map(|_| ())
        .map_err(|error| describe_error(&error))
}

/// 扫描入口：对已解析目标执行 SYN 扫描，结果流式写入通道。
///
/// IPv6 目标会先退回 connect 扫描执行完，再处理 IPv4 目标。
///
/// # 参数
///
/// * `resolved` - 已解析的目标列表。
/// * `ports` - 端口列表。
/// * `config` - 扫描配置（使用 `concurrency`、`connect_timeout` 与 `rate_limit`）。
/// * `sender` - 结果通道发送端。
/// * `cancel` - 取消令牌。
pub async fn scan_to_channel_with_cancel(
    resolved: Vec<ResolvedTarget>,
    ports: &[u16],
    config: &crate::scanner::ScanConfig,
    sender: async_mpsc::Sender<Vec<ScanResult>>,
    cancel: CancellationToken,
) {
    let (ipv6, ipv4): (Vec<_>, Vec<_>) = resolved
        .into_iter()
        .partition(|target| !target.ip.is_ipv4());
    if !ipv6.is_empty() {
        scan_connect_resolved(ipv6, ports, config, sender.clone(), cancel.clone()).await;
    }
    if ipv4.is_empty() {
        return;
    }

    let ports: Vec<u16> = ports.to_vec();
    let concurrency = config.concurrency.max(1);
    let timeout = config.connect_timeout;
    let rate_limit = config.rate_limit.filter(|rate| *rate > 0);
    let cancelled = Arc::new(AtomicBool::new(false));
    let watcher = {
        let cancelled = cancelled.clone();
        tokio::spawn(async move {
            cancel.cancelled().await;
            cancelled.store(true, Ordering::Relaxed);
        })
    };
    let engine = tokio::task::spawn_blocking(move || {
        run_syn_scan(
            ipv4,
            &ports,
            concurrency,
            timeout,
            rate_limit,
            sender,
            cancelled,
        );
    });
    let _ = engine.await;
    watcher.abort();
}

/// 阻塞式 SYN 扫描引擎：创建套接字、启动接收线程，并逐个目标扫描。
///
/// # 参数
///
/// * `resolved` - IPv4 目标列表。
/// * `ports` - 端口列表。
/// * `concurrency` - 同时在途的探针上限。
/// * `timeout` - 单个探针的判定超时。
/// * `rate_limit` - 每秒探针上限；`None` 表示不限速。
/// * `sender` - 结果通道发送端。
/// * `cancelled` - 取消标志。
fn run_syn_scan(
    resolved: Vec<ResolvedTarget>,
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
    rate_limit: Option<u32>,
    sender: async_mpsc::Sender<Vec<ScanResult>>,
    cancelled: Arc<AtomicBool>,
) {
    let socket = match open_raw_socket() {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("pscan: cannot start SYN scan: {}", describe_error(&error));
            return;
        }
    };
    let Some(listen) = duplicate(&socket) else {
        eprintln!("pscan: cannot start SYN scan: failed to duplicate socket");
        return;
    };

    let stop = Arc::new(AtomicBool::new(false));
    let (reply_tx, reply_rx) = mpsc::sync_channel::<Vec<TcpReply>>(REPLY_CHANNEL_CAPACITY);
    let receiver = {
        let stop = stop.clone();
        std::thread::spawn(move || receive_loop(listen, stop, reply_tx))
    };

    // 65536 个端口的探针槽位，整场扫描复用，不逐目标重新分配。
    let mut probes = vec![ProbeState::default(); PORT_COUNT];
    for target in resolved {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        let IpAddr::V4(ip) = target.ip else {
            continue;
        };
        scan_one(
            &socket,
            ip,
            &target.host,
            ports,
            concurrency,
            timeout,
            rate_limit,
            &mut probes,
            &reply_rx,
            &sender,
            &cancelled,
        );
    }

    stop.store(true, Ordering::Relaxed);
    let _ = receiver.join();
}

/// 扫描单个 IPv4 目标。
///
/// # 参数
///
/// * `socket` - 发送用原始套接字。
/// * `ip` - 目标地址。
/// * `host` - 目标的文本形式，写入结果。
/// * `ports` - 端口列表。
/// * `concurrency` - 同时在途的探针上限。
/// * `timeout` - 单个探针的判定超时。
/// * `rate_limit` - 每秒探针上限；`None` 表示不限速。
/// * `probes` - 复用的探针槽位表。
/// * `reply_rx` - 接收线程送来的响应批次。
/// * `sender` - 结果通道发送端。
/// * `cancelled` - 取消标志。
#[allow(clippy::too_many_arguments)]
fn scan_one(
    socket: &OwnedFd,
    ip: Ipv4Addr,
    host: &str,
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
    rate_limit: Option<u32>,
    probes: &mut [ProbeState],
    reply_rx: &mpsc::Receiver<Vec<TcpReply>>,
    sender: &async_mpsc::Sender<Vec<ScanResult>>,
    cancelled: &AtomicBool,
) {
    // 槽位表按端口下标复用；上一个目标被取消时可能留有残值，先清空。
    probes.fill(ProbeState::default());
    let source_port = allocate_source_port();
    let source = source_ip_for(ip);
    let timeout_ms = duration_millis(timeout).max(1);
    let interval = rate_limit.map(|rate| Duration::from_secs_f64(1.0 / f64::from(rate)));
    let mut next_send: Option<Instant> = interval.map(|_| Instant::now());
    let mut batch = BatchSender::new(source, source_port, ip);

    let start = Instant::now();
    let mut sequence = initial_sequence();
    let mut index = 0usize;
    let mut in_flight = 0usize;
    let mut active: Vec<u16> = Vec::with_capacity(concurrency.min(ports.len()).saturating_add(1));
    // 端口 -> 在 active 中的下标；`u32::MAX` 表示不在途。用于 O(1) 移除。
    let mut positions = vec![u32::MAX; PORT_COUNT];

    loop {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        let now_ms = duration_millis(start.elapsed());

        // 1. 把接收线程已经送到队列里的响应一次抽干。
        let mut progressed = false;
        while let Ok(replies) = reply_rx.try_recv() {
            if absorb_replies(
                &replies,
                ip,
                source_port,
                probes,
                &mut active,
                &mut positions,
                &mut in_flight,
                now_ms,
                host,
                sender,
                cancelled,
            ) {
                progressed = true;
            }
        }

        // 2. 结算超时的探针。
        let mut expired: Vec<ScanResult> = Vec::new();
        let mut position = 0usize;
        while position < active.len() {
            let port = active[position];
            let probe = probes[usize::from(port)];
            if probe.sequence != 0 && probe.deadline_ms <= now_ms {
                let latency_ms = now_ms.saturating_sub(probe.started_ms);
                probes[usize::from(port)] = ProbeState::default();
                in_flight = in_flight.saturating_sub(1);
                deactivate(port, &mut active, &mut positions);
                expired.push(syn_result(host, ip, port, TcpState::Filtered, latency_ms));
                progressed = true;
            } else {
                position += 1;
            }
        }

        if !expired.is_empty() && !emit_batch(sender, cancelled, expired) {
            return;
        }

        // 3. 补充新探针，凑满一批后一次提交。
        let mut queued = 0usize;
        while in_flight < concurrency && index < ports.len() && queued < SEND_BATCH {
            let port = ports[index];
            index += 1;
            if probes[usize::from(port)].sequence != 0 {
                continue;
            }
            if let (Some(interval), Some(next)) = (interval, next_send) {
                let now = Instant::now();
                if now < next {
                    std::thread::sleep(next - now);
                }
                next_send = Some(next + interval);
            }
            sequence = sequence.wrapping_add(1);
            probes[usize::from(port)] = ProbeState {
                sequence,
                started_ms: now_ms,
                deadline_ms: now_ms + timeout_ms,
            };
            positions[usize::from(port)] = active.len() as u32;
            active.push(port);
            in_flight += 1;
            batch.push(port, sequence);
            queued += 1;
        }
        if queued > 0 && batch.flush(socket).is_err() {
            // 发送失败时这批探针会在超时后结算为 filtered，不影响整体流程。
            eprintln!("pscan: SYN packet send failed; some probes will time out");
        }

        if index >= ports.len() && in_flight == 0 {
            break;
        }
        if queued == 0 && !progressed {
            // 无事可做时阻塞等待：以最近的超时时刻为上限，并周期性醒来检查取消。
            let wait_ms = active
                .iter()
                .map(|port| probes[usize::from(*port)].deadline_ms)
                .min()
                .map_or(WAIT_SLICE_MILLIS, |deadline| {
                    deadline.saturating_sub(now_ms)
                })
                .clamp(1, WAIT_SLICE_MILLIS);
            if let Ok(replies) = reply_rx.recv_timeout(Duration::from_millis(wait_ms)) {
                absorb_replies(
                    &replies,
                    ip,
                    source_port,
                    probes,
                    &mut active,
                    &mut positions,
                    &mut in_flight,
                    now_ms,
                    host,
                    sender,
                    cancelled,
                );
                continue;
            }
        }
    }
}

/// 把端口从在途列表里移除，并维护「端口 -> 下标」映射。
///
/// 用「与末尾交换」的方式删除，保证 O(1)；被换过来的端口同步更新下标。
///
/// # 参数
///
/// * `port` - 要移除的端口。
/// * `active` - 在途端口列表。
/// * `positions` - 端口到列表下标的映射。
fn deactivate(port: u16, active: &mut Vec<u16>, positions: &mut [u32]) {
    let index = usize::from(port);
    let slot = positions[index];
    if slot == u32::MAX {
        return;
    }
    positions[index] = u32::MAX;
    let last = active.len().saturating_sub(1);
    active.swap_remove(slot as usize);
    if (slot as usize) != last {
        let moved = active[slot as usize];
        positions[usize::from(moved)] = slot;
    }
}

/// 处理一批响应，把命中的探针结算成结果。
///
/// # 参数
///
/// * `replies` - 接收线程解析出的响应。
/// * `ip` - 当前目标地址。
/// * `source_port` - 本次扫描使用的本机源端口。
/// * `probes` - 探针槽位表。
/// * `active` - 在途端口列表。
/// * `in_flight` - 在途探针计数。
/// * `now_ms` - 当前时刻（相对扫描起点）。
/// * `host` - 目标文本形式。
/// * `sender` - 结果通道。
/// * `cancelled` - 取消标志。
///
/// # 返回
///
/// * `true` - 至少结算了一条结果。
/// * `false` - 没有命中任何在途探针。
#[allow(clippy::too_many_arguments)]
fn absorb_replies(
    replies: &[TcpReply],
    ip: Ipv4Addr,
    source_port: u16,
    probes: &mut [ProbeState],
    active: &mut Vec<u16>,
    positions: &mut [u32],
    in_flight: &mut usize,
    now_ms: u64,
    host: &str,
    sender: &async_mpsc::Sender<Vec<ScanResult>>,
    cancelled: &AtomicBool,
) -> bool {
    let mut handled = false;
    let mut results: Vec<ScanResult> = Vec::with_capacity(replies.len());
    for reply in replies {
        if reply.dst != ip || reply.dest_port != source_port {
            continue;
        }
        let slot = &mut probes[usize::from(reply.source_port)];
        if slot.sequence == 0 {
            continue;
        }
        let is_syn_ack = reply.flags & TCP_FLAGS_SYN_ACK == TCP_FLAGS_SYN_ACK
            && reply.ack == slot.sequence.wrapping_add(1);
        let is_reset = reply.flags & TCP_FLAG_RST != 0;
        if !is_syn_ack && !is_reset {
            continue;
        }
        let state = if is_reset {
            TcpState::Closed
        } else {
            TcpState::Open
        };
        let latency_ms = now_ms.saturating_sub(slot.started_ms);
        *slot = ProbeState::default();
        *in_flight = in_flight.saturating_sub(1);
        deactivate(reply.source_port, active, positions);
        handled = true;
        results.push(syn_result(host, ip, reply.source_port, state, latency_ms));
    }
    if !results.is_empty() && !emit_batch(sender, cancelled, results) {
        cancelled.store(true, Ordering::Relaxed);
    }
    handled
}

/// 向结果通道发送一批结果。
///
/// # 参数
///
/// * `sender` - 结果通道。
/// * `cancelled` - 取消标志；通道关闭时置位以便主循环尽快退出。
/// * `results` - 待发送结果批次。
///
/// # 返回
///
/// * `true` - 发送成功。
/// * `false` - 接收端已关闭，调用方应停止扫描。
fn emit_batch(
    sender: &async_mpsc::Sender<Vec<ScanResult>>,
    cancelled: &AtomicBool,
    results: Vec<ScanResult>,
) -> bool {
    if results.is_empty() {
        return true;
    }
    if sender.blocking_send(results).is_ok() {
        true
    } else {
        cancelled.store(true, Ordering::Relaxed);
        false
    }
}

/// 组装 SYN 扫描结果。
///
/// # 参数
///
/// * `host` - 目标文本形式。
/// * `ip` - 目标 IPv4 地址。
/// * `port` - 目标端口。
/// * `state` - 判定结果。
/// * `latency_ms` - 探针从发出到判定的毫秒数。
///
/// # 返回
///
/// * [`ScanResult`] - 服务名取端口表，`open` 仅对 `open` 状态为真。
fn syn_result(host: &str, ip: Ipv4Addr, port: u16, state: TcpState, latency_ms: u64) -> ScanResult {
    ScanResult {
        kind: "scan",
        host: host.to_owned(),
        ip: ip.to_string(),
        port,
        open: state == TcpState::Open,
        latency_ms,
        transport: Transport::Tcp,
        udp_state: None,
        tcp_state: Some(state),
        service: fingerprint::service_for_port(port).map(str::to_owned),
        product: None,
        version: None,
        banner: None,
        error: None,
    }
}

/// 创建发送 / 接收共用的原始套接字。
///
/// 打开 `IP_HDRINCL` 后由调用方自行拼装 IP 首部；同时放大接收缓冲区，
/// 避免高并发下 SYN-ACK 被内核丢弃。
///
/// # 返回
///
/// * `Ok(OwnedFd)` - 配置完成的原始套接字。
/// * `Err(io::Error)` - 权限不足或系统调用失败。
fn open_raw_socket() -> io::Result<OwnedFd> {
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    set_int_option(socket.as_raw_fd(), libc::IPPROTO_IP, libc::IP_HDRINCL, 1)?;
    set_int_option(
        socket.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        RECV_SOCKET_BUFFER,
    )?;
    set_int_option(
        socket.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_SNDBUF,
        RECV_SOCKET_BUFFER,
    )?;
    Ok(socket)
}

/// 复制一个文件描述符。
///
/// # 参数
///
/// * `socket` - 原始套接字。
///
/// # 返回
///
/// * `Some(OwnedFd)` - 新的描述符，接收线程负责关闭。
/// * `None` - `dup` 失败。
fn duplicate(socket: &OwnedFd) -> Option<OwnedFd> {
    let fd = unsafe { libc::dup(socket.as_raw_fd()) };
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// 设置一个 `c_int` 类型的套接字选项。
///
/// # 参数
///
/// * `fd` - 套接字描述符。
/// * `level` - 选项层级。
/// * `name` - 选项名。
/// * `value` - 选项值。
///
/// # 返回
///
/// * `Ok(())` - 设置成功。
/// * `Err(io::Error)` - 系统调用失败。
fn set_int_option(fd: i32, level: i32, name: i32, value: i32) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&value as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// 接收线程主循环：把内核送来的 TCP 报文解析成批转发给扫描主循环。
///
/// Linux 上用 `recvmmsg` 一次收一批；其它平台逐包 `recv`。两种情况都设置了
/// `SO_RCVTIMEO`，让线程定期醒来观察取消标志。
///
/// # 参数
///
/// * `socket` - 只用于接收的原始套接字副本。
/// * `stop` - 取消标志，主循环结束时置位。
/// * `replies` - 解析结果批次通道。
fn receive_loop(socket: OwnedFd, stop: Arc<AtomicBool>, replies: mpsc::SyncSender<Vec<TcpReply>>) {
    #[cfg(target_os = "linux")]
    receive_loop_linux(socket, stop, replies);
    #[cfg(not(target_os = "linux"))]
    receive_loop_portable(socket, stop, replies);
}

/// Linux 批量接收实现。
///
/// # 参数
///
/// * `socket` - 接收套接字。
/// * `stop` - 取消标志。
/// * `replies` - 解析结果批次通道。
#[cfg(target_os = "linux")]
fn receive_loop_linux(
    socket: OwnedFd,
    stop: Arc<AtomicBool>,
    replies: mpsc::SyncSender<Vec<TcpReply>>,
) {
    let fd = socket.as_raw_fd();
    let mut storage = vec![0u8; RECV_BATCH * MAX_PACKET_BYTES];
    let mut iovecs: Vec<libc::iovec> = (0..RECV_BATCH)
        .map(|_| libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        })
        .collect();
    let mut messages: Vec<libc::mmsghdr> = (0..RECV_BATCH)
        .map(|_| unsafe { std::mem::zeroed() })
        .collect();

    while !stop.load(Ordering::Relaxed) {
        for index in 0..RECV_BATCH {
            iovecs[index] = libc::iovec {
                iov_base: unsafe { storage.as_mut_ptr().add(index * MAX_PACKET_BYTES) }.cast(),
                iov_len: MAX_PACKET_BYTES,
            };
            messages[index].msg_hdr.msg_iov = unsafe { iovecs.as_mut_ptr().add(index) };
            messages[index].msg_hdr.msg_iovlen = 1;
            messages[index].msg_hdr.msg_name = std::ptr::null_mut();
            messages[index].msg_hdr.msg_namelen = 0;
            messages[index].msg_len = 0;
        }
        // 先 poll 再收：避免 recvmmsg 在 SO_RCVTIMEO 上整段睡眠。
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, RECV_POLL_MILLIS) };
        if ready <= 0 {
            continue;
        }
        let count = unsafe {
            libc::recvmmsg(
                fd,
                messages.as_mut_ptr(),
                RECV_BATCH as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if count <= 0 {
            continue;
        }
        let mut batch = Vec::with_capacity(count as usize);
        for (index, message) in messages.iter().take(count as usize).enumerate() {
            let length = message.msg_len as usize;
            if length == 0 {
                continue;
            }
            let offset = index * MAX_PACKET_BYTES;
            if let Some(reply) = parse_tcp_packet(&storage[offset..offset + length]) {
                batch.push(reply);
            }
        }
        if !batch.is_empty() && !forward_batch(&replies, &stop, batch) {
            break;
        }
    }
}

/// 非 Linux 平台的逐包接收实现。
///
/// # 参数
///
/// * `socket` - 接收套接字。
/// * `stop` - 取消标志。
/// * `replies` - 解析结果批次通道。
#[cfg(not(target_os = "linux"))]
fn receive_loop_portable(
    socket: OwnedFd,
    stop: Arc<AtomicBool>,
    replies: mpsc::SyncSender<Vec<TcpReply>>,
) {
    let mut buffer = [0u8; MAX_PACKET_BYTES];
    while !stop.load(Ordering::Relaxed) {
        let read = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if read <= 0 {
            continue;
        }
        if let Some(reply) = parse_tcp_packet(&buffer[..read as usize])
            && !forward_batch(&replies, &stop, vec![reply])
        {
            break;
        }
    }
}

/// 把一批响应交给主循环；队列满时短暂等待，取消后返回 `false`。
///
/// # 参数
///
/// * `replies` - 结果批次通道。
/// * `stop` - 取消标志。
/// * `batch` - 待转发的响应。
///
/// # 返回
///
/// * `true` - 已交给主循环。
/// * `false` - 已取消或主循环已退出。
fn forward_batch(
    replies: &mpsc::SyncSender<Vec<TcpReply>>,
    stop: &AtomicBool,
    batch: Vec<TcpReply>,
) -> bool {
    match replies.try_send(batch) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full(batch)) => {
            if stop.load(Ordering::Relaxed) {
                return false;
            }
            std::thread::sleep(SEND_RETRY_DELAY);
            forward_batch_slow(replies, stop, batch)
        }
        Err(mpsc::TrySendError::Disconnected(_)) => false,
    }
}

/// `forward_batch` 在队列满时的重试部分。
///
/// # 参数
///
/// * `replies` - 结果批次通道。
/// * `stop` - 取消标志。
/// * `batch` - 待转发的响应。
///
/// # 返回
///
/// * `true` - 已交给主循环。
/// * `false` - 已取消或主循环已退出。
fn forward_batch_slow(
    replies: &mpsc::SyncSender<Vec<TcpReply>>,
    stop: &AtomicBool,
    batch: Vec<TcpReply>,
) -> bool {
    let mut batch = batch;
    loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        match replies.try_send(batch) {
            Ok(()) => return true,
            Err(mpsc::TrySendError::Full(returned)) => {
                batch = returned;
                std::thread::sleep(SEND_RETRY_DELAY);
            }
            Err(mpsc::TrySendError::Disconnected(_)) => return false,
        }
    }
}

/// 解析一个 IPv4 / TCP 报文。
///
/// # 参数
///
/// * `bytes` - 从原始套接字读到的完整报文（含 IP 首部）。
///
/// # 返回
///
/// * `Some(TcpReply)` - 非分片、协议为 TCP 的 IPv4 报文。
/// * `None` - 截断、非 IPv4、非 TCP 或分片报文。
fn parse_tcp_packet(bytes: &[u8]) -> Option<TcpReply> {
    if bytes.len() < SYN_PACKET_LEN || bytes[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(bytes[0] & 0x0f) * 4;
    if header_len < IP_HEADER_LEN || bytes.len() < header_len + TCP_HEADER_LEN {
        return None;
    }
    if bytes[9] != libc::IPPROTO_TCP as u8 {
        return None;
    }
    // 分片报文里没有完整的 TCP 首部，直接跳过（掩码含 MF 位，不含 DF）。
    if u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0 {
        return None;
    }
    let tcp = &bytes[header_len..];
    Some(TcpReply {
        dst: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
        source_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dest_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: tcp[13],
    })
}

/// 拼装一个带 IP 首部的 TCP SYN 报文。
///
/// IP 首部与 TCP 首部的校验和都在这里算好，发送时只需 `sendto`。
/// 批量发送路径不复用这个函数（它每次都要重新计算两个校验和）。
///
/// # 参数
///
/// * `source` - 本机源地址。
/// * `destination` - 目标地址。
/// * `source_port` - 本机源端口。
/// * `destination_port` - 目标端口。
/// * `sequence` - TCP 序号；响应里的确认号应当等于 `sequence + 1`。
///
/// # 返回
///
/// * `[u8; SYN_PACKET_LEN]` - 可直接发送的报文。
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn build_syn_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
) -> [u8; SYN_PACKET_LEN] {
    let mut packet = [0u8; SYN_PACKET_LEN];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(SYN_PACKET_LEN as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&IP_ID.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = SYN_TTL;
    packet[9] = libc::IPPROTO_TCP as u8;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_checksum = checksum(&packet[..IP_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    packet[IP_HEADER_LEN..IP_HEADER_LEN + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[IP_HEADER_LEN + 2..IP_HEADER_LEN + 4].copy_from_slice(&destination_port.to_be_bytes());
    packet[IP_HEADER_LEN + 4..IP_HEADER_LEN + 8].copy_from_slice(&sequence.to_be_bytes());
    packet[IP_HEADER_LEN + 12] = (TCP_HEADER_LEN as u8 / 4) << 4;
    packet[IP_HEADER_LEN + 13] = TCP_FLAG_SYN;
    packet[IP_HEADER_LEN + 14..IP_HEADER_LEN + 16].copy_from_slice(&SYN_WINDOW.to_be_bytes());
    let tcp_checksum = tcp_checksum(source, destination, &packet[IP_HEADER_LEN..]);
    packet[IP_HEADER_LEN + 16..IP_HEADER_LEN + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    packet
}

/// 批量发送器：预先算好 IP 首部与伪首部校验和，逐包只填变化字段。
///
/// # 字段
///
/// * `packets` - 一批报文的连续缓冲区，每包 [`SYN_PACKET_LEN`] 字节。
/// * `ip_header` - 预计算好的 20 字节 IP 首部（含校验和）。
/// * `pseudo` - TCP 伪首部的反码和部分和。
/// * `source_port` - 本机源端口。
/// * `pending` - 当前已填入、尚未发送的报文数。
struct BatchSender {
    /// 一批报文的连续缓冲区。
    packets: Vec<u8>,
    /// 预计算好的 IP 首部。
    ip_header: [u8; IP_HEADER_LEN],
    /// TCP 伪首部部分和。
    pseudo: u32,
    /// 本机源端口。
    source_port: u16,
    /// 已填入、尚未发送的报文数。
    pending: usize,
    /// Linux 上给 `sendmmsg` 用的报文头数组。
    #[cfg(target_os = "linux")]
    messages: Vec<libc::mmsghdr>,
    /// Linux 上给 `sendmmsg` 用的分散/聚集数组。
    #[cfg(target_os = "linux")]
    iovecs: Vec<libc::iovec>,
    /// Linux 上复用的目标地址结构。
    #[cfg(target_os = "linux")]
    address: libc::sockaddr_in,
    /// 非 Linux 平台逐包发送时使用的目标地址。
    #[cfg(not(target_os = "linux"))]
    destination: Ipv4Addr,
}

impl BatchSender {
    /// 构造一个批量发送器。
    ///
    /// # 参数
    ///
    /// * `source` - 本机源地址。
    /// * `source_port` - 本机源端口。
    /// * `destination` - 目标地址。
    ///
    /// # 返回
    ///
    /// * [`BatchSender`] - 可直接用于 `push` / `flush` 的发送器。
    fn new(source: Ipv4Addr, source_port: u16, destination: Ipv4Addr) -> Self {
        let mut ip_header = [0u8; IP_HEADER_LEN];
        ip_header[0] = 0x45;
        ip_header[2..4].copy_from_slice(&(SYN_PACKET_LEN as u16).to_be_bytes());
        ip_header[4..6].copy_from_slice(&IP_ID.to_be_bytes());
        ip_header[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        ip_header[8] = SYN_TTL;
        ip_header[9] = libc::IPPROTO_TCP as u8;
        ip_header[12..16].copy_from_slice(&source.octets());
        ip_header[16..20].copy_from_slice(&destination.octets());
        let checksum = checksum(&ip_header);
        ip_header[10..12].copy_from_slice(&checksum.to_be_bytes());

        let source_octets = source.octets();
        let destination_octets = destination.octets();
        let pseudo = u32::from(u16::from_be_bytes([source_octets[0], source_octets[1]]))
            + u32::from(u16::from_be_bytes([source_octets[2], source_octets[3]]))
            + u32::from(u16::from_be_bytes([
                destination_octets[0],
                destination_octets[1],
            ]))
            + u32::from(u16::from_be_bytes([
                destination_octets[2],
                destination_octets[3],
            ]))
            + u32::from(libc::IPPROTO_TCP as u16)
            + SYN_PACKET_LEN as u32
            - IP_HEADER_LEN as u32;

        Self {
            packets: vec![0u8; SEND_BATCH * SYN_PACKET_LEN],
            ip_header,
            pseudo,
            source_port,
            pending: 0,
            #[cfg(target_os = "linux")]
            messages: (0..SEND_BATCH)
                .map(|_| unsafe { std::mem::zeroed() })
                .collect(),
            #[cfg(target_os = "linux")]
            iovecs: (0..SEND_BATCH)
                .map(|_| libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                })
                .collect(),
            #[cfg(target_os = "linux")]
            address: libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from(destination).to_be(),
                },
                sin_zero: [0; 8],
            },
            #[cfg(not(target_os = "linux"))]
            destination,
        }
    }

    /// 往当前批次里追加一个报文。
    ///
    /// # 参数
    ///
    /// * `destination_port` - 目标端口。
    /// * `sequence` - TCP 序号。
    ///
    /// # 断言
    ///
    /// 调用方保证当前批次未满（`pending < SEND_BATCH`）。
    fn push(&mut self, destination_port: u16, sequence: u32) {
        let offset = self.pending * SYN_PACKET_LEN;
        let packet = &mut self.packets[offset..offset + SYN_PACKET_LEN];
        packet[..IP_HEADER_LEN].copy_from_slice(&self.ip_header);
        packet[IP_HEADER_LEN..IP_HEADER_LEN + 2].copy_from_slice(&self.source_port.to_be_bytes());
        packet[IP_HEADER_LEN + 2..IP_HEADER_LEN + 4]
            .copy_from_slice(&destination_port.to_be_bytes());
        packet[IP_HEADER_LEN + 4..IP_HEADER_LEN + 8].copy_from_slice(&sequence.to_be_bytes());
        packet[IP_HEADER_LEN + 12] = (TCP_HEADER_LEN as u8 / 4) << 4;
        packet[IP_HEADER_LEN + 13] = TCP_FLAG_SYN;
        packet[IP_HEADER_LEN + 14..IP_HEADER_LEN + 16].copy_from_slice(&SYN_WINDOW.to_be_bytes());
        let checksum =
            incremental_tcp_checksum(self.pseudo, self.source_port, destination_port, sequence);
        packet[IP_HEADER_LEN + 16..IP_HEADER_LEN + 18].copy_from_slice(&checksum.to_be_bytes());
        self.pending += 1;
    }

    /// 把当前批次交给内核，成功后清空批次。
    ///
    /// Linux 上用 `sendmmsg` 一次提交；其它平台逐包 `sendto`。
    ///
    /// # 参数
    ///
    /// * `socket` - 发送用原始套接字。
    ///
    /// # 返回
    ///
    /// * `Ok(())` - 整批发送完成。
    /// * `Err(io::Error)` - 系统调用失败；调用方按超时处理这批探针。
    fn flush(&mut self, socket: &OwnedFd) -> io::Result<()> {
        if self.pending == 0 {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            self.flush_linux(socket)?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.flush_portable(socket)?;
        }
        self.pending = 0;
        Ok(())
    }

    /// Linux 上的 `sendmmsg` 发送路径。
    ///
    /// # 参数
    ///
    /// * `socket` - 发送用原始套接字。
    ///
    /// # 返回
    ///
    /// * `Ok(())` - 整批发送完成。
    /// * `Err(io::Error)` - 重试后仍然失败。
    #[cfg(target_os = "linux")]
    fn flush_linux(&mut self, socket: &OwnedFd) -> io::Result<()> {
        for index in 0..self.pending {
            self.iovecs[index] = libc::iovec {
                iov_base: unsafe { self.packets.as_mut_ptr().add(index * SYN_PACKET_LEN) }.cast(),
                iov_len: SYN_PACKET_LEN,
            };
            self.messages[index].msg_hdr.msg_name =
                (&mut self.address as *mut libc::sockaddr_in).cast();
            self.messages[index].msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            self.messages[index].msg_hdr.msg_iov = unsafe { self.iovecs.as_mut_ptr().add(index) };
            self.messages[index].msg_hdr.msg_iovlen = 1;
            self.messages[index].msg_len = 0;
        }
        let mut sent = 0usize;
        let mut retries = 0usize;
        while sent < self.pending {
            let count = unsafe {
                libc::sendmmsg(
                    socket.as_raw_fd(),
                    self.messages.as_mut_ptr().add(sent),
                    (self.pending - sent) as libc::c_uint,
                    0,
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EAGAIN | libc::ENOBUFS | libc::EINTR)
                ) && retries < SEND_RETRIES
                {
                    retries += 1;
                    std::thread::sleep(SEND_RETRY_DELAY);
                    continue;
                }
                return Err(error);
            }
            sent += count as usize;
        }
        Ok(())
    }

    /// 非 Linux 平台的逐包发送路径。
    ///
    /// # 参数
    ///
    /// * `socket` - 发送用原始套接字。
    ///
    /// # 返回
    ///
    /// * `Ok(())` - 整批发送完成。
    /// * `Err(io::Error)` - 某个报文重试后仍然失败。
    #[cfg(not(target_os = "linux"))]
    fn flush_portable(&mut self, socket: &OwnedFd) -> io::Result<()> {
        for index in 0..self.pending {
            let offset = index * SYN_PACKET_LEN;
            let destination = SocketAddrV4::new(
                self.destination,
                u16::from_be_bytes([
                    self.packets[offset + IP_HEADER_LEN + 2],
                    self.packets[offset + IP_HEADER_LEN + 3],
                ]),
            );
            send_with_retry(
                socket,
                &self.packets[offset..offset + SYN_PACKET_LEN],
                destination,
            );
        }
        Ok(())
    }
}

/// 用伪首部部分和 + 变化字段增量求出 TCP 校验和。
///
/// TCP 首部中除源 / 目的端口、序号与校验和本身以外的字段都是常量，
/// 因此整段求和可以化简为几次 16 位加法。
///
/// # 参数
///
/// * `pseudo` - 伪首部（源地址、目的地址、协议号、TCP 长度）的反码和部分和。
/// * `source_port` - 源端口。
/// * `destination_port` - 目的端口。
/// * `sequence` - TCP 序号。
///
/// # 返回
///
/// * `u16` - 网络字节序下的 TCP 校验和。
fn incremental_tcp_checksum(
    pseudo: u32,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
) -> u16 {
    let mut sum = pseudo
        + u32::from(source_port)
        + u32::from(destination_port)
        + (sequence >> 16)
        + (sequence & 0xffff)
        + u32::from(u16::from((TCP_HEADER_LEN as u8 / 4) << 4) << 8)
        + u32::from(u16::from(TCP_FLAG_SYN))
        + u32::from(SYN_WINDOW);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 计算 TCP 校验和（含 12 字节伪首部）。
///
/// # 参数
///
/// * `source` - 源地址。
/// * `destination` - 目标地址。
/// * `segment` - 不含伪首部的 TCP 段。
///
/// # 返回
///
/// * `u16` - 网络字节序下的校验和数值。
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn tcp_checksum(source: Ipv4Addr, destination: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut data = [0u8; 12 + SYN_PACKET_LEN - IP_HEADER_LEN];
    data[..4].copy_from_slice(&source.octets());
    data[4..8].copy_from_slice(&destination.octets());
    data[9] = libc::IPPROTO_TCP as u8;
    data[10..12].copy_from_slice(&(segment.len() as u16).to_be_bytes());
    data[12..12 + segment.len()].copy_from_slice(segment);
    checksum(&data[..12 + segment.len()])
}

/// 计算 RFC 1071 反码和校验和。
///
/// # 参数
///
/// * `bytes` - 参与计算的数据（长度可为奇数，末字节按高位补零处理）。
///
/// # 返回
///
/// * `u16` - 反码和。
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in bytes.chunks(2) {
        let word = match chunk {
            [high, low] => u16::from_be_bytes([*high, *low]),
            [high] => u16::from(*high) << 8,
            _ => 0,
        };
        sum = sum.wrapping_add(u32::from(word));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 发送一个报文，缓冲满时短暂重试。
///
/// # 参数
///
/// * `socket` - 发送用原始套接字。
/// * `packet` - 完整报文（含 IP 首部）。
/// * `destination` - 目标地址与端口。
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn send_with_retry(socket: &OwnedFd, packet: &[u8], destination: SocketAddrV4) {
    for attempt in 0..=SEND_RETRIES {
        if send_packet(socket, packet, destination).is_ok() {
            return;
        }
        if attempt < SEND_RETRIES {
            std::thread::sleep(SEND_RETRY_DELAY);
        }
    }
}

/// 通过原始套接字发送报文。
///
/// # 参数
///
/// * `socket` - 发送用原始套接字。
/// * `packet` - 完整报文（含 IP 首部）。
/// * `destination` - 目标地址与端口。
///
/// # 返回
///
/// * `Ok(())` - `sendto` 成功。
/// * `Err(io::Error)` - 系统调用失败。
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn send_packet(socket: &OwnedFd, packet: &[u8], destination: SocketAddrV4) -> io::Result<()> {
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: destination.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(*destination.ip()).to_be(),
        },
        sin_zero: [0; 8],
    };
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            packet.as_ptr().cast(),
            packet.len(),
            0,
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// 查询到达某个目标的出站源地址。
///
/// 用 `connect` 一个 UDP 套接字让内核选路，不会真的发出任何报文。
///
/// # 参数
///
/// * `destination` - 目标地址。
///
/// # 返回
///
/// * `Ipv4Addr` - 出站源地址；选路失败时退回 `0.0.0.0`，由内核自行填充。
fn source_ip_for(destination: Ipv4Addr) -> Ipv4Addr {
    let Ok(socket) = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
        return Ipv4Addr::UNSPECIFIED;
    };
    if socket.connect((destination, 9)).is_err() {
        return Ipv4Addr::UNSPECIFIED;
    }
    match socket.local_addr().map(|address| address.ip()) {
        Ok(IpAddr::V4(ip)) => ip,
        _ => Ipv4Addr::UNSPECIFIED,
    }
}

/// 选一个不太可能与真实连接冲突的本机源端口。
///
/// # 返回
///
/// * `u16` - 落在 [`SOURCE_PORT_MIN`] 起的 20000 个端口内。
fn allocate_source_port() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_nanos() as u64)
        .unwrap_or(0);
    SOURCE_PORT_MIN + (nanos % u64::from(SOURCE_PORT_SPAN)) as u16
}

/// 生成初始 TCP 序号，避免不同进程的探针互相混淆。
///
/// # 返回
///
/// * `u32` - 基于当前时间的伪随机起点。
fn initial_sequence() -> u32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_nanos() as u32) ^ (std::process::id() << 16)
}

/// 把 `Duration` 折算成毫秒，并保证不超过 `u64` 表示范围。
///
/// # 参数
///
/// * `duration` - 任意时长。
///
/// # 返回
///
/// * `u64` - 毫秒数。
fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// 把原始套接字错误翻译成用户能看懂的提示。
///
/// # 参数
///
/// * `error` - 原始错误。
///
/// # 返回
///
/// * `String` - 权限不足时给出 `setcap` 建议，其余情况保留系统错误文本。
fn describe_error(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => {
            "SYN 扫描需要 root 或 CAP_NET_RAW 权限，可执行 `sudo setcap cap_net_raw+ep ./pscan`"
                .into()
        }
        _ => format!("原始套接字创建失败: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_known_ip_header() {
        // 一个手工构造、校验和占位为 0 的 IPv4 首部。
        let header = [
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 0, 2, 1,
            198, 51, 100, 7,
        ];
        assert_eq!(checksum(&header), 0x3c60);
    }

    #[test]
    fn syn_packet_round_trips_through_parser() {
        let source = Ipv4Addr::new(192, 0, 2, 1);
        let destination = Ipv4Addr::new(198, 51, 100, 7);
        let packet = build_syn_packet(source, destination, 40_000, 443, 0x1234_5678);

        // IP 首部自身校验和应为 0 的结果（再算一次整段得到 0）。
        assert_eq!(checksum(&packet[..IP_HEADER_LEN]), 0);
        let reply = parse_tcp_packet(&packet).expect("valid packet");
        assert_eq!(reply.source_port, 40_000);
        assert_eq!(reply.dest_port, 443);
        assert_eq!(reply.flags, TCP_FLAG_SYN);
        assert_eq!(reply.dst, destination);
    }

    #[test]
    fn incremental_checksum_matches_full_calculation() {
        let source = Ipv4Addr::new(192, 0, 2, 1);
        let destination = Ipv4Addr::new(198, 51, 100, 7);
        for port in [1u16, 80, 443, 40_000, 65_535] {
            for sequence in [0u32, 7, 0x1234_5678, u32::MAX] {
                let packet = build_syn_packet(source, destination, 40_000, port, sequence);
                let expected =
                    u16::from_be_bytes([packet[IP_HEADER_LEN + 16], packet[IP_HEADER_LEN + 17]]);
                let mut sender = BatchSender::new(source, 40_000, destination);
                sender.push(port, sequence);
                let actual = u16::from_be_bytes([
                    sender.packets[IP_HEADER_LEN + 16],
                    sender.packets[IP_HEADER_LEN + 17],
                ]);
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn batch_packets_round_trip_through_parser() {
        let source = Ipv4Addr::new(192, 0, 2, 1);
        let destination = Ipv4Addr::new(198, 51, 100, 7);
        let mut sender = BatchSender::new(source, 40_000, destination);
        for index in 0..8u16 {
            sender.push(1000 + index, 0xabc0_0000 + u32::from(index));
        }
        assert_eq!(sender.pending, 8);
        for index in 0..8usize {
            let offset = index * SYN_PACKET_LEN;
            let packet = &sender.packets[offset..offset + SYN_PACKET_LEN];
            let reply = parse_tcp_packet(packet).expect("valid packet");
            assert_eq!(reply.source_port, 40_000);
            assert_eq!(reply.dest_port, 1000 + index as u16);
            assert_eq!(reply.dst, destination);
            // 包含校验和的整段 IP 首部反码和为 0。
            assert_eq!(checksum(&packet[..IP_HEADER_LEN]), 0);
            // TCP 段（含伪首部）校验和也应为 0。
            assert_eq!(
                tcp_checksum(source, destination, &packet[IP_HEADER_LEN..]),
                0
            );
        }
    }

    #[test]
    fn truncated_or_fragmented_packets_are_rejected() {
        let source = Ipv4Addr::new(192, 0, 2, 1);
        let destination = Ipv4Addr::new(198, 51, 100, 7);
        let mut packet = build_syn_packet(source, destination, 40_000, 80, 7);
        assert!(parse_tcp_packet(&packet[..20]).is_none());

        // 设置 MF 位后应判定为分片并丢弃。
        packet[6] |= 0x20;
        assert!(parse_tcp_packet(&packet).is_none());
    }

    #[test]
    fn source_port_stays_in_scan_range() {
        for _ in 0..64 {
            let port = allocate_source_port();
            assert!((SOURCE_PORT_MIN..SOURCE_PORT_MIN + SOURCE_PORT_SPAN).contains(&port));
        }
    }
}
