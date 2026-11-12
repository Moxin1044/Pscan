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
//! 实现要点：单个发送用原始套接字 + 一个阻塞接收线程。发送端自行拼装
//! IP / TCP 首部并计算校验和，接收端把内核送来的每个 TCP 报文解析成
//! [`TcpReply`]，由扫描主循环按「目标 IP + 目标端口」匹配在途探针。

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio::time::{Instant as TokioInstant, sleep_until};
pub use tokio_util::sync::CancellationToken;

use crate::fingerprint;
use crate::scanner::{
    RatePacer, ResolvedTarget, ScanConfig, ScanResult, TcpState, Transport, elapsed_millis,
    scan_connect_resolved,
};

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

/// 探针的 TTL；1 跳以内的目标都能收到，也避免探针在广域网上跑太远。
const SYN_TTL: u8 = 64;

/// 探针声明的接收窗口；值本身不影响判定。
const SYN_WINDOW: u16 = 65535;

/// 接收缓冲区大小，覆盖常见以太网 MTU。
const RECV_BUFFER_BYTES: usize = 2048;

/// 接收线程的单次阻塞时长：足够短以便及时响应取消，又避免空转。
const RECV_POLL_MICROS: i64 = 100_000;

/// 接收套接字缓冲区大小；高并发扫描时内核会一次性堆很多 SYN-ACK。
const RECV_SOCKET_BUFFER: i32 = 4 * 1024 * 1024;

/// 源端口范围的起点。
const SOURCE_PORT_MIN: u16 = 40_000;

/// 源端口范围的宽度。
const SOURCE_PORT_SPAN: u16 = 20_000;

/// 发送缓冲满时的重试间隔。
const SEND_RETRY_DELAY: Duration = Duration::from_millis(1);

/// 发送失败的最大重试次数。
const SEND_RETRIES: usize = 3;

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

/// 在途探针。
struct InFlight {
    /// 目标主机文本（用于结果里的 `host` 字段）。
    host: String,
    /// 我方发出的 TCP 序号，用于校验 `SYN-ACK` 的确认号。
    sequence: u32,
    /// 探测开始时刻，用于计算延迟。
    started: Instant,
    /// 超时时刻，过了就判为 `filtered`。
    deadline: TokioInstant,
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
    config: &ScanConfig,
    sender: mpsc::Sender<ScanResult>,
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
    scan_ipv4(ipv4, ports, config, sender, cancel).await;
}

/// 对 IPv4 目标执行 SYN 扫描。
///
/// # 参数
///
/// * `resolved` - IPv4 目标。
/// * `ports` - 端口列表。
/// * `config` - 扫描配置。
/// * `sender` - 结果通道发送端。
/// * `cancel` - 取消令牌。
async fn scan_ipv4(
    resolved: Vec<ResolvedTarget>,
    ports: &[u16],
    config: &ScanConfig,
    sender: mpsc::Sender<ScanResult>,
    cancel: CancellationToken,
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
    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel();
    let receiver = {
        let stop = stop.clone();
        tokio::task::spawn_blocking(move || receive_loop(listen, stop, reply_tx))
    };

    let pacer = config
        .rate_limit
        .filter(|rate| *rate > 0)
        .map(RatePacer::new)
        .map(Arc::new);
    let source_port = allocate_source_port();
    let mut source_ips: HashMap<Ipv4Addr, Ipv4Addr> = HashMap::new();
    let mut in_flight: HashMap<(Ipv4Addr, u16), InFlight> = HashMap::new();
    let mut jobs = resolved.into_iter().flat_map(|target| {
        ports
            .iter()
            .copied()
            .map(move |port| (target.clone(), port))
    });
    let mut sequence = initial_sequence();
    let mut exhausted = false;

    loop {
        while in_flight.len() < config.concurrency.max(1) {
            let Some((target, port)) = jobs.next() else {
                exhausted = true;
                break;
            };
            if cancel.is_cancelled() {
                exhausted = true;
                break;
            }
            if let Some(pacer) = &pacer
                && !pacer.wait(&cancel).await
            {
                exhausted = true;
                break;
            }
            let IpAddr::V4(destination) = target.ip else {
                continue;
            };
            let source = *source_ips
                .entry(destination)
                .or_insert_with(|| source_ip_for(destination));
            sequence = sequence.wrapping_add(1);
            let packet = build_syn_packet(source, destination, source_port, port, sequence);
            send_with_retry(&socket, &packet, SocketAddrV4::new(destination, port));
            in_flight.insert(
                (destination, port),
                InFlight {
                    host: target.host.clone(),
                    sequence,
                    started: Instant::now(),
                    deadline: TokioInstant::now() + config.connect_timeout,
                },
            );
        }

        if in_flight.is_empty() && exhausted {
            break;
        }
        // 先把内核队列里已经到达的响应一次抽干，避免「一个响应一次
        // select」把主循环拖成瓶颈；高并发下这决定了实际吞吐。
        let mut handled = 0usize;
        while let Ok(reply) = reply_rx.try_recv() {
            handle_reply(reply, source_port, &mut in_flight, &sender).await;
            handled += 1;
        }
        if handled > 0 {
            continue;
        }

        let next_deadline = match in_flight.values().map(|probe| probe.deadline).min() {
            Some(deadline) => deadline,
            None => TokioInstant::now() + SEND_RETRY_DELAY,
        };
        // `biased` 让到期的探针优先结算，避免持续有响应时永久推迟超时判定。
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = sleep_until(next_deadline) => {
                expire_probes(&mut in_flight, &sender).await;
            }
            reply = reply_rx.recv() => {
                if let Some(reply) = reply {
                    handle_reply(reply, source_port, &mut in_flight, &sender).await;
                }
            }
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = receiver.await;
}

/// 按报文类型结算命中探针。
///
/// # 参数
///
/// * `reply` - 内核送来的 TCP 报文。
/// * `source_port` - 本次扫描使用的本机源端口。
/// * `in_flight` - 在途探针表。
/// * `sender` - 结果通道。
async fn handle_reply(
    reply: TcpReply,
    source_port: u16,
    in_flight: &mut HashMap<(Ipv4Addr, u16), InFlight>,
    sender: &mpsc::Sender<ScanResult>,
) {
    if reply.dest_port != source_port {
        return;
    }
    let Some(probe) = in_flight.get(&(reply.dst, reply.source_port)) else {
        return;
    };
    let is_syn_ack = reply.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK) == TCP_FLAG_SYN | TCP_FLAG_ACK
        && reply.ack == probe.sequence.wrapping_add(1);
    let is_reset = reply.flags & TCP_FLAG_RST != 0;
    if !is_syn_ack && !is_reset {
        return;
    }
    let state = if is_reset {
        TcpState::Closed
    } else {
        TcpState::Open
    };
    let Some(probe) = in_flight.remove(&(reply.dst, reply.source_port)) else {
        return;
    };
    let result = syn_result(&probe, reply.dst, reply.source_port, state);
    let _ = sender.send(result).await;
}

/// 把超过截止时间仍未收到响应的探针结算为 `filtered`。
///
/// # 参数
///
/// * `in_flight` - 在途探针表。
/// * `sender` - 结果通道。
async fn expire_probes(
    in_flight: &mut HashMap<(Ipv4Addr, u16), InFlight>,
    sender: &mpsc::Sender<ScanResult>,
) {
    let now = TokioInstant::now();
    let expired: Vec<(Ipv4Addr, u16)> = in_flight
        .iter()
        .filter(|(_, probe)| probe.deadline <= now)
        .map(|(key, _)| *key)
        .collect();
    for key in expired {
        if let Some(probe) = in_flight.remove(&key) {
            let result = syn_result(&probe, key.0, key.1, TcpState::Filtered);
            let _ = sender.send(result).await;
        }
    }
}

/// 组装 SYN 扫描结果。
///
/// # 参数
///
/// * `probe` - 命中的在途探针（提供主机文本与起始时刻）。
/// * `ip` - 目标 IPv4 地址。
/// * `port` - 目标端口。
/// * `state` - 判定结果。
///
/// # 返回
///
/// * [`ScanResult`] - 服务名取端口表，`open` 仅对 `open` 状态为真。
fn syn_result(probe: &InFlight, ip: Ipv4Addr, port: u16, state: TcpState) -> ScanResult {
    ScanResult {
        kind: "scan",
        host: probe.host.clone(),
        ip: ip.to_string(),
        port,
        open: state == TcpState::Open,
        latency_ms: elapsed_millis(probe.started),
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
    let poll = libc::timeval {
        tv_sec: 0,
        tv_usec: RECV_POLL_MICROS,
    };
    set_timeval_option(
        socket.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_RCVTIMEO,
        poll,
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

/// 设置一个 `timeval` 类型的套接字选项。
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
fn set_timeval_option(fd: i32, level: i32, name: i32, value: libc::timeval) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&value as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// 接收线程主循环：把内核送来的 TCP 报文解析后转发给扫描主循环。
///
/// 用带超时的阻塞 `recv` 而不是 `poll`：超时既让线程能观察取消标志，
/// 又避免忙等占用 CPU。
///
/// # 参数
///
/// * `socket` - 只用于接收的原始套接字副本。
/// * `stop` - 取消标志，主循环结束时置位。
/// * `replies` - 解析结果的无界通道。
fn receive_loop(socket: OwnedFd, stop: Arc<AtomicBool>, replies: mpsc::UnboundedSender<TcpReply>) {
    let mut buffer = [0u8; RECV_BUFFER_BYTES];
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
        if let Some(reply) = parse_tcp_packet(&buffer[..read as usize]) {
            let _ = replies.send(reply);
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
    packet[4..6].copy_from_slice(&(sequence as u16).to_be_bytes());
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
