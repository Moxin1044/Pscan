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

const MAX_BANNER_BYTES: usize = 2048;
const PASSIVE_WAIT: Duration = Duration::from_millis(180);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdpState {
    Open,
    Closed,
    OpenOrFiltered,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub concurrency: usize,
    pub connect_timeout: Duration,
    pub fingerprint_timeout: Duration,
    pub service_detection: bool,
    pub rate_limit: Option<u32>,
    pub result_buffer: usize,
    pub transport: Transport,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub kind: &'static str,
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub open: bool,
    pub latency_ms: u64,
    pub transport: Transport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_state: Option<UdpState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HostState {
    Alive,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostDiscoveryResult {
    pub kind: &'static str,
    pub host: String,
    pub ip: String,
    pub state: HostState,
    pub method: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone)]
pub struct HostDiscoveryConfig {
    pub concurrency: usize,
    pub timeout: Duration,
    pub tcp_ports: Vec<u16>,
    pub icmp: bool,
}

#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub host: String,
    pub ip: IpAddr,
}

#[derive(Debug)]
struct RatePacer {
    interval: Duration,
    next: Mutex<tokio::time::Instant>,
}

impl RatePacer {
    fn new(rate: u32) -> Self {
        Self {
            interval: Duration::from_secs_f64(1.0 / f64::from(rate)),
            next: Mutex::new(tokio::time::Instant::now()),
        }
    }

    async fn wait(&self, cancel: &CancellationToken) -> bool {
        let mut next = self.next.lock().await;
        let now = tokio::time::Instant::now();
        if *next > now {
            tokio::select! {
                _ = cancel.cancelled() => return false,
                _ = sleep_until(*next) => {}
            }
        }
        *next = std::cmp::max(*next, now) + self.interval;
        true
    }
}

pub async fn scan(targets: &[String], ports: &[u16], config: &ScanConfig) -> Vec<ScanResult> {
    scan_with_cancel(targets, ports, config, CancellationToken::new()).await
}

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
        while let Some(result) = receiver.recv().await {
            results.push(result);
        }
        results
    };
    let (_, results) = tokio::join!(scan, collect);
    results
}

pub async fn scan_to_channel(
    targets: &[String],
    ports: &[u16],
    config: &ScanConfig,
    sender: mpsc::Sender<ScanResult>,
) {
    scan_to_channel_with_cancel(targets, ports, config, sender, CancellationToken::new()).await;
}

pub async fn scan_to_channel_with_cancel(
    targets: &[String],
    ports: &[u16],
    config: &ScanConfig,
    sender: mpsc::Sender<ScanResult>,
    cancel: CancellationToken,
) {
    let (resolved, _failures) = resolve_targets(targets, config.connect_timeout, &cancel).await;
    let pacer = config
        .rate_limit
        .filter(|rate| *rate > 0)
        .map(RatePacer::new)
        .map(Arc::new);
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
                    let _ = sender.send(result).await;
                }
            }
        })
        .await;
    drop(sender);
}

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

pub async fn resolve_targets(
    targets: &[String],
    resolve_timeout: Duration,
    cancel: &CancellationToken,
) -> (Vec<ResolvedTarget>, Vec<(String, String)>) {
    let concurrency = targets.len().clamp(1, 64);
    type PerHostResult = (Vec<ResolvedTarget>, Option<(String, String)>);
    let per_host: Vec<PerHostResult> = stream::iter(targets.iter().cloned())
        .take_until(cancel.cancelled())
        .map(|host| {
            let cancel = cancel.clone();
            async move {
                if let Ok(ip) = host.parse::<IpAddr>() {
                    return (vec![ResolvedTarget { host, ip }], None);
                }
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
        let ping = pinger.ping(PingSequence(0), b"Pscan");
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

async fn fingerprint_stream(
    socket: &mut TcpStream,
    host: &str,
    port: u16,
    fingerprint_timeout: Duration,
) -> (Fingerprint, Option<String>) {
    let deadline = tokio::time::Instant::now() + fingerprint_timeout;
    let mut banner = Vec::with_capacity(512);
    read_banner(socket, &mut banner, PASSIVE_WAIT.min(fingerprint_timeout)).await;
    let mut result = fingerprint::identify(port, &banner);

    let http_candidate = matches!(result.service.as_deref(), None | Some("http" | "https"));
    if http_candidate && (!result.is_identified() || result.product.is_none()) {
        let request = format!("HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Pscan/2\r\n\r\n");
        if let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
            && let Ok(Ok(())) = timeout(remaining, socket.write_all(request.as_bytes())).await
        {
            read_until_deadline(socket, &mut banner, deadline).await;
            let probed = fingerprint::identify(port, &banner);
            if matches!(probed.service.as_deref(), Some("http" | "https")) {
                result = probed;
            }
        }
    }

    if !result.is_identified() {
        result = fingerprint::port_fallback(port);
    }

    let banner = (!banner.is_empty()).then(|| sanitize_banner(&banner));
    (result, banner)
}

async fn read_until_deadline(
    socket: &mut TcpStream,
    banner: &mut Vec<u8>,
    deadline: tokio::time::Instant,
) {
    let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now()) else {
        return;
    };
    read_banner(socket, banner, remaining).await;
}

async fn read_banner(socket: &mut TcpStream, banner: &mut Vec<u8>, wait: Duration) {
    if banner.len() >= MAX_BANNER_BYTES || wait.is_zero() {
        return;
    }
    let mut buffer = [0_u8; 1024];
    if let Ok(Ok(count)) = timeout(wait, socket.read(&mut buffer)).await {
        banner.extend_from_slice(&buffer[..count.min(MAX_BANNER_BYTES - banner.len())]);
    }
}

fn udp_probe(port: u16) -> &'static [u8] {
    match port {
        53 => b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01",
        123 => b"\x1b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        _ => b"Pscan",
    }
}

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
        service,
        product: None,
        version: None,
        banner,
        error,
    }
}

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
        service: None,
        product: None,
        version: None,
        banner: None,
        error: Some(error),
    }
}

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

fn host_identifier(ip: IpAddr) -> u16 {
    match ip {
        IpAddr::V4(ip) => ip
            .octets()
            .into_iter()
            .fold(0_u16, |acc, byte| acc.wrapping_add(u16::from(byte))),
        IpAddr::V6(ip) => ip.segments().into_iter().fold(0_u16, u16::wrapping_add),
    }
}

fn sanitize_banner(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|character| {
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

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn elapsed_millis(started: Instant) -> u64 {
    duration_millis(started.elapsed())
}
