use std::time::Duration;

use pscan::scanner::{
    CancellationToken, HostDiscoveryConfig, HostState, ScanConfig, Transport, UdpState,
    discover_hosts, scan_with_cancel,
};
use tokio::net::{TcpListener, UdpSocket};

fn scan_config() -> ScanConfig {
    ScanConfig {
        concurrency: 8,
        connect_timeout: Duration::from_millis(300),
        fingerprint_timeout: Duration::from_millis(200),
        service_detection: false,
        rate_limit: None,
        result_buffer: 16,
        transport: Transport::Tcp,
    }
}

#[tokio::test]
async fn udp_echo_response_marks_port_open() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (count, peer) = socket.recv_from(&mut buffer).await.unwrap();
        socket.send_to(&buffer[..count], peer).await.unwrap();
    });

    let mut config = scan_config();
    config.transport = Transport::Udp;
    let results = scan_with_cancel(
        &["127.0.0.1".into()],
        &[port],
        &config,
        CancellationToken::new(),
    )
    .await;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].udp_state, Some(UdpState::Open));
}

#[tokio::test]
async fn silent_udp_port_is_open_or_filtered() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let _ = socket.recv_from(&mut buffer).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let mut config = scan_config();
    config.transport = Transport::Udp;
    let results = scan_with_cancel(
        &["127.0.0.1".into()],
        &[port],
        &config,
        CancellationToken::new(),
    )
    .await;

    assert_eq!(results[0].udp_state, Some(UdpState::OpenOrFiltered));
}

#[tokio::test]
async fn closed_udp_port_reports_closed_when_icmp_is_available() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);

    let mut config = scan_config();
    config.transport = Transport::Udp;
    let results = scan_with_cancel(
        &["127.0.0.1".into()],
        &[port],
        &config,
        CancellationToken::new(),
    )
    .await;

    assert_eq!(results[0].udp_state, Some(UdpState::Closed));
}

#[tokio::test]
async fn tcp_fallback_discovers_local_host() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = listener.accept().await.unwrap();
    });

    let results = discover_hosts(
        &["127.0.0.1".into()],
        &HostDiscoveryConfig {
            concurrency: 4,
            timeout: Duration::from_millis(500),
            tcp_ports: vec![port],
            icmp: false,
        },
        CancellationToken::new(),
    )
    .await;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].state, HostState::Alive);
    assert!(results[0].method.starts_with("tcp/"));
}

#[tokio::test]
async fn cancellation_stops_before_all_jobs_start() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accepted_server = accepted.clone();
    tokio::spawn(async move {
        while let Ok((_stream, _)) = listener.accept().await {
            accepted_server.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let targets = (1..=200)
        .map(|last| format!("127.0.0.{last}"))
        .collect::<Vec<_>>();
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        trigger.cancel();
    });

    let mut config = scan_config();
    config.concurrency = 4;
    config.rate_limit = Some(20);
    let _ = scan_with_cancel(&targets, &[port], &config, cancel).await;

    assert!(accepted.load(std::sync::atomic::Ordering::SeqCst) < targets.len());
}
