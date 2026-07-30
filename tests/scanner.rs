use std::time::Duration;

use pscan::scanner::{ScanConfig, Transport, scan};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn config() -> ScanConfig {
    ScanConfig {
        concurrency: 4,
        connect_timeout: Duration::from_secs(2),
        fingerprint_timeout: Duration::from_secs(1),
        service_detection: true,
        rate_limit: None,
        result_buffer: 8,
        transport: Transport::Tcp,
    }
}

#[tokio::test]
async fn scans_open_local_port_and_captures_banner() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"SSH-2.0-Pscan_Test\r\n").await.unwrap();
    });

    let results = scan(&["127.0.0.1".into()], &[port], &config()).await;
    assert_eq!(results.len(), 1);
    assert!(results[0].open);
    assert_eq!(results[0].service.as_deref(), Some("ssh"));
    assert_eq!(results[0].product.as_deref(), Some("Pscan"));
    assert_eq!(results[0].version.as_deref(), Some("Test"));
}

#[tokio::test]
async fn actively_identifies_http_on_a_nonstandard_port() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 512];
        let count = stream.read(&mut request).await.unwrap();
        assert!(String::from_utf8_lossy(&request[..count]).starts_with("HEAD / HTTP/1.0"));
        stream
            .write_all(b"HTTP/1.0 200 OK\r\nServer: pscan-test/2.0\r\n\r\n")
            .await
            .unwrap();
    });

    let results = scan(&["127.0.0.1".into()], &[port], &config()).await;
    assert_eq!(results[0].service.as_deref(), Some("http"));
    assert_eq!(results[0].product.as_deref(), Some("pscan-test"));
    assert_eq!(results[0].version.as_deref(), Some("2.0"));
}

#[tokio::test]
async fn applies_global_connection_start_rate() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = tokio::spawn(async move {
        let mut times = Vec::new();
        for _ in 0..3 {
            let (_, _) = listener.accept().await.unwrap();
            times.push(tokio::time::Instant::now());
        }
        times
    });

    let mut scan_config = config();
    scan_config.service_detection = false;
    scan_config.rate_limit = Some(5);
    let started = tokio::time::Instant::now();
    let results = scan(&["127.0.0.1".into()], &[port, port, port], &scan_config).await;
    let times = accepted.await.unwrap();

    assert_eq!(results.len(), 3);
    assert!(times[2].duration_since(started) >= Duration::from_millis(350));
}
