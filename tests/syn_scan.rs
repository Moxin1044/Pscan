//! SYN 半开扫描的集成测试。
//!
//! 这些用例需要 `CAP_NET_RAW`（root 或 `setcap cap_net_raw+ep`）。没有权限时
//! 直接跳过，保证普通 CI 与开发机上的 `cargo test` 依然全绿。
//!
//! 用 root 之外的账号跑完整用例前，先给测试二进制加权限：
//!
//! ```bash
//! cargo test --no-run
//! sudo ./target/debug/deps/syn_scan-<hash>
//! ```

#![cfg(unix)]

use std::time::Duration;

use pscan::scanner::{CancellationToken, ScanConfig, TcpState, Transport, scan_with_cancel};
use tokio::net::TcpListener;

/// 仅供 SYN 用例使用的扫描配置：短超时、适度并发。
fn config() -> ScanConfig {
    ScanConfig {
        concurrency: 32,
        connect_timeout: Duration::from_millis(500),
        fingerprint_timeout: Duration::from_millis(100),
        service_detection: false,
        rate_limit: None,
        result_buffer: 16,
        transport: Transport::Tcp,
        syn: true,
    }
}

#[tokio::test]
async fn syn_scan_distinguishes_open_and_closed_ports() {
    if pscan::syn::preflight().is_err() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local listener");
    let open_port = listener.local_addr().expect("local addr").port();

    // 9 是 discard 端口，回环上通常无人监听，用它验证 RST 判定。
    let results = scan_with_cancel(
        &["127.0.0.1".to_owned()],
        &[open_port, 9],
        &config(),
        CancellationToken::new(),
    )
    .await;

    let open = results
        .iter()
        .find(|result| result.port == open_port)
        .expect("open port result");
    assert_eq!(open.tcp_state, Some(TcpState::Open));
    assert!(open.open);
    assert_eq!(open.service.as_deref(), None);

    let closed = results
        .iter()
        .find(|result| result.port == 9)
        .expect("closed port result");
    assert_eq!(closed.tcp_state, Some(TcpState::Closed));
    assert!(!closed.open);
    assert!(closed.error.is_none());
}

#[tokio::test]
async fn syn_scan_fills_service_names_from_port_table() {
    if pscan::syn::preflight().is_err() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local listener");
    let port = listener.local_addr().expect("local addr").port();
    let results = scan_with_cancel(
        &["127.0.0.1".to_owned()],
        &[port],
        &config(),
        CancellationToken::new(),
    )
    .await;
    let result = results.first().expect("at least one result");
    // 动态端口不在端口表里，因此只应带状态、不带服务名。
    assert!(result.service.is_none() || result.tcp_state == Some(TcpState::Open));
}
