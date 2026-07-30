use std::fs;

use pscan::output::{OutputFormat, ResultWriter};
use pscan::scanner::{ScanResult, Transport};

#[test]
fn text_output_preserves_closed_state_and_error() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("results.txt");
    let mut writer = ResultWriter::new(OutputFormat::Text, Some(&path)).unwrap();
    writer
        .write(&ScanResult {
            kind: "scan",
            host: "127.0.0.1".into(),
            ip: "127.0.0.1".into(),
            port: 9,
            open: false,
            latency_ms: 0,
            service: None,
            product: None,
            version: None,
            banner: None,
            error: Some("connection refused".into()),
            transport: Transport::Tcp,
            udp_state: None,
        })
        .unwrap();
    writer.flush().unwrap();
    let output = fs::read_to_string(path).unwrap();
    assert!(output.contains("127.0.0.1:9/tcp closed"));
    assert!(output.contains("error=\"connection refused\""));
}

#[test]
fn text_output_brackets_ipv6_addresses() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ipv6.txt");
    let mut writer = ResultWriter::new(OutputFormat::Text, Some(&path)).unwrap();
    writer
        .write(&ScanResult {
            kind: "scan",
            host: "::1".into(),
            ip: "::1".into(),
            port: 22,
            open: true,
            latency_ms: 0,
            service: Some("ssh".into()),
            product: None,
            version: None,
            banner: None,
            error: None,
            transport: Transport::Tcp,
            udp_state: None,
        })
        .unwrap();
    writer.flush().unwrap();
    let output = fs::read_to_string(path).unwrap();
    assert!(output.contains("[::1]:22/tcp open"));
}
