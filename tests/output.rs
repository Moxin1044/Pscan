use std::fs;

use pscan::output::{ColorMode, OutputFormat, OutputSummary, ResultWriter};
use pscan::scanner::{ScanResult, Transport, UdpState};

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
    assert!(output.contains("- closed"));
    assert!(output.contains("127.0.0.1:9"));
    assert!(output.contains("tcp"));
    assert!(output.contains("error   connection refused"));
    assert!(!output.contains("\x1b["));
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
    assert!(output.contains("+ open"));
    assert!(output.contains("[::1]:22"));
    assert!(output.contains("tcp"));
    assert!(output.contains("ssh"));
}

#[test]
fn color_always_emits_ansi_for_text_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("color.txt");
    let mut writer =
        ResultWriter::with_color(OutputFormat::Text, Some(&path), ColorMode::Always).unwrap();
    writer.write(&scan_result(true, None)).unwrap();
    writer.flush().unwrap();

    let output = fs::read_to_string(path).unwrap();
    assert!(output.contains("\x1b[32m+\x1b[0m"));
}

#[test]
fn summary_counts_hidden_and_uncertain_results() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("summary.txt");
    let mut writer = ResultWriter::new(OutputFormat::Text, Some(&path)).unwrap();
    writer.write(&scan_result(true, None)).unwrap();
    writer.record_hidden(&scan_result(false, None));
    writer
        .write(&scan_result(false, Some(UdpState::OpenOrFiltered)))
        .unwrap();
    writer.write_summary().unwrap();
    writer.flush().unwrap();

    assert_eq!(
        writer.summary(),
        OutputSummary {
            scanned: 3,
            open: 1,
            closed: 1,
            uncertain: 1,
            ..OutputSummary::default()
        }
    );
    let output = fs::read_to_string(path).unwrap();
    assert!(output.contains("Summary  3 scanned  1 open  1 uncertain  1 closed"));
}

fn scan_result(open: bool, udp_state: Option<UdpState>) -> ScanResult {
    ScanResult {
        kind: "scan",
        host: "127.0.0.1".into(),
        ip: "127.0.0.1".into(),
        port: 80,
        open,
        latency_ms: 3,
        service: Some("http".into()),
        product: None,
        version: None,
        banner: None,
        error: (!open && udp_state.is_none()).then(|| "connection refused".into()),
        transport: if udp_state.is_some() {
            Transport::Udp
        } else {
            Transport::Tcp
        },
        udp_state,
    }
}
