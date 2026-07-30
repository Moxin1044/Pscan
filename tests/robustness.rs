use std::path::PathBuf;
use std::process::Command;

fn pscan() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pscan"))
}

#[test]
fn dns_failures_are_reported_and_exit_code_is_nonzero() {
    let output = pscan()
        .args([
            "--target",
            "does-not-exist.pscan.invalid",
            "--ports",
            "80",
            "--timeout-ms",
            "500",
        ])
        .output()
        .unwrap();
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does-not-exist.pscan.invalid"));
    assert!(stderr.contains("resolve"));
}

#[test]
fn output_failure_cancels_and_reports_error() {
    let missing: PathBuf = ["/pscan-nonexistent-dir", "results.txt"].iter().collect();
    let output = pscan()
        .args([
            "--target",
            "127.0.0.1",
            "--ports",
            "1-16",
            "--timeout-ms",
            "200",
            "--output",
        ])
        .arg(&missing)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("pscan:"));
}
