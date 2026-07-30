use std::process::Command;

fn pscan() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pscan"))
}

#[test]
fn help_exposes_only_scanner_options() {
    let output = pscan().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--target"));
    assert!(stdout.contains("--ports"));
    assert!(stdout.contains("--rate"));
    assert!(stdout.contains("--service-detection"));
    assert!(stdout.contains("--udp"));
    assert!(stdout.contains("--ping"));
    assert!(stdout.contains("--ping-only"));
    assert!(!stdout.contains("audit"));
    assert!(!stdout.contains("template"));
}

#[test]
fn rejects_zero_sized_execution_limits() {
    for option in ["--concurrency", "--result-buffer"] {
        let output = pscan()
            .args(["--target", "127.0.0.1", "--ports", "80", option, "0"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("greater than zero"));
    }
}
