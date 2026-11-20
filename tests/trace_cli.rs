//! Trace CLI smoke tests without dependence on the host traceroute utility.

use std::process::Command;

#[test]
fn trace_help_lists_observation_options() {
    let output = Command::new(env!("CARGO_BIN_EXE_pscan"))
        .args(["trace", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("--rounds"));
    assert!(text.contains("--format"));
}

#[test]
fn zero_max_hops_is_rejected_before_starting_backend() {
    let output = Command::new(env!("CARGO_BIN_EXE_pscan"))
        .args(["trace", "127.0.0.1", "--max-hops", "0"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--max-hops"));
}
