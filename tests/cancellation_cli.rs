#[cfg(unix)]
#[test]
fn ctrl_c_returns_130_and_flushes_output() {
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;

    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("partial.jsonl");
    let child = Command::new(env!("CARGO_BIN_EXE_pscan"))
        .args([
            "--target",
            "10.255.0.0/20",
            "--ports",
            "1-100",
            "--concurrency",
            "8",
            "--rate",
            "20",
            "--show-closed",
            "--format",
            "jsonl",
            "--output",
        ])
        .arg(&output_path)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_millis(250));
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());

    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(130));
    assert!(String::from_utf8_lossy(&output.stderr).contains("completed results were flushed"));
    let contents = std::fs::read_to_string(output_path).unwrap();
    for line in contents.lines() {
        serde_json::from_str::<serde_json::Value>(line).unwrap();
    }
}
