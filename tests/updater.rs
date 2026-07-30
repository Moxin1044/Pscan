use pscan::updater::is_newer;

#[test]
fn semver_comparison_detects_newer_patch() {
    assert!(is_newer("2.0.0", "2.0.1"));
    assert!(is_newer("2.0.0", "v2.0.1"));
    assert!(is_newer("v2.0.0", "2.0.1"));
}

#[test]
fn semver_comparison_rejects_older_or_same() {
    assert!(!is_newer("2.0.1", "2.0.0"));
    assert!(!is_newer("2.0.0", "2.0.0"));
    assert!(!is_newer("v2.0.0", "v2.0.0"));
}

#[test]
fn semver_comparison_detects_minor_and_major_bumps() {
    assert!(is_newer("2.0.9", "2.1.0"));
    assert!(is_newer("2.9.9", "3.0.0"));
    assert!(!is_newer("3.0.0", "2.9.9"));
}

#[test]
fn semver_comparison_handles_partial_versions() {
    assert!(is_newer("2.0", "2.0.1"));
    assert!(is_newer("2", "2.1"));
    assert!(!is_newer("2.1", "2"));
}
