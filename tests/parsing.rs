use pscan::ports::parse_ports;
use pscan::target::{TargetOptions, parse_target_expressions};

#[test]
fn parses_deduplicated_port_ranges() {
    assert_eq!(
        parse_ports("443,80,8000-8002,80").unwrap(),
        vec![80, 443, 8000, 8001, 8002]
    );
}

#[test]
fn rejects_invalid_ports() {
    assert!(parse_ports("0,80").is_err());
    assert!(parse_ports("90-80").is_err());
}

#[test]
fn expands_cidr_and_keeps_hostnames() {
    let targets = parse_target_expressions(
        &["192.0.2.0/30,localhost".into()],
        &TargetOptions { max_hosts: 16 },
    )
    .unwrap();
    assert_eq!(targets, vec!["192.0.2.1", "192.0.2.2", "localhost"]);
}

#[test]
fn preserves_point_to_point_and_single_host_cidrs() {
    let targets = parse_target_expressions(
        &["192.0.2.0/31,192.0.2.2/32,2001:db8::1/128".into()],
        &TargetOptions { max_hosts: 16 },
    )
    .unwrap();
    assert_eq!(
        targets,
        vec!["192.0.2.0", "192.0.2.1", "192.0.2.2", "2001:db8::1"]
    );
}

#[test]
fn expands_ipv4_ranges_and_deduplicates_targets() {
    let targets = parse_target_expressions(
        &["192.0.2.3-192.0.2.5,192.0.2.4,localhost".into()],
        &TargetOptions { max_hosts: 16 },
    )
    .unwrap();
    assert_eq!(
        targets,
        vec!["192.0.2.3", "192.0.2.4", "192.0.2.5", "localhost"]
    );
}

#[test]
fn rejects_descending_or_mixed_family_ranges() {
    assert!(
        parse_target_expressions(
            &["192.0.2.5-192.0.2.3".into()],
            &TargetOptions { max_hosts: 16 }
        )
        .is_err()
    );
    assert!(
        parse_target_expressions(
            &["192.0.2.1-2001:db8::1".into()],
            &TargetOptions { max_hosts: 16 }
        )
        .is_err()
    );
}

#[test]
fn enforces_target_limit() {
    let result =
        parse_target_expressions(&["10.0.0.0/8".into()], &TargetOptions { max_hosts: 100 });
    assert!(result.is_err());
}
