use pscan::fingerprint::identify;

#[test]
fn parses_common_passive_banners() {
    let ssh = identify(49152, b"SSH-2.0-OpenSSH_9.9p1 Debian-1\r\n");
    assert_eq!(ssh.service.as_deref(), Some("ssh"));
    assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
    assert_eq!(ssh.version.as_deref(), Some("9.9p1"));

    let mysql = identify(49153, b"\x4a\x00\x00\x00\x0a8.4.0\x00");
    assert_eq!(mysql.service.as_deref(), Some("mysql"));
    assert_eq!(mysql.version.as_deref(), Some("8.4.0"));
}

#[test]
fn rejects_mysql_shaped_random_bytes() {
    // 3-byte length header claims 0 bytes of payload; byte 4 accidentally matches protocol 0x0a.
    let banner = [0x00, 0x00, 0x00, 0x00, 0x0a, 0x41, 0x42];
    let fingerprint = identify(0, &banner);
    assert_ne!(fingerprint.service.as_deref(), Some("mysql"));
}

#[test]
fn parses_http_server_header() {
    let result = identify(
        49154,
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.27.0\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(result.service.as_deref(), Some("http"));
    assert_eq!(result.product.as_deref(), Some("nginx"));
    assert_eq!(result.version.as_deref(), Some("1.27.0"));
}
