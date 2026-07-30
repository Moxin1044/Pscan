use serde::Serialize;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Fingerprint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl Fingerprint {
    pub fn is_identified(&self) -> bool {
        self.service.is_some()
    }
}

pub fn identify(port: u16, banner: &[u8]) -> Fingerprint {
    if banner.starts_with(b"SSH-") {
        return parse_ssh(banner);
    }
    if is_mysql_handshake(banner) {
        return parse_mysql(banner);
    }

    let text = String::from_utf8_lossy(banner);
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("http/") {
        return parse_http(&text, port);
    }
    if lower.starts_with("+pong") || lower.starts_with("-err") && lower.contains("redis") {
        return service("redis");
    }
    if lower.starts_with("+ok") {
        return service("pop3");
    }
    if lower.starts_with("* ok") || lower.starts_with("* preauth") {
        return service("imap");
    }
    if lower.starts_with("220") {
        if lower.contains("smtp") || lower.contains("esmtp") {
            return service("smtp");
        }
        if lower.contains("ftp") || port == 21 {
            return service("ftp");
        }
    }
    if banner == b"S" || banner == b"N" {
        return service("postgresql");
    }

    service_for_port(port).map_or_else(Fingerprint::default, service)
}

pub fn port_fallback(port: u16) -> Fingerprint {
    service_for_port(port).map_or_else(Fingerprint::default, service)
}

pub fn service_for_port(port: u16) -> Option<&'static str> {
    match port {
        20 | 21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 | 465 | 587 => Some("smtp"),
        53 => Some("dns"),
        80 | 8000 | 8080 | 8888 => Some("http"),
        110 | 995 => Some("pop3"),
        143 | 993 => Some("imap"),
        443 | 8443 => Some("https"),
        3306 => Some("mysql"),
        5432 => Some("postgresql"),
        6379 => Some("redis"),
        _ => None,
    }
}

fn parse_ssh(banner: &[u8]) -> Fingerprint {
    let text = String::from_utf8_lossy(banner);
    let software = text.trim().splitn(3, '-').nth(2).unwrap_or_default();
    let token = software.split_whitespace().next().unwrap_or_default();
    let (product, version) = token.split_once('_').unwrap_or((token, ""));
    Fingerprint {
        service: Some("ssh".into()),
        product: nonempty(product),
        version: nonempty(version),
    }
}

fn parse_mysql(banner: &[u8]) -> Fingerprint {
    let version = banner[5..]
        .split(|byte| *byte == 0)
        .next()
        .map(String::from_utf8_lossy)
        .map(|value| value.into_owned())
        .filter(|value| !value.is_empty());
    Fingerprint {
        service: Some("mysql".into()),
        product: Some("MySQL".into()),
        version,
    }
}

fn is_mysql_handshake(banner: &[u8]) -> bool {
    // MySQL/MariaDB handshake framing: u24 payload length, u8 sequence, protocol version byte.
    if banner.len() < 6 || banner[4] != 0x0a {
        return false;
    }
    let declared_length =
        u32::from(banner[0]) | (u32::from(banner[1]) << 8) | (u32::from(banner[2]) << 16);
    if declared_length < 6 {
        return false;
    }
    let Some(nul_offset) = banner[5..].iter().position(|byte| *byte == 0) else {
        return false;
    };
    if nul_offset == 0 {
        return false;
    }
    banner[5..5 + nul_offset]
        .iter()
        .all(|byte| byte.is_ascii_graphic())
}

fn parse_http(text: &str, port: u16) -> Fingerprint {
    let server = text.lines().find_map(|line| {
        line.split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("server"))
            .map(|(_, value)| value.trim())
    });
    let (product, version) = server
        .and_then(|value| value.split_whitespace().next())
        .map(|token| token.split_once('/').unwrap_or((token, "")))
        .unwrap_or(("", ""));
    Fingerprint {
        service: Some(if matches!(port, 443 | 8443) {
            "https".into()
        } else {
            "http".into()
        }),
        product: nonempty(product),
        version: nonempty(version),
    }
}

fn service(name: &str) -> Fingerprint {
    Fingerprint {
        service: Some(name.into()),
        ..Fingerprint::default()
    }
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}
