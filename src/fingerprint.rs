//! 服务指纹识别。
//!
//! 识别分三层，由粗到细：
//!
//! 1. **banner 匹配**：根据服务主动发送的欢迎信息判断协议，再尝试提取
//!    产品名与版本号（如 SSH 的 `SSH-2.0-OpenSSH_9.9p1`）。
//! 2. **主动探针**：对不会主动说话的协议（HTTP、TLS）由
//!    [`crate::scanner`] 与 [`crate::tls`] 发送探针后，把响应交回
//!    [`identify`] 或 [`identify_http`] 判定。
//! 3. **端口回退**：仍无法识别时，用静态端口表给出低置信度的服务名。
//!
//! 本模块是纯函数式的：只解析字节，不进行任何 IO。

use serde::Serialize;

/// 「端口 → 服务名」回退表，按端口升序排列，查找走二分。
///
/// 收录范围是 IANA 常见注册端口与广泛使用的应用端口；名称沿用
/// IANA / `services(5)` 的写法，避免自创词汇。表只用于低置信度回退，
/// 真实判定始终以 banner / 主动探针为准。
const PORT_NAMES: &[(u16, &str)] = &[
    (20, "ftp-data"),
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "domain"),
    (67, "dhcp"),
    (68, "dhcp"),
    (69, "tftp"),
    (80, "http"),
    (88, "kerberos"),
    (110, "pop3"),
    (111, "rpcbind"),
    (119, "nntp"),
    (123, "ntp"),
    (135, "msrpc"),
    (137, "netbios-ns"),
    (138, "netbios-dgm"),
    (139, "netbios-ssn"),
    (143, "imap"),
    (161, "snmp"),
    (162, "snmp-trap"),
    (179, "bgp"),
    (194, "irc"),
    (389, "ldap"),
    (443, "https"),
    (445, "microsoft-ds"),
    (465, "smtps"),
    (500, "isakmp"),
    (514, "syslog"),
    (515, "printer"),
    (520, "route"),
    (546, "dhcpv6-client"),
    (547, "dhcpv6-server"),
    (554, "rtsp"),
    (563, "nntps"),
    (587, "submission"),
    (623, "ipmi"),
    (631, "ipp"),
    (636, "ldaps"),
    (873, "rsync"),
    (902, "vmware-auth"),
    (989, "ftps-data"),
    (990, "ftps"),
    (992, "telnets"),
    (993, "imaps"),
    (994, "ircs"),
    (995, "pop3s"),
    (1080, "socks"),
    (1099, "rmi-registry"),
    (1194, "openvpn"),
    (1433, "ms-sql-s"),
    (1521, "oracle"),
    (1701, "l2tp"),
    (1723, "pptp"),
    (1812, "radius"),
    (1813, "radius-acct"),
    (1883, "mqtt"),
    (2049, "nfs"),
    (2082, "cpanel"),
    (2083, "cpanel-ssl"),
    (2181, "zookeeper"),
    (2375, "docker"),
    (2376, "docker-ssl"),
    (2379, "etcd"),
    (3128, "squid"),
    (3260, "iscsi"),
    (3306, "mysql"),
    (3389, "ms-wbt-server"),
    (3478, "stun"),
    (3690, "svn"),
    (4369, "epmd"),
    (4500, "ipsec-nat-t"),
    (5060, "sip"),
    (5061, "sips"),
    (5353, "mdns"),
    (5355, "llmnr"),
    (5432, "postgresql"),
    (5601, "kibana"),
    (5671, "amqps"),
    (5672, "amqp"),
    (5900, "vnc"),
    (5901, "vnc"),
    (5938, "teamviewer"),
    (5984, "couchdb"),
    (5985, "wsman"),
    (5986, "wsmans"),
    (6000, "x11"),
    (6379, "redis"),
    (6443, "kubernetes-api"),
    (6667, "irc"),
    (7077, "spark"),
    (8000, "http"),
    (8008, "http"),
    (8009, "ajp13"),
    (8080, "http"),
    (8081, "http"),
    (8086, "influxdb"),
    (8088, "http"),
    (8090, "http"),
    (8118, "privoxy"),
    (8161, "activemq"),
    (8200, "vault"),
    (8333, "bitcoin"),
    (8443, "https"),
    (8500, "consul"),
    (8529, "arangodb"),
    (8880, "http"),
    (8888, "http"),
    (8983, "solr"),
    (9000, "http"),
    (9042, "cassandra"),
    (9090, "http"),
    (9092, "kafka"),
    (9100, "printer"),
    (9200, "elasticsearch"),
    (9300, "elasticsearch"),
    (9418, "git"),
    (9443, "https"),
    (10000, "http"),
    (10250, "kubelet"),
    (10443, "https"),
    (11211, "memcached"),
    (15672, "rabbitmq-mgmt"),
    (25565, "minecraft"),
    (27017, "mongodb"),
    (27018, "mongodb"),
    (50070, "hdfs"),
    (61616, "activemq"),
];

/// 默认按 TLS 处理的端口。
///
/// 这些端口上不会主动说话的协议占绝对多数，因此扫描器会直接尝试 TLS
/// 握手，而不是先等被动 banner。列表可被 `--tls` 之类的显式参数覆盖。
pub(crate) const TLS_PORTS: &[u16] = &[
    443, 465, 636, 853, 989, 990, 992, 993, 994, 995, 8443, 9443, 10443,
];

/// 默认按 HTTPS 处理的端口，用于决定 TLS 握手后是否补发 HTTP 请求。
pub(crate) const HTTPS_PORTS: &[u16] = &[443, 8443, 9443, 10443];

/// 默认按明文 HTTP 处理的端口，用于决定是否发送 `HEAD` 探针。
pub(crate) const HTTP_PORTS: &[u16] = &[
    80, 81, 591, 8000, 8008, 8080, 8081, 8088, 8090, 8880, 8888, 9000, 10000,
];

/// SSH banner 的前缀。
const SSH_PREFIX: &[u8] = b"SSH-";

/// VNC 服务端问候语前缀，形如 `RFB 003.008\n`。
const VNC_PREFIX: &[u8] = b"RFB ";

/// VNC 协议版本主次版本分界：`003.008` → `3.8`。
const VNC_MAJOR_DIGITS: usize = 3;

/// MySQL 握手包的协议版本字节（服务端握手固定为 0x0a）。
const MYSQL_PROTOCOL_VERSION: u8 = 0x0a;

/// MySQL 握手包头部长度：3 字节长度 + 1 字节序号 + 1 字节协议版本。
const MYSQL_HANDSHAKE_HEADER_LEN: usize = 5;

/// MySQL 握手包声明的最小载荷长度，低于该值视为噪声。
const MYSQL_MIN_PAYLOAD_LEN: u32 = 6;

/// 从 banner / 探针响应解析出的服务指纹。
///
/// 三个字段都可能为空：完全无法识别时返回默认值（全 `None`）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Fingerprint {
    /// 协议 / 服务名，如 `ssh`、`http`、`mysql`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,

    /// 产品名，如 `OpenSSH`、`nginx`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,

    /// 版本号，如 `9.9p1`、`1.25.3`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl Fingerprint {
    /// 是否已识别出协议。
    ///
    /// # 返回
    ///
    /// * `true` - [`Fingerprint::service`] 非空。
    /// * `false` - 尚未识别出任何协议。
    pub fn is_identified(&self) -> bool {
        self.service.is_some()
    }

    /// 是否同时拿到了产品与版本，足以结束后续探测。
    ///
    /// # 返回
    ///
    /// * `true` - 产品与版本都已知。
    pub fn is_complete(&self) -> bool {
        self.product.is_some() && self.version.is_some()
    }
}

/// 根据端口与已读取的 banner 识别服务。
///
/// 识别顺序固定：SSH → VNC → MySQL → HTTP → Redis → AMQP → POP3 → IMAP →
/// SMTP/FTP → PostgreSQL → 端口表回退。先匹配特征最长的协议，避免通用
/// 行（如 `220`）误判为其它服务。
///
/// # 参数
///
/// * `port` - 目标端口，用于端口回退与 HTTP/HTTPS 区分。
/// * `banner` - 已读取的响应字节，可能为空、可能是二进制协议数据。
///
/// # 返回
///
/// * [`Fingerprint`] - 识别结果；无法识别时各字段为 `None`。
pub fn identify(port: u16, banner: &[u8]) -> Fingerprint {
    if banner.starts_with(SSH_PREFIX) {
        return parse_ssh(banner);
    }
    if banner.starts_with(VNC_PREFIX) {
        return parse_vnc(banner);
    }
    if is_mysql_handshake(banner) {
        return parse_mysql(banner);
    }

    let text = String::from_utf8_lossy(banner);
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("http/") {
        return parse_http(&text, TLS_PORTS.contains(&port));
    }
    if lower.starts_with("+pong") || lower.starts_with("-err") && lower.contains("redis") {
        return service("redis");
    }
    if lower.starts_with("amqp") {
        return service("amqp");
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
    // PostgreSQL 对 SSLRequest 的应答只有单字节 S / N。
    if banner == b"S" || banner == b"N" {
        return service("postgresql");
    }

    service_for_port(port).map_or_else(Fingerprint::default, service)
}

/// 解析明文 HTTP 响应，提取 `Server` 头中的产品与版本。
///
/// 供主动 HTTP 探针使用：调用方已确认对端返回了 `HTTP/` 状态行。
///
/// # 参数
///
/// * `text` - HTTP 响应文本（至少包含状态行与头部）。
/// * `tls` - 该响应是否来自 TLS 连接，决定服务名为 `https` 还是 `http`。
///
/// # 返回
///
/// * [`Fingerprint`] - 服务名固定为 `http` / `https`；`Server` 头缺失时
///   产品与版本为空。
pub fn identify_http(text: &str, tls: bool) -> Fingerprint {
    parse_http(text, tls)
}

/// 仅按端口给出口径最保守的服务名（低置信度）。
///
/// # 参数
///
/// * `port` - 目标端口。
///
/// # 返回
///
/// * [`Fingerprint`] - 命中端口表时带 `service`，否则各字段为 `None`。
pub fn port_fallback(port: u16) -> Fingerprint {
    service_for_port(port).map_or_else(Fingerprint::default, service)
}

/// 查询端口对应的服务名。
///
/// # 参数
///
/// * `port` - 目标端口。
///
/// # 返回
///
/// * `Some(&'static str)` - 端口表中的服务名。
/// * `None` - 表中无此端口。
pub fn service_for_port(port: u16) -> Option<&'static str> {
    PORT_NAMES
        .binary_search_by_key(&port, |(candidate, _)| *candidate)
        .ok()
        .map(|index| PORT_NAMES[index].1)
}

/// 判断端口是否在默认 TLS 端口表内。
///
/// # 参数
///
/// * `port` - 目标端口。
///
/// # 返回
///
/// * `true` - 该端口通常直接以 TLS 开始会话。
pub fn is_tls_port(port: u16) -> bool {
    TLS_PORTS.contains(&port)
}

/// 判断端口是否在默认 HTTPS 端口表内。
///
/// # 参数
///
/// * `port` - 目标端口。
///
/// # 返回
///
/// * `true` - 该端口通常是 HTTPS（而非任意 TLS 协议）。
pub fn is_https_port(port: u16) -> bool {
    HTTPS_PORTS.contains(&port)
}

/// 判断端口是否在默认明文 HTTP 端口表内。
///
/// # 参数
///
/// * `port` - 目标端口。
///
/// # 返回
///
/// * `true` - 该端口通常是明文 HTTP。
pub fn is_http_port(port: u16) -> bool {
    HTTP_PORTS.contains(&port)
}

/// 解析 SSH banner，提取产品与版本。
///
/// banner 形如 `SSH-2.0-OpenSSH_9.9p1`：按 `-` 切三段，第三段的第一个
/// 空白分隔 token 即软件标识，再按 `_` 拆成产品与版本。
///
/// # 参数
///
/// * `banner` - 以 `SSH-` 开头的 banner 字节。
///
/// # 返回
///
/// * [`Fingerprint`] - `service` 固定为 `ssh`，产品与版本可能为空。
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

/// 解析 VNC 服务端问候语，提取协议版本。
///
/// 问候语固定 12 字节：`RFB 003.008\n`，前 3 位为主版本、后 3 位为次版本，
/// 需要去掉前导零后拼接。
///
/// # 参数
///
/// * `banner` - 以 `RFB ` 开头的问候语。
///
/// # 返回
///
/// * [`Fingerprint`] - `service` 为 `vnc`，版本形如 `3.8`。
fn parse_vnc(banner: &[u8]) -> Fingerprint {
    let text = String::from_utf8_lossy(banner);
    let version = text
        .get(VNC_PREFIX.len()..VNC_PREFIX.len() * 2 + VNC_MAJOR_DIGITS)
        .map(|digits| digits.trim())
        .and_then(|digits| digits.split_once('.'))
        .map(|(major, minor)| {
            let major = major.trim_start_matches('0');
            let minor = minor.trim_start_matches('0');
            format!("{}.{}", if major.is_empty() { "0" } else { major }, minor)
        })
        .filter(|value| !value.is_empty());
    Fingerprint {
        service: Some("vnc".into()),
        product: Some("VNC".into()),
        version,
    }
}

/// 解析 MySQL 握手包，提取服务端版本号。
///
/// # 参数
///
/// * `banner` - 已通过 [`is_mysql_handshake`] 校验的握手字节。
///
/// # 返回
///
/// * [`Fingerprint`] - `service` 为 `mysql`，版本取自首个 NUL 前的文本。
fn parse_mysql(banner: &[u8]) -> Fingerprint {
    let version = banner[MYSQL_HANDSHAKE_HEADER_LEN..]
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

/// 判断字节流是否符合 MySQL / MariaDB 服务端握手包结构。
///
/// 结构为 `[u24 载荷长度][u8 序号][u8 协议版本 = 0x0a][以 NUL 结尾的版本串]`。
/// 全部字节必须是可打印 ASCII，用于排除随机二进制数据误判。
///
/// # 参数
///
/// * `banner` - 待检测字节。
///
/// # 返回
///
/// * `true` - 结构合法，可交给 [`parse_mysql`] 解析。
/// * `false` - 长度不足、协议版本不符或版本串含非可打印字符。
fn is_mysql_handshake(banner: &[u8]) -> bool {
    if banner.len() <= MYSQL_HANDSHAKE_HEADER_LEN || banner[4] != MYSQL_PROTOCOL_VERSION {
        return false;
    }
    let declared_length =
        u32::from(banner[0]) | (u32::from(banner[1]) << 8) | (u32::from(banner[2]) << 16);
    if declared_length < MYSQL_MIN_PAYLOAD_LEN {
        return false;
    }
    let Some(nul_offset) = banner[MYSQL_HANDSHAKE_HEADER_LEN..]
        .iter()
        .position(|byte| *byte == 0)
    else {
        return false;
    };
    if nul_offset == 0 {
        return false;
    }
    banner[MYSQL_HANDSHAKE_HEADER_LEN..MYSQL_HANDSHAKE_HEADER_LEN + nul_offset]
        .iter()
        .all(|byte| byte.is_ascii_graphic())
}

/// 从 HTTP 响应头解析 `Server` 字段，提取产品与版本。
///
/// # 参数
///
/// * `text` - HTTP 响应（至少包含状态行与头部）。
/// * `tls` - 响应是否来自 TLS 连接。
///
/// # 返回
///
/// * [`Fingerprint`] - `service` 为 `http` / `https`，产品版本来自
///   `Server: Product/Version`，缺失时为空。
fn parse_http(text: &str, tls: bool) -> Fingerprint {
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
        service: Some(if tls { "https".into() } else { "http".into() }),
        product: nonempty(product),
        version: nonempty(version),
    }
}

/// 构造只含服务名的指纹。
///
/// # 参数
///
/// * `name` - 协议 / 服务名。
///
/// # 返回
///
/// * [`Fingerprint`] - 仅 `service` 有值。
fn service(name: &str) -> Fingerprint {
    Fingerprint {
        service: Some(name.into()),
        ..Fingerprint::default()
    }
}

/// 把空字符串转换为 `None`，避免输出里出现空字段。
///
/// # 参数
///
/// * `value` - 待转换文本。
///
/// # 返回
///
/// * `Some(String)` - 文本非空。
/// * `None` - 文本为空。
fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 端口表必须严格升序，二分查找才成立。
    #[test]
    fn port_table_is_sorted_and_unique() {
        for window in PORT_NAMES.windows(2) {
            assert!(
                window[0].0 < window[1].0,
                "{} 与 {} 顺序错误或重复",
                window[0].0,
                window[1].0
            );
        }
    }

    /// 常见端口都能命中，且二分边界正确。
    #[test]
    fn known_ports_resolve() {
        assert_eq!(service_for_port(22), Some("ssh"));
        assert_eq!(service_for_port(443), Some("https"));
        assert_eq!(service_for_port(61616), Some("activemq"));
        assert_eq!(service_for_port(1), None);
        assert_eq!(service_for_port(65535), None);
    }

    /// TLS / HTTP 端口判定与端口表保持一致。
    #[test]
    fn protocol_port_sets_are_consistent() {
        assert!(is_tls_port(443));
        assert!(is_tls_port(995));
        assert!(!is_tls_port(80));
        assert!(is_http_port(8080));
        assert!(!is_http_port(443));
        assert_eq!(service_for_port(993), Some("imaps"));
    }

    /// VNC 问候语解析出版本，且不把 `0` 前缀带进输出。
    #[test]
    fn parses_vnc_greeting() {
        let parsed = identify(5900, b"RFB 003.008\n");
        assert_eq!(parsed.service.as_deref(), Some("vnc"));
        assert_eq!(parsed.version.as_deref(), Some("3.8"));
        assert_eq!(parsed.product.as_deref(), Some("VNC"));
    }

    /// TLS 端口上的 HTTP 响应应标为 https。
    #[test]
    fn http_over_tls_port_is_https() {
        let parsed = identify_http("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n", true);
        assert_eq!(parsed.service.as_deref(), Some("https"));
        assert_eq!(parsed.product.as_deref(), Some("nginx"));
        assert_eq!(parsed.version.as_deref(), Some("1.25.3"));
    }
}
