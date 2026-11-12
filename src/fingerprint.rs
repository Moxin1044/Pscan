//! 服务指纹识别。
//!
//! 识别分两层，由粗到细：
//!
//! 1. **banner 匹配**：根据服务主动发送的欢迎信息判断协议，再尝试提取
//!    产品名与版本号（如 SSH 的 `SSH-2.0-OpenSSH_9.9p1`）。
//! 2. **端口回退**：banner 无法识别时，用静态端口表给出低置信度的服务名。
//!
//! 本模块不执行 TLS 握手、不发送协议专属探针；主动 HTTP `HEAD` 探针由
//! [`crate::scanner`] 在拿到连接后调用本模块的 [`identify`] 完成判定。

use serde::Serialize;

/// banner 回退到端口表时使用的「端口 → 服务名」映射。
///
/// 顺序不重要，查找走线性扫描（表规模在十几个量级，开销可忽略）。
const PORT_SERVICES: &[(&str, &[u16])] = &[
    ("ftp", &[20, 21]),
    ("ssh", &[22]),
    ("telnet", &[23]),
    ("smtp", &[25, 465, 587]),
    ("dns", &[53]),
    ("http", &[80, 8000, 8080, 8888]),
    ("pop3", &[110, 995]),
    ("imap", &[143, 993]),
    ("https", &[443, 8443]),
    ("mysql", &[3306]),
    ("postgresql", &[5432]),
    ("redis", &[6379]),
];

/// 被视为 HTTPS 的端口，用于把 HTTP banner 修正为 `https`。
const TLS_PORTS: &[u16] = &[443, 8443];

/// SSH banner 的前缀。
const SSH_PREFIX: &[u8] = b"SSH-";

/// MySQL 握手包的协议版本字节（服务端握手固定为 0x0a）。
const MYSQL_PROTOCOL_VERSION: u8 = 0x0a;

/// MySQL 握手包头部长度：3 字节长度 + 1 字节序号 + 1 字节协议版本。
const MYSQL_HANDSHAKE_HEADER_LEN: usize = 5;

/// MySQL 握手包声明的最小载荷长度，低于该值视为噪声。
const MYSQL_MIN_PAYLOAD_LEN: u32 = 6;

/// 从 banner 解析出的服务指纹。
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
}

/// 根据端口与已读取的 banner 识别服务。
///
/// 识别顺序固定：SSH → MySQL → HTTP → Redis → POP3 → IMAP → SMTP/FTP →
/// PostgreSQL → 端口表回退。先匹配特征最长的协议，避免通用行（如 `220`）
/// 误判为其它服务。
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
    // PostgreSQL 对 SSLRequest 的应答只有单字节 S / N。
    if banner == b"S" || banner == b"N" {
        return service("postgresql");
    }

    service_for_port(port).map_or_else(Fingerprint::default, service)
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
    PORT_SERVICES
        .iter()
        .find(|(_, ports)| ports.contains(&port))
        .map(|(service, _)| *service)
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
/// * `port` - 目标端口，用于把结果标为 `http` 或 `https`。
///
/// # 返回
///
/// * [`Fingerprint`] - `service` 为 `http` / `https`，产品版本来自
///   `Server: Product/Version`，缺失时为空。
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
        service: Some(if TLS_PORTS.contains(&port) {
            "https".into()
        } else {
            "http".into()
        }),
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
    (!value.is_empty()).then(|| value.to_owned())
}
