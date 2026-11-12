//! TLS 服务指纹。
//!
//! 对「不会主动说话」的 TLS 端点，单靠被动 banner 什么都拿不到。本模块在
//! 已建立的 TCP 连接上完成一次真实 TLS 握手，然后采集：
//!
//! - 协商出的协议版本（`TLS1.2` / `TLS1.3`）
//! - 密码套件名
//! - ALPN 协商结果（`h2` / `http/1.1`）
//! - 证书的主体与签发者 `CN`
//! - 握手成功后补发 `HEAD /` 得到的 `Server` 头（HTTP 系产品与版本）
//!
//! 握手**不校验证书**：扫描器面对的是任意主机，自签名与过期证书都很常见，
//! 校验失败会掩盖我们真正想知道的协议信息。这也意味着本模块只用于探测，
//! 不能用于任何需要身份保证的场景。

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error, ProtocolVersion, SignatureScheme,
};

use crate::fingerprint::{self, Fingerprint};

/// 握手成功后读取 HTTP 响应的最长等待时间。
const HTTP_READ_WAIT: Duration = Duration::from_millis(300);

/// HTTP 探针的最大读取字节数，足够覆盖状态行与常见响应头。
const HTTP_MAX_BYTES: usize = 2048;

/// 证书 `commonName` 的 DER 编码（OID 2.5.4.3）。
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// DER `SEQUENCE` 标签。
const DER_SEQUENCE: u8 = 0x30;

/// DER `SET` 标签。
const DER_SET: u8 = 0x31;

/// DER `INTEGER` 标签。
const DER_INTEGER: u8 = 0x02;

/// DER `OID` 标签。
const DER_OID: u8 = 0x06;

/// DER 上下文标签 `[0]`（证书的 version 字段）。
const DER_CONTEXT_ZERO: u8 = 0xa0;

/// 一次 TLS 握手中采集到的信息。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsInfo {
    /// 协商版本，如 `TLS1.3`。
    pub version: Option<String>,

    /// 协商的密码套件，如 `TLS13_AES_128_GCM_SHA256`。
    pub cipher: Option<String>,

    /// ALPN 结果，如 `h2`；服务端不支持 ALPN 时为 `None`。
    pub alpn: Option<String>,

    /// 证书主体 `CN`。
    pub subject: Option<String>,

    /// 证书签发者 `CN`。
    pub issuer: Option<String>,

    /// 握手成功后补发 `HEAD /` 得到的 HTTP 指纹。
    pub http: Option<Fingerprint>,
}

impl TlsInfo {
    /// 拼一行人类可读的摘要，供 banner 字段展示。
    ///
    /// # 返回
    ///
    /// * `String` - 以空格分隔的 `版本 套件 ALPN 主体 签发者`；全空时为空串。
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(version) = &self.version {
            parts.push(version.clone());
        }
        if let Some(cipher) = &self.cipher {
            parts.push(cipher.clone());
        }
        if let Some(alpn) = &self.alpn {
            parts.push(alpn.clone());
        }
        if let Some(subject) = &self.subject {
            parts.push(format!("subject={subject}"));
        }
        if let Some(issuer) = &self.issuer {
            parts.push(format!("issuer={issuer}"));
        }
        parts.join(" ")
    }
}

/// 接受任意服务端证书的校验器。
///
/// 扫描器只关心协议特征，不关心证书链是否可信，因此 `verify_*` 一律返回
/// 成功。签名校验同理——即使证书是自签名的，握手也要继续。
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    /// 无条件接受服务端证书。
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    /// 跳过 TLS 1.2 握手签名校验。
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// 跳过 TLS 1.3 握手签名校验。
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// 返回本进程 crypto provider 支持的全部签名算法。
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 构造「不校验证书」的客户端配置。
///
/// # 返回
///
/// * `Ok(ClientConfig)` - 配置就绪。
///
/// # 错误
///
/// * `Error` - 协议版本配置异常（正常构建下不会发生）。
fn client_config() -> Result<ClientConfig, Error> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    // 只声明 http/1.1：拿到 h2 后我们无法在明文层发请求，反而读不到
    // `Server` 头；服务端不支持 ALPN 时会忽略该字段。
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// 把主机字符串转换成 rustls 的服务器名。
///
/// IP 字面量走 `IpAddress` 分支（此时 rustls 不会发送 SNI），其余按 DNS
/// 名称处理。
///
/// # 参数
///
/// * `host` - 目标主机名或 IP 文本。
///
/// # 返回
///
/// * `Some(ServerName)` - 可用的服务器名。
/// * `None` - 既不是合法 IP 也不是合法 DNS 名称（如含非法字符）。
fn server_name(host: &str) -> Option<ServerName<'static>> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_owned()).ok()
}

/// 把 rustls 的协议版本枚举转成惯用写法。
///
/// # 参数
///
/// * `version` - rustls 协商出的版本。
///
/// # 返回
///
/// * `String` - `TLS1.3` / `TLS1.2` / `TLS1.1` / `TLS1.0`；其它版本回退到
///   调试名，避免出现空值。
fn protocol_version_name(version: ProtocolVersion) -> String {
    match version {
        ProtocolVersion::TLSv1_3 => "TLS1.3".into(),
        ProtocolVersion::TLSv1_2 => "TLS1.2".into(),
        ProtocolVersion::TLSv1_1 => "TLS1.1".into(),
        ProtocolVersion::TLSv1_0 => "TLS1.0".into(),
        other => format!("{other:?}"),
    }
}

/// 在已连通的 TCP 流上完成 TLS 握手并采集指纹。
///
/// # 参数
///
/// * `socket` - 已连通的 TCP 流；函数会接管其读写，但不会关闭它。
/// * `host` - 目标主机名或 IP，用于 SNI 与 `Host` 头。
/// * `budget` - 握手与后续读取共享的总预算。
/// * `expect_http` - 端口是否按 HTTPS 处理；为 `false` 时只有 ALPN 协商出
///   `http/1.1` 才会补发 HTTP 请求，避免向 IMAP / SMTP 等协议写入垃圾数据。
///
/// # 返回
///
/// * `Some(TlsInfo)` - 握手成功，字段按可得情况填充。
/// * `None` - 握手失败、超时，或对端不是 TLS。
pub async fn probe(
    socket: &mut TcpStream,
    host: &str,
    budget: Duration,
    expect_http: bool,
) -> Option<TlsInfo> {
    let deadline = tokio::time::Instant::now() + budget;
    let name = server_name(host)?;
    let config = client_config().ok()?;
    let connector = TlsConnector::from(Arc::new(config));

    let mut stream = timeout(budget, connector.connect(name, &mut *socket))
        .await
        .ok()?
        .ok()?;

    let mut info = TlsInfo::default();
    {
        let (_, connection) = stream.get_ref();
        info.version = connection.protocol_version().map(protocol_version_name);
        info.cipher = connection
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite()));
        info.alpn = connection
            .alpn_protocol()
            .map(|protocol| String::from_utf8_lossy(protocol).into_owned());
        if let Some(certificate) = connection
            .peer_certificates()
            .and_then(|certificates| certificates.first())
        {
            let (subject, issuer) = certificate_names(certificate.as_ref());
            info.subject = subject;
            info.issuer = issuer;
        }
    }

    let http_expected = expect_http
        || info
            .alpn
            .as_deref()
            .is_some_and(|alpn| alpn.starts_with("http/"));
    if http_expected
        && let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
    {
        info.http = http_over_tls(&mut stream, host, remaining).await;
    }
    Some(info)
}

/// 在 TLS 通道上补发一次 `HEAD /`，解析响应头。
///
/// # 参数
///
/// * `stream` - 已握手的 TLS 流。
/// * `host` - 目标主机名，用于 `Host` 头。
/// * `budget` - 本次读写的总预算。
///
/// # 返回
///
/// * `Some(Fingerprint)` - 对端返回了合法的 HTTP 响应。
/// * `None` - 写入或读取失败、超时，或响应不是 HTTP。
async fn http_over_tls<S>(stream: &mut S, host: &str, budget: Duration) -> Option<Fingerprint>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!("HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Pscan/2\r\n\r\n");
    let wait = budget.min(HTTP_READ_WAIT);
    timeout(wait, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buffer = vec![0_u8; HTTP_MAX_BYTES];
    let read = timeout(wait, stream.read(&mut buffer)).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&buffer[..read]);
    if !text.to_ascii_lowercase().starts_with("http/") {
        return None;
    }
    Some(fingerprint::identify_http(&text, true))
}

/// 从 DER 编码的证书中提取主体与签发者 `commonName`。
///
/// 证书结构固定为
/// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }`，
/// 其中 `tbsCertificate` 依次是 `[0] version`（可选）、`serialNumber`、
/// `signature`、`issuer`、`validity`、`subject`、`subjectPublicKeyInfo`。
///
/// # 参数
///
/// * `der` - 单张证书的 DER 字节。
///
/// # 返回
///
/// * `(Option<String>, Option<String>)` - `(subject CN, issuer CN)`；解析失败
///   的字段为 `None`。
fn certificate_names(der: &[u8]) -> (Option<String>, Option<String>) {
    let Some(certificate) = der_sequence(der) else {
        return (None, None);
    };
    let Some(tbs) = der_sequence(certificate) else {
        return (None, None);
    };
    let mut rest = tbs;
    // 可选字段：显式的 version 上下文标签。
    if let Some((DER_CONTEXT_ZERO, _, next)) = der_tlv(rest) {
        rest = next;
    }
    // serialNumber、signature 之后才是 issuer。
    let Some((DER_INTEGER, _, next)) = der_tlv(rest) else {
        return (None, None);
    };
    let Some((DER_SEQUENCE, _, next)) = der_tlv(next) else {
        return (None, None);
    };
    let Some((DER_SEQUENCE, issuer, next)) = der_tlv(next) else {
        return (None, None);
    };
    // 跳过 validity，取 subject。
    let Some((_, _, next)) = der_tlv(next) else {
        return (None, None);
    };
    let Some((DER_SEQUENCE, subject, _)) = der_tlv(next) else {
        return (None, None);
    };
    (common_name(subject), common_name(issuer))
}

/// 在 `RDNSequence` 中查找 `commonName`。
///
/// 结构为 `RDNSequence ::= SEQUENCE OF SET OF SEQUENCE { OID, value }`。
///
/// # 参数
///
/// * `name` - `Name` 的内容字节（不含外层 `SEQUENCE` 头）。
///
/// # 返回
///
/// * `Some(String)` - 第一个 `commonName` 的值。
/// * `None` - 未找到或编码非法。
fn common_name(name: &[u8]) -> Option<String> {
    let mut rdns = name;
    while !rdns.is_empty() {
        let (tag, set, next) = der_tlv(rdns)?;
        rdns = next;
        if tag != DER_SET {
            continue;
        }
        let mut attributes = set;
        while !attributes.is_empty() {
            let (tag, attribute, next) = der_tlv(attributes)?;
            attributes = next;
            if tag != DER_SEQUENCE {
                continue;
            }
            if let Some(value) = attribute_common_name(attribute) {
                return Some(value);
            }
        }
    }
    None
}

/// 判断一个 `AttributeTypeAndValue` 是否 `commonName` 并取出其值。
///
/// # 参数
///
/// * `attribute` - `SEQUENCE { OID, value }` 的内容字节。
///
/// # 返回
///
/// * `Some(String)` - OID 为 2.5.4.3 时的值。
/// * `None` - 不是 `commonName`，或值不是可解码的字符串。
fn attribute_common_name(attribute: &[u8]) -> Option<String> {
    let (tag, oid, rest) = der_tlv(attribute)?;
    if tag != DER_OID || oid != OID_COMMON_NAME {
        return None;
    }
    let (_, value, _) = der_tlv(rest)?;
    // 0x0c UTF8String / 0x13 PrintableString / 0x16 IA5String / 0x14 T61String
    matches!(der_tag(rest)?, 0x0c | 0x13 | 0x14 | 0x16)
        .then(|| String::from_utf8_lossy(value).into_owned())
}

/// 读取 DER TLV 的标签字节。
///
/// # 参数
///
/// * `data` - 起始于标签的字节。
///
/// # 返回
///
/// * `Some(u8)` - 标签字节；多字节标签（0x1f 起）不在证书常见字段中出现，
///   返回 `None`。
fn der_tag(data: &[u8]) -> Option<u8> {
    der_tlv(data).map(|(tag, _, _)| tag)
}

/// 解析一个 DER TLV。
///
/// # 参数
///
/// * `data` - 起始于标签的字节。
///
/// # 返回
///
/// * `Some((tag, value, rest))` - 标签、值切片与剩余字节。
/// * `None` - 长度字段越界或使用不支持的编码。
fn der_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (length, rest) = der_length(rest)?;
    if rest.len() < length {
        return None;
    }
    Some((tag, &rest[..length], &rest[length..]))
}

/// 解析 DER 长度字段（支持短形式与 1–3 字节长形式）。
///
/// # 参数
///
/// * `data` - 长度字段起始字节。
///
/// # 返回
///
/// * `Some((usize, &[u8]))` - 长度与剩余字节。
/// * `None` - 长度字段非法或超过 3 字节（证书不会出现）。
fn der_length(data: &[u8]) -> Option<(usize, &[u8])> {
    let (&first, rest) = data.split_first()?;
    if first < 0x80 {
        return Some((usize::from(first), rest));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 3 || rest.len() < count {
        return None;
    }
    let (bytes, rest) = rest.split_at(count);
    let length = bytes
        .iter()
        .fold(0_usize, |acc, byte| (acc << 8) | usize::from(*byte));
    Some((length, rest))
}

/// 读取一个 DER `SEQUENCE` 的内容。
///
/// # 参数
///
/// * `data` - 起始于 `SEQUENCE` 标签的字节。
///
/// # 返回
///
/// * `Some(&[u8])` - 内容字节。
/// * `None` - 标签不是 `SEQUENCE` 或编码非法。
fn der_sequence(data: &[u8]) -> Option<&[u8]> {
    match der_tlv(data)? {
        (DER_SEQUENCE, value, _) => Some(value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个 TLV，长度按短形式或单字节长形式编码。
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 0x80 {
            out.push(value.len() as u8);
        } else {
            out.push(0x81);
            out.push(value.len() as u8);
        }
        out.extend_from_slice(value);
        out
    }

    /// 构造一个只含 `commonName` 的 Name。
    fn name(cn: &str) -> Vec<u8> {
        let mut attribute = tlv(DER_OID, OID_COMMON_NAME);
        attribute.extend(tlv(0x0c, cn.as_bytes()));
        let attribute = tlv(DER_SEQUENCE, &attribute);
        tlv(DER_SET, &attribute)
    }

    /// 构造最小证书骨架：tbs 里只保留 issuer 与 subject 前的必填字段。
    fn certificate(issuer: &str, subject: &str) -> Vec<u8> {
        let mut tbs = Vec::new();
        tbs.extend(tlv(DER_CONTEXT_ZERO, &[0x02, 0x01, 0x02])); // version v3
        tbs.extend(tlv(DER_INTEGER, &[0x01])); // serial
        tbs.extend(tlv(DER_SEQUENCE, &tlv(DER_OID, &[0x2a, 0x86, 0x48]))); // sig alg
        tbs.extend(tlv(DER_SEQUENCE, &name(issuer))); // issuer
        tbs.extend(tlv(DER_SEQUENCE, b"\x17\x0d20240101000000Z")); // validity
        tbs.extend(tlv(DER_SEQUENCE, &name(subject))); // subject
        let tbs = tlv(DER_SEQUENCE, &tbs);
        let mut cert = tbs;
        cert.extend(tlv(DER_SEQUENCE, b"\x06\x01\x01"));
        cert.extend(tlv(0x03, b"\x00\x01"));
        tlv(DER_SEQUENCE, &cert)
    }

    /// 能从合成证书中取出 subject 与 issuer 的 CN。
    #[test]
    fn extracts_common_names() {
        let der = certificate("Example CA", "example.com");
        let (subject, issuer) = certificate_names(&der);
        assert_eq!(subject.as_deref(), Some("example.com"));
        assert_eq!(issuer.as_deref(), Some("Example CA"));
    }

    /// 截断的证书不会 panic，只是返回空。
    #[test]
    fn truncated_certificate_is_safe() {
        let der = certificate("Example CA", "example.com");
        for cut in 0..der.len() {
            let (subject, issuer) = certificate_names(&der[..cut]);
            assert!(subject.is_none() && issuer.is_none());
        }
    }

    /// IP 与域名都能构造成服务器名。
    #[test]
    fn builds_server_names() {
        assert!(matches!(
            server_name("127.0.0.1"),
            Some(ServerName::IpAddress(_))
        ));
        assert!(matches!(
            server_name("example.com"),
            Some(ServerName::DnsName(_))
        ));
        assert!(server_name("bad host").is_none());
    }
}
