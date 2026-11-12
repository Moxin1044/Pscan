//! 目标表达式解析与展开。
//!
//! 支持的目标写法：
//!
//! - 域名：`example.com`（合法性在此校验，解析留到扫描阶段）
//! - IPv4 / IPv6 字面量：`192.0.2.10`、`2001:db8::1`
//! - CIDR：`192.0.2.0/24`、`2001:db8::/64`
//! - IP 范围：`192.0.2.10-192.0.2.20`
//! - 逗号组合与多行文件：`-t a,b` 或 `-f targets.txt`
//!
//! 展开结果会去重，并受 [`TargetOptions::max_hosts`] 上限保护，避免误输入
//! `0.0.0.0/0` 之类的表达式把内存打满。

use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use ipnet::IpNet;

use crate::{PscanError, Result};

/// 域名总长度上限（不含结尾的点），来自 RFC 1035 §2.3.4。
const MAX_HOSTNAME_LEN: usize = 253;

/// 单个 DNS 标签（点分段）长度上限，来自 RFC 1035 §2.3.4。
const MAX_LABEL_LEN: usize = 63;

/// 目标展开的配置项。
#[derive(Debug, Clone)]
pub struct TargetOptions {
    /// 允许展开的最大目标数量；超过即报错而不是静默截断。
    pub max_hosts: usize,
}

/// 从命令行表达式与可选目标文件加载并展开目标。
///
/// # 参数
///
/// * `expressions` - 命令行 `-t` 收集到的表达式列表，可重复。
/// * `file` - 可选的目标文件路径；每行一个表达式，空行与 `#` 注释被忽略。
/// * `options` - 展开限制配置。
///
/// # 返回
///
/// * `Ok(Vec<String>)` - 去重后的目标列表（域名保持原样，IP 为规范化文本）。
///
/// # 错误
///
/// * [`PscanError::Io`] - 目标文件读取失败。
/// * [`PscanError::InvalidInput`] - 表达式非法、无有效目标或超过 `max_hosts`。
///
/// # 示例
///
/// ```no_run
/// use pscan::target::{TargetOptions, load_targets};
///
/// let targets = load_targets(&["192.0.2.0/30".into()], None, &TargetOptions { max_hosts: 1024 })
///     .expect("表达式合法");
/// assert_eq!(targets.len(), 2);
/// ```
pub fn load_targets(
    expressions: &[String],
    file: Option<&Path>,
    options: &TargetOptions,
) -> Result<Vec<String>> {
    let mut all = expressions.to_vec();
    if let Some(path) = file {
        let contents = fs::read_to_string(path)?;
        all.extend(contents.lines().map(str::to_owned));
    }
    parse_target_expressions(&all, options)
}

/// 解析并展开目标表达式列表。
///
/// # 参数
///
/// * `expressions` - 每项可以是用逗号分隔的多个表达式。
/// * `options` - 展开限制配置。
///
/// # 返回
///
/// * `Ok(Vec<String>)` - 去重后的目标列表，保持首次出现的顺序。
///
/// # 错误
///
/// * [`PscanError::InvalidInput`] - 单个表达式非法、IP 范围跨地址族、
///   范围倒序、无有效目标，或展开数量超过 `options.max_hosts`。
pub fn parse_target_expressions(
    expressions: &[String],
    options: &TargetOptions,
) -> Result<Vec<String>> {
    if options.max_hosts == 0 {
        return Err(PscanError::InvalidInput(
            "max_hosts must be greater than zero".into(),
        ));
    }

    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    for token in expressions
        .iter()
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.starts_with('#'))
    {
        if token.contains('/') {
            let net: IpNet = token
                .parse()
                .map_err(|_| PscanError::InvalidInput(format!("invalid CIDR: {token}")))?;
            for ip in net.hosts() {
                push_target(ip.to_string(), &mut targets, &mut seen, options.max_hosts)?;
            }
        } else if let Some((start, end)) = parse_ip_range(token)? {
            match (start, end) {
                (IpAddr::V4(start), IpAddr::V4(end)) => {
                    let start = u32::from(start);
                    let end = u32::from(end);
                    if start > end {
                        return Err(PscanError::InvalidInput(format!(
                            "descending IP range: {token}"
                        )));
                    }
                    for value in start..=end {
                        push_target(
                            Ipv4Addr::from(value).to_string(),
                            &mut targets,
                            &mut seen,
                            options.max_hosts,
                        )?;
                    }
                }
                (IpAddr::V6(start), IpAddr::V6(end)) => {
                    let start = u128::from(start);
                    let end = u128::from(end);
                    if start > end {
                        return Err(PscanError::InvalidInput(format!(
                            "descending IP range: {token}"
                        )));
                    }
                    // IPv6 值域是 u128，必须先做上限比较，否则 `::1-ffff::1`
                    // 会在循环里无界展开。
                    let count = end - start + 1;
                    if count > options.max_hosts as u128 {
                        return Err(limit_error(options.max_hosts));
                    }
                    for value in start..=end {
                        push_target(
                            Ipv6Addr::from(value).to_string(),
                            &mut targets,
                            &mut seen,
                            options.max_hosts,
                        )?;
                    }
                }
                _ => {
                    return Err(PscanError::InvalidInput(format!(
                        "IP range endpoints use different address families: {token}"
                    )));
                }
            }
        } else {
            validate_target(token)?;
            push_target(
                token.to_string(),
                &mut targets,
                &mut seen,
                options.max_hosts,
            )?;
        }
    }

    if targets.is_empty() {
        return Err(PscanError::InvalidInput("no targets supplied".into()));
    }
    Ok(targets)
}

/// 尝试把 `a-b` 形式解析为 IP 范围。
///
/// # 参数
///
/// * `token` - 待解析的表达式片段。
///
/// # 返回
///
/// * `Ok(Some((start, end)))` - 两端都能解析为 IP，构成闭合范围。
/// * `Ok(None)` - 不含 `-`，或两端都不是 IP（交由域名校验处理）。
///
/// # 错误
///
/// * [`PscanError::InvalidInput`] - 只有一端能解析为 IP，属于畸形范围。
fn parse_ip_range(token: &str) -> Result<Option<(IpAddr, IpAddr)>> {
    let Some((start, end)) = token.split_once('-') else {
        return Ok(None);
    };
    let start_ip = start.parse::<IpAddr>();
    let end_ip = end.parse::<IpAddr>();
    match (start_ip, end_ip) {
        (Ok(start), Ok(end)) => Ok(Some((start, end))),
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => Err(PscanError::InvalidInput(format!(
            "invalid IP range: {token}"
        ))),
        (Err(_), Err(_)) => Ok(None),
    }
}

/// 校验一个非 IP 目标是否为合法域名。
///
/// # 参数
///
/// * `target` - 待校验的域名文本。
///
/// # 返回
///
/// * `Ok(())` - 是合法域名，或本身就是 IP 字面量。
///
/// # 错误
///
/// * [`PscanError::InvalidInput`] - 长度超限、含空标签、标签以 `-` 开头/结尾，
///   或包含字母数字与 `-` 之外的字符。
fn validate_target(target: &str) -> Result<()> {
    if target.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let valid = target.len() <= MAX_HOSTNAME_LEN
        && target.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LEN
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if valid {
        Ok(())
    } else {
        Err(PscanError::InvalidInput(format!(
            "invalid target: {target}"
        )))
    }
}

/// 追加一个目标，自动去重并检查上限。
///
/// # 参数
///
/// * `target` - 规范化后的目标文本。
/// * `targets` - 结果累积容器。
/// * `seen` - 已出现目标的集合，用于去重。
/// * `limit` - 允许的最大目标数量。
///
/// # 返回
///
/// * `Ok(())` - 已追加，或在 `seen` 中已存在（此时不重复追加）。
///
/// # 错误
///
/// * [`PscanError::InvalidInput`] - 追加后数量超过 `limit`。
fn push_target(
    target: String,
    targets: &mut Vec<String>,
    seen: &mut HashSet<String>,
    limit: usize,
) -> Result<()> {
    if seen.insert(target.clone()) {
        if targets.len() >= limit {
            return Err(limit_error(limit));
        }
        targets.push(target);
    }
    Ok(())
}

/// 构造「目标数量超限」错误。
///
/// # 参数
///
/// * `limit` - 被超过的上限值。
///
/// # 返回
///
/// * [`PscanError::InvalidInput`] - 带有提升上限提示的错误。
fn limit_error(limit: usize) -> PscanError {
    PscanError::InvalidInput(format!(
        "target limit exceeded ({limit}); raise --max-hosts deliberately"
    ))
}
