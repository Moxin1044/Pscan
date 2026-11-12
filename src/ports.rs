//! 端口表达式解析。
//!
//! 支持的语法：
//!
//! - 单端口：`22`
//! - 闭区间：`8000-8010`
//! - 组合表达式：`22,80,443,8000-8010`
//!
//! 解析结果始终是**升序去重**的端口列表，便于上层按固定顺序下发扫描任务。

use std::collections::BTreeSet;

use crate::{PscanError, Result};

/// 端口号下界。0 号端口没有可扫描的服务语义，视为非法输入。
const MIN_PORT: u16 = 1;

/// 解析端口表达式。
///
/// # 参数
///
/// * `expression` - 端口表达式，如 `"22,80,443,8000-8010"`；允许空白与空项。
///
/// # 返回
///
/// * `Ok(Vec<u16>)` - 升序、去重后的端口列表，至少包含一个端口。
///
/// # 错误
///
/// 返回 [`PscanError::InvalidInput`]，当：
///
/// * 某项不是 `1..=65535` 的整数（含 0、负数、溢出值）；
/// * 区间起点大于终点（如 `90-80`）；
/// * 表达式中不含任何有效端口。
pub fn parse_ports(expression: &str) -> Result<Vec<u16>> {
    let mut ports = BTreeSet::new();
    for item in expression
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some((start, end)) = item.split_once('-') {
            let start = parse_port(start)?;
            let end = parse_port(end)?;
            if start > end {
                return Err(PscanError::InvalidInput(format!(
                    "descending port range: {item}"
                )));
            }
            ports.extend(start..=end);
        } else {
            ports.insert(parse_port(item)?);
        }
    }
    if ports.is_empty() {
        return Err(PscanError::InvalidInput("no ports supplied".into()));
    }
    Ok(ports.into_iter().collect())
}

/// 解析单个端口号。
///
/// # 参数
///
/// * `value` - 待解析的端口文本，允许首尾空白。
///
/// # 返回
///
/// * `Ok(u16)` - 合法的端口号（`1..=65535`）。
///
/// # 错误
///
/// 返回 [`PscanError::InvalidInput`]，当文本无法解析为 `u16` 或等于 0。
fn parse_port(value: &str) -> Result<u16> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port >= MIN_PORT)
        .ok_or_else(|| PscanError::InvalidInput(format!("invalid port: {value}")))
}
