//! Pscan 库入口。
//!
//! Pscan 是一个基于 Rust + Tokio 的高性能端口扫描器，同时以二进制（`pscan`）
//! 和库（`pscan`）两种形态发布。库内各模块职责如下：
//!
//! | 模块 | 职责 |
//! | --- | --- |
//! | [`ports`] | 端口表达式解析（单端口、闭区间、组合表达式） |
//! | [`target`] | 目标表达式解析与展开（域名、IP、CIDR、IP 范围、文件） |
//! | [`scanner`] | DNS 解析、TCP/UDP 扫描、主机发现、限速、取消、背压 |
//! | [`fingerprint`] | 基于 banner 与端口表的服务 / 产品 / 版本识别 |
//! | [`tls`] | TLS 握手指纹（版本、套件、ALPN、证书 CN、HTTPS 产品） |
//! | [`output`] | 终端文本与 JSONL 流式输出 |
//! | [`updater`] | 基于 GitHub Releases 的自更新 |
//!
//! # 示例
//!
//! ```
//! use pscan::ports::parse_ports;
//!
//! let ports = parse_ports("22,80,443-445").expect("表达式应合法");
//! assert_eq!(ports, vec![22, 80, 443, 444, 445]);
//! ```
//!
//! 更多用法见仓库根目录的 `README.md`。

pub mod fingerprint;
pub mod output;
pub mod ports;
pub mod scanner;
pub mod target;
pub mod tls;
pub mod updater;

use thiserror::Error;

/// 库内统一的错误类型。
///
/// 所有对外函数都通过 [`Result`] 返回该枚举，调用方可据此区分「用户输入错误」
/// 与「运行期 I/O / 序列化错误」。
#[derive(Debug, Error)]
pub enum PscanError {
    /// 用户输入的表达式非法（端口、目标、CIDR、上限等）。
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// 底层文件或网络 I/O 失败。
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON 序列化 / 反序列化失败。
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// 库内统一的结果别名，错误类型固定为 [`PscanError`]。
pub type Result<T> = std::result::Result<T, PscanError>;
