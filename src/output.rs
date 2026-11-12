//! 结果输出。
//!
//! 两种格式：
//!
//! - `text`：终端友好的流式文本，带颜色与稳定列宽，扫描结束追加汇总行。
//! - `jsonl`：每行一个 JSON 对象，字段与 [`crate::scanner::ScanResult`] /
//!   [`crate::scanner::HostDiscoveryResult`] 一一对应，便于下游消费。
//!
//! 颜色策略遵循 `NO_COLOR` 环境变量与 `--color` 参数；输出到文件或管道时
//! 默认不写 ANSI 转义序列，保证结果可直接参与文本比对。

use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::path::Path;

use clap::ValueEnum;

use crate::Result;
use crate::scanner::{HostDiscoveryResult, HostState, ScanResult, Transport, UdpState};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";

/// 汇总行分隔线，长度与最长结果行的视觉宽度接近。
const SUMMARY_RULE: &str = "------------------------------------------------------------";

/// 状态列宽（`open|filtered` 需要 13 列）。
const STATE_COLUMN_WIDTH: usize = 13;

/// 端点列宽（覆盖 `[2001:db8::1]:65535` 这类最长形式）。
const ENDPOINT_COLUMN_WIDTH: usize = 23;

/// 协议列宽（`tcp` / `udp`）。
const PROTOCOL_COLUMN_WIDTH: usize = 3;

/// 延迟列宽。
const LATENCY_COLUMN_WIDTH: usize = 6;

/// 主机发现的方法列宽。
const METHOD_COLUMN_WIDTH: usize = 8;

/// 输出格式。
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    /// 终端文本。
    Text,
    /// 每行一个 JSON 对象。
    Jsonl,
}

/// 颜色策略。
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ColorMode {
    /// 仅交互终端启用，且未设置 `NO_COLOR`。
    Auto,
    /// 始终输出 ANSI 转义。
    Always,
    /// 从不输出 ANSI 转义。
    Never,
}

/// 扫描结束时的累计统计。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OutputSummary {
    /// 已扫描的端口总数。
    pub scanned: u64,
    /// 开放端口数。
    pub open: u64,
    /// 关闭端口数。
    pub closed: u64,
    /// 无法确定状态的端口数（UDP `open|filtered`）。
    pub uncertain: u64,
    /// 非预期错误数（TCP 拒绝不算错误）。
    pub errors: u64,
    /// 确认存活的主机数。
    pub hosts_alive: u64,
    /// 未确认存活的主机数。
    pub hosts_unknown: u64,
}

/// 流式结果写入器。
///
/// 内部持有唯一的输出句柄与累计统计；所有 `write_*` 方法只追加，
/// 统计在 [`ResultWriter::flush`] 之前任意时刻读取都是一致的。
pub struct ResultWriter {
    /// 输出目标（stdout 或文件）。
    writer: Box<dyn Write + Send>,
    /// 输出格式。
    format: OutputFormat,
    /// 是否启用 ANSI 颜色。
    color: bool,
    /// 累计统计。
    summary: OutputSummary,
}

impl ResultWriter {
    /// 以自动颜色策略创建写入器。
    ///
    /// # 参数
    ///
    /// * `format` - 输出格式。
    /// * `output` - 输出文件；`None` 表示写标准输出。
    ///
    /// # 返回
    ///
    /// * `Ok(ResultWriter)` - 写入器已就绪。
    ///
    /// # 错误
    ///
    /// * [`crate::PscanError::Io`] - 输出文件无法创建。
    pub fn new(format: OutputFormat, output: Option<&Path>) -> Result<Self> {
        Self::with_color(format, output, ColorMode::Auto)
    }

    /// 以显式颜色策略创建写入器。
    ///
    /// # 参数
    ///
    /// * `format` - 输出格式。
    /// * `output` - 输出文件；`None` 表示写标准输出。
    /// * `color_mode` - 颜色策略。
    ///
    /// # 返回
    ///
    /// * `Ok(ResultWriter)` - 写入器已就绪。
    ///
    /// # 错误
    ///
    /// * [`crate::PscanError::Io`] - 输出文件无法创建。
    pub fn with_color(
        format: OutputFormat,
        output: Option<&Path>,
        color_mode: ColorMode,
    ) -> Result<Self> {
        let is_terminal = output.is_none() && io::stdout().is_terminal();
        // JSONL 是机器可读格式，永远不写颜色，避免污染字段。
        let color = format == OutputFormat::Text
            && match color_mode {
                ColorMode::Auto => is_terminal && std::env::var_os("NO_COLOR").is_none(),
                ColorMode::Always => true,
                ColorMode::Never => false,
            };
        let writer: Box<dyn Write + Send> = match output {
            Some(path) => Box::new(BufWriter::new(File::create(path)?)),
            None => Box::new(BufWriter::new(io::stdout())),
        };
        Ok(Self {
            writer,
            format,
            color,
            summary: OutputSummary::default(),
        })
    }

    /// 写出一条端口扫描结果并累计统计。
    ///
    /// # 参数
    ///
    /// * `result` - 扫描结果。
    ///
    /// # 返回
    ///
    /// * `Ok(())` - 已写入缓冲区。
    ///
    /// # 错误
    ///
    /// * [`crate::PscanError::Io`] - 底层写入失败。
    pub fn write(&mut self, result: &ScanResult) -> Result<()> {
        self.record_scan(result);
        match self.format {
            OutputFormat::Jsonl => {
                serde_json::to_writer(&mut self.writer, result)?;
                writeln!(self.writer)?;
            }
            OutputFormat::Text => self.write_scan_text(result)?,
        }
        Ok(())
    }

    /// 写出一条主机发现结果并累计统计。
    ///
    /// # 参数
    ///
    /// * `result` - 主机发现结果。
    ///
    /// # 返回
    ///
    /// * `Ok(())` - 已写入缓冲区。
    ///
    /// # 错误
    ///
    /// * [`crate::PscanError::Io`] - 底层写入失败。
    pub fn write_host(&mut self, result: &HostDiscoveryResult) -> Result<()> {
        match result.state {
            HostState::Alive => self.summary.hosts_alive += 1,
            HostState::Unknown => self.summary.hosts_unknown += 1,
        }
        match self.format {
            OutputFormat::Jsonl => {
                serde_json::to_writer(&mut self.writer, result)?;
                writeln!(self.writer)?;
            }
            OutputFormat::Text => {
                let (state, marker, color) = match result.state {
                    HostState::Alive => ("alive", "+", GREEN),
                    HostState::Unknown => ("unknown", "?", YELLOW),
                };
                self.paint(color, marker)?;
                write!(self.writer, " ")?;
                self.paint_bold(&format!("{state:<width$}", width = STATE_COLUMN_WIDTH))?;
                write!(self.writer, " ")?;
                self.paint(
                    CYAN,
                    &format!("{:<width$}", result.ip, width = ENDPOINT_COLUMN_WIDTH),
                )?;
                write!(
                    self.writer,
                    " {:<width$}",
                    result.method,
                    width = METHOD_COLUMN_WIDTH
                )?;
                self.paint(
                    DIM,
                    &format!(
                        " {:>width$} ms",
                        result.latency_ms,
                        width = LATENCY_COLUMN_WIDTH
                    ),
                )?;
                if result.host != result.ip {
                    self.paint(DIM, &format!("  ({})", result.host))?;
                }
                writeln!(self.writer)?;
            }
        }
        Ok(())
    }

    /// 写出汇总行（仅 `text` 格式）。
    ///
    /// # 返回
    ///
    /// * `Ok(())` - 已写入或格式为 JSONL 时直接返回。
    ///
    /// # 错误
    ///
    /// * [`crate::PscanError::Io`] - 底层写入失败。
    pub fn write_summary(&mut self) -> Result<()> {
        if self.format == OutputFormat::Jsonl {
            return Ok(());
        }
        let summary = self.summary;
        self.paint(DIM, SUMMARY_RULE)?;
        writeln!(self.writer)?;
        self.paint_bold("Summary")?;
        if summary.scanned > 0 {
            write!(self.writer, "  {} scanned", summary.scanned)?;
            self.paint(GREEN, &format!("  {} open", summary.open))?;
            if summary.uncertain > 0 {
                self.paint(YELLOW, &format!("  {} uncertain", summary.uncertain))?;
            }
            self.paint(DIM, &format!("  {} closed", summary.closed))?;
            if summary.errors > 0 {
                self.paint(RED, &format!("  {} errors", summary.errors))?;
            }
        }
        if summary.hosts_alive + summary.hosts_unknown > 0 {
            self.paint(GREEN, &format!("  {} alive", summary.hosts_alive))?;
            if summary.hosts_unknown > 0 {
                self.paint(YELLOW, &format!("  {} unknown", summary.hosts_unknown))?;
            }
        }
        writeln!(self.writer)?;
        Ok(())
    }

    /// 读取当前累计统计。
    ///
    /// # 返回
    ///
    /// * [`OutputSummary`] - 统计快照。
    pub fn summary(&self) -> OutputSummary {
        self.summary
    }

    /// 记录一条不输出的结果（只更新统计）。
    ///
    /// 用于 `--show-closed` 未启用时跳过 `closed` 明细但仍需汇总的场景。
    ///
    /// # 参数
    ///
    /// * `result` - 被隐藏的扫描结果。
    pub fn record_hidden(&mut self, result: &ScanResult) {
        self.record_scan(result);
    }

    /// 刷出缓冲内容。
    ///
    /// # 返回
    ///
    /// * `Ok(())` - 数据已交给操作系统。
    ///
    /// # 错误
    ///
    /// * [`crate::PscanError::Io`] - 刷出失败。
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    /// 以文本格式写出单条扫描结果。
    ///
    /// # 参数
    ///
    /// * `result` - 扫描结果。
    ///
    /// # 返回
    ///
    /// * `Ok(())` - 已写入缓冲区。
    ///
    /// # 错误
    ///
    /// * [`crate::PscanError::Io`] - 底层写入失败。
    fn write_scan_text(&mut self, result: &ScanResult) -> Result<()> {
        let (state, marker, color) = scan_state(result);
        let protocol = match result.transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        };
        let endpoint = endpoint(&result.ip, result.port);
        let identity = service_identity(result);

        self.paint(color, marker)?;
        write!(self.writer, " ")?;
        self.paint_bold(&format!("{state:<width$}", width = STATE_COLUMN_WIDTH))?;
        write!(self.writer, " ")?;
        self.paint(
            CYAN,
            &format!("{endpoint:<width$}", width = ENDPOINT_COLUMN_WIDTH),
        )?;
        write!(
            self.writer,
            " {protocol:<width$} ",
            width = PROTOCOL_COLUMN_WIDTH
        )?;
        self.paint(
            DIM,
            &format!(
                "{:>width$} ms",
                result.latency_ms,
                width = LATENCY_COLUMN_WIDTH
            ),
        )?;
        if !identity.is_empty() {
            write!(self.writer, "  {identity}")?;
        }
        if result.host != result.ip {
            self.paint(DIM, &format!("  ({})", result.host))?;
        }
        writeln!(self.writer)?;

        if let Some(banner) = &result.banner {
            self.paint(DIM, "    banner  ")?;
            writeln!(self.writer, "{}", sanitize(banner))?;
        }
        if let Some(error) = &result.error {
            self.paint(RED, "    error   ")?;
            writeln!(self.writer, "{}", sanitize(error))?;
        }
        Ok(())
    }

    /// 更新扫描累计统计。
    ///
    /// # 参数
    ///
    /// * `result` - 扫描结果。
    fn record_scan(&mut self, result: &ScanResult) {
        self.summary.scanned += 1;
        if result.error.is_some() && !is_expected_closed(result) {
            self.summary.errors += 1;
        }
        match result.udp_state {
            Some(UdpState::Open) => self.summary.open += 1,
            Some(UdpState::Closed) => self.summary.closed += 1,
            Some(UdpState::OpenOrFiltered) => self.summary.uncertain += 1,
            None if result.open => self.summary.open += 1,
            None => self.summary.closed += 1,
        }
    }

    /// 按颜色策略输出一段文本。
    ///
    /// # 参数
    ///
    /// * `color` - ANSI 颜色前缀。
    /// * `text` - 待输出文本。
    ///
    /// # 返回
    ///
    /// * `Ok(())` - 已写入。
    ///
    /// # 错误
    ///
    /// * [`std::io::Error`] - 底层写入失败。
    fn paint(&mut self, color: &str, text: &str) -> io::Result<()> {
        if self.color {
            write!(self.writer, "{color}{text}{RESET}")
        } else {
            write!(self.writer, "{text}")
        }
    }

    /// 以加粗样式输出文本。
    ///
    /// # 参数
    ///
    /// * `text` - 待输出文本。
    ///
    /// # 返回
    ///
    /// * `Ok(())` - 已写入。
    ///
    /// # 错误
    ///
    /// * [`std::io::Error`] - 底层写入失败。
    fn paint_bold(&mut self, text: &str) -> io::Result<()> {
        self.paint(BOLD, text)
    }
}

/// 把扫描结果映射为文本状态、标记与颜色。
///
/// # 参数
///
/// * `result` - 扫描结果。
///
/// # 返回
///
/// * `(&'static str, &'static str, &'static str)` - 状态名、标记、颜色。
fn scan_state(result: &ScanResult) -> (&'static str, &'static str, &'static str) {
    match result.udp_state {
        Some(UdpState::Open) => ("open", "+", GREEN),
        Some(UdpState::Closed) => ("closed", "-", DIM),
        Some(UdpState::OpenOrFiltered) => ("open|filtered", "?", YELLOW),
        None if result.open => ("open", "+", GREEN),
        None if result.error.is_some() => ("closed", "-", DIM),
        None => ("closed", "-", DIM),
    }
}

/// 把 IP 与端口拼成端点文本，IPv6 加方括号消除歧义。
///
/// # 参数
///
/// * `ip` - IP 文本。
/// * `port` - 端口。
///
/// # 返回
///
/// * `String` - `1.2.3.4:80` 或 `[2001:db8::1]:80` 形式。
fn endpoint(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

/// 拼出服务标识文本，供文本输出展示。
///
/// 依次拼接 `service`、`product`、`version`，产品名与服务名相同则去重。
///
/// # 参数
///
/// * `result` - 扫描结果。
///
/// # 返回
///
/// * `String` - 以空格分隔的标识；全部为空时返回空串。
fn service_identity(result: &ScanResult) -> String {
    let mut parts = Vec::new();
    if let Some(service) = &result.service {
        parts.push(service.as_str());
    }
    if let Some(product) = &result.product
        && !parts.contains(&product.as_str())
    {
        parts.push(product.as_str());
    }
    if let Some(version) = &result.version {
        parts.push(version.as_str());
    }
    parts.join(" ")
}

/// 转义文本中的控制字符，避免终端注入。
///
/// # 参数
///
/// * `value` - 原始文本。
///
/// # 返回
///
/// * `String` - 转义后的单行文本。
fn sanitize(value: &str) -> String {
    value
        .chars()
        .flat_map(char::escape_default)
        .collect::<String>()
}

/// 判断一条 TCP 失败结果是否属于预期内的「端口关闭」。
///
/// `Connection refused` 是正常扫描结论，不应计入错误数。
///
/// # 参数
///
/// * `result` - 扫描结果。
///
/// # 返回
///
/// * `true` - 非开放且为 TCP 结果，视为预期关闭。
fn is_expected_closed(result: &ScanResult) -> bool {
    !result.open && matches!(result.transport, Transport::Tcp)
}
