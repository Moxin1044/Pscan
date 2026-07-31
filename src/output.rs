use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::path::Path;

use clap::ValueEnum;
use serde::Serialize;

use crate::Result;
use crate::scanner::{HostDiscoveryResult, HostState, ScanResult, Transport, UdpState};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Jsonl,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OutputSummary {
    pub scanned: u64,
    pub open: u64,
    pub closed: u64,
    pub uncertain: u64,
    pub errors: u64,
    pub hosts_alive: u64,
    pub hosts_unknown: u64,
}

pub fn write_record<T: Serialize>(
    record: &T,
    format: OutputFormat,
    output: Option<&Path>,
) -> Result<()> {
    let mut writer: Box<dyn Write> = match output {
        Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        None => Box::new(BufWriter::new(io::stdout())),
    };
    match format {
        OutputFormat::Jsonl => serde_json::to_writer(&mut writer, record)?,
        OutputFormat::Text => write!(writer, "{}", serde_json::to_string(record)?)?,
    }
    writeln!(writer)?;
    writer.flush()?;
    Ok(())
}

pub struct ResultWriter {
    writer: Box<dyn Write + Send>,
    format: OutputFormat,
    color: bool,
    summary: OutputSummary,
}

impl ResultWriter {
    pub fn new(format: OutputFormat, output: Option<&Path>) -> Result<Self> {
        Self::with_color(format, output, ColorMode::Auto)
    }

    pub fn with_color(
        format: OutputFormat,
        output: Option<&Path>,
        color_mode: ColorMode,
    ) -> Result<Self> {
        let is_terminal = output.is_none() && io::stdout().is_terminal();
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
        self.paint_bold(&format!("{state:<13}"))?;
        write!(self.writer, " ")?;
        self.paint(CYAN, &format!("{endpoint:<23}"))?;
        write!(self.writer, " {protocol:<3} ")?;
        self.paint(DIM, &format!("{:>6} ms", result.latency_ms))?;
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
                self.paint_bold(&format!("{state:<13}"))?;
                write!(self.writer, " ")?;
                self.paint(CYAN, &format!("{:<23}", result.ip))?;
                write!(self.writer, " {:<8}", result.method)?;
                self.paint(DIM, &format!(" {:>6} ms", result.latency_ms))?;
                if result.host != result.ip {
                    self.paint(DIM, &format!("  ({})", result.host))?;
                }
                writeln!(self.writer)?;
            }
        }
        Ok(())
    }

    pub fn write_summary(&mut self) -> Result<()> {
        if self.format == OutputFormat::Jsonl {
            return Ok(());
        }
        let summary = self.summary;
        self.paint(
            DIM,
            "------------------------------------------------------------",
        )?;
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

    pub fn summary(&self) -> OutputSummary {
        self.summary
    }

    pub fn record_hidden(&mut self, result: &ScanResult) {
        self.record_scan(result);
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

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

    fn paint(&mut self, color: &str, text: &str) -> io::Result<()> {
        if self.color {
            write!(self.writer, "{color}{text}{RESET}")
        } else {
            write!(self.writer, "{text}")
        }
    }

    fn paint_bold(&mut self, text: &str) -> io::Result<()> {
        self.paint(BOLD, text)
    }
}

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

fn endpoint(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

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

fn sanitize(value: &str) -> String {
    value
        .chars()
        .flat_map(char::escape_default)
        .collect::<String>()
}

fn is_expected_closed(result: &ScanResult) -> bool {
    !result.open && matches!(result.transport, Transport::Tcp)
}
