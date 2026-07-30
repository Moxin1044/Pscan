use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use clap::ValueEnum;
use serde::Serialize;

use crate::Result;
use crate::scanner::{HostDiscoveryResult, ScanResult, Transport};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Text,
    Jsonl,
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
}

impl ResultWriter {
    pub fn new(format: OutputFormat, output: Option<&Path>) -> Result<Self> {
        let writer: Box<dyn Write + Send> = match output {
            Some(path) => Box::new(BufWriter::new(File::create(path)?)),
            None => Box::new(BufWriter::new(io::stdout())),
        };
        Ok(Self { writer, format })
    }

    pub fn write(&mut self, result: &ScanResult) -> Result<()> {
        match self.format {
            OutputFormat::Jsonl => {
                serde_json::to_writer(&mut self.writer, result)?;
                writeln!(self.writer)?;
            }
            OutputFormat::Text => {
                let state = result
                    .udp_state
                    .map(|state| match state {
                        crate::scanner::UdpState::Open => "open",
                        crate::scanner::UdpState::Closed => "closed",
                        crate::scanner::UdpState::OpenOrFiltered => "open|filtered",
                    })
                    .unwrap_or(if result.open { "open" } else { "closed" });
                let protocol = match result.transport {
                    Transport::Tcp => "tcp",
                    Transport::Udp => "udp",
                };
                let ip = if result.ip.contains(':') {
                    format!("[{}]", result.ip)
                } else {
                    result.ip.clone()
                };
                write!(self.writer, "{}:{}/{} {state}", ip, result.port, protocol)?;
                if result.host != result.ip {
                    write!(self.writer, " host={}", result.host)?;
                }
                if let Some(service) = &result.service {
                    write!(self.writer, " service={service}")?;
                }
                if let Some(product) = &result.product {
                    write!(self.writer, " product={product}")?;
                }
                if let Some(version) = &result.version {
                    write!(self.writer, " version={version}")?;
                }
                if let Some(banner) = &result.banner {
                    write!(self.writer, " banner={banner:?}")?;
                }
                if let Some(error) = &result.error {
                    write!(self.writer, " error={error:?}")?;
                }
                writeln!(self.writer)?;
            }
        }
        Ok(())
    }

    pub fn write_host(&mut self, result: &HostDiscoveryResult) -> Result<()> {
        match self.format {
            OutputFormat::Jsonl => {
                serde_json::to_writer(&mut self.writer, result)?;
                writeln!(self.writer)?;
            }
            OutputFormat::Text => {
                let state = match result.state {
                    crate::scanner::HostState::Alive => "alive",
                    crate::scanner::HostState::Unknown => "unknown",
                };
                write!(
                    self.writer,
                    "{} {state} method={} latency_ms={}",
                    result.ip, result.method, result.latency_ms
                )?;
                if result.host != result.ip {
                    write!(self.writer, " host={}", result.host)?;
                }
                writeln!(self.writer)?;
            }
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}
