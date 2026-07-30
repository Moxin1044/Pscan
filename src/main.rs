use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use pscan::output::{OutputFormat, ResultWriter};
use pscan::ports::parse_ports;
use pscan::scanner::{
    CancellationToken, HostDiscoveryConfig, HostState, ScanConfig, Transport, discover_hosts,
    resolve_targets, scan_to_channel_with_cancel,
};
use pscan::target::{TargetOptions, load_targets};
use pscan::{PscanError, Result};
use tokio::sync::mpsc;

#[derive(Debug, Parser)]
#[command(
    name = "pscan",
    version,
    about = "High-performance TCP/UDP port scanner with host discovery and service fingerprinting"
)]
struct Cli {
    /// Target expression; repeat or comma-separate domains, IPs, CIDRs, and IP ranges.
    #[arg(short = 't', long = "target")]
    targets: Vec<String>,

    /// File containing one target expression per line.
    #[arg(short = 'f', long = "target-file")]
    target_file: Option<PathBuf>,

    /// Ports and inclusive ranges, for example 22,80,443,8000-8010.
    #[arg(short = 'p', long, default_value = "1-1024")]
    ports: String,

    /// Scan UDP instead of TCP.
    #[arg(short = 'U', long)]
    udp: bool,

    /// Discover live hosts with ICMP Echo and TCP fallback before port scanning.
    #[arg(long)]
    ping: bool,

    /// Only perform host discovery; do not scan ports.
    #[arg(long)]
    ping_only: bool,

    /// TCP ports used as host-discovery fallback when ICMP gets no reply.
    #[arg(long, default_value = "80,443,22")]
    ping_ports: String,

    /// Maximum concurrent network operations.
    #[arg(short = 'c', long, default_value_t = 512)]
    concurrency: usize,

    /// Maximum scan attempts started per second; zero means unlimited.
    #[arg(long, default_value_t = 0)]
    rate: u32,

    /// DNS, TCP connect, UDP reply, and host-discovery timeout in milliseconds.
    #[arg(long, default_value_t = 1200)]
    timeout_ms: u64,

    /// Total service fingerprinting budget per open TCP connection in milliseconds.
    #[arg(long, default_value_t = 800)]
    fingerprint_timeout_ms: u64,

    /// Read passive TCP banners and send small protocol identification probes.
    #[arg(short = 's', long)]
    service_detection: bool,

    /// Include closed, unknown, and error results.
    #[arg(long)]
    show_closed: bool,

    /// Maximum expanded target count.
    #[arg(long, default_value_t = 65_536)]
    max_hosts: usize,

    /// Bounded result queue capacity.
    #[arg(long, default_value_t = 1024)]
    result_buffer: usize,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Write results to a file instead of stdout.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

enum RunOutcome {
    Ok,
    Cancelled,
    ResolutionFailure,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(RunOutcome::Ok) => ExitCode::SUCCESS,
        Ok(RunOutcome::Cancelled) => {
            eprintln!("pscan: cancelled; completed results were flushed");
            ExitCode::from(130)
        }
        Ok(RunOutcome::ResolutionFailure) => ExitCode::from(2),
        Err(error) => {
            eprintln!("pscan: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<RunOutcome> {
    validate_cli(&cli)?;
    let targets = load_targets(
        &cli.targets,
        cli.target_file.as_deref(),
        &TargetOptions {
            max_hosts: cli.max_hosts,
        },
    )?;
    let ports = parse_ports(&cli.ports)?;
    let ping_ports = parse_ports(&cli.ping_ports)?;
    let cancel = CancellationToken::new();
    let signal_cancel = cancel.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancel.cancel();
        }
    });

    let mut writer = ResultWriter::new(cli.format, cli.output.as_deref())?;
    let (resolved, resolution_failures) =
        resolve_targets(&targets, Duration::from_millis(cli.timeout_ms), &cancel).await;
    for (host, error) in &resolution_failures {
        eprintln!("pscan: {host}: {error}");
    }
    let has_failures = !resolution_failures.is_empty();
    let mut resolved_hosts: Vec<String> = resolved
        .into_iter()
        .map(|target| target.ip.to_string())
        .collect();
    resolved_hosts.sort();
    resolved_hosts.dedup();

    if resolved_hosts.is_empty() {
        writer.flush()?;
        signal_task.abort();
        if cancel.is_cancelled() {
            return Ok(RunOutcome::Cancelled);
        }
        return Ok(if has_failures {
            RunOutcome::ResolutionFailure
        } else {
            RunOutcome::Ok
        });
    }

    let scan_targets = if cli.ping || cli.ping_only {
        let discovered = discover_hosts(
            &resolved_hosts,
            &HostDiscoveryConfig {
                concurrency: cli.concurrency,
                timeout: Duration::from_millis(cli.timeout_ms),
                tcp_ports: ping_ports,
                icmp: true,
            },
            cancel.clone(),
        )
        .await;
        let mut alive = Vec::new();
        for result in discovered {
            if result.state == HostState::Alive {
                alive.push(result.ip.clone());
            }
            if result.state == HostState::Alive || cli.show_closed {
                writer.write_host(&result)?;
            }
        }
        writer.flush()?;
        alive
    } else {
        resolved_hosts
    };

    if !cli.ping_only && !cancel.is_cancelled() && !scan_targets.is_empty() {
        let config = ScanConfig {
            concurrency: cli.concurrency,
            connect_timeout: Duration::from_millis(cli.timeout_ms),
            fingerprint_timeout: Duration::from_millis(cli.fingerprint_timeout_ms),
            service_detection: cli.service_detection && !cli.udp,
            rate_limit: (cli.rate > 0).then_some(cli.rate),
            result_buffer: cli.result_buffer,
            transport: if cli.udp {
                Transport::Udp
            } else {
                Transport::Tcp
            },
        };

        let (sender, mut receiver) = mpsc::channel(config.result_buffer);
        let scan_cancel = cancel.clone();
        let scan = scan_to_channel_with_cancel(&scan_targets, &ports, &config, sender, scan_cancel);
        let output_cancel = cancel.clone();
        let output = async {
            let mut result: Result<()> = Ok(());
            while let Some(record) = receiver.recv().await {
                if (record.open || cli.show_closed)
                    && let Err(error) = writer.write(&record)
                {
                    result = Err(error);
                    output_cancel.cancel();
                    break;
                }
            }
            while receiver.recv().await.is_some() {}
            if result.is_ok()
                && let Err(error) = writer.flush()
            {
                result = Err(error);
            }
            result
        };
        let (_, output_result) = tokio::join!(scan, output);
        output_result?;
    }

    signal_task.abort();
    if cancel.is_cancelled() {
        Ok(RunOutcome::Cancelled)
    } else if has_failures {
        Ok(RunOutcome::ResolutionFailure)
    } else {
        Ok(RunOutcome::Ok)
    }
}

fn validate_cli(cli: &Cli) -> Result<()> {
    if cli.targets.is_empty() && cli.target_file.is_none() {
        return Err(PscanError::InvalidInput(
            "provide --target or --target-file".into(),
        ));
    }
    if cli.concurrency == 0 {
        return Err(PscanError::InvalidInput(
            "concurrency must be greater than zero".into(),
        ));
    }
    if cli.result_buffer == 0 {
        return Err(PscanError::InvalidInput(
            "result buffer must be greater than zero".into(),
        ));
    }
    if cli.timeout_ms == 0 || cli.fingerprint_timeout_ms == 0 {
        return Err(PscanError::InvalidInput(
            "timeouts must be greater than zero".into(),
        ));
    }
    if cli.service_detection && cli.udp {
        return Err(PscanError::InvalidInput(
            "--service-detection currently applies to TCP only".into(),
        ));
    }
    Ok(())
}
