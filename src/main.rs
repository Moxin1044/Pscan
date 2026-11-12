//! `pscan` 命令行入口。
//!
//! 本文件只负责三件事：
//!
//! 1. 定义 CLI（[`Cli`]）并做参数校验；
//! 2. 编排「目标展开 → DNS 解析 → 主机发现 → 端口扫描 → 结果输出」的流程；
//! 3. 把结果映射为进程退出码。
//!
//! 真正的扫描逻辑在 [`pscan::scanner`]，输出在 [`pscan::output`]。

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use pscan::output::{ColorMode, OutputFormat, ResultWriter};
use pscan::ports::parse_ports;
use pscan::scanner::{
    CancellationToken, HostDiscoveryConfig, HostState, ScanConfig, Transport, discover_hosts,
    resolve_targets, scan_to_channel_with_cancel,
};
use pscan::target::{TargetOptions, load_targets};
use pscan::{PscanError, Result};
use tokio::sync::mpsc;

/// 未指定 `--ports` 时的默认扫描范围。
const DEFAULT_PORTS: &str = "1-1024";

/// 未指定 `--ping-ports` 时的 TCP 回退端口。
const DEFAULT_PING_PORTS: &str = "80,443,22";

/// 默认并发网络操作数。
const DEFAULT_CONCURRENCY: usize = 512;

/// 默认 DNS / TCP / UDP / 主机发现超时（毫秒）。
const DEFAULT_TIMEOUT_MS: u64 = 1_200;

/// 默认每条连接的指纹识别预算（毫秒）。
const DEFAULT_FINGERPRINT_TIMEOUT_MS: u64 = 800;

/// 默认目标展开上限。
const DEFAULT_MAX_HOSTS: usize = 65_536;

/// 默认结果通道容量。
const DEFAULT_RESULT_BUFFER: usize = 1_024;

/// 默认限速值，0 表示不限速。
const DEFAULT_RATE: u32 = 0;

/// `Ctrl-C` / 写入失败导致的取消退出码。
const EXIT_CODE_CANCELLED: u8 = 130;

/// 至少一个目标解析失败时的退出码。
const EXIT_CODE_RESOLUTION_FAILURE: u8 = 2;

/// 命令行参数。
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
    #[arg(short = 'p', long, default_value = DEFAULT_PORTS)]
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
    #[arg(long, default_value = DEFAULT_PING_PORTS)]
    ping_ports: String,

    /// Maximum concurrent network operations.
    #[arg(short = 'c', long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// Maximum scan attempts started per second; zero means unlimited.
    #[arg(long, default_value_t = DEFAULT_RATE)]
    rate: u32,

    /// DNS, TCP connect, UDP reply, and host-discovery timeout in milliseconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
    timeout_ms: u64,

    /// Total service fingerprinting budget per open TCP connection in milliseconds.
    #[arg(long, default_value_t = DEFAULT_FINGERPRINT_TIMEOUT_MS)]
    fingerprint_timeout_ms: u64,

    /// Read passive TCP banners and send small protocol identification probes.
    #[arg(short = 's', long)]
    service_detection: bool,

    /// Include closed, unknown, and error results.
    #[arg(long)]
    show_closed: bool,

    /// Maximum expanded target count.
    #[arg(long, default_value_t = DEFAULT_MAX_HOSTS)]
    max_hosts: usize,

    /// Bounded result queue capacity.
    #[arg(long, default_value_t = DEFAULT_RESULT_BUFFER)]
    result_buffer: usize,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Write results to a file instead of stdout.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Colorize text output: auto, always, or never.
    #[arg(long, value_enum, default_value_t = ColorMode::Auto)]
    color: ColorMode,

    /// Check whether a newer release is available on GitHub and exit.
    #[arg(long)]
    check_update: bool,

    /// Download the latest release and replace the current binary.
    #[arg(long)]
    update: bool,

    /// Disable the background update check that normally runs at startup.
    #[arg(long)]
    no_update_check: bool,
}

/// 一次扫描的最终走向，用于决定退出码。
enum RunOutcome {
    /// 全部目标扫描完成。
    Ok,
    /// 被 `Ctrl-C` 或写入失败取消。
    Cancelled,
    /// 至少一个目标 DNS 解析失败。
    ResolutionFailure,
}

/// 进程入口：解析参数、分派自更新或扫描、映射退出码。
///
/// # 返回
///
/// * [`ExitCode`] - 0 成功、1 参数/IO 错误、2 解析失败、130 取消。
#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.check_update {
        return run_check_update();
    }
    if cli.update {
        return run_self_update();
    }

    // 只在真正要扫描时才做后台更新提示：`--help` / `--version` 走 clap
    // 内部路径，根本到不了这里。
    if !cli.no_update_check {
        pscan::updater::maybe_prompt_from_cache();
        if !pscan::updater::should_skip_check() {
            pscan::updater::refresh_cache_in_background();
        }
    }

    match run(cli).await {
        Ok(RunOutcome::Ok) => ExitCode::SUCCESS,
        Ok(RunOutcome::Cancelled) => {
            eprintln!("pscan: cancelled; completed results were flushed");
            ExitCode::from(EXIT_CODE_CANCELLED)
        }
        Ok(RunOutcome::ResolutionFailure) => ExitCode::from(EXIT_CODE_RESOLUTION_FAILURE),
        Err(error) => {
            eprintln!("pscan: {error}");
            ExitCode::FAILURE
        }
    }
}

/// 处理 `--check-update`。
///
/// # 返回
///
/// * [`ExitCode`] - 查询成功为 0，网络或解析失败为 1。
fn run_check_update() -> ExitCode {
    match pscan::updater::check_now() {
        Ok(outcome) if outcome.is_newer => {
            println!(
                "pscan {} is available (current {}). Run `pscan --update` to install.",
                outcome.latest, outcome.current
            );
            ExitCode::SUCCESS
        }
        Ok(outcome) => {
            println!("pscan is up to date ({})", outcome.current);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("pscan: update check failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// 处理 `--update`。
///
/// # 返回
///
/// * [`ExitCode`] - 更新或已是最新为 0，失败为 1。
fn run_self_update() -> ExitCode {
    match pscan::updater::install_latest() {
        Ok(status) if status.is_updated() => {
            println!("pscan updated to {}", status.version());
            ExitCode::SUCCESS
        }
        Ok(status) => {
            println!("pscan is already on {}", status.version());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("pscan: update failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// 执行一次完整扫描流程。
///
/// 流程顺序：目标展开 → 注册信号 → 解析 DNS →（可选）主机发现 → 端口扫描
/// → 汇总输出。扫描与输出用 `tokio::join!` 并行，避免输出慢拖住扫描。
///
/// # 参数
///
/// * `cli` - 已解析的命令行参数。
///
/// # 返回
///
/// * `Ok(RunOutcome)` - 扫描完成、被取消或存在解析失败。
///
/// # 错误
///
/// * [`PscanError::InvalidInput`] - 参数组合非法。
/// * [`PscanError::Io`] - 目标文件或输出文件读写失败。
/// * [`PscanError::Json`] - JSONL 序列化失败。
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

    let mut writer = ResultWriter::with_color(cli.format, cli.output.as_deref(), cli.color)?;
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
            // `unknown` 不等于离线，只在显式 `--show-closed` 时才展示。
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
                if record.open || cli.show_closed {
                    if let Err(error) = writer.write(&record) {
                        // 写入失败：立即取消扫描，避免继续做无用功。
                        result = Err(error);
                        output_cancel.cancel();
                        break;
                    }
                } else {
                    writer.record_hidden(&record);
                }
            }
            // 排空通道，让扫描侧不会阻塞在已无人消费的发送上。
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

    writer.write_summary()?;
    writer.flush()?;
    signal_task.abort();
    if cancel.is_cancelled() {
        Ok(RunOutcome::Cancelled)
    } else if has_failures {
        Ok(RunOutcome::ResolutionFailure)
    } else {
        Ok(RunOutcome::Ok)
    }
}

/// 校验参数组合是否合法。
///
/// # 参数
///
/// * `cli` - 命令行参数。
///
/// # 返回
///
/// * `Ok(())` - 参数组合合法。
///
/// # 错误
///
/// * [`PscanError::InvalidInput`] - 缺少目标、并发/缓冲/超时为 0，
///   或在 UDP 模式下请求了服务指纹。
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
