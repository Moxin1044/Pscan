//! Single-target route diagnostics and streaming observation summaries.

#[path = "trace_backend.rs"]
mod backend;

use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

/// Optional diagnostic commands alongside the legacy scan flags.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Observe the route to a single IP address or hostname.
    Trace(TraceArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    Text,
    Jsonl,
}

/// Route parameters, independent of port scan settings.
#[derive(Debug, Args)]
pub(crate) struct TraceArgs {
    target: String,
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..), default_value_t = 30)]
    max_hops: u8,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=60000), default_value_t = 1000)]
    timeout_ms: u64,
    /// Number of rounds; zero observes until Ctrl-C.
    #[arg(long, default_value_t = 1)]
    rounds: u64,
    /// Delay between completed rounds, in milliseconds.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=3600000), default_value_t = 1000)]
    interval_ms: u64,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Recent RTTs remain bounded during indefinite observation.
const RTT_WINDOW: usize = 256;

#[derive(Default)]
struct Stats {
    responses: u64,
    timeouts: u64,
    recent: std::collections::VecDeque<f64>,
}

impl Stats {
    /// Accumulate reported replies and retain a bounded RTT window.
    fn observe(&mut self, hop: &backend::Hop) {
        self.responses += hop.rtt_ms.len() as u64;
        self.timeouts += hop.timeouts as u64;
        for &rtt in &hop.rtt_ms {
            if self.recent.len() == RTT_WINDOW {
                self.recent.pop_front();
            }
            self.recent.push_back(rtt);
        }
    }

    /// Return the median and nearest-rank P95 of recent samples.
    fn percentiles(&self) -> (Option<f64>, Option<f64>) {
        let mut values: Vec<_> = self.recent.iter().copied().collect();
        values.sort_by(f64::total_cmp);
        let n = values.len();
        if n == 0 {
            return (None, None);
        }
        let median = (values[(n - 1) / 2] + values[n / 2]) / 2.0;
        (Some(median), Some(values[(n * 95).div_ceil(100) - 1]))
    }
}

#[derive(Serialize)]
struct Summary {
    hop: u8,
    replies: u64,
    timeouts: u64,
    response_pct: Option<f64>,
    median_ms: Option<f64>,
    p95_ms: Option<f64>,
    rtt_samples: usize,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Record<'a> {
    TraceHop {
        target: IpAddr,
        round: u64,
        #[serde(flatten)]
        hop: &'a backend::Hop,
    },
    TraceRound {
        target: IpAddr,
        round: u64,
        reached: bool,
        path_changed: Option<bool>,
        summary: Vec<Summary>,
    },
}

/// Resolve once and return the command's process exit code.
pub(crate) async fn entry(args: TraceArgs) -> ExitCode {
    let ip = match tokio::select! {
        result = resolve(&args.target, args.timeout_ms) => result,
        result = tokio::signal::ctrl_c() => return if result.is_ok() { ExitCode::from(130) } else { ExitCode::FAILURE },
    } {
        Ok(ip) => ip,
        Err(error) => {
            eprintln!("pscan trace: {error}");
            return ExitCode::from(2);
        }
    };
    match observe(args, ip).await {
        Ok(true) => ExitCode::from(130),
        Ok(false) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pscan trace: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Accept numeric addresses or resolve a hostname to one stable address.
async fn resolve(target: &str, timeout_ms: u64) -> io::Result<IpAddr> {
    if let Ok(ip) = target.parse() {
        return Ok(ip);
    }
    tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        tokio::net::lookup_host((target, 0)),
    )
    .await??
    .next()
    .map(|addr| addr.ip())
    .ok_or_else(|| io::Error::other("target resolved to no addresses"))
}

/// Run serial rounds, flushing each completed round to the selected destination.
async fn observe(args: TraceArgs, ip: IpAddr) -> io::Result<bool> {
    let mut out: Box<dyn Write> = match args.output {
        Some(path) => Box::new(io::BufWriter::new(std::fs::File::create(path)?)),
        None => Box::new(io::BufWriter::new(io::stdout())),
    };
    let mut stats = BTreeMap::<u8, Stats>::new();
    let mut previous = None;
    let stop = tokio::signal::ctrl_c();
    tokio::pin!(stop);
    for round in 1.. {
        let hops = tokio::select! {
            biased;
            result = &mut stop => { result?; return Ok(true); }
            result = backend::run(ip, args.max_hops, args.timeout_ms) => result?,
        };
        let mut path = BTreeMap::new();
        let mut reached = false;
        for hop in &hops {
            reached |= hop.addresses.contains(&ip);
            path.insert(
                hop.hop,
                hop.addresses.iter().copied().collect::<BTreeSet<_>>(),
            );
            stats.entry(hop.hop).or_default().observe(hop);
            emit(
                &mut out,
                args.format,
                Record::TraceHop {
                    target: ip,
                    round,
                    hop,
                },
            )?;
        }
        let changed = previous.as_ref().map(|prior| prior != &path);
        previous = Some(path);
        let summary = stats
            .iter()
            .map(|(&hop, stats)| {
                let (median_ms, p95_ms) = stats.percentiles();
                let total = stats.responses + stats.timeouts;
                Summary {
                    hop,
                    replies: stats.responses,
                    timeouts: stats.timeouts,
                    response_pct: (total != 0)
                        .then(|| 100.0 * stats.responses as f64 / total as f64),
                    median_ms,
                    p95_ms,
                    rtt_samples: stats.recent.len(),
                }
            })
            .collect();
        emit(
            &mut out,
            args.format,
            Record::TraceRound {
                target: ip,
                round,
                reached,
                path_changed: changed,
                summary,
            },
        )?;
        out.flush()?;
        if round == args.rounds {
            break;
        }
        tokio::select! {
            biased;
            result = &mut stop => { result?; return Ok(true); }
            () = tokio::time::sleep(Duration::from_millis(args.interval_ms)) => {},
        }
    }
    Ok(false)
}

/// Write one JSONL record or its human-readable equivalent.
fn emit(out: &mut dyn Write, format: Format, record: Record<'_>) -> io::Result<()> {
    match format {
        Format::Jsonl => {
            serde_json::to_writer(&mut *out, &record)?;
            writeln!(out)
        }
        Format::Text => match record {
            Record::TraceHop { target, round, hop } => writeln!(
                out,
                "{target} round {round} hop {:>3}: {:?} RTT {:?} ms, {} timeout(s)",
                hop.hop, hop.addresses, hop.rtt_ms, hop.timeouts
            ),
            Record::TraceRound {
                target,
                round,
                reached,
                path_changed,
                summary,
            } => {
                writeln!(
                    out,
                    "{target} round {round}: {}{}",
                    if reached {
                        "target replied"
                    } else {
                        "target not observed"
                    },
                    if path_changed == Some(true) {
                        "; observed route changed"
                    } else {
                        ""
                    }
                )?;
                for row in summary {
                    let pct = row
                        .response_pct
                        .map_or_else(|| "-".into(), |v| format!("{v:.1}%"));
                    let ms = |value: Option<f64>| {
                        value.map_or_else(|| "-".into(), |v| format!("{v:.2} ms"))
                    };
                    writeln!(
                        out,
                        "  hop {:>3}: {pct} replies ({}/{}), median {}, P95 {}",
                        row.hop,
                        row.replies,
                        row.replies + row.timeouts,
                        ms(row.median_ms),
                        ms(row.p95_ms)
                    )?;
                }
                Ok(())
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_structured_hops_and_accumulates_round_samples() {
        let ip = IpAddr::from([127, 0, 0, 1]);
        let hop = backend::Hop {
            hop: 1,
            addresses: vec![ip],
            rtt_ms: vec![2.0, 4.0],
            timeouts: 1,
        };
        let mut stats = Stats::default();
        stats.observe(&hop);
        stats.observe(&hop);
        assert_eq!((stats.responses, stats.timeouts), (4, 2));
        assert_eq!(stats.percentiles(), (Some(3.0), Some(4.0)));
        let mut out = Vec::new();
        emit(
            &mut out,
            Format::Jsonl,
            Record::TraceHop {
                target: ip,
                round: 2,
                hop: &hop,
            },
        )
        .unwrap();
        assert_eq!(out.last(), Some(&b'\n'));
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["kind"], "trace_hop");
        assert_eq!(value["round"], 2);
        assert_eq!(value["hop"], 1);
        assert_eq!(value["addresses"][0], "127.0.0.1");
        assert_eq!(value["timeouts"], 1);
    }
}
