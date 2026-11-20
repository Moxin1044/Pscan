//! Adapter for native, numeric single-target route diagnostics.
//!
//! The timeout is a per-probe wait, not a deadline for the whole command.
//! Utilities differ in probe protocol and scheduling; a missing reply can also
//! mean filtering or rate limiting. Success does not imply the destination was
//! reached. A hop contains aggregates, not a mapping of individual RTTs to IPs.

use std::{io, net::IpAddr};

use serde::Serialize;
use tokio::process::Command;

#[derive(Debug, Serialize)]
pub(super) struct Hop {
    pub hop: u8,
    pub addresses: Vec<IpAddr>,
    pub rtt_ms: Vec<f64>,
    pub timeouts: usize,
}

/// Run the OS utility without a shell. Both limits must be positive. Unix
/// waits are rounded up to whole seconds for compatibility with BSD variants.
/// Dropping this future after spawning the utility requests child termination.
pub(super) async fn run(ip: IpAddr, max_hops: u8, timeout_ms: u64) -> io::Result<Vec<Hop>> {
    if max_hops == 0 || timeout_ms == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "max_hops and timeout_ms must be positive",
        ));
    }

    let hops = max_hops.to_string();
    let (program, dialect, mut command) = if cfg!(windows) {
        let program = "tracert.exe";
        let mut cmd = Command::new(program);
        cmd.args([
            "-d",
            if ip.is_ipv4() { "-4" } else { "-6" },
            "-h",
            &hops,
            "-w",
        ])
        .arg(timeout_ms.to_string());
        (program, Dialect::Windows, cmd)
    } else if cfg!(unix) {
        // BSD systems and macOS traditionally ship a separate IPv6 utility.
        let separate_v6 = cfg!(any(
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ));
        let program = if separate_v6 && ip.is_ipv6() {
            "traceroute6"
        } else {
            "traceroute"
        };
        let mut cmd = Command::new(program);
        if !separate_v6 {
            cmd.arg(if ip.is_ipv4() { "-4" } else { "-6" });
        }
        cmd.env("LC_ALL", "C")
            .args(["-n", "-m", &hops, "-w"])
            .arg(timeout_ms.div_ceil(1000).to_string());
        (program, Dialect::Unix, cmd)
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no route utility for this platform",
        ));
    };

    let output = command
        .arg(ip.to_string())
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|err| io::Error::new(err.kind(), format!("could not run {program}: {err}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        let detail: String = detail.chars().take(512).collect();
        return Err(io::Error::other(format!(
            "{program} exited with {}: {detail}",
            output.status
        )));
    }
    let hops = parse(&stdout, dialect, max_hops);
    if hops.is_empty() {
        let detail: String = stdout.trim().chars().take(512).collect();
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{program} returned no recognizable hop rows: {detail}"),
        ));
    }
    Ok(hops)
}

#[derive(Clone, Copy)]
enum Dialect {
    Windows,
    Unix,
}

fn parse(output: &str, dialect: Dialect, max_hops: u8) -> Vec<Hop> {
    let mut hops: Vec<Hop> = Vec::new();
    for line in output.lines() {
        let mut fields = line
            .trim_start_matches('\u{feff}')
            .split_whitespace()
            .peekable();
        let Some(hop) = fields.next().and_then(|s| s.parse::<u8>().ok()) else {
            continue;
        };
        if hop == 0 || hop > max_hops || hops.last().is_some_and(|last| hop <= last.hop) {
            continue;
        }
        let mut row = Hop {
            hop,
            addresses: Vec::new(),
            rtt_ms: Vec::new(),
            timeouts: 0,
        };
        while let Some(field) = fields.next() {
            if field == "*" {
                row.timeouts += 1;
                continue;
            }
            let compare = if field == "<" {
                fields.next().unwrap_or("")
            } else {
                field
            };
            let compare = compare.trim_start_matches('<');
            // Windows prints `<1 ms`; the threshold is kept as 1 ms because
            // the API has no field for the less-than qualifier.
            if let Some(value) = compare.strip_suffix("ms").and_then(parse_ms) {
                row.rtt_ms.push(value);
            } else if let Some(value) = parse_ms(compare)
                && fields.peek() == Some(&"ms")
            {
                fields.next();
                row.rtt_ms.push(value);
            } else if let Some(addr) = parse_addr(field)
                && !row.addresses.contains(&addr)
            {
                row.addresses.push(addr);
            }
        }
        let probes = row.timeouts + row.rtt_ms.len();
        let usable = match dialect {
            Dialect::Windows => probes == 3,
            Dialect::Unix => probes > 0,
        };
        if usable {
            hops.push(row);
        }
    }
    hops
}

fn parse_ms(token: &str) -> Option<f64> {
    // A decimal comma can appear in locally formatted diagnostic output.
    let value: f64 = if token.contains(',') {
        token.replace(',', ".").parse().ok()?
    } else {
        token.parse().ok()?
    };
    (value.is_finite() && value >= 0.0).then_some(value)
}

fn parse_addr(token: &str) -> Option<IpAddr> {
    let token = token.trim_matches(['(', ')', '[', ']', ',']);
    // IpAddr cannot retain an interface zone. Strip it only for IPv6.
    if let Some((addr, zone)) = token.split_once('%') {
        if addr.contains(':') && !zone.is_empty() {
            return addr.parse().ok();
        }
        return None;
    }
    token.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_numeric_with_locale_and_timeouts() {
        let output = "Tracing route to 2001:db8::1\r\n\r\n\
                      1   <1 ms   < 1 ms   2,5 ms   fe80::1%12\r\n\
                      2    *      *        *        Délai d’attente dépassé.\r\n\
                      3    9 ms   *        11 ms    2001:db8::1\r\nTrace complete.\r\n";
        let hops = parse(output, Dialect::Windows, 3);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].addresses, ["fe80::1".parse::<IpAddr>().unwrap()]);
        assert_eq!(hops[0].rtt_ms, [1.0, 1.0, 2.5]);
        assert_eq!(hops[1].timeouts, 3);
        assert!(hops[1].addresses.is_empty());
        assert_eq!(hops[2].timeouts, 1);
        assert_eq!(hops[2].rtt_ms, [9.0, 11.0]);
    }

    #[test]
    fn unix_numeric_multiple_responders_and_annotations() {
        let output = "traceroute to 192.0.2.4 (192.0.2.4), 30 hops max\n\
                      1  192.0.2.1  0.201 ms  192.0.2.2  0.205ms !H  192.0.2.1  0.221 ms\n\
                      2  *  *  *\n\
                      3  *  (2001:db8::a)  9.0 ms !N  10.1 ms\n";
        let hops = parse(output, Dialect::Unix, 3);
        assert_eq!(hops.len(), 3);
        assert_eq!(
            hops[0].addresses,
            [
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "192.0.2.2".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(hops[0].rtt_ms, [0.201, 0.205, 0.221]);
        assert_eq!(hops[1].timeouts, 3);
        assert_eq!(
            hops[2].addresses,
            ["2001:db8::a".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(hops[2].timeouts, 1);
    }

    #[test]
    fn ignores_invalid_unordered_and_out_of_range_rows() {
        let output = "0 * * *\n1 NaN ms -1 ms inf ms\n2 * * *\n2 * * *\n1 * * *\n4 * * *\n";
        let hops = parse(output, Dialect::Unix, 3);
        assert_eq!(hops.iter().map(|row| row.hop).collect::<Vec<_>>(), [2]);
        assert!(parse("1 *\n", Dialect::Windows, 1).is_empty());
    }
}
