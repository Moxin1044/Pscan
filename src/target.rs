use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use ipnet::IpNet;

use crate::{PscanError, Result};

#[derive(Debug, Clone)]
pub struct TargetOptions {
    pub max_hosts: usize,
}

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

fn validate_target(target: &str) -> Result<()> {
    if target.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let valid = target.len() <= 253
        && target.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
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

fn limit_error(limit: usize) -> PscanError {
    PscanError::InvalidInput(format!(
        "target limit exceeded ({limit}); raise --max-hosts deliberately"
    ))
}
