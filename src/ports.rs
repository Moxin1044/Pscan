use std::collections::BTreeSet;

use crate::{PscanError, Result};

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

fn parse_port(value: &str) -> Result<u16> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| PscanError::InvalidInput(format!("invalid port: {value}")))
}
