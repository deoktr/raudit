/*
 * rAudit, a Linux security auditing toolkit
 * Copyright (C) 2024 - 2025  deoktr
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// TODO: parse individual audit rules into struct

use std::collections::HashMap;
use std::fs;
use std::process;
use std::process::Stdio;

const AUDIT_CFG_PATH: &str = "/etc/audit/auditd.conf";

/// Audit configuration from `/etc/audit/auditd.conf`.
pub type AuditConfig = HashMap<String, String>;

/// List of audit rules.
///
/// Rules are collected by running `auditctl -l`, the format may change from
/// the configuration file, for example the `-k` argument can change to
/// `-F key=`, and list of arguments of `-S` can change order.
/// To set the checks correctly run `auditctl -l` and get the rules from the
/// output.
pub type AuditRules = Vec<String>;

/// Get the system's audit rules by running `auditctl -l`.
pub fn init_audit_rules() -> Result<AuditRules, std::io::Error> {
    let mut cmd = process::Command::new("auditctl");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["-l"]);

    let output = cmd.output()?;

    // one line is one rule, no need for parsing
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|x| x.to_string())
        .collect())
}

/// Parse content of `/etc/audit/auditd.conf`.
fn parse_audit_config(login_defs: String) -> AuditConfig {
    login_defs
        .lines()
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("#"))
        .filter_map(|line| match line.split_once(char::is_whitespace) {
            Some((key, value)) => Some((key.to_string(), value.trim_start().to_string())),
            // should never happen, don't even log it
            None => None,
        })
        .collect()
}

/// Get audit configuration by reading `/etc/audit/auditd.conf`.
pub fn init_audit_config() -> Result<AuditConfig, std::io::Error> {
    let auditd_conf = fs::read_to_string(AUDIT_CFG_PATH)?;
    Ok(parse_audit_config(auditd_conf))
}

/// Get audit configuration value.
pub fn get_audit_config(config: &'static AuditConfig, key: String) -> Result<String, String> {
    match config.get(&key) {
        Some(val) => Ok(val.to_string()),
        None => Err("key not present".to_string()),
    }
}
