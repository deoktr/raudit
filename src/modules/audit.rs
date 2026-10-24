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

// TODO: fix rules collection
// TODO: parse individual audit rules into struct

use core::str;
use std::collections::HashMap;
use std::fs;
use std::process;
use std::process::Stdio;

use crate::check;
use crate::check::State;

const AUDIT_CFG_PATH: &str = "/etc/audit/auditd.conf";

static AUDIT_CONFIG: State<AuditConfig> = State::new("audit config");
static AUDIT_RULES: State<AuditRules> = State::new("audit rules");

/// Audit configuration from `/etc/audit/auditd.conf`.
type AuditConfig = HashMap<String, String>;

/// List of audit rules.
///
/// Rules are collected by running `auditctl -l`, the format may change from
/// the configuration file, for example the `-k` argument can change to
/// `-F key=`, and list of arguments of `-S` can change order.
/// To set the checks correctly run `auditctl -l` and get the rules from the
/// output.
type AuditRules = Vec<String>;

/// Get audit rules by running `auditctl -l`.
fn get_audit_rules() -> Result<AuditRules, String> {
    // FIXME: running `auditctl -l` is not enought to gather all audit rules!
    // for example `-e 2` is missing from the output
    // also note that some command are defined differently from the rule file
    // for example rule `-k foo` converts to `-F key=foo`
    let mut cmd = process::Command::new("auditctl");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["-l"]);

    let output = cmd
        .output()
        .map_err(|err| format!("failed to run \"auditctl -l\": {}", err))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();

        return Err(if stderr.is_empty() {
            format!("\"auditctl -l\" {}", output.status)
        } else {
            format!("\"auditctl -l\" {}: {}", output.status, stderr)
        });
    }

    // one line is one rule, no need for parsing
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|x| x.to_string())
        .collect())
}

/// Init audit rules by running `auditctl -l`.
pub fn init_audit_rules() {
    AUDIT_RULES.init(get_audit_rules);
}

/// Parse content of `/etc/audit/auditd.conf`.
fn parse_audit_config(login_defs: String) -> AuditConfig {
    login_defs
        .lines()
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("#"))
        .filter_map(|line| {
            line.split_once(char::is_whitespace)
                .map(|(key, value)| (key.to_string(), value.trim_start().to_string()))
        })
        .collect()
}

/// Get audit configuration by reading `/etc/audit/auditd.conf`.
fn get_audit_config() -> Result<AuditConfig, String> {
    let content = fs::read_to_string(AUDIT_CFG_PATH)
        .map_err(|err| format!("failed to read {}: {}", AUDIT_CFG_PATH, err))?;
    Ok(parse_audit_config(content))
}

/// Init audit configuration by reading `/etc/audit/auditd.conf`.
pub fn init_audit_config() {
    AUDIT_CONFIG.init(get_audit_config);
}

/// Check audit rule.
pub fn check_audit_rule(rule: &str) -> check::CheckReturn {
    AUDIT_RULES.with(|audit_rules| {
        if audit_rules.contains(&rule.to_string()) {
            (check::CheckState::Pass, None)
        } else {
            (check::CheckState::Fail, Some("not present".to_string()))
        }
    })
}

/// Check audit configuration value.
pub fn check_audit_config(key: &str, value: &str) -> check::CheckReturn {
    AUDIT_CONFIG.with(|audit_config| match audit_config.get(key) {
        Some(conf_value) => {
            if conf_value == value {
                (check::CheckState::Pass, None)
            } else {
                (
                    check::CheckState::Fail,
                    Some(format!("found: {}", conf_value)),
                )
            }
        }
        None => (
            check::CheckState::Fail,
            Some(format!("key {:?} not present", key)),
        ),
    })
}
