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
use std::sync::OnceLock;

use crate::check;
use crate::{log_debug, log_error};

const AUDIT_CFG_PATH: &str = "/etc/audit/auditd.conf";

static AUDIT_CONFIG: OnceLock<AuditConfig> = OnceLock::new();
static AUDIT_RULES: OnceLock<AuditRules> = OnceLock::new();

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

/// Initialize audit rules by running `auditctl -l`.
pub fn init_audit_rules() {
    if AUDIT_RULES.get().is_some() {
        return;
    }

    // FIXME: running `auditctl -l` is not enought to gather all audit rules!
    // for example `-e 2` is missing from the output
    // also note that some command are defined differently from the rule file
    // for example rule `-k foo` converts to `-F key=foo`
    let mut cmd = process::Command::new("auditctl");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["-l"]);

    match cmd.output() {
        Ok(output) => {
            match str::from_utf8(&output.stderr) {
                Ok(stderr) => {
                    if stderr == "You must be root to run this program.\n" {
                        log_error!("Failed to initialize audit rules, root required");
                        return;
                    }
                }
                Err(_) => (),
            };

            AUDIT_RULES.get_or_init(|| {
                // one line is one rule, no need for parsing
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(|x| x.to_string())
                    .collect()
            });
        }
        Err(err) => {
            log_error!("Failed to initialize audit rules: {}", err);
            return;
        }
    };

    log_debug!("initialized audit rules");
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

/// Initialize audit configuration by reading `/etc/audit/auditd.conf`.
pub fn init_audit_config() {
    if AUDIT_CONFIG.get().is_some() {
        return;
    }

    match fs::read_to_string(AUDIT_CFG_PATH) {
        Ok(content) => {
            AUDIT_CONFIG.get_or_init(|| parse_audit_config(content));
        }
        Err(err) => {
            log_error!("Failed to initialize audit configuration: {}", err);
            return;
        }
    };

    log_debug!("initialized audit config");
}

/// Check audit rule.
pub fn check_audit_rule(rule: &str) -> check::CheckReturn {
    let audit_rules = match AUDIT_RULES.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("audit rules not initialized".to_string()),
            );
        }
    };

    if audit_rules.contains(&rule.to_string()) {
        (check::CheckState::Passed, None)
    } else {
        (check::CheckState::Failed, Some("not present".to_string()))
    }
}

/// Check audit configuration value.
pub fn check_audit_config(key: &str, value: &str) -> check::CheckReturn {
    let audit_config = match AUDIT_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("audit rules not initialized".to_string()),
            );
        }
    };

    match audit_config.get(key) {
        Some(conf_value) => {
            if conf_value == value {
                (check::CheckState::Passed, None)
            } else {
                (
                    check::CheckState::Failed,
                    Some(format!("found: {}", conf_value)),
                )
            }
        }
        None => (
            check::CheckState::Failed,
            Some(format!("key {:?} not present", key)),
        ),
    }
}
