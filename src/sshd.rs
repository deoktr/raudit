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

use std::collections::HashMap;
use std::process;
use std::process::Stdio;
use std::sync::OnceLock;

use crate::{check, log_debug, log_error};

static SSHD_CONFIG: OnceLock<SshdConfig> = OnceLock::new();

/// OpenSSH (sshd) configuration.
pub type SshdConfig = HashMap<String, String>;

/// Parse OpenSSH configuration from `sshd -T` command stdout.
fn parse_sshd_config(sshd_t: String) -> SshdConfig {
    sshd_t
        .lines()
        .filter_map(|line| match line.to_string().split_once(" ") {
            Some((key, value)) => Some((key.to_string(), value.to_string())),
            // should never happen, don't even log it
            None => None,
        })
        .collect()
}

/// Get the sshd (OpenSSH) configuration by running `sshd -T`.
pub fn init_sshd_config() {
    if SSHD_CONFIG.get().is_some() {
        return;
    }

    let mut cmd = process::Command::new("sshd");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["-T"]);

    match cmd.output() {
        Ok(output) => {
            match output.status.code() {
                Some(status) => {
                    if status != 0 {
                        log_error!(
                            "Failed to get sshd configuration, got status code {} while running \"sshd -T\"",
                            status
                        );
                        return;
                    }
                }
                None => (),
            };

            SSHD_CONFIG.get_or_init(|| {
                parse_sshd_config(String::from_utf8_lossy(&output.stdout).to_string())
            });
        }
        Err(err) => {
            log_error!("Failed to initialize sshd configuration: {}", err);
            return;
        }
    };

    log_debug!("initialized sshd config");
}

/// Get sshd configuration value from a collected configuration.
pub fn get_sshd_config(key: &str) -> Result<String, String> {
    let sshd_config = match SSHD_CONFIG.get() {
        Some(c) => c,
        None => return Err("ssh configuration not initialized".to_string()),
    };

    match sshd_config.get(key) {
        Some(val) => Ok(val.to_string()),
        None => Err(format!("{:?} not found in sshd configuration", key)),
    }
}

/// Get sshd configuration value from a collected configuration.
pub fn check_sshd_config(key: &str, value: &str) -> check::CheckReturn {
    let sshd_config = match SSHD_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("sshd configuration not initialized".to_string()),
            );
        }
    };

    match sshd_config.get(key) {
        Some(val) => {
            if val == value {
                (check::CheckState::Passed, None)
            } else {
                (check::CheckState::Failed, Some(val.to_string()))
            }
        }
        None => (check::CheckState::Failed, None),
    }
}
