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

use crate::check::State;
use crate::modules::ps;
use crate::{check, log_error, utils};

static SSHD_CONFIG: State<SshdConfig> = State::new("sshd config");

/// OpenSSH (sshd) configuration.
type SshdConfig = HashMap<String, String>;

/// Skip if sshd is not installed, or installed but not running.
pub fn skip_no_sshd() -> bool {
    if utils::which("sshd").is_none() {
        return true;
    }

    ps::init_proc();
    match ps::is_running("sshd") {
        Ok(is_running) => !is_running,
        Err(err) => {
            log_error!("failed to verify that sshd is running: {}", err);
            false
        }
    }
}

/// Parse OpenSSH configuration from `sshd -T` command stdout.
fn parse_sshd_config(sshd_t: String) -> SshdConfig {
    sshd_t
        .lines()
        .filter_map(|line| {
            line.to_string()
                .split_once(" ")
                .map(|(key, value)| (key.to_string(), value.to_string()))
        })
        .collect()
}

/// Get the sshd (OpenSSH) configuration by running `sshd -T`.
fn get_sshd_config() -> Result<SshdConfig, String> {
    let mut cmd = process::Command::new("sshd");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["-T"]);

    let output = cmd
        .output()
        .map_err(|err| format!("failed to run \"sshd -T\": {}", err))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();

        return Err(if stderr.is_empty() {
            format!("\"sshd -T\" {}", output.status)
        } else {
            format!("\"sshd -T\" {}: {}", output.status, stderr)
        });
    }

    Ok(parse_sshd_config(
        String::from_utf8_lossy(&output.stdout).to_string(),
    ))
}

/// Init the sshd (OpenSSH) configuration by running `sshd -T`.
pub fn init_sshd_config() {
    SSHD_CONFIG.init(get_sshd_config);
}

/// Get sshd configuration value from a collected configuration.
pub fn get_sshd_config_value(key: &str) -> Result<String, String> {
    match SSHD_CONFIG.try_get()?.get(key) {
        Some(val) => Ok(val.to_string()),
        None => Err(format!("{:?} not found in sshd configuration", key)),
    }
}

/// Get sshd configuration value from a collected configuration.
pub fn check_sshd_config(key: &str, value: &str) -> check::CheckReturn {
    SSHD_CONFIG.with(|sshd_config| match sshd_config.get(key) {
        Some(val) => {
            if val == value {
                (check::CheckState::Pass, None)
            } else {
                (check::CheckState::Fail, Some(val.to_string()))
            }
        }
        None => (check::CheckState::Fail, None),
    })
}
