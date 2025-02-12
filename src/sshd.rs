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
pub fn init_sshd_config() -> Result<SshdConfig, std::io::Error> {
    let mut cmd = process::Command::new("sshd");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["-T"]);

    let output = cmd.output()?;

    // TODO: error if not 0
    // match output.status.code() {
    //     Some(c) => c,
    //     None => 0,
    // }

    Ok(parse_sshd_config(
        String::from_utf8_lossy(&output.stdout).to_string(),
    ))
}

/// Get sshd configuration value from a collected configuration.
pub fn get_sshd_config(config: &'static SshdConfig, key: &str) -> Result<&'static str, String> {
    match config.get(key) {
        Some(val) => Ok(val),
        None => Err("error getting sshd config value".to_string()),
    }
}
