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

use crate::check::{self, State};

static APT_CONFIG: State<AptConfig> = State::new("apt config");

/// Kenel params configuration from apt.
type AptConfig = HashMap<String, String>;

/// Parse `apt-config dump` command stdout.
fn parse_apt_config(stdout: String) -> AptConfig {
    stdout
        .lines()
        .filter_map(|line| {
            line.to_string().split_once(" ").map(|(key, value)| {
                (
                    key.to_string(),
                    value.trim_end_matches(';').trim_matches('"').to_string(),
                )
            })
        })
        .collect()
}

/// Get apt configuration by running `apt-config dump`.
fn get_apt_config() -> Result<AptConfig, String> {
    let mut cmd = process::Command::new("apt-config");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["dump"]);

    let output = cmd
        .output()
        .map_err(|err| format!("failed to run `apt-config dump`: {}", err))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();

        return Err(if stderr.is_empty() {
            format!("`apt-config dump` {}", output.status)
        } else {
            format!("`apt-config dump` {}: {}", output.status, stderr)
        });
    }

    Ok(parse_apt_config(
        String::from_utf8_lossy(&output.stdout).to_string(),
    ))
}

/// Init apt configuration by running `apt-config dump`.
pub fn init_apt_config() {
    APT_CONFIG.init(get_apt_config);
}

/// Ensure APT is configured correctly.
pub fn check_apt(key: &str, value: &str) -> check::CheckReturn {
    APT_CONFIG.with(|config| match config.get(key) {
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
            Some(format!("key `{}` not present", key)),
        ),
    })
}

fn matches_bool_value(conf_value: &str, expected: bool) -> bool {
    match expected {
        true => conf_value == "true" || conf_value == "1",
        false => conf_value == "false" || conf_value == "0",
    }
}

/// Ensure APT is configured correctly, when the key is a boolean.
pub fn check_apt_bool(key: &str, value: bool) -> check::CheckReturn {
    APT_CONFIG.with(|config| match config.get(key) {
        Some(conf_value) => {
            if matches_bool_value(conf_value, value) {
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
            Some(format!("key `{}` not present", key)),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_apt_config() {
        let lines = parse_apt_config(
            "Acquire::http::AllowRedirect \"false\";
Acquire::AllowDowngradeToInsecureRepositories \"false\";
APT::Sandbox::Seccomp \"1\";
"
            .to_string(),
        );
        assert_eq!(lines.len(), 3);
        assert!(lines.get("Acquire::http::AllowRedirect").is_some());
        assert_eq!(
            lines.get("Acquire::http::AllowRedirect").unwrap(),
            &"false".to_string()
        );
        assert!(
            lines
                .get("Acquire::AllowDowngradeToInsecureRepositories")
                .is_some()
        );
        assert_eq!(
            lines
                .get("Acquire::AllowDowngradeToInsecureRepositories")
                .unwrap(),
            &"false".to_string()
        );
        assert!(lines.get("APT::Sandbox::Seccomp").is_some());
        assert_eq!(
            lines.get("APT::Sandbox::Seccomp").unwrap(),
            &"1".to_string()
        );
    }
}
