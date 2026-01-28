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

static APT_CONFIG: OnceLock<AptConfig> = OnceLock::new();

/// Kenel params configuration from apt.
pub type AptConfig = HashMap<String, String>;

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
fn get_apt_config() -> Result<AptConfig, std::io::Error> {
    let mut cmd = process::Command::new("apt-config");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["dump"]);

    let output = cmd.output()?;
    Ok(parse_apt_config(
        String::from_utf8_lossy(&output.stdout).to_string(),
    ))
}

/// Init apt configuration by running `apt-config dump`.
pub fn init_apt_config() {
    if APT_CONFIG.get().is_some() {
        return;
    }

    match get_apt_config() {
        Ok(c) => {
            APT_CONFIG.get_or_init(|| c);
            log_debug!("initialized apt config");
        }
        Err(err) => log_error!("failed to initialize apt config: {}", err),
    }
}

pub fn check_apt(key: &str, value: &str) -> check::CheckReturn {
    let config = match APT_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("apt configuration not initialized".to_string()),
            );
        }
    };

    match config.get(key) {
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
