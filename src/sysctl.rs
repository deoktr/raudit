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

static SYSCTL_CONFIG: OnceLock<SysctlConfig> = OnceLock::new();

/// Kenel params configuration from sysctl.
pub type SysctlConfig = HashMap<String, String>;

/// Parse `sysctl --all` command stdout.
fn parse_sysctl_config(stdout: String) -> SysctlConfig {
    stdout
        .lines()
        .filter_map(|line| {
            line.to_string()
                .split_once(" = ")
                .map(|(key, value)| (key.to_string(), value.to_string()))
        })
        .collect()
}

/// Get sysctl configuration by running `sysctl --all`.
fn get_sysctl_config() -> Result<SysctlConfig, String> {
    let mut cmd = process::Command::new("sysctl");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["--all"]);

    Ok(parse_sysctl_config(
        String::from_utf8_lossy(&cmd.output().map_err(|e| e.to_string())?.stdout).to_string(),
    ))
}

/// Init sysctl configuration by running `sysctl --all`.
pub fn init_sysctl_config() {
    if SYSCTL_CONFIG.get().is_some() {
        return;
    }

    match get_sysctl_config() {
        Ok(c) => {
            SYSCTL_CONFIG.get_or_init(|| c);
            log_debug!("initialized sysctl config");
        }
        Err(err) => log_error!("failed to initialize sysctl configuration: {}", err),
    }
}

pub trait SysctlValue {
    fn check_sysctl(&self, key: &str) -> check::CheckReturn;
}

impl SysctlValue for &str {
    /// Get sysctl value from a collected configuration and compare it to &str.
    fn check_sysctl(&self, key: &str) -> check::CheckReturn {
        let config = match SYSCTL_CONFIG.get() {
            Some(c) => c,
            None => {
                return (
                    check::CheckState::Error,
                    Some("sysctl configuration not initialized".to_string()),
                );
            }
        };

        match config.get(key) {
            Some(value) => {
                if value == self {
                    (check::CheckState::Passed, None)
                } else {
                    (
                        check::CheckState::Failed,
                        Some(format!("{:?} != {:?}", value, self)),
                    )
                }
            }
            None => (
                check::CheckState::Error,
                Some(format!("missing sysctl {:?} key", key)),
            ),
        }
    }
}

impl SysctlValue for i32 {
    /// Get sysctl value from a collected configuration and compare it to i32.
    fn check_sysctl(&self, key: &str) -> check::CheckReturn {
        let config = match SYSCTL_CONFIG.get() {
            Some(c) => c,
            None => {
                return (
                    check::CheckState::Error,
                    Some("sysctl configuration not initialized".to_string()),
                );
            }
        };

        match config.get(key) {
            Some(value) => match value.parse::<i32>() {
                Ok(val) => {
                    if val == *self {
                        (check::CheckState::Passed, None)
                    } else {
                        (
                            check::CheckState::Failed,
                            Some(format!("{:?} != {:?}", val, self)),
                        )
                    }
                }
                Err(err) => (
                    check::CheckState::Error,
                    Some(format!("failed to convert {:?} to i32: {}", value, err)),
                ),
            },
            None => (
                check::CheckState::Error,
                Some(format!("missing sysctl {:?} key", key)),
            ),
        }
    }
}

pub fn check_sysctl<T: SysctlValue>(key: &str, value: T) -> check::CheckReturn {
    value.check_sysctl(key)
}

pub fn get_sysctl_i32_value(key: &str) -> Result<i32, String> {
    let config = match SYSCTL_CONFIG.get() {
        Some(c) => c,
        None => return Err("sysctl configuration not initialized".to_string()),
    };

    match config.get(key) {
        Some(value) => match value.parse::<i32>() {
            Ok(val) => Ok(val),
            Err(err) => Err(err.to_string()),
        },
        None => Err(format!("missing sysctl {:?} key", key)),
    }
}

macro_rules! add_sysctl_check {
    ($id:tt, $tags:expr, $key:tt, $val:tt) => {
        $crate::check::Check::new(
            $id,
            format!("Ensure sysctl {:?} = {:?}", $key, $val).as_str(),
            $tags,
            || $crate::sysctl::check_sysctl($key, $val),
            vec![$crate::sysctl::init_sysctl_config],
        )
    };
}

pub(crate) use add_sysctl_check;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sysctl_config() {
        let lines = parse_sysctl_config(
            "vm.swappiness = 60
vm.unprivileged_userfaultfd = 0
vm.user_reserve_kbytes = 131072
vm.vfs_cache_pressure = 100
vm.watermark_boost_factor = 15000"
                .to_string(),
        );
        assert_eq!(lines.len(), 5);
        assert!(lines.get("vm.swappiness").is_some());
        assert_eq!(lines.get("vm.swappiness").unwrap(), &"60".to_string());
        assert!(lines.get("vm.watermark_boost_factor").is_some());
        assert_eq!(
            lines.get("vm.watermark_boost_factor").unwrap(),
            &"15000".to_string()
        );
    }
}
