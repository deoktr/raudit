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
use crate::log_warn;

static SYSCTL_CONFIG: State<SysctlConfig> = State::new("sysctl configuration");

/// Kernel params configuration from `sysctl --all`.
type SysctlConfig = HashMap<String, String>;

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

    let output = cmd
        .output()
        .map_err(|err| format!("failed to run `sysctl --all`: {}", err))?;

    let config = parse_sysctl_config(String::from_utf8_lossy(&output.stdout).to_string());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();

    // keep partial results, `sysctl --all` also fails on unreadable keys
    if !config.is_empty() {
        if !output.status.success() {
            log_warn!("`sysctl --all` {}: {}", output.status, stderr);
        }

        return Ok(config);
    }

    if stderr.is_empty() {
        Err(format!(
            "`sysctl --all` {} and returned no key",
            output.status
        ))
    } else {
        Err(format!("`sysctl --all` returned no key: {}", stderr))
    }
}

/// Init sysctl configuration by running `sysctl --all`.
pub fn init_sysctl_config() {
    SYSCTL_CONFIG.init(get_sysctl_config);
}

pub trait SysctlValue {
    fn check_sysctl(&self, key: &str) -> check::CheckReturn;
}

impl SysctlValue for &str {
    /// Get sysctl value from a collected configuration and compare it to &str.
    fn check_sysctl(&self, key: &str) -> check::CheckReturn {
        SYSCTL_CONFIG.with(|config| match config.get(key) {
            Some(value) if value == self => (check::CheckState::Pass, None),
            Some(value) => (
                check::CheckState::Fail,
                Some(format!("`{}` != `{}`", value, self)),
            ),
            None => (
                check::CheckState::Warning,
                Some(format!("missing key `{}`", key)),
            ),
        })
    }
}

impl SysctlValue for i32 {
    /// Get sysctl value from a collected configuration and compare it to i32.
    fn check_sysctl(&self, key: &str) -> check::CheckReturn {
        SYSCTL_CONFIG.with(|config| match config.get(key) {
            Some(value) => match value.parse::<i32>() {
                Ok(val) if val == *self => (check::CheckState::Pass, None),
                Ok(val) => (
                    check::CheckState::Fail,
                    Some(format!("{} != {}", val, self)),
                ),
                Err(err) => (
                    check::CheckState::Warning,
                    Some(format!("failed to convert `{}` to i32: {}", value, err)),
                ),
            },
            None => (
                check::CheckState::Warning,
                Some(format!("missing key `{}`", key)),
            ),
        })
    }
}

pub fn check_sysctl<T: SysctlValue>(key: &str, value: T) -> check::CheckReturn {
    value.check_sysctl(key)
}

pub fn get_sysctl_i32_value(key: &str) -> Result<i32, String> {
    let config = SYSCTL_CONFIG.try_get()?;

    match config.get(key) {
        Some(value) => match value.parse::<i32>() {
            Ok(val) => Ok(val),
            Err(err) => Err(err.to_string()),
        },
        None => Err(format!("missing key `{}`", key)),
    }
}

pub fn get_sysctl_str_value(key: &str) -> Result<String, String> {
    let config = SYSCTL_CONFIG.try_get()?;

    match config.get(key) {
        Some(value) => Ok(value.clone()),
        None => Err(format!("missing key `{}`", key)),
    }
}

macro_rules! add_sysctl_check {
    ($id:tt, $severity:expr, $tags:expr, $key:tt, $val:tt) => {
        $crate::check::Check::new(
            $id,
            format!("Ensure sysctl `{} = {}`", $key, $val).as_str(),
            $severity,
            $tags,
            || $crate::modules::sysctl::check_sysctl($key, $val),
            vec![$crate::modules::sysctl::init_sysctl_config],
        )
        .with_fix(&format!(
            "Add `{} = {}` in a sysctl config file `/etc/sysctl.d/*.conf`. Then run `sysctl --system`.",
            $key, $val,
        ))
    };
}

macro_rules! add_sysctl_min_check {
    ($id:tt, $severity:expr, $tags:expr, $key:tt, $val:tt) => {
        $crate::check::Check::new(
            $id,
            format!("Ensure sysctl `{} >= {}`", $key, $val).as_str(),
            $severity,
            $tags,
            || {
                const VAL: i32 = $val;
                match $crate::modules::sysctl::get_sysctl_i32_value($key) {
                    Ok(value) => {
                        if value >= VAL {
                            ($crate::check::CheckState::Pass, Some(format!("{}", value)))
                        } else {
                            (
                                $crate::check::CheckState::Fail,
                                Some(format!("{} < {}", value, VAL)),
                            )
                        }
                    }
                    Err(err) => ($crate::check::CheckState::Warning, Some(err)),
                }
            },
            vec![$crate::modules::sysctl::init_sysctl_config],
        )
        .with_fix(&format!(
            "Add `{} = {}` (or higher) in a sysctl config file `/etc/sysctl.d/*.conf`. Then run `sysctl --system`.",
            $key, $val,
        ))
    };
}

macro_rules! add_sysctl_max_check {
    ($id:tt, $severity:expr, $tags:expr, $key:tt, $val:tt) => {
        $crate::check::Check::new(
            $id,
            format!("Ensure sysctl `{} <= {}`", $key, $val).as_str(),
            $severity,
            $tags,
            || {
                const VAL: i32 = $val;
                match $crate::modules::sysctl::get_sysctl_i32_value($key) {
                    Ok(value) => {
                        if value <= VAL {
                            ($crate::check::CheckState::Pass, Some(format!("{}", value)))
                        } else {
                            (
                                $crate::check::CheckState::Fail,
                                Some(format!("{} > {}", value, VAL)),
                            )
                        }
                    }
                    Err(err) => ($crate::check::CheckState::Warning, Some(err)),
                }
            },
            vec![$crate::modules::sysctl::init_sysctl_config],
        )
        .with_fix(&format!(
            "Add `{} = {}` (or lower) in a sysctl config file `/etc/sysctl.d/*.conf`. Then run `sysctl --system`.",
            $key, $val,
        ))
    };
}

pub(crate) use add_sysctl_check;
pub(crate) use add_sysctl_max_check;
pub(crate) use add_sysctl_min_check;

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
