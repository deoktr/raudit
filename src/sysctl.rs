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

/// Kenel params configuration from sysctl.
pub type SysctlConfig = HashMap<String, String>;

/// Parse `sysctl --all` command stdout.
fn parse_sysctl_config(stdout: String) -> SysctlConfig {
    stdout
        .lines()
        .filter_map(|line| match line.to_string().split_once(" = ") {
            Some((key, value)) => Some((key.to_string(), value.to_string())),
            // should never happen, don't even log it
            None => None,
        })
        .collect()
}

/// Get the system's sysctl configuration by running `sysctl --all`.
pub fn init_sysctl_config() -> Result<SysctlConfig, std::io::Error> {
    let mut cmd = process::Command::new("sysctl");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["--all"]);

    let output = cmd.output()?;

    // TODO: error if not 0
    // match output.status.code() {
    //     Some(c) => c,
    //     None => 0,
    // }

    Ok(parse_sysctl_config(
        String::from_utf8_lossy(&output.stdout).to_string(),
    ))
}

/// Get sysctl value from a collected configuration.
pub fn get_ssyctl(config: &'static SysctlConfig, key: &str) -> Result<&'static str, String> {
    match config.get(key) {
        Some(val) => Ok(val),
        None => Err("error getting sysctl value".to_string()),
    }
}

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
