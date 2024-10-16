/*
 * rAudit, a Linux security auditing toolkit
 * Copyright (C) 2024  deoktr
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
use std::fs;

/// Systemd configuration.
pub type SystemdConfig = HashMap<String, String>;

/// Parse content of `/etc/systemd/system.conf`.
fn parse_systemd_config(systemd_config: String) -> SystemdConfig {
    systemd_config
        .lines()
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("#"))
        // ignore `[Manager]` line
        .filter(|line| !line.starts_with("["))
        .filter_map(|line| match line.split_once("=") {
            Some((key, value)) => Some((key.to_string(), value.trim_start().to_string())),
            // should never happen, don't even log it
            None => None,
        })
        .collect()
}

/// Get systemd configuration by reading `/etc/systemd/system.conf`.
pub fn init_systemd_config() -> Result<SystemdConfig, std::io::Error> {
    let cfg = fs::read_to_string("/etc/systemd/system.conf")?;
    Ok(parse_systemd_config(cfg))
}

/// Get systemd value from a collected configuration.
pub fn get_systemd_config(
    config: &'static SystemdConfig,
    key: &str,
) -> Result<&'static str, String> {
    match config.get(key) {
        Some(val) => Ok(val),
        None => Err("not present".to_string()),
    }
}
