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
use std::fs;
use std::sync::OnceLock;

use crate::{check, log_error};

const SYSTEMD_CONF_PATH: &str = "/etc/systemd/system.conf";

static SYSTEMD_CONFIG: OnceLock<SystemdConfig> = OnceLock::new();

/// Systemd configuration.
pub type SystemdConfig = HashMap<String, String>;

/// Parse content of `/etc/systemd/system.conf`.
fn parse_systemd_config(systemd_config: String) -> SystemdConfig {
    systemd_config
        .lines()
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("#"))
        // ignore `[Manager]` line
        // TODO: update parser to collect sections
        .filter(|line| !line.starts_with("["))
        .filter_map(|line| match line.split_once("=") {
            Some((key, value)) => Some((key.to_string(), value.trim_start().to_string())),
            // should never happen, don't even log it
            None => None,
        })
        .collect()
}

/// Get systemd configuration by reading `/etc/systemd/system.conf`.
pub fn init_systemd_config() {
    if SYSTEMD_CONFIG.get().is_some() {
        return;
    }

    match fs::read_to_string(SYSTEMD_CONF_PATH) {
        Ok(cfg) => {
            SYSTEMD_CONFIG.get_or_init(|| parse_systemd_config(cfg));
        }
        Err(err) => log_error!("Failed to initialize systemd configuration: {}", err),
    };
}

// TODO: init by parsing JSON
// pub fn init_systemd_mount() {
//     // systemd-mount --list --no-ask-password --json=short --full
// }

/// Get systemd value from a collected configuration.
pub fn get_systemd_config(key: &str, value: &str) -> check::CheckReturn {
    let systemd_config = match SYSTEMD_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("systemd config not initialized".to_string()),
            )
        }
    };

    match systemd_config.get(key) {
        Some(conf_value) => {
            if conf_value == value {
                (check::CheckState::Passed, None)
            } else {
                (
                    check::CheckState::Failed,
                    Some(format!("{:?} != {:?}", conf_value, value)),
                )
            }
        }
        None => (
            check::CheckState::Failed,
            Some(format!("missing key {:?}", key)),
        ),
    }
}
