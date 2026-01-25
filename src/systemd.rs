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
use std::path::Path;
use std::sync::OnceLock;

use crate::{check, log_debug, log_error, utils::run};

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
        Err(err) => {
            log_error!("Failed to initialize systemd configuration: {}", err);
            return;
        }
    };

    log_debug!("initialized systemd config");
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
            );
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

/// Get the path of the systemd service file.
pub fn get_systemd_file(service: &str) -> Option<String> {
    let sys_path = format!("/etc/systemd/system/{}", service);
    if Path::new(&sys_path).exists() {
        return Some(sys_path);
    }

    let lib_path = format!("/lib/systemd/system/{}", service);
    if Path::new(&lib_path).exists() {
        return Some(lib_path);
    }

    match run!("systemctl", "show", "-p", "FragmentPath", &service).strip_prefix("FragmentPath=") {
        Some(p) => {
            if p != "" {
                return Some(p.to_string());
            }
        }
        None => (),
    };

    let usr_lib_path = format!("/usr/lib/systemd/system/{}", service);
    if Path::new(&usr_lib_path).exists() {
        return Some(usr_lib_path);
    }

    None
}

pub fn get_service_file(name: &str) -> Option<String> {
    get_systemd_file(&format!("{}.service", name))
}

pub fn get_socket_file(name: &str) -> Option<String> {
    get_systemd_file(&format!("{}.socket", name))
}
