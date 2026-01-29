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
        .filter_map(|line| {
            line.split_once("=")
                .map(|(key, value)| (key.to_string(), value.trim_start().to_string()))
        })
        .collect()
}

/// Get systemd configuration by reading `/etc/systemd/system.conf`.
fn get_systemd_config() -> Result<SystemdConfig, String> {
    Ok(parse_systemd_config(
        fs::read_to_string(SYSTEMD_CONF_PATH).map_err(|e| e.to_string())?,
    ))
}

/// Init systemd configuration by reading `/etc/systemd/system.conf`.
pub fn init_systemd_config() {
    if SYSTEMD_CONFIG.get().is_some() {
        return;
    }

    match get_systemd_config() {
        Ok(c) => {
            SYSTEMD_CONFIG.get_or_init(|| c);
            log_debug!("initialized systemd config");
        }
        Err(err) => log_error!("failed to initialize systemd configuration: {}", err),
    };
}

// TODO: init by parsing JSON
// pub fn init_systemd_mount() {
//     // systemd-mount --list --no-ask-password --json=short --full
// }

/// Get systemd value from a collected configuration.
pub fn get_systemd_config_value(key: &str, value: &str) -> check::CheckReturn {
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

    if let Some(p) =
        run!("systemctl", "show", "-p", "FragmentPath", &service).strip_prefix("FragmentPath=")
        && !p.is_empty()
    {
        return Some(p.to_string());
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
