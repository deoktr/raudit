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
use std::process::Command;
use std::process::Stdio;

use crate::check::{self, State};

const SYSTEMD_CONF_PATH: &str = "/etc/systemd/system.conf";

static SYSTEMD_CONFIG: State<SystemdConfig> = State::new("systemd config");

#[allow(dead_code)]
static SYSTEMD_ACTIVE_UNITS: State<Vec<String>> = State::new("systemd active units");

/// Systemd configuration.
type SystemdConfig = HashMap<String, String>;

/// Skip when systemd is not used. Systemd creates a notification socket that
/// services can communicate with.
pub fn skip_no_systemd() -> bool {
    !Path::new("/run/systemd/notify").exists()
}

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
    let content = fs::read_to_string(SYSTEMD_CONF_PATH)
        .map_err(|err| format!("failed to read {}: {}", SYSTEMD_CONF_PATH, err))?;
    Ok(parse_systemd_config(content))
}

/// Init systemd configuration by reading `/etc/systemd/system.conf`.
pub fn init_systemd_config() {
    SYSTEMD_CONFIG.init(get_systemd_config);
}

/// Returns a Vec of unit names reported as "active" by `systemctl list-units`.
#[allow(dead_code)]
fn get_systemd_active_units() -> Result<Vec<String>, String> {
    let mut cmd = Command::new("systemctl");
    cmd.stdin(Stdio::null());
    cmd.args([
        "list-units",
        "--type=service",
        "--state=active",
        "--no-legend",
        "--no-pager",
    ]);

    let output = cmd
        .output()
        .map_err(|err| format!("failed to run \"systemctl list-units\": {}", err))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();

        return Err(if stderr.is_empty() {
            format!("\"systemctl list-units\" {}", output.status)
        } else {
            format!("\"systemctl list-units\" {}: {}", output.status, stderr)
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let units = stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(|unit| unit.to_string())
        .collect();

    Ok(units)
}

/// Init systemd active units by running `systemctl list-units`.
#[allow(dead_code)]
pub fn init_systemd_active_units() {
    SYSTEMD_ACTIVE_UNITS.init(get_systemd_active_units);
}

// TODO: init by parsing JSON
// pub fn init_systemd_mount() {
//     // systemd-mount --list --no-ask-password --json=short --full
// }

/// Get systemd value from a collected configuration.
pub fn get_systemd_config_value(key: &str, value: &str) -> check::CheckReturn {
    SYSTEMD_CONFIG.with(|systemd_config| match systemd_config.get(key) {
        Some(conf_value) => {
            if conf_value == value {
                (check::CheckState::Pass, None)
            } else {
                (
                    check::CheckState::Fail,
                    Some(format!("{:?} != {:?}", conf_value, value)),
                )
            }
        }
        None => (
            check::CheckState::Fail,
            Some(format!("missing key {:?}", key)),
        ),
    })
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

    let mut cmd = Command::new("systemctl");
    cmd.stdin(Stdio::null());
    cmd.args(&["show", "-p", "FragmentPath", &service]);
    if let Ok(output) = cmd.output() {
        if let Some(p) = String::from_utf8_lossy(&output.stdout)
            .to_string()
            .replace("\n", "")
            .strip_prefix("FragmentPath=")
            && p.is_empty()
        {
            return Some(p.to_string());
        }
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

/// Check if a systemd unit (service, socket, etc.) is running.
#[allow(dead_code)]
pub fn systemd_unit_active(name: &str) -> Result<bool, String> {
    Ok(SYSTEMD_ACTIVE_UNITS.try_get()?.contains(&name.to_string()))
}
