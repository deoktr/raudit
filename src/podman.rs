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

// TODO: check: <https://github.com/docker/docker-bench-security>
// TODO: ensure that ports are only exposed on loopback/localhost (if they are
// not 80/443)
// TODO: ensure docker is running rootless
// https://docs.docker.com/engine/security/rootless/
// TODO: ensure no containers has the docker socket mounted to it (`/var/run/docker.sock`), capabilities or is unconfined
// https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html#automatic-enumeration-and-escape
// TODO: ensure containers are isolated with user namespaces <https://docs.docker.com/engine/security/userns-remap/>
// TODO: ensure resources are limited to avoid container DOS the host
// TODO: if no containers to check because no running, mark as skipped

use serde_json::Value;
use std::collections::HashMap;
use std::process;
use std::process::Stdio;
use std::sync::OnceLock;

use crate::{check, log_debug, log_error};

static PODMAN_INFO: OnceLock<PodmanInfo> = OnceLock::new();
static CONTAINERS: OnceLock<Containers> = OnceLock::new();

pub type PodmanInfo = Value;
pub type Containers = HashMap<String, Value>;

/// Get podman info by running `podman info -f json`.
fn get_podman_info() -> Result<PodmanInfo, String> {
    let mut cmd = process::Command::new("podman");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["info", "-f", "json"]);

    let output = cmd.output().map_err(|e| e.to_string())?;
    let stdout = str::from_utf8(&output.stdout).map_err(|e| e.to_string())?;
    let config: PodmanInfo = serde_json::from_str(stdout).map_err(|e| e.to_string())?;
    Ok(config)
}

/// Init podman info by running `podman info -f json`.
pub fn init_podman_info() {
    if PODMAN_INFO.get().is_some() {
        return;
    }

    match get_podman_info() {
        Ok(c) => {
            PODMAN_INFO.get_or_init(|| c);
            log_debug!("initialized podman info");
        }
        Err(err) => log_error!("failed to initialize podman info: {}", err),
    }
}

/// Get container inspect by running `podman ps --format '{{.ID}}'` and
/// then `podman container inspect <ids>`.
fn get_containers_inspect() -> Result<Containers, String> {
    let mut podman_ps = process::Command::new("podman");
    podman_ps.stdin(Stdio::null());
    podman_ps.args(vec!["ps", "--format", "{{.ID}}"]);

    let output = podman_ps.output().map_err(|e| e.to_string())?;
    let stdout = str::from_utf8(&output.stdout).map_err(|e| e.to_string())?;
    let ids: Vec<&str> = stdout.lines().collect();

    if ids.is_empty() {
        return Ok(Containers::new());
    }

    let mut podman_inspect = process::Command::new("podman");
    podman_inspect.stdin(Stdio::null());

    let mut args: Vec<&str> = vec!["inspect"];
    args.extend(ids);
    podman_inspect.args(args);

    let output = podman_inspect.output().map_err(|e| e.to_string())?;
    let stdout = str::from_utf8(&output.stdout).map_err(|e| e.to_string())?;
    let inspect: Value = serde_json::from_str(stdout).map_err(|e| e.to_string())?;
    let inspects = match inspect.as_array() {
        Some(i) => i,
        None => return Err("failed to parse \"podman inspect\" json: not an array".to_string()),
    };

    let mut containers: Containers = Containers::new();
    for container in inspects {
        let id: String = container["Id"].to_string();
        containers.insert(id, container.clone());
    }

    Ok(containers)
}

/// Initialize container inspect by running `podman ps --format '{{.ID}}'` and
/// then `podman container inspect <ids>`.
pub fn init_containers_inspect() {
    if CONTAINERS.get().is_some() {
        return;
    }

    match get_containers_inspect() {
        Ok(c) => {
            CONTAINERS.get_or_init(|| c);
            log_debug!("initialized podman containers");
        }
        Err(err) => log_error!("failed to initialize podman containers: {}", err),
    }
}

pub fn check_podman_info(pointer: &str, expected: Value) -> check::CheckReturn {
    let info = match PODMAN_INFO.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("podman info not initialized".to_string()),
            );
        }
    };

    match &info.pointer(pointer) {
        Some(val) => {
            if **val != expected {
                (
                    check::CheckState::Failed,
                    Some(format!("{:?} != {:?}", val, expected)),
                )
            } else {
                (check::CheckState::Passed, None)
            }
        }
        None => (
            check::CheckState::Error,
            Some(format!("pointer {:?} not found", pointer)),
        ),
    }
}

/// Ensure containers are not started with `--privileged` flag.
///
/// Don't start containers with `--privileged`.
/// Check manually with:
/// podman container inspect --format '{{.Id}}\t{{.HostConfig.Privileged}}' <id>
pub fn podman_not_privileged() -> check::CheckReturn {
    let containers = match CONTAINERS.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("containers inspect not initialized".to_string()),
            );
        }
    };

    if containers.is_empty() {
        return (check::CheckState::Passed, Some("no containers".to_string()));
    }

    let ids: Vec<String> = containers
        .iter()
        .filter_map(|(id, container)| {
            let privileged = &container["HostConfig"]["Privileged"];
            log_debug!("podman container {} privileged: {:?}", id, privileged);

            if privileged == &Value::Bool(true) {
                Some(id.clone())
            } else {
                None
            }
        })
        .collect();

    if ids.is_empty() {
        (check::CheckState::Passed, None)
    } else {
        log_debug!("containers running with `--privileged`: {:?}", ids);
        (check::CheckState::Failed, Some(ids.join(", ")))
    }
}

/// Ensure containers capabilities are dopped.
///
/// Start containers with `--cap-drop=all` to remove all capabilities.
/// check manually with:
/// podman container inspect --format '{{.Id}}={{.HostConfig.CapDrop}}' <id>
pub fn podman_cap_drop() -> check::CheckReturn {
    let containers = match CONTAINERS.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("containers inspect not initialized".to_string()),
            );
        }
    };

    if containers.is_empty() {
        return (check::CheckState::Passed, Some("no containers".to_string()));
    }

    let ids: Vec<String> = containers
        .iter()
        .filter_map(|(id, container)| {
            let capdrop = container["HostConfig"]["CapDrop"].as_array()?;
            log_debug!("podman container {} cap drop: {:?}", id, capdrop);

            if capdrop.len() < 11 {
                Some(id.clone())
            } else {
                None
            }
        })
        .collect();

    if ids.is_empty() {
        (check::CheckState::Passed, None)
    } else {
        log_debug!("Missing cap drop on containers: {:?}", ids);
        (check::CheckState::Failed, Some(ids.join(", ")))
    }
}

/// Ensure containers services are running as user.
///
/// Start containers and run process as a user inside it.
/// check manually with:
/// podman container inspect --format '{{.Id}}\t{{.Config.User}}' <id>
pub fn podman_user() -> check::CheckReturn {
    let containers = match CONTAINERS.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("containers inspect not initialized".to_string()),
            );
        }
    };

    if containers.is_empty() {
        return (check::CheckState::Passed, Some("no containers".to_string()));
    }

    let ids: Vec<String> = containers
        .iter()
        .filter_map(|(id, container)| {
            let user = &container["Config"]["User"];
            log_debug!("podman container {} user: {}", id, user);
            if *user == Value::String("0".to_string()) {
                Some(id.clone())
            } else {
                None
            }
        })
        .collect();

    if ids.is_empty() {
        (check::CheckState::Passed, None)
    } else {
        log_debug!("Running as root on containers: {:?}", ids);
        (check::CheckState::Failed, Some(ids.join(", ")))
    }
}

/// Ensure containers are running with an apparmor profile.
///
/// check manually with:
/// podman container inspect -l --format '{{.Id}}\t{{.AppArmorProfile}}'
pub fn podman_apparmor() -> check::CheckReturn {
    let containers = match CONTAINERS.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("containers inspect not initialized".to_string()),
            );
        }
    };

    if containers.is_empty() {
        return (check::CheckState::Passed, Some("no containers".to_string()));
    }

    let ids: Vec<String> = containers
        .iter()
        .filter_map(|(id, container)| {
            let aap = &container["AppArmorProfile"];
            log_debug!("podman container {} apparmor profile: {}", id, aap);
            if *aap == Value::String("".to_string()) {
                Some(id.clone())
            } else {
                None
            }
        })
        .collect();

    if ids.is_empty() {
        (check::CheckState::Passed, None)
    } else {
        log_debug!("Running without apparmor profile on containers: {:?}", ids);
        (check::CheckState::Failed, Some(ids.join(", ")))
    }
}
