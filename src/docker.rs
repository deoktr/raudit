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
// TODO: ensure an apparmor profile is enabled for containers
// TODO: ensure containers are isolated with user namespaces <https://docs.docker.com/engine/security/userns-remap/>
// TODO: ensure resources are limited to avoid container DOS the host

use serde_json::Value;
use std::collections::HashMap;
use std::process;
use std::process::Stdio;
use std::sync::OnceLock;

use crate::{check, log_debug, log_error};

static DOCKER_INFO: OnceLock<DockerInfo> = OnceLock::new();
static CONTAINERS: OnceLock<Containers> = OnceLock::new();

pub type DockerInfo = Value;
pub type Containers = HashMap<String, Value>;

/// Get docker info by running `docker info -f json`.
fn get_docker_info() -> Result<DockerInfo, String> {
    let mut cmd = process::Command::new("docker");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["info", "-f", "json"]);

    let output = cmd.output().map_err(|e| e.to_string())?;
    let stdout = str::from_utf8(&output.stdout).map_err(|e| e.to_string())?;
    let config: DockerInfo = serde_json::from_str(stdout).map_err(|e| e.to_string())?;
    Ok(config)
}

/// Init docker info by running `docker info -f json`.
pub fn init_docker_info() {
    if DOCKER_INFO.get().is_some() {
        return;
    }

    match get_docker_info() {
        Ok(c) => {
            DOCKER_INFO.get_or_init(|| c);
            log_debug!("initialized docker info");
        }
        Err(err) => log_error!("failed to initialize docker info: {}", err),
    }
}

/// Get container inspect by running `docker ps --format '{{.ID}}'` and
/// then `docker container inspect <ids>`.
fn get_containers_inspect() -> Result<Containers, String> {
    let mut docker_ps = process::Command::new("docker");
    docker_ps.stdin(Stdio::null());
    docker_ps.args(vec!["ps", "--format", "{{.ID}}"]);

    let output = docker_ps.output().map_err(|e| e.to_string())?;
    let stdout = str::from_utf8(&output.stdout).map_err(|e| e.to_string())?;
    let ids: Vec<&str> = stdout.lines().collect();

    if ids.len() == 0 {
        return Ok(Containers::new());
    }

    let mut docker_inspect = process::Command::new("docker");
    docker_inspect.stdin(Stdio::null());

    let mut args: Vec<&str> = vec!["inspect"];
    args.extend(ids);
    docker_inspect.args(args);

    let output = docker_inspect.output().map_err(|e| e.to_string())?;
    let stdout = str::from_utf8(&output.stdout).map_err(|e| e.to_string())?;
    let inspect: Value = serde_json::from_str(stdout).map_err(|e| e.to_string())?;
    let inspects = match inspect.as_array() {
        Some(i) => i,
        None => return Err("failed to parse \"docker inspect\" json: not an array".to_string()),
    };

    let mut containers: Containers = Containers::new();
    for container in inspects {
        let id: String = container["Id"].to_string();
        containers.insert(id, container.clone());
    }

    Ok(containers)
}

/// Init container inspect by running `docker ps --format '{{.ID}}'` and
/// then `docker container inspect <ids>`.
pub fn init_containers_inspect() {
    if CONTAINERS.get().is_some() {
        return;
    }

    match get_containers_inspect() {
        Ok(c) => {
            CONTAINERS.get_or_init(|| c);
            log_debug!("initialized docker containers");
        }
        Err(err) => log_error!("failed to initialize docker containers: {}", err),
    }
}

/// Check a configuration from Docker, the pointer are defined by RFC6901.
pub fn check_docker_info(pointer: &str, expected: Value) -> check::CheckReturn {
    let info = match DOCKER_INFO.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("docker info not initialized".to_string()),
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
/// docker container inspect --format '{{.Id}}={{.HostConfig.Privileged}}' <id>
pub fn docker_not_privileged() -> check::CheckReturn {
    let containers = match CONTAINERS.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("containers inspect not initialized".to_string()),
            );
        }
    };

    if containers.len() == 0 {
        return (check::CheckState::Passed, Some("no containers".to_string()));
    }

    let ids: Vec<String> = containers
        .into_iter()
        .filter_map(|(id, container)| {
            let privileged = &container["HostConfig"]["Privileged"];
            log_debug!("docker container {} privileged: {:?}", id, privileged);

            if privileged == &Value::Bool(true) {
                Some(id.clone())
            } else {
                None
            }
        })
        .collect();

    if ids.len() == 0 {
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
/// docker container inspect --format '{{.Id}}={{.HostConfig.CapDrop}}' <id>
pub fn docker_cap_drop() -> check::CheckReturn {
    let containers = match CONTAINERS.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("containers inspect not initialized".to_string()),
            );
        }
    };

    if containers.len() == 0 {
        return (check::CheckState::Passed, Some("no containers".to_string()));
    }

    let ids: Vec<String> = containers
        .into_iter()
        .filter_map(|(id, container)| {
            let capdrop_json = &container["HostConfig"]["CapDrop"];
            log_debug!("docker container {} cap drop: {:?}", id, capdrop_json);

            // if CapDrop == null then no cap drop is enabled
            let capdrop = match capdrop_json.as_array() {
                Some(c) => c,
                None => return Some(id.clone()),
            };

            if capdrop.len() == 1 && capdrop[0] == Value::String("ALL".to_string()) {
                None
            } else {
                Some(id.clone())
            }
        })
        .collect();

    if ids.len() == 0 {
        (check::CheckState::Passed, None)
    } else {
        log_debug!("Missing cap drop on containers: {:?}", ids);
        (check::CheckState::Failed, Some(ids.join(", ")))
    }
}

/// Ensure all containers are running with non-root user.
///
/// check manually with:
/// docker container inspect --format '{{.Id}}={{.Config.User}}' <id>
pub fn docker_container_user() -> check::CheckReturn {
    let containers = match CONTAINERS.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("containers inspect not initialized".to_string()),
            );
        }
    };

    if containers.len() == 0 {
        return (check::CheckState::Passed, Some("no containers".to_string()));
    }

    let ids: Vec<String> = containers
        .into_iter()
        .filter_map(|(id, container)| {
            let user = &container["Config"]["User"];
            log_debug!("docker container {} user: {}", id, user);
            if *user == Value::String("0".to_string()) {
                Some(id.clone())
            } else {
                None
            }
        })
        .collect();

    if ids.len() == 0 {
        (check::CheckState::Passed, None)
    } else {
        log_debug!("Running as root on containers: {:?}", ids);
        (check::CheckState::Failed, Some(ids.join(", ")))
    }
}
