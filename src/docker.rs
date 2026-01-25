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

// TODO: cache containers JSON config instead of query for all checks
// TODO: check: <https://github.com/docker/docker-bench-security>
// docker container inspect -l --format '{{.Id}}={{.Config.User}}'
// each line are id=user
// the user should also define the group, ex: `999:999`
// with uid and gid > 0 and < 1000
// TODO: ensure that ports are only exposed on loopback/localhost (if they are
// not 80/443)
// TODO: ensure docker is running rootless
// https://docs.docker.com/engine/security/rootless/
// TODO: ensure no containers has the docker socket mounted to it (`/var/run/docker.sock`), capabilities or is unconfined
// https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html#automatic-enumeration-and-escape
// TODO: ensure an apparmor profile is enabled for containers
// TODO: ensure containers are isolated with user namespaces <https://docs.docker.com/engine/security/userns-remap/>
// TODO: ensure resources are limited to avoid container DOS the host
// TODO: get and store docker configuration from `docker info -f json`

use std::process;
use std::process::Stdio;

use crate::{check, log_debug, log_trace};

/// Ensure containers are not started with `--privileged` flag.
///
/// Don't start containers with `--privileged`.
/// Check manually with:
/// docker container inspect --format '{{.Id}}={{.Config.CreateCommand}}' <id>
pub fn docker_not_privileged() -> check::CheckReturn {
    // FIXME: iter over containers

    let mut cmd = process::Command::new("docker");
    cmd.stdin(Stdio::null());
    cmd.args(vec![
        "container",
        "inspect",
        "--format",
        "{{.Id}}\t{{.Config.CreateCommand}}",
    ]);

    let output = match cmd.output() {
        Ok(output) => output,
        Err(err) => return (check::CheckState::Failed, Some(err.to_string())),
    };

    let ids: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|x| x.to_string())
        .filter_map(|line| match line.split_once("\t") {
            Some((id, create_cmd)) => {
                // remove []
                let cmd: Vec<&str> = create_cmd[1..create_cmd.len() - 1].split(" ").collect();

                log_trace!("docker privileged {} {:?}", id, cmd);

                if cmd.contains(&"--privileged") {
                    Some(id.to_string())
                } else {
                    None
                }
            }
            // should never happen, don't even log it
            None => None,
        })
        .collect();

    if ids.len() > 0 {
        log_debug!("containers running with `--privileged`: {:?}", ids);
    }

    if ids.len() == 0 {
        (check::CheckState::Passed, None)
    } else {
        (check::CheckState::Failed, Some(ids.join(", ")))
    }
}

/// Ensure containers capabilities are dopped.
///
/// Start containers with `--cap-drop=all` to remove all capabilities.
/// check manually with:
/// docker container inspect --format '{{.Id}}={{.HostConfig.CapDrop}}' <id>
pub fn docker_cap_drop() -> check::CheckReturn {
    // FIXME: iter over containers

    let mut cmd = process::Command::new("docker");
    cmd.stdin(Stdio::null());
    cmd.args(vec![
        "container",
        "inspect",
        "--format",
        "{{.Id}}\t{{.HostConfig.CapDrop}}",
    ]);

    let output = match cmd.output() {
        Ok(output) => output,
        Err(err) => return (check::CheckState::Failed, Some(err.to_string())),
    };

    let ids: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|x| x.to_string())
        .filter_map(|line| match line.split_once("\t") {
            Some((id, cap_drop)) => {
                // remove []
                let cap_list: Vec<&str> = cap_drop[1..cap_drop.len() - 1].split(" ").collect();

                log_trace!("docker cap {} {:?}", id, cap_list);

                if cap_list.len() < 11 {
                    Some(id.to_string())
                } else {
                    None
                }
            }
            // should never happen, don't even log it
            None => None,
        })
        .collect();

    if ids.len() > 0 {
        log_debug!("Missing cap drop on containers: {:?}", ids);
    }

    if ids.len() == 0 {
        (check::CheckState::Passed, None)
    } else {
        (check::CheckState::Failed, Some(ids.join(", ")))
    }
}

/// Ensure all containers are running with non-root user.
///
/// check manually with:
/// docker container inspect --format '{{.Id}}={{.Config.User}}' <id>
pub fn docker_container_user() -> check::CheckReturn {
    // FIXME: iter over containers

    let mut cmd = process::Command::new("docker");
    cmd.stdin(Stdio::null());
    cmd.args(vec![
        "container",
        "inspect",
        "--format",
        "{{.Id}}\t{{.Config.User}}",
    ]);

    let output = match cmd.output() {
        Ok(output) => output,
        Err(err) => return (check::CheckState::Failed, Some(err.to_string())),
    };

    let ids: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|x| x.to_string())
        .filter_map(|line| match line.split_once("\t") {
            Some((id, cap_drop)) => {
                // remove []
                let cap_list: Vec<&str> = cap_drop[1..cap_drop.len() - 1].split(" ").collect();

                log_trace!("docker user {} {:?}", id, cap_list);

                if cap_list.len() < 11 {
                    Some(id.to_string())
                } else {
                    None
                }
            }
            // should never happen, don't even log it
            None => None,
        })
        .collect();

    if ids.len() > 0 {
        log_debug!("Missing user on containers: {:?}", ids);
    }

    if ids.len() == 0 {
        (check::CheckState::Passed, None)
    } else {
        (check::CheckState::Failed, Some(ids.join(", ")))
    }
}
