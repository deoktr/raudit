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
// TODO: ensure that ports are only exposed on loopback/localhost (if they are
// not 80/443)
// TODO: ensure docker is running rootless
// https://docs.docker.com/engine/security/rootless/
// TODO: ensure no containers has the docker socket mounted to it (`/var/run/docker.sock`), capabilities or is unconfined
// https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html#automatic-enumeration-and-escape
// TODO: ensure an apparmor profile is enabled for containers
// TODO: ensure containers are isolated with user namespaces <https://docs.docker.com/engine/security/userns-remap/>
// TODO: ensure resources are limited to avoid container DOS the host

use std::process;
use std::process::Stdio;

use crate::{check, log_debug, log_trace};

/// Ensure containers are not started with `--privileged` flag.
///
/// Don't start containers with `--privileged`.
/// Check manually with:
/// podman container inspect -l --format '{{.Id}}\t{{.Config.CreateCommand}}'
pub fn podman_not_privileged() -> check::CheckReturn {
    let mut cmd = process::Command::new("podman");
    cmd.stdin(Stdio::null());
    cmd.args(vec![
        "container",
        "inspect",
        "-l",
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

                log_trace!("podman privileged {} {:?}", id, cmd);

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

    log_debug!("containers running with `--privileged`: {:?}", ids);

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
/// podman container inspect -l --format '{{.Id}}={{.Config.CreateCommand}}'
pub fn podman_cap_drop() -> check::CheckReturn {
    let mut cmd = process::Command::new("podman");
    cmd.stdin(Stdio::null());
    cmd.args(vec![
        "container",
        "inspect",
        "-l",
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

                log_trace!("cap list for podman container {} {:?}", id, cap_list);

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

    log_debug!("Missing cap drop on containers: {:?}", ids);

    if ids.len() == 0 {
        (check::CheckState::Passed, None)
    } else {
        (check::CheckState::Failed, Some(ids.join(", ")))
    }
}

/// Ensure containers services are running as user.
///
/// Start containers and run process as a user inside it.
/// check manually with:
/// podman container inspect -l --format '{{.Id}}\t{{.Config.User}}'
pub fn podman_user() -> check::CheckReturn {
    let mut cmd = process::Command::new("podman");
    cmd.stdin(Stdio::null());
    cmd.args(vec![
        "container",
        "inspect",
        "-l",
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
            Some((id, uid)) => {
                // debug
                log_trace!("podman container user {} {:?}", id, uid);

                if uid == "0" {
                    Some(id.to_string())
                } else {
                    None
                }
            }
            // should never happen, don't even log it
            None => None,
        })
        .collect();

    log_debug!("Running as root on containers: {:?}", ids);

    if ids.len() == 0 {
        (check::CheckState::Passed, None)
    } else {
        (check::CheckState::Failed, Some(ids.join(", ")))
    }
}
