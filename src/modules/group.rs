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

use std::fs;

use crate::check;
use crate::check::State;

const GROUP_PATH: &str = "/etc/group";
const SHADOW_PATH: &str = "/etc/gshadow";

static GROUPS: State<Groups> = State::new("groups");

/// Group configuration from `/etc/group`.
type Groups = Vec<Group>;

/// Group entry found in `/etc/group`.
#[allow(dead_code)]
struct Group {
    /// group name
    name: String,
    /// optional encrypted password
    password: String,
    /// numeric group ID
    gid: u32,
    /// user list
    user_list: Vec<String>,
}

/// Parse the content of `/etc/group`.
///
/// Parsed group following the format: `group_name:password:GID:user_list`.
fn parse_group(content: String) -> Groups {
    content
        .lines()
        .map(|line| {
            let mut kvs = line.splitn(4, ":");
            let name = kvs.next().unwrap_or_default().to_string();
            let password = kvs.next().unwrap_or_default().to_string();
            let gid = kvs
                .next()
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or_default();

            let user_list = kvs
                .next()
                .unwrap_or_default()
                .split(",")
                .filter(|i| !i.is_empty())
                .map(|i| i.to_string())
                .collect();

            Group {
                name,
                password,
                gid,
                user_list,
            }
        })
        .collect()
}

/// Get groups from `/etc/group`.
fn get_group() -> Result<Groups, String> {
    let content = fs::read_to_string(GROUP_PATH)
        .map_err(|err| format!("failed to read `{}`: {}", GROUP_PATH, err))?;
    Ok(parse_group(content))
}

/// Init groups from `/etc/group`.
pub fn init_group() {
    GROUPS.init(get_group);
}

/// Ensure no usable group password in `/etc/gshadow`.
///
/// The file may be missing, or hold entries whose password field is locked
/// (`!`/`*` prefix, what `gpasswd -r` and the distro tooling produce) or
/// empty (no password). Only a real password hash is an attack vector, it
/// lets anyone holding it switch into the group via `newgrp`.
pub fn no_usable_gshadow_passwords() -> check::CheckReturn {
    let content = match fs::read_to_string(SHADOW_PATH) {
        Ok(content) => content,
        Err(err) => {
            return match err.kind() {
                std::io::ErrorKind::NotFound => {
                    (check::CheckState::Pass, Some("file missing".to_string()))
                }
                _ => (check::CheckState::Warning, Some(err.to_string())),
            };
        }
    };

    let groups: Vec<String> = content
        .lines()
        .filter_map(|line| {
            // gshadow format: `group_name:encrypted_password:admins:members`
            let mut fields = line.splitn(4, ':');
            let name = fields.next()?;
            let password = fields.next().unwrap_or_default();
            if password.is_empty() || password.starts_with('!') || password.starts_with('*') {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect();

    if groups.is_empty() {
        (check::CheckState::Pass, None)
    } else {
        (check::CheckState::Fail, Some(groups.join(", ")))
    }
}

/// Ensure no group has a usable password set in `/etc/group`.
///
/// The password field should be `x` (delegated to `/etc/gshadow`), empty (no
/// password) or locked (`!`/`*`). Only a real hash is reported, it is a
/// world-readable shared credential: anyone with it assumes the group's
/// privileges via `newgrp`, bypassing the membership list.
pub fn no_password_in_group() -> check::CheckReturn {
    GROUPS.with(|groups| {
        let g: Vec<String> = groups
            .iter()
            .filter(|group| {
                let password = group.password.as_str();
                !(password == "x"
                    || password.is_empty()
                    || password.starts_with('!')
                    || password.starts_with('*'))
            })
            .map(|group| group.name.clone())
            .collect();

        if !g.is_empty() {
            (check::CheckState::Fail, Some(g.join(", ")))
        } else {
            (check::CheckState::Pass, None)
        }
    })
}

/// Ensure that only root has GID 0.
pub fn one_gid_zero() -> check::CheckReturn {
    GROUPS.with(|groups| {
        let g: Vec<String> = groups
            .iter()
            .filter(|group| group.gid == 0 && group.name != "root")
            .map(|group| group.name.clone())
            .collect();

        if !g.is_empty() {
            (check::CheckState::Fail, Some(g.join(", ")))
        } else {
            (check::CheckState::Pass, None)
        }
    })
}

/// Ensure no duplicate GIDs exist.
pub fn no_dup_gid() -> check::CheckReturn {
    GROUPS.with(|groups| {
        let g: Vec<String> = groups
            .iter()
            .filter(|group| groups.iter().filter(|g| g.gid == group.gid).count() > 1)
            .map(|group| group.name.clone())
            .collect();

        if !g.is_empty() {
            (check::CheckState::Fail, Some(g.join(", ")))
        } else {
            (check::CheckState::Pass, None)
        }
    })
}

/// Ensure no duplicate group names exist.
pub fn no_dup_name() -> check::CheckReturn {
    GROUPS.with(|groups| {
        let g: Vec<String> = groups
            .iter()
            .filter(|group| groups.iter().filter(|g| g.name == group.name).count() > 1)
            .map(|group| group.name.clone())
            .collect();

        if !g.is_empty() {
            (check::CheckState::Fail, Some(g.join(", ")))
        } else {
            (check::CheckState::Pass, None)
        }
    })
}

/// Ensure group is empty.
pub fn no_members(group_name: &str) -> check::CheckReturn {
    GROUPS.with(|groups| {
        for group in groups {
            if group.name != group_name {
                continue;
            }

            if !group.user_list.is_empty() {
                return (check::CheckState::Fail, Some(group.user_list.join(", ")));
            } else {
                return (check::CheckState::Pass, None);
            }
        }

        (
            check::CheckState::Warning,
            Some(format!("no `{}` group found", group_name)),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_group() {
        let lines = parse_group("wheel:x:1:ping".to_string());
        assert_eq!(lines.len(), 1);
        assert!(lines.get(0).is_some());
        let line = lines.get(0).unwrap();
        assert_eq!(line.name, "wheel".to_string());
        assert_eq!(line.password, "x".to_string());
        assert_eq!(line.gid, 1);
        assert_eq!(line.user_list, vec!["ping".to_string()]);

        let lines = parse_group(
            "qemu-libvirtd:x:301:
kvm:x:302:
render:x:303:
sgx:x:304:
shadow:x:318:
systemd-oom:x:991:
systemd-coredump:x:992:
rtkit:x:993:
polkituser:x:994:
nscd:x:995:
gnome-remote-desktop:x:996:
geoclue:x:997:
colord:x:998:
avahi:x:999:
"
            .to_string(),
        );
        assert_eq!(lines.len(), 14);
        assert!(lines.get(0).is_some());
        let line = lines.get(0).unwrap();
        assert_eq!(line.name, "qemu-libvirtd".to_string());
        assert_eq!(line.password, "x".to_string());
        assert_eq!(line.gid, 301);
        assert_eq!(line.user_list, Vec::<String>::new());

        assert!(lines.get(1).is_some());
        let line = lines.get(1).unwrap();
        assert_eq!(line.name, "kvm".to_string());
        assert_eq!(line.password, "x".to_string());
        assert_eq!(line.gid, 302);
        assert_eq!(line.user_list, Vec::<String>::new());

        assert!(lines.get(13).is_some());
        let line = lines.get(13).unwrap();
        assert_eq!(line.name, "avahi".to_string());
        assert_eq!(line.password, "x".to_string());
        assert_eq!(line.gid, 999);
        assert_eq!(line.user_list, Vec::<String>::new());
    }
}
