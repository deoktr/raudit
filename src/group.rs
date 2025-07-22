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
use std::sync::OnceLock;

use crate::base::empty_or_missing_file;
use crate::check;

const GROUP_PATH: &str = "/etc/group";

const SHADOW_PATH: &str = "/etc/gshadow";

static GROUPS: OnceLock<Groups> = OnceLock::new();

/// Group configuration from `/etc/group`.
pub type Groups = Vec<Group>;

/// Group entry found in `/etc/group`.
#[allow(dead_code)]
pub struct Group {
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
pub fn parse_group(content: String) -> Groups {
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
                .filter(|i| i.len() != 0)
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

/// Initialize groups from `/etc/group`.
pub fn init_group() {
    if GROUPS.get().is_some() {
        return;
    }

    match fs::read_to_string(GROUP_PATH) {
        Ok(content) => {
            GROUPS.get_or_init(|| parse_group(content));
        }
        Err(err) => println!("Failed to initialize groups: {}", err),
    };
}

fn get_groups() -> &'static Groups {
    GROUPS.get().expect("group not initialized")
}

/// Ensure group shadow empty or missing.
///
/// File `/etc/gshadow` must either be empty or missing.
pub fn empty_gshadow() -> check::CheckReturn {
    empty_or_missing_file(SHADOW_PATH)
}

/// Ensure no group has a password set (not set to `x`).
pub fn no_password_in_group() -> check::CheckReturn {
    let g: Vec<String> = get_groups()
        .iter()
        .filter(|group| group.password != "x".to_string())
        .map(|group| group.name.clone())
        .collect();

    if g.len() != 0 {
        (check::CheckState::Failure, Some(g.join(", ")))
    } else {
        (check::CheckState::Success, None)
    }
}

/// Ensure that only root has GID 0.
pub fn one_gid_zero() -> check::CheckReturn {
    let g: Vec<String> = get_groups()
        .iter()
        .filter(|group| group.gid == 0 && group.name != "root")
        .map(|group| group.name.clone())
        .collect();

    if g.len() != 0 {
        (check::CheckState::Failure, Some(g.join(", ")))
    } else {
        (check::CheckState::Success, None)
    }
}

/// Ensure no duplicate GIDs exist.
pub fn no_dup_gid() -> check::CheckReturn {
    let groups = get_groups();

    let g: Vec<String> = groups
        .iter()
        .filter(|group| groups.iter().filter(|g| g.gid == group.gid).count() > 1)
        .map(|group| group.name.clone())
        .collect();

    if g.len() != 0 {
        (check::CheckState::Failure, Some(g.join(", ")))
    } else {
        (check::CheckState::Success, None)
    }
}

/// Ensure no duplicate group names exist.
pub fn no_dup_name() -> check::CheckReturn {
    let groups = get_groups();

    let g: Vec<String> = groups
        .iter()
        .filter(|group| groups.iter().filter(|g| g.name == group.name).count() > 1)
        .map(|group| group.name.clone())
        .collect();

    if g.len() != 0 {
        (check::CheckState::Failure, Some(g.join(", ")))
    } else {
        (check::CheckState::Success, None)
    }
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
