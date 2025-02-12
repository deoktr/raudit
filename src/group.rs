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

// use crate::base::empty_or_missing_file;
use crate::base::empty_or_missing_file;

const GROUP_PATH: &str = "/etc/group";

const SHADOW_PATH: &str = "/etc/gshadow";

/// Group configuration from `/etc/group`.
pub type GroupConfig = Vec<Group>;

/// Group entry found in `/etc/group`.
#[allow(dead_code)]
pub struct Group {
    name: String,
    password: String,
    gid: u32,
    list: Vec<String>,
}

/// Parse the content of `/etc/group`.
pub fn parse_group(content: String) -> GroupConfig {
    content
        .lines()
        .map(|line| {
            let mut kvs = line.splitn(9, ":");
            let name = kvs.next().unwrap_or_default().to_string();
            let password = kvs.next().unwrap_or_default().to_string();
            let gid = kvs
                .next()
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or_default();

            let list = kvs
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
                list,
            }
        })
        .collect()
}

/// Get the system's groups from `/etc/group`.
pub fn init_group() -> Result<GroupConfig, std::io::Error> {
    let gc = fs::read_to_string(GROUP_PATH)?;
    Ok(parse_group(gc))
}

/// Ensure group shadow empty or missing.
///
/// File `/etc/gshadow` must either be empty or missing.
pub fn empty_gshadow() -> Result<bool, std::io::Error> {
    empty_or_missing_file(SHADOW_PATH)
}

/// Ensure that only root has GID 0.
pub fn one_gid_zero(gc: &GroupConfig) -> bool {
    // FIXME: also verify the name of the group to be `root`
    gc.iter().filter(|g| g.gid == 0).count() == 1
}

/// Ensure no duplicate GIDs exist.
///
/// Returns true if no duplicate is found.
pub fn no_dup_gid(groups: &GroupConfig) -> bool {
    !groups
        .iter()
        .any(|group| groups.iter().filter(|g| g.gid == group.gid).count() > 1)
}

/// Ensure no duplicate group names exist.
///
/// Returns true if no duplicate is found.
pub fn no_dup_name(groups: &GroupConfig) -> bool {
    !groups
        .iter()
        .any(|group| groups.iter().filter(|g| g.name == group.name).count() > 1)
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
        assert_eq!(line.list, vec!["ping".to_string()]);

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
        assert_eq!(line.list, Vec::<String>::new());

        assert!(lines.get(1).is_some());
        let line = lines.get(1).unwrap();
        assert_eq!(line.name, "kvm".to_string());
        assert_eq!(line.password, "x".to_string());
        assert_eq!(line.gid, 302);
        assert_eq!(line.list, Vec::<String>::new());

        assert!(lines.get(13).is_some());
        let line = lines.get(13).unwrap();
        assert_eq!(line.name, "avahi".to_string());
        assert_eq!(line.password, "x".to_string());
        assert_eq!(line.gid, 999);
        assert_eq!(line.list, Vec::<String>::new());
    }
}
