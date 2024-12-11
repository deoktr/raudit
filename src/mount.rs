/*
 * rAudit, a Linux security auditing toolkit
 * Copyright (C) 2024  deoktr
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

const PROC_MOUNTS_PATH: &str = "/proc/mounts";

/// List of mount configurations.
pub type MountConfig = Vec<Mount>;

/// List of options applied to a mount.
pub type MountOptions = Vec<String>;

/// A single mount configuration.
#[allow(dead_code)]
pub struct Mount {
    source: String,
    target: String,
    fs_type: String,
    options: Vec<String>,
}

/// Parse the content for `/proc/mounts`.
fn parse_mounts(mounts: String) -> MountConfig {
    mounts
        .lines()
        .map(|line| {
            let mut kvs = line.splitn(6, " ");
            let source = kvs.next().unwrap_or_default();
            let target = kvs.next().unwrap_or_default();
            let fs_type = kvs.next().unwrap_or_default();
            let options = kvs.next().unwrap_or_default();
            Mount {
                source: source.to_string(),
                target: target.to_string(),
                fs_type: fs_type.to_string(),
                options: options.split(",").map(str::to_string).collect(),
            }
        })
        .collect()
}

/// Get mounts configuration by reading `/proc/mounts`.
pub fn init_mounts() -> Result<MountConfig, std::io::Error> {
    let mounts = fs::read_to_string(PROC_MOUNTS_PATH)?;
    Ok(parse_mounts(mounts))
}

/// Get mount from a collected configuration.
pub fn get_mount(
    mounts: &'static MountConfig,
    target: &str,
) -> Result<Option<&'static Mount>, String> {
    // TODO: is it possible to remove the lifetime?
    for mount in mounts {
        if mount.target == target {
            return Ok(Some(mount));
        }
    }
    return Ok(None);
}

/// Get mount options from a collected configuration.
pub fn get_mount_options(
    mounts: &'static MountConfig,
    target: &str,
) -> Result<MountOptions, String> {
    match get_mount(mounts, target) {
        Ok(res) => match res {
            Some(mount) => Ok(mount.options.clone()),
            None => Err("mount does not exist".to_string()),
        },
        Err(error) => Err(error),
    }
}
