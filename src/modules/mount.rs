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
use std::path::Path;
use std::sync::OnceLock;

use crate::{check, log_debug, log_error, log_trace};

const PROC_MOUNTS_PATH: &str = "/proc/mounts";

const SYS_BLOCK_PATH: &str = "/sys/block";

/// Maximum recursion depth while walking the block device stack, prevents
/// infinite loops on unexpected sysfs layouts.
const MAX_DEVICE_DEPTH: usize = 16;

static MOUNT_CONFIG: OnceLock<MountConfig> = OnceLock::new();

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
    options: MountOptions,
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
fn get_mounts() -> Result<MountConfig, std::io::Error> {
    Ok(parse_mounts(fs::read_to_string(PROC_MOUNTS_PATH)?))
}

/// Init mounts configuration by reading `/proc/mounts`.
pub fn init_mounts() {
    if MOUNT_CONFIG.get().is_some() {
        return;
    }

    match get_mounts() {
        Ok(m) => {
            MOUNT_CONFIG.get_or_init(|| m);
            log_debug!("initialized mounts");
        }
        Err(err) => log_error!("failed to initialize mount config: {}", err),
    }
}

/// Get mount from a collected configuration.
fn get_mount(mounts: &'static MountConfig, target: &str) -> Option<&'static Mount> {
    mounts
        .iter()
        .find(|&mount| mount.target == target)
        .map(|v| v as _)
}

/// Ensure that mount exist.
pub fn check_mount_present(target: &str) -> check::CheckReturn {
    let mounts = match MOUNT_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Warning,
                Some("mount configuration not initialized".to_string()),
            );
        }
    };

    match get_mount(mounts, target) {
        Some(_) => (check::CheckState::Pass, None),
        None => (check::CheckState::Fail, None),
    }
}

/// Get mount options from a collected configuration.
fn get_mount_options(mounts: &'static MountConfig, target: &str) -> Option<MountOptions> {
    get_mount(mounts, target).map(|mount| mount.options.clone())
}

/// Ensure that option is set on mount target.
pub fn check_mount_option(target: &str, option: &str) -> check::CheckReturn {
    let mounts = match MOUNT_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Warning,
                Some("mount configuration not initialized".to_string()),
            );
        }
    };

    match get_mount_options(mounts, target) {
        Some(options) => {
            if options.contains(&option.to_string()) {
                (check::CheckState::Pass, None)
            } else {
                (check::CheckState::Fail, Some("missing option".to_string()))
            }
        }
        None => (
            check::CheckState::Fail,
            Some("not a mount point".to_string()),
        ),
    }
}

/// Resolve a device path to its `/sys/block` name, following symlinks like
/// `/dev/mapper/foo` to `/dev/dm-0`.
fn resolve_device_name(source: &str) -> Option<String> {
    let path = fs::canonicalize(source).ok()?;
    path.file_name()?.to_str().map(|name| name.to_string())
}

/// Check if the content of a device-mapper `uuid` sysfs file belongs to a LUKS
/// device opened by cryptsetup, e.g. `CRYPT-LUKS2-<digest>-<name>`.
fn dm_uuid_is_luks(content: &str) -> bool {
    content.trim().starts_with("CRYPT-LUKS")
}

/// Check if a block device is a LUKS device opened by cryptsetup.
fn dev_is_luks(dev: &str) -> Option<bool> {
    let path = Path::new(SYS_BLOCK_PATH).join(dev).join("dm/uuid");
    let content = fs::read_to_string(path).ok()?;
    Some(dm_uuid_is_luks(&content))
}

/// Check if a block device, or any device underneath it in the stack (e.g. LVM
/// on top of LUKS), is a LUKS device.
fn device_is_luks(dev: &str, depth: usize) -> bool {
    if depth > MAX_DEVICE_DEPTH {
        return false;
    }

    if let Some(is_luks) = dev_is_luks(dev) {
        log_trace!("device {} is luks: {}", dev, is_luks);
        if is_luks {
            return true;
        }
    }

    let slaves_path = Path::new(SYS_BLOCK_PATH).join(dev).join("slaves");
    if let Ok(entries) = fs::read_dir(slaves_path) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && device_is_luks(name, depth + 1)
            {
                return true;
            }
        }
    }

    false
}

/// Ensure the block device backing a mount target is encrypted with LUKS.
pub fn check_luks_mount(target: &str) -> check::CheckReturn {
    let mounts = match MOUNT_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Warning,
                Some("mount configuration not initialized".to_string()),
            );
        }
    };

    let source = match get_mount(mounts, target) {
        Some(mount) => &mount.source,
        None => {
            return (
                check::CheckState::Warning,
                Some(format!("target {} is not a mount", target)),
            );
        }
    };

    let dev = match resolve_device_name(&source) {
        Some(dev) => dev,
        None => {
            return (
                check::CheckState::Warning,
                Some(format!("failed to resolve device {}", source)),
            );
        }
    };

    if device_is_luks(&dev, 0) {
        (check::CheckState::Pass, None)
    } else {
        (check::CheckState::Fail, None)
    }
}
