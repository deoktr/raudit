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

/// Unescape the octal sequences (`\ooo`) used by the kernel in the device,
/// mount point and filesystem type fields of `/proc/mounts`, e.g. a space is
/// reported as `\040`.
fn unescape_octal(value: &str) -> String {
    if !value.contains('\\') {
        return value.to_string();
    }

    let value = value.as_bytes();
    let mut bytes = Vec::with_capacity(value.len());
    let mut i = 0;

    while i < value.len() {
        if value[i] != b'\\' {
            bytes.push(value[i]);
            i += 1;
            continue;
        }

        i += 1;
        let mut octal: u8 = 0;
        let mut digits = 0;
        while digits < 3 && i < value.len() && (b'0'..=b'7').contains(&value[i]) {
            octal = octal * 8 + (value[i] - b'0');
            i += 1;
            digits += 1;
        }

        if digits == 0 {
            bytes.push(b'\\');
            continue;
        }

        bytes.push(octal);
    }

    String::from_utf8_lossy(&bytes).into_owned()
}

/// Parse the content for `/proc/mounts`.
fn parse_mounts(mounts: String) -> MountConfig {
    mounts
        .lines()
        .map(|line| {
            let mut kvs = line.splitn(4, " ");
            let source = unescape_octal(kvs.next().unwrap_or_default());
            let target = unescape_octal(kvs.next().unwrap_or_default());
            let fs_type = unescape_octal(kvs.next().unwrap_or_default());

            // The remainder holds the option list followed by the dump and pass
            // values, the kernel does not escape the options, they may contain
            // spaces.
            let remainder = kvs.next().unwrap_or_default();
            let options = remainder
                .strip_suffix(" 0 0")
                .unwrap_or(remainder)
                .split(",")
                .map(str::to_string)
                .collect();

            Mount {
                source,
                target,
                fs_type,
                options,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unescape_octal() {
        assert_eq!(unescape_octal("/home"), "/home".to_string());
        assert_eq!(unescape_octal("/mnt/my\\040dir"), "/mnt/my dir".to_string());
        assert_eq!(
            unescape_octal("a\\011b\\012c\\015d\\134e\\043f"),
            "a\tb\nc\rd\\e#f".to_string()
        );
        assert_eq!(unescape_octal("\\377"), "\u{fffd}".to_string());
        assert_eq!(unescape_octal("\\12\\1"), "\n\u{1}".to_string());
        assert_eq!(unescape_octal("trailing\\"), "trailing\\".to_string());
    }

    #[test]
    fn test_parse_mounts() {
        let mounts = parse_mounts(
            "/dev/mapper/vg-root / ext4 rw,relatime 0 0
/dev/disk/by-label/Data\\040Disk /mnt/data\\040dir fuse\\043sshfs ro,nosuid,nodev 0 0
tmpfs /tmp tmpfs rw,seclabel,context=\"system_u:object_r:tmp_t\\040a b\" 0 0
"
            .to_string(),
        );

        assert_eq!(mounts.len(), 3);

        assert_eq!(mounts[0].source, "/dev/mapper/vg-root".to_string());
        assert_eq!(mounts[0].target, "/".to_string());
        assert_eq!(mounts[0].fs_type, "ext4".to_string());
        assert_eq!(
            mounts[0].options,
            vec!["rw".to_string(), "relatime".to_string()]
        );

        assert_eq!(mounts[1].source, "/dev/disk/by-label/Data Disk".to_string());
        assert_eq!(mounts[1].target, "/mnt/data dir".to_string());
        assert_eq!(mounts[1].fs_type, "fuse#sshfs".to_string());
        assert_eq!(
            mounts[1].options,
            vec!["ro".to_string(), "nosuid".to_string(), "nodev".to_string()]
        );

        assert_eq!(
            mounts[2].options,
            vec![
                "rw".to_string(),
                "seclabel".to_string(),
                "context=\"system_u:object_r:tmp_t\\040a b\"".to_string()
            ]
        );
    }
}
