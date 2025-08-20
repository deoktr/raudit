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

use crate::{check, log_debug, log_error};

const PROC_MOUNTS_PATH: &str = "/proc/mounts";

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

/// Initialize mounts configuration by reading `/proc/mounts`.
pub fn init_mounts() {
    if MOUNT_CONFIG.get().is_some() {
        return;
    }

    match fs::read_to_string(PROC_MOUNTS_PATH) {
        Ok(mounts) => {
            MOUNT_CONFIG.get_or_init(|| parse_mounts(mounts));
        }
        Err(err) => {
            log_error!("Failed to initialize mount config: {}", err);
            return;
        }
    };

    log_debug!("initialized mounts");
}

/// Get mount from a collected configuration.
fn get_mount(mounts: &'static MountConfig, target: &str) -> Option<&'static Mount> {
    for mount in mounts {
        if mount.target == target {
            return Some(mount);
        }
    }
    return None;
}

/// Ensure that mount exist.
pub fn check_mount_present(target: &str) -> check::CheckReturn {
    let mounts = match MOUNT_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("mount configuration not initialized".to_string()),
            );
        }
    };

    match get_mount(mounts, target) {
        Some(_) => (check::CheckState::Passed, None),
        None => (check::CheckState::Failed, None),
    }
}

/// Get mount options from a collected configuration.
fn get_mount_options(mounts: &'static MountConfig, target: &str) -> Option<MountOptions> {
    match get_mount(mounts, target) {
        Some(mount) => Some(mount.options.clone()),
        None => None,
    }
}

/// Ensure that option is set on mount target.
pub fn check_mount_option(target: &str, option: &str) -> check::CheckReturn {
    let mounts = match MOUNT_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("mount configuration not initialized".to_string()),
            );
        }
    };

    match get_mount_options(mounts, target) {
        Some(options) => {
            if options.contains(&option.to_string()) {
                (check::CheckState::Passed, None)
            } else {
                (
                    check::CheckState::Failed,
                    Some("missing option".to_string()),
                )
            }
        }
        None => (
            check::CheckState::Failed,
            Some("not a mount point".to_string()),
        ),
    }
}
