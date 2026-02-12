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
use std::collections::HashMap;
use std::fs;
use std::sync::OnceLock;

use crate::{log_debug, log_error};

const KOSTYPE_PATH: &str = "/proc/sys/kernel/ostype";
const KOSRELEASE_PATH: &str = "/proc/sys/kernel/osrelease";
const OS_RELEASE_PATH: &str = "/etc/os-release";

static OS_RELEASE: OnceLock<OSRelease> = OnceLock::new();

/// OS.
pub struct OS {
    os: String,
    name: String,
    version: String,
    full_name: String,
}

/// OS release.
pub type OSRelease = HashMap<String, String>;

/// Init system OS type by reading `/proc/sys/kernel/ostype`.
pub fn init_kernel_os_type() -> Result<String, std::io::Error> {
    let content = fs::read_to_string(KOSTYPE_PATH)?;
    Ok(content.trim_end().to_string())
}

/// Init system OS release by reading `/proc/sys/kernel/osrelease`.
pub fn init_kernel_os_release() -> Result<String, std::io::Error> {
    let content = fs::read_to_string(KOSRELEASE_PATH)?;
    Ok(content.trim_end().to_string())
}

/// Parse content of `/etc/os-release`.
fn parse_os_release(content: String) -> OSRelease {
    content
        .lines()
        .filter_map(|line| match line.split_once("=") {
            Some((key, value)) => Some((
                key.to_string(),
                // parse the value, can be inside quotes single or double
                value.to_string().replace("'", "").replace("\"", ""),
            )),
            // should never happen, don't even log it
            None => None,
        })
        .collect()
}

/// Get OS release info from `/etc/os-release`.
fn get_os_release() -> Result<OSRelease, std::io::Error> {
    let content = fs::read_to_string(OS_RELEASE_PATH)?;
    Ok(parse_os_release(content))
}

/// Init OS release info from `/etc/os-release`.
pub fn init_os_release() {
    if OS_RELEASE.get().is_some() {
        return;
    }

    match get_os_release() {
        Ok(m) => {
            OS_RELEASE.get_or_init(|| m);
            log_debug!("initialized os release");
        }
        Err(err) => log_error!("failed to initialize os release: {}", err),
    }
}

/// Helper to check if current distro is Debian.
pub fn is_debian() -> bool {
    let os_release = match OS_RELEASE.get() {
        Some(c) => c,
        None => {
            log_error!("os release not initialized");
            return false;
        }
    };

    os_release.get("ID").is_some_and(|v| v == "debian")
}

/// Helper to check if current distro is ArchLinux.
pub fn is_arch() -> bool {
    let os_release = match OS_RELEASE.get() {
        Some(c) => c,
        None => {
            log_error!("os release not initialized");
            return false;
        }
    };

    os_release.get("ID").is_some_and(|v| v == "arch")
}
