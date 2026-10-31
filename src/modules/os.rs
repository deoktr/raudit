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

use crate::{check::State, log_error};

const KOSTYPE_PATH: &str = "/proc/sys/kernel/ostype";
#[allow(dead_code)]
const KOSRELEASE_PATH: &str = "/proc/sys/kernel/osrelease";
const OS_RELEASE_PATH: &str = "/etc/os-release";

static OS_RELEASE: State<OSRelease> = State::new("osrelease");

/// OS.
#[allow(dead_code)]
struct OS {
    os: String,
    name: String,
    version: String,
    full_name: String,
}

/// OS release.
type OSRelease = HashMap<String, String>;

/// Init system OS type by reading `/proc/sys/kernel/ostype`.
#[allow(dead_code)]
pub fn init_kernel_os_type() -> Result<String, String> {
    let content = fs::read_to_string(KOSTYPE_PATH)
        .map_err(|err| format!("failed to read `{}`: {}", KOSTYPE_PATH, err))?;
    Ok(content.trim_end().to_string())
}

/// Init system OS release by reading `/proc/sys/kernel/osrelease`.
#[allow(dead_code)]
pub fn init_kernel_os_release() -> Result<String, String> {
    let content = fs::read_to_string(KOSRELEASE_PATH)
        .map_err(|err| format!("failed to read `{}`: {}", KOSRELEASE_PATH, err))?;
    Ok(content.trim_end().to_string())
}

/// Parse content of `/etc/os-release`.
fn parse_os_release(content: String) -> OSRelease {
    content
        .lines()
        .filter_map(|line| {
            line.split_once("=").map(|(key, value)| {
                (
                    key.to_string(),
                    // parse the value, can be inside quotes single or double
                    value.to_string().replace("'", "").replace("\"", ""),
                )
            })
        })
        .collect()
}

/// Get OS release info from `/etc/os-release`.
fn get_os_release() -> Result<OSRelease, String> {
    let content = fs::read_to_string(OS_RELEASE_PATH)
        .map_err(|err| format!("failed to read `{}`: {}", OS_RELEASE_PATH, err))?;
    Ok(parse_os_release(content))
}

/// Init OS release info from `/etc/os-release`.
pub fn init_os_release() {
    OS_RELEASE.init(get_os_release);
}

/// Helper to check if current distro is Debian.
pub fn is_debian() -> bool {
    let os_release = match OS_RELEASE.try_get() {
        Ok(c) => c,
        Err(err) => {
            log_error!("{}", err);
            return false;
        }
    };

    os_release.get("ID").is_some_and(|v| v == "debian")
        || os_release
            .get("ID_LIKE")
            .is_some_and(|v| v.split_whitespace().any(|w| w == "debian"))
}

/// Skip when the host is not part of the Debian family.
pub fn skip_not_debian() -> bool {
    init_os_release();
    !is_debian()
}
