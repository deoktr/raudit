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

use crate::{check, log_debug, log_error};

const CMDLINE_PATH: &str = "/proc/cmdline";
const OSRELEASE_PATH: &str = "/proc/sys/kernel/osrelease";

static KERNEL_PARAMS: OnceLock<KernelParams> = OnceLock::new();
static KERNEL_VERSION: OnceLock<(u32, u32, u32)> = OnceLock::new();

/// Kernel params from `/proc/cmdline`.
pub type KernelParams = Vec<String>;

/// Parse content for `/proc/cmdline`.
fn parse_kernel_params(cmdline: String) -> KernelParams {
    cmdline
        .replace("\n", "")
        // TODO: use shlex to split arguments, they could contain spaces in them
        .split(" ")
        .map(|line| line.to_string())
        .collect()
}

/// Get kernel params by reading from `/proc/cmdline`.
fn get_kernel_params() -> Result<KernelParams, std::io::Error> {
    Ok(parse_kernel_params(fs::read_to_string(CMDLINE_PATH)?))
}

/// Init kernel params by reading from `/proc/cmdline`.
pub fn init_kernel_params() {
    if KERNEL_PARAMS.get().is_some() {
        return;
    }

    match get_kernel_params() {
        Ok(c) => {
            KERNEL_PARAMS.get_or_init(|| c);
            log_debug!("initialized kernel params");
        }
        Err(err) => log_error!("failed to initialize kernel params: {}", err),
    }
}

/// Get kernel params presence from a collected configuration.
pub fn check_kernel_params(variable: &str) -> check::CheckReturn {
    let kparams = match KERNEL_PARAMS.get() {
        Some(kparams) => kparams,
        None => {
            return (
                check::CheckState::Warning,
                Some("kernel params not initialized".to_string()),
            );
        }
    };

    if kparams.contains(&variable.to_string()) {
        (check::CheckState::Pass, None)
    } else {
        (check::CheckState::Fail, None)
    }
}

/// Parse a kernel version string like "6.8.0-45-generic" into (major, minor, patch).
pub fn parse_kernel_version(version: &str) -> Option<(u32, u32, u32)> {
    let numeric_part: String = version
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut parts = numeric_part.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// Init kernel version by reading `/proc/sys/kernel/osrelease`.
pub fn init_kernel_version() {
    if KERNEL_VERSION.get().is_some() {
        return;
    }

    let content = match fs::read_to_string(OSRELEASE_PATH) {
        Ok(c) => c,
        Err(err) => {
            log_error!("failed to read kernel osrelease: {}", err);
            return;
        }
    };

    if let Some(v) = parse_kernel_version(content.trim()) {
        KERNEL_VERSION.get_or_init(|| v);
        log_debug!("initialized kernel version: {}.{}.{}", v.0, v.1, v.2);
    } else {
        log_error!("failed to parse kernel version from: {}", content.trim());
    }
}

/// Skip check when the running kernel is not in the vulnerable range for CopyFail.
/// Vulnerable range: >= 4.14.0 and <= 6.19.12.
pub fn skip_not_vulnerable_copyfail() -> bool {
    init_kernel_version();
    match KERNEL_VERSION.get() {
        Some(&(major, minor, patch)) => {
            let version = (major, minor, patch);
            !((4, 14, 0)..=(6, 19, 12)).contains(&version)
        }
        None => {
            log_error!("kernel version not initialized, skipping CopyFail check");
            true
        }
    }
}

/// Check if system needs a reboot.
pub fn check_reboot_required() -> check::CheckReturn {
    // TODO: on RHEL use `needs-restarting -r` command, status 0 no reboot
    // required, 1 if it is
    if !(Path::new("/var/run/reboot-required.pkgs").exists()
        || Path::new("/var/run/reboot-required").exists()
        || Path::new("/var/run/needs_restarting").exists())
    {
        (check::CheckState::Pass, None)
    } else {
        (check::CheckState::Fail, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kernel_version() {
        assert_eq!(
            parse_kernel_version("7.1.9-hardened1-1-hardened"),
            Some((7, 1, 9))
        );
        assert_eq!(parse_kernel_version("6.8.0-45-generic"), Some((6, 8, 0)));
        assert_eq!(parse_kernel_version("5.15.0-134-generic"), Some((5, 15, 0)));
        assert_eq!(parse_kernel_version("4.14.0"), Some((4, 14, 0)));
        assert_eq!(parse_kernel_version("6.19.12"), Some((6, 19, 12)));
        assert_eq!(
            parse_kernel_version("3.10.0-1160.el7.x86_64"),
            Some((3, 10, 0))
        );
        assert_eq!(parse_kernel_version("6.1"), Some((6, 1, 0)));
        assert_eq!(parse_kernel_version(""), None);
        assert_eq!(parse_kernel_version("abc"), None);
    }

    #[test]
    fn test_copyfail_vulnerable_range() {
        let vulnerable = |v: (u32, u32, u32)| ((4, 14, 0)..=(6, 19, 12)).contains(&v);

        assert!(!vulnerable((3, 10, 0)));
        assert!(!vulnerable((4, 13, 99)));
        assert!(vulnerable((4, 14, 0)));
        assert!(vulnerable((5, 15, 0)));
        assert!(vulnerable((6, 8, 0)));
        assert!(vulnerable((6, 19, 12)));
        assert!(!vulnerable((6, 19, 13)));
        assert!(!vulnerable((7, 0, 0)));
    }
}
