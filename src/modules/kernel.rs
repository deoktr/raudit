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

use crate::check::{self, State};
use crate::{log_error, log_trace};

const CMDLINE_PATH: &str = "/proc/cmdline";
const OSRELEASE_PATH: &str = "/proc/sys/kernel/osrelease";

static KERNEL_PARAMS: State<KernelParams> = State::new("kernel params");
static KERNEL_VERSION: State<(u32, u32, u32)> = State::new("kernel version");

/// Kernel params from `/proc/cmdline`.
type KernelParams = Vec<String>;

/// Parse content of `/proc/cmdline`.
///
/// Arguments are split like the kernel does in `next_arg()`: whitespace outside
/// double quotes separates arguments, double quotes protect spaces and are
/// stripped from the result.
fn parse_kernel_params(cmdline: &str) -> KernelParams {
    let mut params = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut started = false;

    for c in cmdline.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                started = true;
            }
            c if c.is_ascii_whitespace() && !in_quote => {
                if started {
                    params.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }

    if started {
        params.push(current);
    }

    params
}

/// Get kernel params by reading from `/proc/cmdline`.
fn get_kernel_params() -> Result<KernelParams, String> {
    let content = fs::read_to_string(CMDLINE_PATH)
        .map_err(|err| format!("failed to read `{}`: {}", CMDLINE_PATH, err))?;
    Ok(parse_kernel_params(&content))
}

/// Init kernel params by reading from `/proc/cmdline`.
pub fn init_kernel_params() {
    KERNEL_PARAMS.init(get_kernel_params)
}

/// Get kernel params presence from a collected configuration.
pub fn check_kernel_params(variable: &str) -> check::CheckReturn {
    KERNEL_PARAMS.with(|kparams| {
        if kparams.contains(&variable.to_string()) {
            (check::CheckState::Pass, None)
        } else {
            (check::CheckState::Fail, None)
        }
    })
}

/// Parse a kernel version string like "6.8.0-45-generic" into (major, minor,
/// patch).
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
fn get_kernel_version() -> Result<(u32, u32, u32), String> {
    let content = fs::read_to_string(OSRELEASE_PATH)
        .map_err(|err| format!("failed to read `{}`: {}", OSRELEASE_PATH, err))?;
    match parse_kernel_version(content.trim()) {
        Some(v) => {
            log_trace!("found kernel version: {}.{}.{}", v.0, v.1, v.2);
            Ok(v)
        }
        None => Err(format!(
            "failed to parse kernel version from {}: `{}`",
            OSRELEASE_PATH,
            content.trim()
        )),
    }
}

/// Init kernel version by reading `/proc/sys/kernel/osrelease`.
pub fn init_kernel_version() {
    KERNEL_VERSION.init(get_kernel_version);
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

/// Skip check when the running kernel is not in the vulnerable range for
/// CopyFail. Vulnerable range: >= 4.14.0 and <= 6.19.12.
pub fn skip_not_vulnerable_copyfail() -> bool {
    init_kernel_version();
    match KERNEL_VERSION.try_get() {
        Ok(&(major, minor, patch)) => {
            let version = (major, minor, patch);
            !((4, 14, 0)..=(6, 19, 12)).contains(&version)
        }
        Err(err) => {
            log_error!("skipping CopyFail check: {}", err);
            true
        }
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
    fn test_parse_kernel_params() {
        assert_eq!(
            parse_kernel_params("BOOT_IMAGE=/vmlinuz ro quiet\n"),
            ["BOOT_IMAGE=/vmlinuz", "ro", "quiet"]
        );
        assert_eq!(
            parse_kernel_params(r#"mod.opt="a b c" pti=on"#),
            ["mod.opt=a b c", "pti=on"]
        );
        assert_eq!(parse_kernel_params("  a=1   \t b=2  \n"), ["a=1", "b=2"]);
        assert!(parse_kernel_params("").is_empty());
        assert!(parse_kernel_params("   \n").is_empty());
        assert_eq!(parse_kernel_params(r#""foo bar" baz"#), ["foo bar", "baz"]);
        // backslash are literals
        assert_eq!(parse_kernel_params(r#"a=b\ c"#), [r"a=b\", "c"]);
        assert_eq!(parse_kernel_params(r#"a="b c"#), ["a=b c"]);
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
