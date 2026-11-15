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
use std::process;
use std::process::Stdio;

use crate::ps;
use crate::utils;
use raudit_core::check::State;
use raudit_core::{check, log_debug, log_error};

static SSHD_CONFIG: State<SshdConfig> = State::new("sshd config");
static SSHD_VERSION: State<SshdVersion> = State::new("sshd version");

/// OpenSSH (sshd) configuration.
type SshdConfig = HashMap<String, String>;

/// OpenSSH (sshd) version, as `(major, minor, patch)`.
type SshdVersion = (u32, u32, u32);

/// Skip if sshd is not installed, or installed but not running.
pub fn skip_no_sshd() -> bool {
    if utils::which("sshd").is_none() {
        return true;
    }

    ps::init_proc();
    match ps::is_running("sshd") {
        Ok(is_running) => !is_running,
        Err(err) => {
            log_error!("failed to verify that sshd is running: {}", err);
            false
        }
    }
}

/// Parse OpenSSH configuration from `sshd -T` command stdout.
fn parse_sshd_config(sshd_t: String) -> SshdConfig {
    sshd_t
        .lines()
        .filter_map(|line| {
            line.to_string()
                .split_once(" ")
                // normalize the key to lowercase, it was the default before
                // version 10.6 something like that, after it was mixed case,
                // like in the configuration
                .map(|(key, value)| (key.to_lowercase(), value.to_string()))
        })
        .collect()
}

/// Get the sshd (OpenSSH) configuration by running `sshd -T`.
fn get_sshd_config() -> Result<SshdConfig, String> {
    let mut cmd = process::Command::new("sshd");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["-T"]);

    let output = cmd
        .output()
        .map_err(|err| format!("failed to run `sshd -T`: {}", err))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();

        return Err(if stderr.is_empty() {
            format!("`sshd -T` {}", output.status)
        } else {
            format!("`sshd -T` {}: {}", output.status, stderr)
        });
    }

    Ok(parse_sshd_config(
        String::from_utf8_lossy(&output.stdout).to_string(),
    ))
}

/// Init the sshd (OpenSSH) configuration by running `sshd -T`.
pub fn init_sshd_config() {
    SSHD_CONFIG.init(get_sshd_config);
}

/// Parse the sshd (OpenSSH) version output.
///
/// Example format:
/// `OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026`
fn parse_sshd_version(version_string: &str) -> Option<SshdVersion> {
    let version_part = version_string.split_whitespace().next()?;

    let version_numbers = version_part.strip_prefix("OpenSSH_")?;

    let parts: Vec<&str> = version_numbers.split('p').collect();
    if parts.len() != 2 {
        return None;
    }

    let major_minor: Vec<&str> = parts[0].split('.').collect();
    if major_minor.len() != 2 {
        return None;
    }

    let major: u32 = major_minor[0].parse().ok()?;
    let minor: u32 = major_minor[1].parse().ok()?;
    // the patch level may be directly followed by a comma and the crypto
    // library, ex: `OpenSSH_9.6p1, OpenSSL 3.0.13`
    let patch: u32 = parts[1]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()?;

    log_debug!("found sshd version: {}.{}.{}", major, minor, patch);

    Some((major, minor, patch))
}

/// Get the sshd (OpenSSH) version by running `sshd -V`.
fn get_sshd_version() -> Result<SshdVersion, String> {
    let mut cmd = process::Command::new("sshd");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["-V"]);

    let output = cmd
        .output()
        .map_err(|err| format!("failed to run `sshd -V`: {}", err))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();

        return Err(if stderr.is_empty() {
            format!("`sshd -V` {}", output.status)
        } else {
            format!("`sshd -V` {}: {}", output.status, stderr)
        });
    }

    // `sshd -V` writes the version to stderr, but some wrappers or future
    // versions may use stdout, so accept either.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    parse_sshd_version(&stdout)
        .or_else(|| parse_sshd_version(&stderr))
        .ok_or_else(|| {
            let output = if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            };
            format!("failed to parse `sshd -V` output: `{}`", output)
        })
}

/// Init the sshd (OpenSSH) version by running `sshd -V`.
pub fn init_sshd_version() {
    SSHD_VERSION.init(get_sshd_version);
}

/// Version of the installed OpenSSH server, as `(major, minor, patch)`.
///
/// Collected on first use, so other modules can compare the running sshd with
/// the release that introduced or removed an option without declaring a
/// dependency on [init_sshd_version].
pub fn sshd_version() -> Result<SshdVersion, String> {
    init_sshd_version();
    SSHD_VERSION.try_get().copied()
}

/// Skip a check when the installed OpenSSH is older than `version`.
pub fn skip_sshd_before(version: SshdVersion) -> bool {
    match is_sshd_version_before(version) {
        Ok(before) => before,
        Err(err) => {
            log_debug!("sshd version not available, keeping the check: {err}");
            false
        }
    }
}

/// Skip a check when the installed OpenSSH is `version` or newer.
///
/// No sshd check is currently limited to older releases, but this completes
/// the version skip API next to [`skip_sshd_before`].
#[allow(dead_code)]
pub fn skip_sshd_since(version: SshdVersion) -> bool {
    match is_sshd_version_since(version) {
        Ok(since) => since,
        Err(err) => {
            log_debug!("sshd version not available, keeping the check: {err}");
            false
        }
    }
}

/// Check whether the installed OpenSSH is older than `compared`.
pub fn is_sshd_version_before(compared: SshdVersion) -> Result<bool, String> {
    Ok(sshd_version()? < compared)
}

/// Check whether the installed OpenSSH is `compared` or newer.
pub fn is_sshd_version_since(compared: SshdVersion) -> Result<bool, String> {
    Ok(sshd_version()? >= compared)
}

/// Get sshd configuration value from a collected configuration.
pub fn get_sshd_config_value(key_upper: &str) -> Result<String, String> {
    // command `sshd -T` outputs configuration to lowercase
    let kl = key_upper.to_lowercase();
    let key = kl.as_str();
    match SSHD_CONFIG.try_get()?.get(key) {
        Some(val) => Ok(val.to_string()),
        None => Err(format!("`{}` not found in sshd configuration", key)),
    }
}

/// Get sshd configuration value from a collected configuration.
pub fn check_sshd_config(key_upper: &str, value: &str) -> check::CheckReturn {
    // command `sshd -T` outputs configuration to lowercase
    let kl = key_upper.to_lowercase();
    let key = kl.as_str();
    SSHD_CONFIG.with(|sshd_config| match sshd_config.get(key) {
        Some(val) => {
            if val == value {
                (check::CheckState::Pass, None)
            } else {
                (
                    check::CheckState::Fail,
                    Some(format!("`{}` != `{}`", val, value)),
                )
            }
        }
        None => (check::CheckState::Fail, None),
    })
}

/// Check the `subsystem sftp` line reported by `sshd -T` for the logging
/// options, whatever the sftp-server path is.
///
/// The path of `sftp-server` is distro dependent, and `internal-sftp` is just
/// as valid, so only the subsystem name and the `-f`/`-l` options are compared.
pub fn check_sshd_sftp_subsystem(facility: &str, level: &str) -> check::CheckReturn {
    SSHD_CONFIG.with(|sshd_config| match sshd_config.get("subsystem") {
        Some(val) => check_sftp_subsystem_value(val, facility, level),
        None => (
            check::CheckState::Fail,
            Some("`subsystem` not set, not reported by `sshd -T`".to_string()),
        ),
    })
}

fn check_sftp_subsystem_value(val: &str, facility: &str, level: &str) -> check::CheckReturn {
    let mut parts = val.split_whitespace();

    if parts.next() != Some("sftp") {
        return (
            check::CheckState::Fail,
            Some(format!("`{}` is not the sftp subsystem", val)),
        );
    }

    match parts.next() {
        Some(cmd) if cmd == "internal-sftp" || cmd.ends_with("/sftp-server") => {}
        _ => {
            return (
                check::CheckState::Fail,
                Some(format!(
                    "`{}` does not run sftp-server or internal-sftp",
                    val
                )),
            );
        }
    }

    let args: Vec<&str> = parts.collect();
    let option = |flag: &str| -> Option<&str> {
        args.iter()
            .position(|arg| *arg == flag)
            .and_then(|i| args.get(i + 1).copied())
    };

    let mut errors = Vec::new();
    for (flag, expected) in [("-f", facility), ("-l", level)] {
        match option(flag) {
            Some(found) if found.eq_ignore_ascii_case(expected) => {}
            Some(found) => errors.push(format!("`{} {}` != `{} {}`", flag, found, flag, expected)),
            None => errors.push(format!("`{} {}` missing", flag, expected)),
        }
    }

    if errors.is_empty() {
        (check::CheckState::Pass, None)
    } else {
        (check::CheckState::Fail, Some(errors.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sshd_version() {
        assert_eq!(
            parse_sshd_version("OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026"),
            Some((10, 2, 1))
        );
        assert_eq!(
            parse_sshd_version("OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024"),
            Some((9, 6, 1))
        );
        assert_eq!(
            parse_sshd_version("OpenSSH_8.9p1, OpenSSL 3.0.16 5 Aug 2025"),
            Some((8, 9, 1))
        );

        assert_eq!(parse_sshd_version(""), None);
        assert_eq!(parse_sshd_version("not openssh"), None);
        assert_eq!(parse_sshd_version("OpenSSH_9.6"), None);
        assert_eq!(parse_sshd_version("OpenSSH_9p1"), None);
    }
}
