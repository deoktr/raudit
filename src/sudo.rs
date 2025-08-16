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
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::{check, log_error, log_warn};

const SUDOERS_PATH: &str = "/etc/sudoers";

static SUDO_CONFIG: OnceLock<SudoConfig> = OnceLock::new();
static SUDO_CONFIG_DEFAULTS: OnceLock<SudoConfigDefaults> = OnceLock::new();

/// List of sudo configuration.
pub type SudoConfig = Vec<String>;

/// List of sudo configuration `Defaults`.
pub type SudoConfigDefaults = Vec<String>;

/// Parse a sudo configuration file content.
fn parse_sudoer(content: String) -> SudoConfig {
    content
        .lines()
        .filter(|line| !line.starts_with("#"))
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect()
}

pub fn init_sudo() {
    init_sudoer();
    init_sudoer_defaults();
}

/// Initialize the sudoers configuration by reading it's config files.
// FIXME: if not file could be red, print an error, and don't initialize sudo
// configuration
pub fn init_sudoer() {
    // TODO: there is an infinite amount of potential location for sudoers
    // configurations, we could try to read the content of `/etc/sudoers` and
    // search for `@includes`
    if SUDO_CONFIG.get().is_some() {
        return;
    }

    let mut paths: Vec<PathBuf> = vec![PathBuf::from(SUDOERS_PATH)];

    // get all sudoers configuration file paths
    match fs::read_dir("/etc/sudoers.d/") {
        Ok(path) => paths.extend(
            path.filter_map(|dentry| dentry.ok())
                .map(|dentry| dentry.path())
                .filter(|path| !path.is_dir())
                // files ending with `~` or containing `.` are ignored, as per
                // the sudo documentation
                .filter(|path| {
                    !path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().ends_with("~"))
                })
                .filter(|path| {
                    !path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().contains("."))
                })
                .collect::<Vec<PathBuf>>(),
        ),
        // if the directory doesn't exist this is not an error, but if we don't
        // have the permissions ir should be
        // TODO: raise error in case of missing permissions
        Err(_) => (),
    };

    let mut valid_paths = paths
        .into_iter()
        .filter(|path| !path.ends_with("README"))
        .filter_map(|path| {
            match fs::read_to_string(&path) {
                Ok(p) => Ok(p),
                Err(error) => {
                    log_warn!(
                        "Failed to open {:?}: {}",
                        path.to_string_lossy(),
                        error.to_string()
                    );
                    Err(error)
                }
            }
            .ok()
        })
        .peekable();

    // check if the list of valid sudo file to parse is empty
    if !valid_paths.peek().is_some() {
        log_error!("Failed to initialize sudo configuration: No sudo file to read");
        return;
    }

    // get the configuration from all config paths
    let config: SudoConfig = valid_paths
        .into_iter()
        .map(|content| parse_sudoer(content))
        .flatten()
        .collect();

    SUDO_CONFIG.get_or_init(|| config);
}

/// Initialize the sudoers `Defaults` configuration.
pub fn init_sudoer_defaults() {
    if !SUDO_CONFIG.get().is_some() {
        return;
    }

    let sudo_config = match SUDO_CONFIG_DEFAULTS.get() {
        Some(c) => c,
        None => return,
    };

    SUDO_CONFIG_DEFAULTS.get_or_init(|| {
        sudo_config
            .into_iter()
            .filter(|config| config.starts_with("Defaults"))
            .map(|config| {
                config
                    // NOTE: we need to remove `Defaults` because some config
                    // can be `Defaults:%sudo !noexec` for example, in that case
                    // we would only consider `:%sudo !noexec` and store it as
                    // `:%sudo!noexec`
                    .replacen("Defaults", "", 1)
                    // this is an effort to make the result consistent, by
                    // removing whitespaces
                    // TODO: this may be annoying to work with, maybe match with
                    // regex instead, the current rules should be slightly
                    // updated but nothing to serious
                    .split_whitespace()
                    .collect::<Vec<&str>>()
                    .join(" ")
            })
            .map(|config| config.to_string())
            .collect()
    });
}

/// Check if sudoers default is present
pub fn check_sudo_defaults(defaults: &str) -> check::CheckReturn {
    let sudo_defaults = match SUDO_CONFIG_DEFAULTS.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("sudo configuration defaults not initialized".to_string()),
            );
        }
    };

    if sudo_defaults.contains(&defaults.to_string()) {
        (check::CheckState::Passed, None)
    } else {
        (check::CheckState::Failed, None)
    }
}

/// Check that no sudo rules contain `NOPASSWD`.
pub fn check_has_no_nopaswd() -> check::CheckReturn {
    let sudo_config = match SUDO_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("sudo configuration not initialized".to_string()),
            );
        }
    };

    let g: Vec<String> = sudo_config
        .iter()
        .filter(|config| config.contains("NOPASSWD"))
        .map(|config| config.clone())
        .collect();

    if g.len() != 0 {
        (check::CheckState::Failed, Some(g.join(", ")))
    } else {
        (check::CheckState::Passed, None)
    }
}

/// Ensure re-authentication for privilege escalation is not disabled globally.
pub fn check_re_authentication_not_disabled() -> check::CheckReturn {
    let sudo_config = match SUDO_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("sudo configuration not initialized".to_string()),
            );
        }
    };

    let g: Vec<String> = sudo_config
        .iter()
        .filter(|config| config.contains("!authenticate"))
        .map(|config| config.clone())
        .collect();

    if g.len() != 0 {
        (check::CheckState::Failed, Some(g.join(", ")))
    } else {
        (check::CheckState::Passed, None)
    }
}
