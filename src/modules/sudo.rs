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

use std::path::PathBuf;
use std::{fs, io};

use crate::check::{self, State};
use crate::utils;

const SUDOERS_PATH: &str = "/etc/sudoers";
const SUDOERS_DIR_PATH: &str = "/etc/sudoers.d";

static SUDO_CONFIG: State<SudoConfig> = State::new("sudo config");
static SUDO_CONFIG_DEFAULTS: State<SudoConfigDefaults> = State::new("sudo config defaults");

/// List of sudo configuration.
type SudoConfig = Vec<String>;

/// List of sudo configuration `Defaults`.
type SudoConfigDefaults = Vec<String>;

/// Skip when sudo is not installed.
pub fn skip_no_sudo() -> bool {
    utils::which("sudo").is_none() && utils::which("sudo-rs").is_none()
}

/// Skip when sudo-rs is installed, hard to tell which one between sudo and
/// sudo-rs would be used, this is a quick skip.
pub fn skip_sudo_rs() -> bool {
    utils::which("sudo-rs").is_some()
}

/// Parse a sudo configuration file content.
fn parse_sudoer(content: String) -> SudoConfig {
    content
        .lines()
        .filter(|line| !line.starts_with("#"))
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect()
}

/// Initialize the sudoers configuration by reading it's config files.
pub fn get_sudoer() -> Result<SudoConfig, String> {
    let mut paths: Vec<PathBuf> = vec![PathBuf::from(SUDOERS_PATH)];

    // get all sudoers configuration file paths
    match fs::read_dir(SUDOERS_DIR_PATH) {
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
                // the `README` file shipped in the directory is not a
                // configuration file
                .filter(|path| {
                    !path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy() == "README")
                })
                .collect::<Vec<PathBuf>>(),
        ),
        // if the directory doesn't exist this is not an error, but if we don't
        // have the permissions it is
        Err(e) => match e.kind() {
            io::ErrorKind::NotFound => (),
            _ => {
                return Err(format!("failed to open {}: {}", SUDOERS_DIR_PATH, e));
            }
        },
    };

    let mut contents: Vec<String> = Vec::new();

    for path in paths {
        match fs::read_to_string(&path) {
            Ok(content) => contents.push(content),
            Err(err) => {
                return Err(format!(
                    "failed to open {}: {}",
                    path.to_string_lossy(),
                    err
                ));
            }
        }
    }

    // check if the list of valid sudo file to parse is empty
    if contents.is_empty() {
        return Err("no sudo file to read".to_string());
    }

    // get the configuration from all config paths
    Ok(contents.into_iter().flat_map(parse_sudoer).collect())
}

/// Initialize the sudoers configuration by reading it's config files.
pub fn init_sudoer() {
    SUDO_CONFIG.init(get_sudoer);
}

/// Initialize the sudoers `Defaults` configuration.
pub fn get_sudoer_defaults() -> Result<SudoConfigDefaults, String> {
    let sudo_config = match SUDO_CONFIG.try_get() {
        Ok(c) => c,
        Err(err) => {
            return Err(err.to_string());
        }
    };

    Ok(sudo_config
        .iter()
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
        .collect())
}

pub fn init_sudoer_defaults() {
    SUDO_CONFIG_DEFAULTS.init(get_sudoer_defaults);
}

pub fn init_sudo() {
    init_sudoer();
    init_sudoer_defaults();
}

/// Check if sudoers default is present
pub fn check_sudo_defaults(defaults: &str) -> check::CheckReturn {
    SUDO_CONFIG_DEFAULTS.with(|sudo_defaults| {
        if sudo_defaults.contains(&defaults.to_string()) {
            (check::CheckState::Pass, None)
        } else {
            (check::CheckState::Fail, None)
        }
    })
}

/// Check that no sudo rules contain `NOPASSWD`.
pub fn check_has_no_nopaswd() -> check::CheckReturn {
    SUDO_CONFIG.with(|sudo_config| {
        let g: Vec<String> = sudo_config
            .iter()
            .filter(|config| config.contains("NOPASSWD"))
            .cloned()
            .collect();

        if !g.is_empty() {
            (check::CheckState::Fail, Some(g.join(", ")))
        } else {
            (check::CheckState::Pass, None)
        }
    })
}

/// Ensure re-authentication for privilege escalation is not disabled globally.
pub fn check_re_authentication_not_disabled() -> check::CheckReturn {
    SUDO_CONFIG.with(|sudo_config| {
        let g: Vec<String> = sudo_config
            .iter()
            .filter(|config| config.contains("!authenticate"))
            .cloned()
            .collect();

        if !g.is_empty() {
            (check::CheckState::Fail, Some(g.join(", ")))
        } else {
            (check::CheckState::Pass, None)
        }
    })
}
