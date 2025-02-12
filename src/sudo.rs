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

const SUDOERS_PATH: &str = "/etc/sudoers";

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

/// Get the sudoers configuration by reading it's config files.
pub fn init_sudoer() -> Result<SudoConfig, std::io::Error> {
    // TODO: there is an infinite amount of potential location for sudoers
    // configurations, we could try to read the content of `/etc/sudoers` and
    // search for `@includes`

    let mut paths: Vec<PathBuf> = vec![PathBuf::from(SUDOERS_PATH)];

    // get all sudoers configuration file paths
    match fs::read_dir("/etc/sudoers.d/") {
        Ok(path) => paths.extend(
            path.filter_map(|dentry| dentry.ok())
                .map(|dentry| dentry.path())
                .filter(|path| !path.is_dir())
                // files ending with `~` or containing `.` are ignored
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

    // get the configuration from all config paths
    let config: SudoConfig = paths
        .into_iter()
        .filter_map(|path| {
            match fs::read_to_string(path.clone()) {
                Ok(p) => Ok(p),
                Err(error) => {
                    println!(
                        "Error opening {}: {}",
                        path.to_string_lossy(),
                        error.to_string()
                    );
                    Err(error)
                }
            }
            .ok()
        })
        .map(|content| parse_sudoer(content))
        .flatten()
        .collect();

    Ok(config)
}

/// Get the sudoers `Defaults` configuration.
pub fn init_sudoer_defaults(config: &SudoConfig) -> SudoConfigDefaults {
    config
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
}

/// Check that no sudo rules contain `NOPASSWD`.
pub fn has_no_nopaswd(config: &SudoConfig) -> bool {
    !config.into_iter().any(|config| config.contains("NOPASSWD"))
}

/// Ensure re-authentication for privilege escalation is not disabled globally.
pub fn re_authentication_not_disabled(config: &SudoConfig) -> bool {
    !config
        .into_iter()
        .any(|config| config.contains("!authenticate"))
}
