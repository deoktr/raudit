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
use crate::modules::base;
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

/// Strip a trailing comment, `#` opens a comment unless inside double quotes.
fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Parse a sudo configuration file content.
///
/// Joins the line continuations (`\` at the end of a line), strips the comments
/// and drops the empty lines.
fn parse_sudoer(content: String) -> SudoConfig {
    content
        .replace("\\\n", "")
        .lines()
        .map(strip_comment)
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect()
}

/// Files of `/etc/sudoers.d` that sudo actually reads.
///
/// Files ending with `~` or containing `.` are ignored, as per the sudo
/// documentation, the `README` file shipped in the directory is not a
/// configuration file either.
fn sudoers_d_files() -> Result<Vec<PathBuf>, String> {
    match fs::read_dir(SUDOERS_DIR_PATH) {
        Ok(path) => Ok(path
            .filter_map(|dentry| dentry.ok())
            .map(|dentry| dentry.path())
            .filter(|path| !path.is_dir())
            .filter(|path| {
                !path.file_name().is_some_and(|name| {
                    name.to_string_lossy().ends_with("~")
                        || name.to_string_lossy().contains(".")
                        || name.to_string_lossy() == "README"
                })
            })
            .collect::<Vec<PathBuf>>()),
        // if the directory doesn't exist this is not an error, but if we don't
        // have the permissions it is
        Err(e) => match e.kind() {
            io::ErrorKind::NotFound => Ok(Vec::new()),
            _ => Err(format!("failed to open {}: {}", SUDOERS_DIR_PATH, e)),
        },
    }
}

/// Initialize the sudoers configuration by reading it's config files.
pub fn get_sudoer() -> Result<SudoConfig, String> {
    let mut paths: Vec<PathBuf> = vec![PathBuf::from(SUDOERS_PATH)];

    // get all sudoers configuration file paths
    paths.extend(sudoers_d_files()?);

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

/// Normalize a sudoers `Defaults` line into individual options.
///
/// Each option of the line becomes its own entry: the whitespaces are
/// collapsed, the spaces around `=` are removed (`umask = 0027` becomes
/// `umask=0027`) and the comma separated lists are split (`Defaults
/// noexec,use_pty` yields two entries). Scoped defaults (`Defaults:%sudo
/// !noexec`, `Defaults>root use_pty`, ...) keep their scope prefix, they only
/// apply to a subset of the invocations and must not satisfy a check looking
/// for the global option.
fn parse_defaults_line(config: &str) -> Vec<String> {
    config
        .replacen("Defaults", "", 1)
        .split(',')
        .map(|option| {
            option
                .split_whitespace()
                .collect::<Vec<&str>>()
                .join(" ")
                .replace(" = ", "=")
                .replace(" =", "=")
                .replace("= ", "=")
        })
        .filter(|option| !option.is_empty())
        .collect()
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
        .flat_map(|config| parse_defaults_line(config))
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
            (
                check::CheckState::Fail,
                Some(format!("`Defaults {}` is not present", defaults)),
            )
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

/// Ensure the sudoers `Defaults secure_path` is set.
pub fn check_secure_path_set() -> check::CheckReturn {
    SUDO_CONFIG_DEFAULTS.with(|defaults| {
        let set = defaults.iter().any(|defaults| {
            defaults
                .split_whitespace()
                .any(|token| token.starts_with("secure_path="))
        });

        if set {
            (check::CheckState::Pass, None)
        } else {
            (
                check::CheckState::Fail,
                Some("`Defaults secure_path` is not present".to_string()),
            )
        }
    })
}

fn check_sudoers_d_files<F>(check: F) -> check::CheckReturn
where
    F: Fn(&str) -> check::CheckReturn,
{
    let files = match sudoers_d_files() {
        Ok(files) => files,
        Err(err) => return (check::CheckState::Warning, Some(err)),
    };

    for file in files {
        let path = file.to_string_lossy();
        let (state, message) = check(path.as_ref());
        if state != check::CheckState::Pass {
            return match message {
                Some(message) => (state, Some(format!("file `{}`: {}", path, message))),
                None => (state, None),
            };
        }
    }

    (check::CheckState::Pass, None)
}

/// Check the permissions of the sudoers drop-in files sudo reads.
///
/// Applies the same file filter as the parser: the files sudo ignores (distro
/// `README`, dot files, `~` backups) cannot influence sudo, auditing their
/// permissions produces false positives.
pub fn check_sudoers_d_files_permission() -> check::CheckReturn {
    check_sudoers_d_files(|path| base::check_file_permission_or_stricter(path, 0o440))
}

/// Check the owner of the sudoers drop-in files sudo reads.
pub fn check_sudoers_d_files_owner() -> check::CheckReturn {
    check_sudoers_d_files(|path| base::check_file_owner_id(path, 0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_comment() {
        assert_eq!(
            strip_comment("Defaults noexec # policy"),
            "Defaults noexec "
        );
        assert_eq!(strip_comment("# full comment"), "");
        assert_eq!(strip_comment("Defaults noexec"), "Defaults noexec");
        // a `#` inside double quotes is not a comment
        assert_eq!(
            strip_comment("Defaults lecture_file=\"/etc/sudo#lecture\""),
            "Defaults lecture_file=\"/etc/sudo#lecture\""
        );
    }

    #[test]
    fn test_parse_sudoer() {
        let config = parse_sudoer(
            "# a comment
root ALL=(ALL) ALL  # trailing comment

Defaults noexec
Defaults secure_path=\"/usr/bin:\\
/usr/sbin\"
"
            .to_string(),
        );

        assert_eq!(
            config,
            vec![
                "root ALL=(ALL) ALL".to_string(),
                "Defaults noexec".to_string(),
                "Defaults secure_path=\"/usr/bin:/usr/sbin\"".to_string(),
            ]
        );
    }

    #[test]
    fn test_parse_defaults_line() {
        assert_eq!(parse_defaults_line("Defaults noexec"), vec!["noexec"]);
        assert_eq!(
            parse_defaults_line("Defaults requiretty,ignore_dot"),
            vec!["requiretty", "ignore_dot"]
        );
        assert_eq!(
            parse_defaults_line("Defaults umask = 0027"),
            vec!["umask=0027"]
        );
        assert_eq!(
            parse_defaults_line("Defaults umask =0027"),
            vec!["umask=0027"]
        );
        assert_eq!(
            parse_defaults_line("Defaults logfile=\"/var/log/sudo.log\""),
            vec!["logfile=\"/var/log/sudo.log\""]
        );
        // scoped defaults keep their scope, they must not match a global
        // expectation
        assert_eq!(
            parse_defaults_line("Defaults:%sudo !noexec"),
            vec![":%sudo !noexec"]
        );
        assert_eq!(
            parse_defaults_line("Defaults>root use_pty"),
            vec![">root use_pty"]
        );
        assert_eq!(parse_defaults_line("Defaults"), Vec::<String>::new());
    }
}
