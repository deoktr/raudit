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

use crate::check;

const LOGIN_DEFS_PATH: &str = "/etc/login.defs";

static LOGIN_DEFS_CONFIG: OnceLock<LoginDefsConfig> = OnceLock::new();

/// Login.defs configuration.
pub type LoginDefsConfig = HashMap<String, String>;

/// Parse content of `/etc/login.defs`.
fn parse_login_defs(login_defs: String) -> LoginDefsConfig {
    login_defs
        .lines()
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("#"))
        .filter_map(|line| match line.split_once(char::is_whitespace) {
            Some((key, value)) => Some((key.to_string(), value.trim_start().to_string())),
            // should never happen, don't even log it
            None => None,
        })
        .collect()
}

/// Initialized login.defs configuration by reading `/etc/login.defs`.
pub fn init_login_defs() {
    if LOGIN_DEFS_CONFIG.get().is_some() {
        return;
    }

    match fs::read_to_string(LOGIN_DEFS_PATH) {
        Ok(login_defs) => {
            LOGIN_DEFS_CONFIG.get_or_init(|| parse_login_defs(login_defs));
        }
        Err(err) => println!("Failed to initialize login defs: {}", err),
    };
}

/// Check login.defs value from a collected configuration.
pub fn get_login_defs(key: &str) -> Result<&str, String> {
    match LOGIN_DEFS_CONFIG
        .get()
        .expect("login defs not initialized")
        .get(key)
    {
        Some(val) => Ok(val),
        None => Err(format!("error getting login.defs value for {}", key)),
    }
}

/// Check login.defs value from a collected configuration.
pub fn check_login_defs(key: &str, expected: &str) -> check::CheckReturn {
    match get_login_defs(key) {
        Ok(val) => {
            if val == expected {
                (check::CheckState::Success, None)
            } else {
                (check::CheckState::Success, None)
            }
        }
        Err(err) => (check::CheckState::Failure, Some(err.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_defs() {
        let lines = parse_login_defs(
            "# HOME_MODE is used by useradd(8) and newusers(8) to set the mode for new
# home directories.
# If HOME_MODE is not set, the value of UMASK is used to create the mode.
HOME_MODE       0750

#
# Password aging controls:
#
#       PASS_MAX_DAYS   Maximum number of days a password may be used.
#       PASS_MIN_DAYS   Minimum number of days allowed between password changes.
#       PASS_WARN_AGE   Number of days warning given before a password expires.
#
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
"
            .to_string(),
        );
        assert_eq!(lines.len(), 4);
        assert!(lines.get("HOME_MODE").is_some());
        assert_eq!(lines.get("HOME_MODE").unwrap(), &"0750".to_string());
        assert!(lines.get("PASS_MAX_DAYS").is_some());
        assert_eq!(lines.get("PASS_MAX_DAYS").unwrap(), &"99999".to_string());
        assert!(lines.get("PASS_WARN_AGE").is_some());
        assert_eq!(lines.get("PASS_WARN_AGE").unwrap(), &"7".to_string());
    }
}
