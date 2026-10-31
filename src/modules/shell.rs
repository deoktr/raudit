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

use crate::check;
use crate::modules::base;

const PROFILE_PATH: &str = "/etc/profile";
const PROFILE_D_PATH: &str = "/etc/profile.d";

/// Ensure automatic logout from shells is configured.
///
/// Any file in `/etc/profile` or `/etc/profile.d/` setting a readonly,
/// exported `TMOUT` satisfies the check:
/// ```sh
/// TMOUT=900
/// readonly TMOUT
/// export TMOUT
/// ```
///
/// <https://wiki.archlinux.org/title/Security#Automatic_logout>
pub fn check_shell_timeout() -> check::CheckReturn {
    // TODO: add a capture group and the result is the value of TMOUT
    const PATTERN: &str = r#"TMOUT=[1-9][0-9]*\nreadonly TMOUT\nexport TMOUT"#;

    let mut paths = vec![PathBuf::from(PROFILE_PATH)];
    match fs::read_dir(PROFILE_D_PATH) {
        Ok(entries) => {
            paths.extend(
                entries
                    .filter_map(|entry| entry.ok())
                    .map(|entry| entry.path())
                    .filter(|path| path.is_file()),
            );
        }
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
            return (
                check::CheckState::Warning,
                Some(format!("failed to open `{}`: {}", PROFILE_D_PATH, err)),
            );
        }
        Err(_) => {}
    }

    for path in paths {
        let (state, _) = base::check_file_content_regex(&path.to_string_lossy(), PATTERN);
        if state == check::CheckState::Pass {
            return (check::CheckState::Pass, None);
        }
    }

    (
        check::CheckState::Fail,
        Some(format!(
            "no readonly exported TMOUT found in `{}` or `{}/`",
            PROFILE_PATH, PROFILE_D_PATH
        )),
    )
}
