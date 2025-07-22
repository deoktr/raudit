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

// TODO: file permission check
// TODO: file owner check
// TODO: file content regex

use std::fs;
use std::path::Path;

use crate::check;

/// Check if file is either empty or not present.
pub fn empty_or_missing_file(path: &str) -> check::CheckReturn {
    match fs::metadata(path) {
        Ok(meta) => {
            if meta.len() == 0 {
                (check::CheckState::Success, None)
            } else {
                (
                    check::CheckState::Failure,
                    Some("file not empty".to_string()),
                )
            }
        }
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => (check::CheckState::Success, None),
            _ => (check::CheckState::Error, Some(err.to_string())),
        },
    }
}

/// Check if file exist and is empty.
pub fn empty_file(path: &str) -> check::CheckReturn {
    match fs::metadata(path) {
        Ok(meta) => {
            if meta.len() == 0 {
                (check::CheckState::Success, None)
            } else {
                (
                    check::CheckState::Failure,
                    Some("file not empty".to_string()),
                )
            }
        }
        Err(err) => (check::CheckState::Error, Some(err.to_string())),
    }
}

/// Check if a directory exist.
pub fn directory_exist(path: &str) -> bool {
    let p = Path::new(path);
    p.exists() && p.is_dir()
}
