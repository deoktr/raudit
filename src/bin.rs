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
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::{check, log_debug};

// TODO: add a customisable whitelist to avoid matching sudo and other common
// executables?

/// Get the list of SUID or SGID bin files.
fn get_sid_bin(directory: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();

    let mut dirs_to_check = vec![directory.to_path_buf()];

    while let Some(current_dir) = dirs_to_check.pop() {
        let Ok(entries) = fs::read_dir(&current_dir) else {
            continue;
        };

        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };

            let path = entry.path();

            if path.is_dir() {
                dirs_to_check.push(path.clone());
                continue;
            } else if !path.is_file() {
                continue;
            }

            if let Ok(metadata) = fs::metadata(&path) {
                let mode = metadata.mode();

                // is executable && is suid or sgid
                if mode & 0o111 != 0 && mode & 0o6000 != 0 {
                    log_debug!("sid bin: {:?}", path);
                    results.push(path);
                }
            }
        }
    }

    results
}

/// Check if a directory contains any executable file has a SUID or SGID.
///
/// Set ID files should be carefully analysed and there numbers should be
/// reduced to a minimum.
pub fn check_sid_bin(root_str: &str) -> check::CheckReturn {
    let root = Path::new(root_str);
    let sid_bin = get_sid_bin(root);

    if !sid_bin.is_empty() {
        (
            check::CheckState::Failed,
            Some(format!(
                "found {}, enable debug logging to see the list",
                sid_bin.len()
            )),
        )
    } else {
        (check::CheckState::Passed, None)
    }
}
