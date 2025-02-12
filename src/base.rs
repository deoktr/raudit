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

/// Check if file exist and is empty.
pub fn empty_file(path: &str) -> Result<bool, std::io::Error> {
    Ok(fs::metadata(path)?.len() == 0)
}

/// Check if file is either empty or not present.
pub fn empty_or_missing_file(path: &str) -> Result<bool, std::io::Error> {
    empty_file(path).or_else(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Ok(true),
        _ => Err(e),
    })
}
