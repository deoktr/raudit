/*
 * rAudit, a Linux security auditing toolkit
 * Copyright (C) 2024 - 2026  deoktr
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
use std::io;

use crate::check;

/// Ensure Secure Boot is enabled.
///
/// Try to read the efivarfs entry for Secure Boot from:
/// `/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c`.
pub fn is_secureboot_enabled() -> check::CheckReturn {
    match fs::read_to_string(
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    ) {
        Ok(content) => {
            // The file contains binary data; the last byte indicates the status
            // 1 = enabled, 0 = disabled
            let bytes = content.into_bytes();
            if bytes.len() >= 5 {
                if (bytes[4] == 1) {
                    (check::CheckState::Pass, None)
                } else {
                    (check::CheckState::Fail, None)
                }
            } else {
                (
                    check::CheckState::Warning,
                    Some("Invalid SecureBoot variable format".to_string()),
                )
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // if the file doesn't exist then Secure Boot is not available
            (check::CheckState::Fail, None)
        }
        Err(e) => (check::CheckState::Warning, Some(e.to_string())),
    }
}
