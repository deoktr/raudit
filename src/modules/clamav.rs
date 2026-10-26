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

// TODO: check if clamav runs periodic scans

use crate::{check, utils};

/// Ensure ClamAV is installed.
pub fn clamav_installed() -> check::CheckReturn {
    match utils::which("clamscan") {
        Some(_) => (check::CheckState::Pass, None),
        None => (
            check::CheckState::Fail,
            Some("clamscan bin was not found".to_string()),
        ),
    }
}
