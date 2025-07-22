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

// TODO: parse apparmor profiles

use crate::{check, utils::run};

/// Ensure AppArmor is enabled.
pub fn apparmor_enabled() -> check::CheckReturn {
    if run!("aa-enabled") == "Yes" {
        (check::CheckState::Success, None)
    } else {
        (check::CheckState::Failure, None)
    }
}
