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

use crate::utils;

/// Skip when no cron daemon is installed (no cron or crond binary).
pub fn skip_no_cron() -> bool {
    utils::which("cron").is_none() && utils::which("crond").is_none()
}

/// Skip when anacron is not installed.
pub fn skip_no_anacron() -> bool {
    utils::which("anacron").is_none()
}
