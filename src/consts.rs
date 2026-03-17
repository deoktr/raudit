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

pub const RESET_COLOR: &str = "\x1b[39m";

pub const CHK_PASS_COLOR: &str = "\x1b[32m";
pub const CHK_FAIL_COLOR: &str = "\x1b[31m";
pub const CHK_WARNING_COLOR: &str = "\x1b[36m";
pub const CHK_UNKNOWN_COLOR: &str = "\x1b[36m";

pub const SEV_INFORMATIONAL_COLOR: &str = "\x1b[34m";
pub const SEV_LOW_COLOR: &str = "\x1b[36m";
pub const SEV_MEDIUM_COLOR: &str = "\x1b[33m";
pub const SEV_HIGH_COLOR: &str = "\x1b[31m";
pub const SEV_CRITICAL_COLOR: &str = "\x1b[91m";
