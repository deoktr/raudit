/*
 * rAudit, a Linux security auditing toolkit
 * Copyright (C) 2024  deoktr
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
use std::sync::OnceLock;

const UPTIME_PATH: &str = "/proc/uptime";

pub static UPTIME: OnceLock<u64> = OnceLock::new();

/// Init system uptime by reading `/proc/uptime`.
pub fn init_uptime() -> Result<(), std::io::Error> {
    let content = fs::read_to_string(UPTIME_PATH)?;
    match content.split_once(" ") {
        Some((uptime, _idle)) => {
            // remove the decimals before parsing to u64
            match uptime[..uptime.len() - 3].parse::<u64>() {
                Ok(u) => {
                    UPTIME.get_or_init(|| u);
                    ()
                }
                // should never happen, don't even log it
                Err(_) => (),
            }
        }
        None => (),
    };
    Ok(())
}
