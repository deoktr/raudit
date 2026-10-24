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

use crate::check::{self, State};

const UPTIME_PATH: &str = "/proc/uptime";

static UPTIME: State<u64> = State::new("uptime");

/// Get system uptime by reading `/proc/uptime`.
fn get_uptime() -> Result<u64, String> {
    let content = fs::read_to_string(UPTIME_PATH)
        .map_err(|err| format!("failed to read {}: {}", UPTIME_PATH, err))?;

    let Some((uptime, _idle)) = content.split_once(" ") else {
        return Err(format!(
            "invalid {} file format: {:?}",
            UPTIME_PATH,
            content.trim()
        ));
    };

    // remove the decimals before parsing to u64
    let seconds = uptime
        .split_once(".")
        .map(|(seconds, _decimals)| seconds)
        .unwrap_or(uptime);

    seconds.parse::<u64>().map_err(|err| {
        format!(
            "failed to parse {} value {:?}: {}",
            UPTIME_PATH, uptime, err
        )
    })
}

/// Init system uptime by reading `/proc/uptime`.
pub fn init_uptime() {
    UPTIME.init(get_uptime);
}

/// Ensure uptime is bellow the maximum allowed.
pub fn uptime_bellow(max_uptime: u64) -> check::CheckReturn {
    UPTIME.with(|uptime| {
        if uptime < &max_uptime {
            (
                check::CheckState::Pass,
                Some(format!("{} h", uptime / 3600)),
            )
        } else {
            (
                check::CheckState::Fail,
                Some(format!("{} h", uptime / 3600)),
            )
        }
    })
}
