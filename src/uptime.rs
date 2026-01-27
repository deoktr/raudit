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
use std::sync::OnceLock;

use crate::{check, log_debug, log_error};

const UPTIME_PATH: &str = "/proc/uptime";

pub static UPTIME: OnceLock<u64> = OnceLock::new();

/// Get system uptime by reading `/proc/uptime`.
fn get_uptime() -> Result<u64, String> {
    match fs::read_to_string(UPTIME_PATH)
        .map_err(|e| e.to_string())?
        .split_once(" ")
    {
        Some((uptime, _idle)) => {
            // remove the decimals before parsing to u64
            uptime[..uptime.len() - 3]
                .parse::<u64>()
                .map_err(|e| e.to_string())
        }
        None => Err("invalide uptime file format".to_string()),
    }
}

/// Init system uptime by reading `/proc/uptime`.
pub fn init_uptime() {
    if UPTIME.get().is_some() {
        return;
    }

    match get_uptime() {
        Ok(u) => {
            UPTIME.get_or_init(|| u);
            log_debug!("initialized uptime");
        }
        Err(err) => log_error!("failed to initialize uptime: {}", err),
    };
}

/// Ensure uptime is bellow the maximum allowed.
pub fn uptime_bellow(max_uptime: u64) -> check::CheckReturn {
    match UPTIME.get() {
        Some(uptime) => {
            if uptime < &max_uptime {
                return (
                    check::CheckState::Passed,
                    Some(format!("{} h", uptime / 3600)),
                );
            } else {
                (
                    check::CheckState::Failed,
                    Some(format!("{} h", uptime / 3600)),
                )
            }
        }
        None => {
            return (
                check::CheckState::Error,
                Some("uptime not initialized".to_string()),
            );
        }
    }
}
