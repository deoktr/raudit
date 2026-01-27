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

use std::time::Duration;

/// Format short duration, under an hour.
pub fn format_duration(dur: Duration) -> String {
    let secs = dur.as_secs();
    if secs >= 60 {
        format!("{} m", secs / 60)
    } else if secs >= 1 {
        format!("{} s", secs)
    } else if dur.as_millis() >= 1 {
        format!("{} ms", dur.as_millis())
    } else {
        format!("{} μs", dur.as_micros())
    }
}

/// Run a command without failling.
macro_rules! run {
    ($bin:tt) => {
        run!($bin,)
    };

    ($bin:tt, $($params:expr),*) => {{
        let mut cmd = std::process::Command::new($bin);
        cmd.stdin(std::process::Stdio::null());
        cmd.args(&[$($params),*]);
        match cmd.output() {
            Ok(output) => String::from_utf8_lossy(&output.stdout).to_string().replace("\n", ""),
            Err(_) => "".to_string(),
        }
    }};
}

pub(crate) use run;
