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

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

/// Resolve an executable name against `$PATH`. Returns the first matching
/// absolute path, or None if the binary is not found.
pub fn which(bin: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn id_from_name(path: &str, name: &str) -> Option<u32> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let mut fields = line.splitn(4, ':');
        if fields.next()? != name {
            continue;
        }
        fields.next()?;
        return fields.next()?.parse::<u32>().ok();
    }
    None
}

/// Resolve UID from a username by reading `/etc/passwd`.
///
/// Returns `None` if the file cannot be read or the user is not found.
#[allow(dead_code)]
pub fn uid_from_name(username: &str) -> Option<u32> {
    id_from_name("/etc/passwd", username)
}

/// Resolve GID from a group name by reading `/etc/group`.
///
/// Returns `None` if the file cannot be read or the group is not found.
pub fn gid_from_name(group: &str) -> Option<u32> {
    id_from_name("/etc/group", group)
}

/// Format short duration, under an hour.
pub fn format_duration(dur: Duration) -> String {
    let total_secs = dur.as_secs_f64();
    if total_secs >= 60.0 {
        format!("{:.2} m", total_secs / 60.0)
    } else if total_secs >= 1.0 {
        format!("{:.2} s", total_secs)
    } else {
        let millis = total_secs * 1000.0;
        if millis >= 1.0 {
            format!("{:.2} ms", millis)
        } else {
            let micros = total_secs * 1_000_000.0;
            format!("{:.2} μs", micros)
        }
    }
}

/// Format text and wrap it on words at a specific width.
pub fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    let mut wrapped_lines = Vec::new();

    for line in text.split("\n") {
        let mut current_line = String::new();

        for word in line.split_whitespace() {
            if current_line.is_empty() {
                current_line.push_str(word);
            } else if current_line.len() + word.len() < max_width {
                current_line.push(' ');
                current_line.push_str(word);
            } else {
                wrapped_lines.push(current_line);
                current_line = word.to_string();
            }
        }

        if !current_line.is_empty() {
            wrapped_lines.push(current_line);
        }
    }

    wrapped_lines
}

/// Run a command without failing.
macro_rules! run {
    ($bin:tt) => {{
        let mut cmd = std::process::Command::new($bin);
        cmd.stdin(std::process::Stdio::null());
        match cmd.output() {
            Ok(output) => String::from_utf8_lossy(&output.stdout).to_string().replace("\n", ""),
            Err(_) => "".to_string(),
        }
    }};

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
