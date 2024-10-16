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

use std::collections::HashMap;
use std::fs;

/// List of running process.
///
/// Collected by reading the content of the `/proc/` dir.
pub type Proc = HashMap<String, String>;

// out: HashMap<Pid, Name>
pub fn init_proc() -> Result<HashMap<String, String>, std::io::Error> {
    let mut output = Proc::new();

    for entry in fs::read_dir("/proc/")? {
        if let Ok(entry) = entry {
            let path = entry.path();

            if !path.is_dir() {
                continue;
            }

            let pid = match entry.file_name().into_string() {
                Ok(pid) => pid,
                Err(_error) => continue,
            };

            if !pid.chars().all(char::is_numeric) {
                continue;
            }

            let mut name: String = String::new();

            match fs::read_to_string(format!("/proc/{pid}/status")) {
                Ok(status) => {
                    for line in status.lines() {
                        if line.starts_with("Name:") {
                            name = line.replace("Name:\t", "").to_string();
                            break;
                        }
                    }
                }
                Err(_) => continue,
            };
            output.insert(pid, name);
        }
    }
    Ok(output)
}

/// Get the list of PID with this name.
pub fn get_pids(config: &'static Proc, name: String) -> Option<Vec<String>> {
    let mut procs: Vec<String> = Vec::new();
    for (k, v) in config {
        if *v != name {
            continue;
        }
        procs.push(k.to_string());
    }

    if procs.len() > 0 {
        Some(procs)
    } else {
        None
    }
}

/// Check if a process is running from it's name.
pub fn is_running(config: &'static Proc, name: String) -> bool {
    match get_pids(config, name) {
        Some(_) => true,
        None => false,
    }
}
