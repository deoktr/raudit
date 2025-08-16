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

use std::collections::HashMap;
use std::fs;
use std::sync::OnceLock;

use crate::{check, log_error};

/// List of running process.
///
/// Collected by reading the content of the `/proc/` dir.
pub type Proc = HashMap<String, String>;

static PROCESSES: OnceLock<Proc> = OnceLock::new();

// out: HashMap<Pid, Name>
pub fn init_proc() {
    if PROCESSES.get().is_some() {
        return;
    }

    let mut output = Proc::new();

    let entries = match fs::read_dir("/proc/") {
        Ok(e) => e,
        Err(err) => {
            log_error!("failed to read \"/proc/\": {}", err);
            return;
        }
    };

    for entry in entries {
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

    PROCESSES.get_or_init(|| output);
}

/// Get the list of PID with this name.
pub fn get_pids(config: &Proc, name: &str) -> Option<Vec<String>> {
    let mut procs: Vec<String> = Vec::new();
    for (k, v) in config {
        if *v != name {
            continue;
        }
        procs.push(k.to_string());
    }

    if procs.len() > 0 { Some(procs) } else { None }
}

/// Check if a process is running from it's name.
pub fn is_running(name: &str) -> check::CheckReturn {
    let procs = match PROCESSES.get() {
        Some(kparams) => kparams,
        None => {
            return (
                check::CheckState::Error,
                Some("processes not initialized".to_string()),
            );
        }
    };

    match get_pids(procs, name) {
        Some(pids) => (check::CheckState::Passed, Some(pids.join(", "))),
        None => (check::CheckState::Failed, None),
    }
}
