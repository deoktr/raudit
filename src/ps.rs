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

use crate::{check, log_debug, log_error};

/// List of running process.
///
/// Collected by reading the content of the `/proc/` dir.
pub type Proc = HashMap<String, String>;

static PROCESSES: OnceLock<Proc> = OnceLock::new();

fn get_proc() -> Result<Proc, std::io::Error> {
    let mut output = Proc::new();

    let entries = fs::read_dir("/proc/")?;

    for entry in entries.flatten() {
        let path = entry.path();

        if !path.is_dir() {
            continue;
        }

        let pid = match entry.file_name().into_string() {
            Ok(pid) => pid,
            Err(_) => continue,
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
    Ok(output)
}

/// Init proc.
pub fn init_proc() {
    if PROCESSES.get().is_some() {
        return;
    }

    match get_proc() {
        Ok(p) => {
            PROCESSES.get_or_init(|| p);
            log_debug!("initialized proc");
        }
        Err(err) => log_error!("failed to initialize proc: {}", err),
    }
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

    if !procs.is_empty() { Some(procs) } else { None }
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

// get process flags
fn get_proc_flags(name: &str) -> Result<Vec<String>, check::CheckReturn> {
    let procs = match PROCESSES.get() {
        Some(kparams) => kparams,
        None => {
            return Err((
                check::CheckState::Error,
                Some("processes not initialized".to_string()),
            ));
        }
    };

    let pids = match get_pids(procs, name) {
        Some(pids) => pids,
        None => {
            return Err((
                check::CheckState::Error,
                Some(format!("no {} process found", name)),
            ));
        }
    };

    if pids.len() > 1 {
        return Err((
            check::CheckState::Error,
            Some(format!(
                "multiple process found with name {}: {}",
                name,
                pids.join(", ")
            )),
        ));
    }

    let path = format!("/proc/{}/cmdline", pids[0]);
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            return Err((
                check::CheckState::Error,
                Some(format!("failed to read file: {}", err)),
            ));
        }
    };

    Ok(content.split("\0").map(String::from).collect())
}

/// Get process flag value.
fn get_proc_flag_value(name: &str, flag: &str) -> Result<String, check::CheckReturn> {
    let cmd = get_proc_flags(name)?;

    for (index, item) in cmd.iter().enumerate() {
        if item.starts_with(&format!("{}=", flag)) {
            return Ok(item.trim_start_matches(&format!("{}=", flag)).to_string());
        } else if item == flag {
            if cmd.len() < index + 2 {
                return Ok(cmd[index + 1].clone());
            } else {
                return Err((
                    check::CheckState::Failed,
                    Some(format!("missing flag {} value", flag)),
                ));
            }
        }
    }

    Err((
        check::CheckState::Failed,
        Some(format!("missing flag {}", flag)),
    ))
}

/// Check if a process is running with the specified flag.
pub fn is_running_with_flag(name: &str, flag: &str) -> check::CheckReturn {
    let cmd = match get_proc_flags(name) {
        Ok(flags) => flags,
        Err(err) => return err,
    };

    if cmd.contains(&flag.to_string()) {
        (check::CheckState::Passed, None)
    } else {
        (
            check::CheckState::Failed,
            Some(format!("missing flag {}", flag)),
        )
    }
}

/// Check if a process is running without the specified flag.
pub fn is_running_without_flag(name: &str, flag: &str) -> check::CheckReturn {
    let cmd = match get_proc_flags(name) {
        Ok(flags) => flags,
        Err(err) => return err,
    };

    if !cmd.contains(&flag.to_string()) {
        (check::CheckState::Passed, None)
    } else {
        (
            check::CheckState::Failed,
            Some(format!("missing flag {}", flag)),
        )
    }
}

/// Check if a process is running with the specified flag with value.
pub fn is_running_with_flag_value(name: &str, flag: &str, value: &str) -> check::CheckReturn {
    let flag_value = match get_proc_flag_value(name, flag) {
        Ok(f) => f,
        Err(err) => return err,
    };

    if flag_value != value {
        (
            check::CheckState::Failed,
            Some(format!(
                "wrong value for flag {} {} != {}",
                flag, flag_value, value
            )),
        )
    } else {
        (check::CheckState::Passed, None)
    }
}

// TODO: add 'is_running_without_flag_value' but would need to modify function
// get_proc_flag_value since it would not matter if the flag is missing
