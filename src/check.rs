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

use crate::{config, consts};

use once_cell::sync::Lazy;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fmt::{Display, Formatter, Result};
use std::sync::Mutex;

pub type CheckReturn = (CheckState, Option<String>);
type CheckFunc = fn() -> CheckReturn;
type DependencyFunc = fn() -> ();

static CHECKS: Lazy<Mutex<Vec<Check>>> = Lazy::new(|| Mutex::new(Vec::new()));

#[derive(PartialEq)]
pub enum CheckState {
    /// check passed
    Success,
    /// check failed
    Failure,
    /// execution error
    Error,
    /// yet to execute
    Waiting,
}

/// Check is a verification to perform on the host.
pub struct Check {
    // TODO: convert to String to &str to increase performance?
    /// ID of the check, can be used to filter the list
    id: String,
    /// Title shown in the check list
    title: String,
    /// List of tags, can be used to filter the list
    tags: Vec<String>,

    /// Message to give result information
    message: Option<String>,
    /// State of the check
    state: CheckState,

    /// Check function
    check: CheckFunc,
    /// List of dependencies to run before the check
    dependencies: Vec<DependencyFunc>,
}

/// Print list of checks, with option to skip successful checks.
pub fn print_checks(skip_success: bool) {
    let checks = CHECKS.lock().unwrap();
    for check in checks.iter() {
        if skip_success && check.state == CheckState::Success {
            continue;
        }
        println!("{}", check);
    }
}

/// Print list of available tags.
pub fn print_tags() {
    let checks = CHECKS.lock().unwrap();
    let mut tags: Vec<String> = vec![];
    for check in checks.iter() {
        for tag in check.tags.iter() {
            if tags.contains(&tag) {
                continue;
            }
            tags.push(tag.clone());
        }
    }
    println!("Available tags: {}.", tags.join(", "));
}

/// Print list of available ID prefixes.
pub fn print_id_prefixes() {
    let checks = CHECKS.lock().unwrap();
    let mut prefixes: Vec<String> = vec![];
    for check in checks.iter() {
        let prefix = match check.id.split_once("_") {
            Some((prefix, _)) => prefix.to_string(),
            None => continue,
        };
        if prefixes.contains(&prefix) {
            continue;
        }
        prefixes.push(prefix.clone());
    }
    println!("Available prefixes: {}.", prefixes.join(", "));
}

/// Run checks in sequence.
pub fn run_checks() {
    let mut checks = CHECKS.lock().unwrap();
    for check in checks.iter_mut() {
        check.run();
    }
}

/// Run checks in parallel.
pub fn par_run_checks() {
    let mut checks = CHECKS.lock().unwrap();

    // use rayon to run checks in parallel
    checks.par_iter_mut().for_each(|check| check.run());
}

/// Filter checks by their tags.
pub fn filter_tags(tags: Vec<String>) {
    if tags.len() == 0 {
        return;
    }

    let mut checks = CHECKS.lock().unwrap();
    checks.retain(|check| tags.iter().any(|tag| check.tags.contains(tag)));
}

/// Filter checks by their ID prefix.
pub fn filter_id(prefixes: Vec<String>) {
    if prefixes.len() == 0 {
        return;
    }

    let mut checks = CHECKS.lock().unwrap();
    checks.retain(|check| prefixes.iter().any(|prefix| check.id.starts_with(prefix)));
}

/// Run dependencies in sequence.
pub fn run_dependencies() {
    let checks = CHECKS.lock().unwrap();
    let mut unique_deps: HashSet<DependencyFunc> = HashSet::new();

    for check in checks.iter() {
        for dep in &check.dependencies {
            unique_deps.insert(*dep);
        }
    }

    unique_deps.iter().for_each(|dep| dep());
}

/// Run dependencies in parallel.
pub fn par_run_dependencies() {
    let checks = CHECKS.lock().unwrap();
    let mut unique_deps: HashSet<DependencyFunc> = HashSet::new();

    for check in checks.iter() {
        for dep in &check.dependencies {
            unique_deps.insert(*dep);
        }
    }

    unique_deps.par_iter().for_each(|dep| dep());
}

impl Check {
    fn run(&mut self) {
        let (state, message) = (self.check)();
        self.state = state;
        self.message = message;
    }
}

impl Display for Check {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let out = format!(
            "[{}] {}{}",
            self.id,
            self.title,
            match &self.message {
                Some(m) => format!(" ({})", m),
                None => "".to_string(),
            }
        );

        let message = if config::is_colored_output_enabled() {
            match self.state {
                CheckState::Success => {
                    format!("{}{}{}", consts::SUCCESS_COLOR, out, consts::RESET_COLOR)
                }
                CheckState::Failure => {
                    format!("{}{}{}", consts::FAILURE_COLOR, out, consts::RESET_COLOR)
                }
                CheckState::Error => {
                    format!("{}{}{}", consts::ERROR_COLOR, out, consts::RESET_COLOR)
                }
                CheckState::Waiting => format!(
                    "{}{} !NOT CHECKED!{}",
                    consts::WAITING_COLOR,
                    out,
                    consts::RESET_COLOR
                ),
            }
        } else {
            match self.state {
                CheckState::Success => format!("PASSED {}", out),
                CheckState::Failure => format!("FAILED {}", out),
                CheckState::Error => format!("ERROR {}", out),
                CheckState::Waiting => format!("N/A {} !NOT CHECKED!", out),
            }
        };

        write!(f, "{}", message)
    }
}

/// Helper function to register a new check.
///
/// Adding a new check only makes it available, it could be filtered out before
/// execution.
pub fn add_check(
    id: &str,
    title: &str,
    tags: Vec<&str>,
    check: CheckFunc,
    dependencies: Vec<DependencyFunc>,
) {
    let mut checks = CHECKS.lock().unwrap();
    checks.push(Check {
        id: id.to_string(),
        title: title.to_string(),
        state: CheckState::Waiting,
        check,
        message: None,
        dependencies,
        tags: tags.iter().map(|t| t.to_string()).collect(),
    });
}

#[derive(Default)]
pub struct CheckListStats {
    total: i32,
    success: i32,
    failure: i32,
    error: i32,
    waiting: i32,
}

pub fn get_stats() -> CheckListStats {
    let checks = CHECKS.lock().unwrap();

    let mut stats = CheckListStats::default();

    for check in checks.iter() {
        stats.total += 1;
        match check.state {
            CheckState::Success => stats.success += 1,
            CheckState::Failure => stats.failure += 1,
            CheckState::Error => stats.error += 1,
            CheckState::Waiting => stats.waiting += 1,
        }
    }
    return stats;
}

pub fn print_stats() {
    let stats = get_stats();
    stats.print();
}

fn format_percent(val: i32, tot: i32) -> String {
    let mut purcent = (val as f32 / tot as f32) * 100.0;
    if purcent.is_nan() {
        purcent = 0.0;
    }
    format!("({:.2}%)", purcent)
}

impl CheckListStats {
    pub fn print(self) {
        let mut success = format!(
            "\tSUCCESS: {:4}/{} {:>9}",
            self.success,
            self.total,
            format_percent(self.success, self.total),
        );
        let mut failure = format!(
            "\tFAILURE: {:4}/{} {:>9}",
            self.failure,
            self.total,
            format_percent(self.failure, self.total),
        );
        let mut error = format!(
            "\tERROR:   {:4}/{} {:>9}",
            self.error,
            self.total,
            format_percent(self.error, self.total),
        );

        if config::is_colored_output_enabled() {
            success = format!(
                "{}{}{}",
                consts::SUCCESS_COLOR,
                success,
                consts::RESET_COLOR
            );
            failure = format!(
                "{}{}{}",
                consts::FAILURE_COLOR,
                failure,
                consts::RESET_COLOR
            );
            error = format!("{}{}{}", consts::ERROR_COLOR, error, consts::RESET_COLOR);
        }

        print!("\n\tResult:\n{}\n{}\n{}\n", success, failure, error);
    }
}
