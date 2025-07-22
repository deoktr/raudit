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

pub fn print_checks(skip_success: bool) {
    let checks = CHECKS.lock().unwrap();
    for check in checks.iter() {
        if skip_success && check.state == CheckState::Success {
            continue;
        }
        println!("{}", check);
    }
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
        check: check,
        message: None,
        dependencies: dependencies,
        tags: tags.iter().map(|t| t.to_string()).collect(),
    });
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

#[derive(Default)]
pub struct CheckListStats {
    total: i32,
    success: i32,
    failure: i32,
    error: i32,
    waiting: i32,
}

impl CheckListStats {
    pub fn print(self) {
        if config::is_colored_output_enabled() {
            println!("");
            println!("\tResult:");
            println!(
                "{}\tSUCCESS: {}/{}{}",
                consts::SUCCESS_COLOR,
                self.success,
                self.total,
                consts::RESET_COLOR
            );
            println!(
                "{}\tFAILURE: {}/{}{}",
                consts::FAILURE_COLOR,
                self.failure,
                self.total,
                consts::RESET_COLOR
            );
            println!(
                "{}\tERROR:   {}/{}{}",
                consts::ERROR_COLOR,
                self.error,
                self.total,
                consts::RESET_COLOR
            );
        } else {
            println!("");
            println!("\tResult:");
            println!("\tSUCCESS: {}/{}", self.success, self.total);
            println!("\tFAILURE: {}/{}", self.failure, self.total);
            println!("\tERROR:   {}/{}", self.error, self.total);
        }
    }
}
