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

use std::collections::HashSet;
use std::fmt::{Display, Formatter, Result};
use std::sync::Mutex;

use once_cell::sync::Lazy;
use rayon::prelude::*;
use serde::Serialize;

pub type CheckReturn = (CheckState, Option<String>);
type CheckFunc = fn() -> CheckReturn;
type DependencyFunc = fn() -> ();

static REPORT: Lazy<Mutex<Report>> = Lazy::new(|| Mutex::new(Report::default()));

#[derive(Serialize, Default)]
pub struct Report {
    /// List of checks
    checks: Vec<Check>,

    /// Check stats
    stats: ReportStats,
}

#[derive(PartialEq, Serialize)]
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
#[derive(Serialize)]
pub struct Check {
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
    #[serde(skip_serializing)]
    check: CheckFunc,
    /// List of dependencies to run before the check
    #[serde(skip_serializing)]
    dependencies: Vec<DependencyFunc>,
}

/// Print list of checks, with option to skip successful checks.
pub fn print_checks(skip_success: bool) {
    let report = REPORT.lock().expect("Checks not initialized");

    for check in report.checks.iter() {
        if skip_success && check.state == CheckState::Success {
            continue;
        }
        println!("{}", check);
    }
}

pub fn print_json(pretty: bool) {
    let report = REPORT.lock().expect("Checks not initialized");

    let json = if pretty {
        serde_json::to_string_pretty(&*report).expect("Failed to serialize report")
    } else {
        serde_json::to_string(&*report).expect("Failed to serialize report")
    };

    println!("{}", json);
}

/// Print list of available tags.
pub fn print_tags() {
    let report = REPORT.lock().unwrap();
    let mut tags: Vec<String> = vec![];
    for check in report.checks.iter() {
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
    let report = REPORT.lock().unwrap();
    let mut prefixes: Vec<String> = vec![];
    for check in report.checks.iter() {
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
    let mut report = REPORT.lock().unwrap();
    for check in report.checks.iter_mut() {
        check.run();
    }
}

/// Run checks in parallel.
pub fn par_run_checks() {
    let mut report = REPORT.lock().unwrap();

    // use rayon to run checks in parallel
    report.checks.par_iter_mut().for_each(|check| check.run());
}

/// Filter checks by their tags.
pub fn filter_tags(tags: Vec<String>) {
    if tags.len() == 0 {
        return;
    }

    let mut report = REPORT.lock().unwrap();
    report
        .checks
        .retain(|check| tags.iter().any(|tag| check.tags.contains(tag)));
}

/// Filter checks by their ID prefix.
pub fn filter_id(prefixes: Vec<String>) {
    if prefixes.len() == 0 {
        return;
    }

    let mut report = REPORT.lock().unwrap();
    report
        .checks
        .retain(|check| prefixes.iter().any(|prefix| check.id.starts_with(prefix)));
}

/// Run dependencies in sequence.
pub fn run_dependencies() {
    let report = REPORT.lock().unwrap();
    let mut unique_deps: HashSet<DependencyFunc> = HashSet::new();

    for check in report.checks.iter() {
        for dep in &check.dependencies {
            unique_deps.insert(*dep);
        }
    }

    unique_deps.iter().for_each(|dep| dep());
}

/// Run dependencies in parallel.
pub fn par_run_dependencies() {
    let report = REPORT.lock().unwrap();
    let mut unique_deps: HashSet<DependencyFunc> = HashSet::new();

    for check in report.checks.iter() {
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
    let mut report = REPORT.lock().unwrap();
    report.checks.push(Check {
        id: id.to_string(),
        title: title.to_string(),
        state: CheckState::Waiting,
        check,
        message: None,
        dependencies,
        tags: tags.iter().map(|t| t.to_string()).collect(),
    });
}

#[derive(Serialize, Default)]
pub struct ReportStats {
    total: i32,
    success: i32,
    failure: i32,
    error: i32,
    waiting: i32,
}

pub fn calculate_stats() {
    let mut report = REPORT.lock().unwrap();

    let mut total = 0;
    let mut success = 0;
    let mut failure = 0;
    let mut error = 0;
    let mut waiting = 0;

    for check in report.checks.iter() {
        total += 1;
        match check.state {
            CheckState::Success => success += 1,
            CheckState::Failure => failure += 1,
            CheckState::Error => error += 1,
            CheckState::Waiting => waiting += 1,
        }
    }

    report.stats.total = total;
    report.stats.success = success;
    report.stats.failure = failure;
    report.stats.error = error;
    report.stats.waiting = waiting;
}

pub fn print_stats() {
    let report = REPORT.lock().unwrap();
    report.stats.print();
}

fn format_percent(val: i32, tot: i32) -> String {
    let mut purcent = (val as f32 / tot as f32) * 100.0;
    if purcent.is_nan() {
        purcent = 0.0;
    }
    format!("({:.2}%)", purcent)
}

impl ReportStats {
    pub fn print(&self) {
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

        print!("\n\tResult:\n{}\n{}\n{}\n\n", success, failure, error);
    }
}
