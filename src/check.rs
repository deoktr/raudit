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

use crate::{config, consts, utils};

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

#[derive(Serialize)]
pub struct Report {
    /// List of checks
    checks: Vec<Check>,
    /// Check stats
    stats: ReportStats,
    /// Raudit version
    version: String,
}

#[derive(PartialEq, Serialize)]
pub enum CheckState {
    /// Check is yet to execute or in progress.
    Unknown,
    /// Check passed.
    Pass,
    /// Check function execution error, usually missing permissions.
    Warning,
    /// Check failed.
    Fail,
}

/// Check is a verification to perform on the host.
#[derive(Serialize)]
pub struct Check {
    /// ID of the check, can be used to filter the list
    id: String,

    /// Title shown in the check list
    title: String,

    /// Description of the check
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,

    /// Fix of the check
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<String>,

    /// List of links
    #[serde(skip_serializing)]
    links: Vec<String>,

    /// List of tags, can be used to filter the list
    #[serde(skip_serializing)]
    tags: Vec<String>,

    /// Message to give result information
    #[serde(skip_serializing_if = "Option::is_none")]
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

impl Check {
    pub fn new(
        id: &str,
        title: &str,
        tags: Vec<&str>,
        check: CheckFunc,
        dependencies: Vec<DependencyFunc>,
    ) -> Self {
        Check {
            id: id.to_string(),
            title: title.to_string(),
            description: None,
            fix: None,
            state: CheckState::Unknown,
            check,
            message: None,
            dependencies,
            links: vec![],
            tags: tags.iter().map(|t| t.to_string()).collect(),
        }
    }

    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    pub fn with_fix(mut self, fix: &str) -> Self {
        self.fix = Some(fix.to_string());
        self
    }

    pub fn with_link(mut self, link: &str) -> Self {
        self.links.push(link.to_string());
        self
    }

    /// Adding a check to makes it available
    pub fn register(self) {
        REPORT.lock().unwrap().checks.push(self);
    }
}

/// Print list of checks, with option to skip passed checks.
pub fn print_checks(skip_passed: bool, no_print_description: bool, no_print_fix: bool) {
    let report = REPORT.lock().expect("Checks not initialized");

    for check in report.checks.iter() {
        if skip_passed && check.state == CheckState::Pass {
            continue;
        }

        println!("{}", check);

        let mut add_new_line = false;

        if check.state != CheckState::Pass
            && !no_print_description
            && let Some(description) = &check.description
        {
            for line in utils::wrap_text(&format!("Description: {}", description), 80) {
                println!("{}", line);
            }
            add_new_line = true;
        }

        if check.state == CheckState::Fail
            && !no_print_fix
            && let Some(fix) = &check.fix
        {
            for line in utils::wrap_text(&format!("Fix: {}", fix), 80) {
                println!("{}", line);
            }
            add_new_line = true;
        }

        if check.state == CheckState::Fail && !check.links.is_empty() {
            println!("Links:");
            for link in &check.links {
                println!("- <{}>", link);
            }
            add_new_line = true;
        }

        if add_new_line {
            println!();
        }
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
            if tags.contains(tag) {
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
    report.checks.iter_mut().for_each(|check| check.run());
}

/// Run checks in parallel.
pub fn par_run_checks() {
    let mut report = REPORT.lock().unwrap();

    // use rayon to run checks in parallel
    report.checks.par_iter_mut().for_each(|check| check.run());
}

/// Filter checks by their tags.
pub fn filter_tags(tags: Vec<String>) {
    if tags.is_empty() {
        return;
    }

    let mut report = REPORT.lock().unwrap();
    report
        .checks
        .retain(|check| tags.iter().any(|tag| check.tags.contains(tag)));
}

/// Filter out checks by their tags.
pub fn filter_tags_exclude(tags: Vec<String>) {
    if tags.is_empty() {
        return;
    }

    let mut report = REPORT.lock().unwrap();
    report
        .checks
        .retain(|check| !tags.iter().any(|tag| check.tags.contains(tag)));
}

/// Filter checks by their ID prefix.
pub fn filter_id(prefixes: Vec<String>) {
    if prefixes.is_empty() {
        return;
    }

    let mut report = REPORT.lock().unwrap();
    report
        .checks
        .retain(|check| prefixes.iter().any(|prefix| check.id.starts_with(prefix)));
}

/// Filter out checks by their ID prefix.
pub fn filter_id_exclude(prefixes: Vec<String>) {
    if prefixes.is_empty() {
        return;
    }

    let mut report = REPORT.lock().unwrap();
    report
        .checks
        .retain(|check| !prefixes.iter().any(|prefix| check.id.starts_with(prefix)));
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

impl Default for Report {
    fn default() -> Self {
        Report {
            checks: vec![],
            stats: ReportStats::default(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
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
                CheckState::Pass => {
                    format!("{}{}{}", consts::PASS_COLOR, out, consts::RESET_COLOR)
                }
                CheckState::Fail => {
                    format!("{}{}{}", consts::FAIL_COLOR, out, consts::RESET_COLOR)
                }
                CheckState::Warning => {
                    format!("{}{}{}", consts::WARNING_COLOR, out, consts::RESET_COLOR)
                }
                CheckState::Unknown => {
                    format!("{}{}{}", consts::UNKNOWN_COLOR, out, consts::RESET_COLOR)
                }
            }
        } else {
            match self.state {
                CheckState::Pass => format!("PAS {}", out),
                CheckState::Fail => format!("FAIL {}", out),
                CheckState::Warning => format!("WARNING {}", out),
                CheckState::Unknown => format!("UNKNOWN {}", out),
            }
        };

        write!(f, "{}", message)
    }
}

#[derive(Serialize, Default)]
pub struct ReportStats {
    total: i32,
    pass: i32,
    fail: i32,
    warning: i32,
    unknown: i32,
}

pub fn calculate_stats() {
    let mut report = REPORT.lock().unwrap();

    let mut total = 0;
    let mut pass = 0;
    let mut fail = 0;
    let mut warning = 0;
    let mut unknown = 0;

    for check in report.checks.iter() {
        total += 1;
        match check.state {
            CheckState::Pass => pass += 1,
            CheckState::Fail => fail += 1,
            CheckState::Warning => warning += 1,
            CheckState::Unknown => unknown += 1,
        }
    }

    report.stats.total = total;
    report.stats.pass = pass;
    report.stats.fail = fail;
    report.stats.warning = warning;
    report.stats.unknown = unknown;
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
        let mut pass = format!(
            "\tPASSED: {:4}/{} {:>9}",
            self.pass,
            self.total,
            format_percent(self.pass, self.total),
        );
        let mut fail = format!(
            "\tFAILED: {:4}/{} {:>9}",
            self.fail,
            self.total,
            format_percent(self.fail, self.total),
        );
        let mut warning = format!(
            "\tWARNING:  {:4}/{} {:>9}",
            self.warning,
            self.total,
            format_percent(self.warning, self.total),
        );

        if config::is_colored_output_enabled() {
            pass = format!("{}{}{}", consts::PASS_COLOR, pass, consts::RESET_COLOR);
            fail = format!("{}{}{}", consts::FAIL_COLOR, fail, consts::RESET_COLOR);
            warning = format!(
                "{}{}{}",
                consts::WARNING_COLOR,
                warning,
                consts::RESET_COLOR
            );
        }

        print!("\n\tResult:\n{}\n{}\n{}\n\n", pass, fail, warning);
    }
}
