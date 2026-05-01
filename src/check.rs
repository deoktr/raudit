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

use crate::{config, consts, ocsf, utils};

use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter, Result};
use std::sync::Mutex;

use once_cell::sync::Lazy;
use rayon::prelude::*;
use serde::Serialize;

pub type CheckReturn = (CheckState, Option<String>);
type CheckFn = fn() -> CheckReturn;
type DependencyFn = fn() -> ();

/// Skip a check if returns true
pub type SkipFn = fn() -> bool;

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

/// Security impact classification for a check.
#[derive(Clone, Copy, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum Severity {
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl Severity {
    /// Parse a severity level from a string (case-insensitive).
    pub fn from_str(s: &str) -> std::result::Result<Self, String> {
        match s.to_lowercase().as_str() {
            "informational" => Ok(Severity::Informational),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(format!(
                "Invalid severity '{}'. Valid: informational, low, medium, high, critical",
                s
            )),
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            Severity::Informational => consts::SEV_INFORMATIONAL_COLOR,
            Severity::Low => consts::SEV_LOW_COLOR,
            Severity::Medium => consts::SEV_MEDIUM_COLOR,
            Severity::High => consts::SEV_HIGH_COLOR,
            Severity::Critical => consts::SEV_CRITICAL_COLOR,
        }
    }
}

impl Display for Severity {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Severity::Informational => write!(f, "Informational"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
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
    pub id: String,
    /// Title shown in the check list
    pub title: String,
    /// Description of the check
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Fix of the check
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// List of links
    #[serde(skip_serializing)]
    pub links: Vec<String>,
    /// List of tags, can be used to filter the list
    #[serde(skip_serializing)]
    pub tags: Vec<String>,
    /// Message to give result information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// State of the check
    pub state: CheckState,
    /// Security impact severity level
    pub severity: Severity,
    /// Check function
    #[serde(skip_serializing)]
    pub check: CheckFn,
    /// List of dependencies to run before the check
    #[serde(skip_serializing)]
    pub dependencies: Vec<DependencyFn>,
    /// List of skip rules, if a check is skipped it will not appear in output
    #[serde(skip_serializing)]
    pub skip_if: Vec<SkipFn>,
}

impl Check {
    pub fn new(
        id: &str,
        title: &str,
        severity: Severity,
        tags: Vec<&str>,
        check: CheckFn,
        dependencies: Vec<DependencyFn>,
    ) -> Self {
        Check {
            id: id.to_string(),
            title: title.to_string(),
            description: None,
            fix: None,
            state: CheckState::Unknown,
            severity,
            check,
            message: None,
            dependencies,
            skip_if: vec![],
            links: vec![],
            tags: tags.iter().map(|t| t.to_string()).collect(),
        }
    }

    pub fn skip_when(mut self, predicate: SkipFn) -> Self {
        self.skip_if.push(predicate);
        self
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

/// Print OCSF-compliant JSON output.
pub fn print_json(timestamp: i64) {
    let mut report = REPORT.lock().expect("Checks not initialized");
    let stats = std::mem::take(&mut report.stats);
    let ocsf_report = ocsf::build_ocsf_report(&report.checks, stats, timestamp);
    let json = serde_json::to_string(&ocsf_report).expect("Failed to serialize OCSF report");
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
pub fn run_checks(parallel: bool) {
    let mut report = REPORT.lock().unwrap();

    if parallel {
        report.checks.par_iter_mut().for_each(|check| check.run());
    } else {
        report.checks.iter_mut().for_each(|check| check.run());
    }
}

/// Evaluate every distinct skip predicate (deduplicated by function pointer)
/// across the currently-registered checks, then drop any check whose
/// predicate returns `true`.
pub fn remove_skipped(parallel: bool) {
    let mut report = REPORT.lock().unwrap();

    let unique: HashSet<SkipFn> = report
        .checks
        .iter()
        .flat_map(|c| c.skip_if.iter().copied())
        .collect();

    if unique.is_empty() {
        return;
    }

    let cache: HashMap<usize, bool> = if parallel {
        unique.par_iter().map(|f| (*f as usize, f())).collect()
    } else {
        unique.iter().map(|f| (*f as usize, f())).collect()
    };

    report.checks.retain(|check| {
        !check
            .skip_if
            .iter()
            .any(|f| cache.get(&(*f as usize)).copied().unwrap_or(false))
    });
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

/// Print list of available severity levels.
pub fn print_severities() {
    println!("Available severities: informational, low, medium, high, critical.");
}

/// Filter checks by minimum severity level.
pub fn filter_severity(min: Severity) {
    let mut report = REPORT.lock().unwrap();
    report.checks.retain(|check| check.severity >= min);
}

/// Filter checks by exact severity levels.
pub fn filter_severity_exact(levels: Vec<Severity>) {
    if levels.is_empty() {
        return;
    }

    let mut report = REPORT.lock().unwrap();
    report
        .checks
        .retain(|check| levels.contains(&check.severity));
}

/// Run dependencies in sequence.
pub fn run_dependencies(parallel: bool) {
    let report = REPORT.lock().unwrap();
    let mut unique_deps: HashSet<DependencyFn> = HashSet::new();

    for check in report.checks.iter() {
        for dep in &check.dependencies {
            unique_deps.insert(*dep);
        }
    }

    if parallel {
        unique_deps.par_iter().for_each(|dep| dep());
    } else {
        unique_deps.iter().for_each(|dep| dep());
    }
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
    pub fn run(&mut self) {
        let (state, message) = (self.check)();
        self.state = state;
        self.message = message;
    }
}

impl Display for Check {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let msg_suffix = match &self.message {
            Some(m) => format!(" ({})", m),
            None => "".to_string(),
        };

        let message = if config::is_colored_output_enabled() {
            let state_color = match self.state {
                CheckState::Pass => consts::CHK_PASS_COLOR,
                CheckState::Fail => consts::CHK_FAIL_COLOR,
                CheckState::Warning => consts::CHK_WARNING_COLOR,
                CheckState::Unknown => consts::CHK_UNKNOWN_COLOR,
            };
            format!(
                "{}[{}] {}[{}]{} {}{}{}",
                state_color,
                self.id,
                self.severity.color(),
                self.severity,
                consts::RESET_COLOR,
                state_color,
                self.title,
                msg_suffix,
            )
        } else {
            let state_label = match self.state {
                CheckState::Pass => "PASS",
                CheckState::Fail => "FAIL",
                CheckState::Warning => "WARNING",
                CheckState::Unknown => "UNKNOWN",
            };
            format!(
                "{} [{}] [{}] {}{}",
                state_label, self.id, self.severity, self.title, msg_suffix,
            )
        };

        write!(f, "{}", message)
    }
}

#[derive(Serialize, Default)]
pub struct ReportStats {
    pub total: i32,
    pub pass: i32,
    pub fail: i32,
    pub warning: i32,
    pub unknown: i32,
    pub fail_critical: i32,
    pub fail_high: i32,
    pub fail_medium: i32,
    pub fail_low: i32,
    pub fail_informational: i32,
}

pub fn calculate_stats() {
    let mut report = REPORT.lock().unwrap();

    let mut total = 0;
    let mut pass = 0;
    let mut fail = 0;
    let mut warning = 0;
    let mut unknown = 0;
    let mut fail_critical = 0;
    let mut fail_high = 0;
    let mut fail_medium = 0;
    let mut fail_low = 0;
    let mut fail_informational = 0;

    for check in report.checks.iter() {
        total += 1;
        match check.state {
            CheckState::Pass => pass += 1,
            CheckState::Fail => {
                fail += 1;
                match check.severity {
                    Severity::Critical => fail_critical += 1,
                    Severity::High => fail_high += 1,
                    Severity::Medium => fail_medium += 1,
                    Severity::Low => fail_low += 1,
                    Severity::Informational => fail_informational += 1,
                }
            }
            CheckState::Warning => warning += 1,
            CheckState::Unknown => unknown += 1,
        }
    }

    report.stats.total = total;
    report.stats.pass = pass;
    report.stats.fail = fail;
    report.stats.warning = warning;
    report.stats.unknown = unknown;
    report.stats.fail_critical = fail_critical;
    report.stats.fail_high = fail_high;
    report.stats.fail_medium = fail_medium;
    report.stats.fail_low = fail_low;
    report.stats.fail_informational = fail_informational;
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
            "\tPass: {:6}/{} {:>9}",
            self.pass,
            self.total,
            format_percent(self.pass, self.total),
        );
        let mut fail = format!(
            "\tFail: {:6}/{} {:>9}",
            self.fail,
            self.total,
            format_percent(self.fail, self.total),
        );
        let mut warning = format!(
            "\tWarning: {:3}/{} {:>9}",
            self.warning,
            self.total,
            format_percent(self.warning, self.total),
        );

        if config::is_colored_output_enabled() {
            pass = format!("{}{}{}", consts::CHK_PASS_COLOR, pass, consts::RESET_COLOR);
            fail = format!("{}{}{}", consts::CHK_FAIL_COLOR, fail, consts::RESET_COLOR);
            warning = format!(
                "{}{}{}",
                consts::CHK_WARNING_COLOR,
                warning,
                consts::RESET_COLOR
            );
        }

        print!(
            "\n\t{}Result:\n{}\n{}\n{}\n",
            consts::RESET_COLOR,
            pass,
            fail,
            warning,
        );

        if self.fail > 0 {
            let mut critical = format!("\tCritical: {:8}", self.fail_critical,);
            let mut high = format!("\tHigh: {:12}", self.fail_high,);
            let mut medium = format!("\tMedium: {:10}", self.fail_medium,);
            let mut low = format!("\tLow: {:13}", self.fail_low,);
            let mut informational = format!("\tInformational: {:3}", self.fail_informational,);

            if config::is_colored_output_enabled() {
                critical = format!(
                    "{}{}{}",
                    consts::SEV_CRITICAL_COLOR,
                    critical,
                    consts::RESET_COLOR
                );
                high = format!("{}{}{}", consts::SEV_HIGH_COLOR, high, consts::RESET_COLOR);
                medium = format!(
                    "{}{}{}",
                    consts::SEV_MEDIUM_COLOR,
                    medium,
                    consts::RESET_COLOR
                );
                low = format!("{}{}{}", consts::SEV_LOW_COLOR, low, consts::RESET_COLOR);
                informational = format!(
                    "{}{}{}",
                    consts::SEV_INFORMATIONAL_COLOR,
                    informational,
                    consts::RESET_COLOR
                );
            }

            print!(
                "\n\tFailed by severity:\n{}\n{}\n{}\n{}\n{}\n",
                critical, high, medium, low, informational
            );
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_display() {
        fn dummy_check() -> CheckReturn {
            (CheckState::Fail, Some("details".to_string()))
        }
        config::set_colored_output(false);
        let mut check = Check::new(
            "TST_002",
            "My check",
            Severity::Low,
            vec![],
            dummy_check,
            vec![],
        );
        check.run();
        let output = format!("{}", check);
        assert!(output.contains("[TST_002] [Low] My check (details)"));
    }

    #[test]
    fn test_severity_display_all_variants() {
        assert_eq!(format!("{}", Severity::Informational), "Informational");
        assert_eq!(format!("{}", Severity::Low), "Low");
        assert_eq!(format!("{}", Severity::Medium), "Medium");
        assert_eq!(format!("{}", Severity::High), "High");
        assert_eq!(format!("{}", Severity::Critical), "Critical");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Informational < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_severity_numeric_values() {
        assert_eq!(Severity::Informational as u8, 1);
        assert_eq!(Severity::Low as u8, 2);
        assert_eq!(Severity::Medium as u8, 3);
        assert_eq!(Severity::High as u8, 4);
        assert_eq!(Severity::Critical as u8, 5);
    }
}
