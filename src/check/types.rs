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

use std::fmt::{Display, Formatter, Result};
use std::sync::Mutex;

use once_cell::sync::Lazy;
use serde::Serialize;

pub type CheckReturn = (CheckState, Option<String>);
type CheckFn = fn() -> CheckReturn;
pub type DependencyFn = fn() -> ();

/// Skip a check if returns true
pub type SkipFn = fn() -> bool;

pub static REPORT: Lazy<Mutex<Report>> = Lazy::new(|| Mutex::new(Report::default()));

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

#[derive(Serialize)]
pub struct Report {
    /// List of checks
    pub(crate) checks: Vec<Check>,
    /// Check stats
    pub(crate) stats: ReportStats,
    /// Raudit version
    pub(crate) version: String,
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

    pub fn run(&mut self) {
        let (state, message) = (self.check)();
        self.state = state;
        self.message = message;
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

impl Default for Report {
    fn default() -> Self {
        Report {
            checks: vec![],
            stats: ReportStats::default(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
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
