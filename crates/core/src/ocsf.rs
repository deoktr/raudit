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

//! OCSF Compliance Finding (class 2003, schema 1.9.0) output types.
//!
//! Provides serialization structs and conversion logic to transform raudit
//! check results into OCSF-compliant Compliance Finding events.

use crate::check::{Check, CheckState, ReportStats, Severity};
use crate::utils;
use serde::Serialize;

/// OCSF schema version emitted in event metadata.
pub const OCSF_VERSION: &str = "1.9.0";

/// Known compliance framework tags and their OCSF standard names.
const FRAMEWORK_TAGS: &[(&str, &str)] = &[("CIS", "CIS Benchmark"), ("STIG", "DISA STIG")];

/// OCSF product identification.
#[derive(Serialize, Clone)]
pub struct OcsfProduct {
    /// Product name.
    pub name: &'static str,
    /// Product version.
    pub version: String,
}

/// OCSF entity that reported the event.
#[derive(Serialize, Clone)]
pub struct OcsfReporter {
    /// Reporter name.
    pub name: String,
    /// Hostname of the reporter, omitted when unknown.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hostname: String,
}

/// OCSF metadata containing schema version, product and reporter info.
#[derive(Serialize, Clone)]
pub struct OcsfMetadata {
    /// OCSF schema version.
    pub version: &'static str,
    /// Product identification.
    pub product: OcsfProduct,
    /// Entity that reported the event, omitted from individual findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reporter: Option<OcsfReporter>,
}

/// Audit execution details, kept outside the OCSF metadata object.
#[derive(Serialize)]
pub struct OcsfAudit {
    /// Audit start time in epoch milliseconds.
    pub start_time: i64,
    /// Audit end time in epoch milliseconds.
    pub end_time: i64,
    /// Audit duration in milliseconds.
    pub duration: i64,
    /// User that started the audit.
    pub username: String,
}

/// OCSF resource affected by a finding.
#[derive(Serialize, Clone)]
pub struct OcsfResource {
    /// Resource name.
    pub name: String,
    /// Hostname of the audited resource.
    pub hostname: String,
    /// Source-specific resource type.
    #[serde(rename = "type")]
    pub resource_type: &'static str,
}

/// OCSF finding identification details.
#[derive(Serialize)]
pub struct OcsfFindingInfo {
    /// Unique identifier (check ID).
    pub uid: String,
    /// Finding title.
    pub title: String,
    /// Finding description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
}

/// OCSF Compliance object.
#[derive(Serialize)]
pub struct OcsfCompliance {
    pub standards: Vec<String>,
    pub status_id: u8,
    pub status: &'static str,
}

/// OCSF remediation guidance.
#[derive(Serialize)]
pub struct OcsfRemediation {
    /// Remediation description.
    pub desc: String,
}

/// OCSF Compliance Finding event (class_uid 2003).
#[derive(Serialize)]
pub struct OcsfComplianceFinding {
    /// Activity identifier (1 = Create).
    pub activity_id: u8,
    /// Human-readable activity name.
    pub activity_name: &'static str,
    /// Category identifier (2 = Findings).
    pub category_uid: u16,
    /// Human-readable category name.
    pub category_name: &'static str,
    /// Class identifier (2003 = Compliance Finding).
    pub class_uid: u16,
    /// Human-readable class name.
    pub class_name: &'static str,
    /// Type identifier (class_uid * 100 + activity_id).
    pub type_uid: u32,
    /// Human-readable type name.
    pub type_name: &'static str,
    /// Finding identification details.
    pub finding_info: OcsfFindingInfo,
    /// Provides context to compliance findings.
    pub compliance: OcsfCompliance,
    /// Runtime result message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Event metadata.
    pub metadata: OcsfMetadata,
    /// Remediation guidance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<OcsfRemediation>,
    /// Resources affected by the finding.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<OcsfResource>,
    /// Severity numeric ID (1-5).
    pub severity_id: u8,
    /// Human-readable severity label.
    pub severity: String,
    /// Status numeric ID (0, 1, or 4).
    pub status_id: u8,
    /// Human-readable status label.
    pub status: &'static str,
    /// Event timestamp in epoch milliseconds.
    pub time: i64,
}

/// Top-level OCSF JSON output envelope.
#[derive(Serialize)]
pub struct OcsfReport {
    /// Array of OCSF Compliance Finding events.
    pub findings: Vec<OcsfComplianceFinding>,
    /// Aggregate statistics.
    pub stats: ReportStats,
    /// Report-level OCSF metadata.
    pub metadata: OcsfMetadata,
    /// Audit execution details.
    pub audit: OcsfAudit,
}

/// Map a CheckState to OCSF (status_id, status label).
pub fn finding_status(state: &CheckState) -> (u8, &'static str) {
    // TODO: since we do not have storage for the moment, it's impossible to
    // compare with previous audits, thus a failed check will always appear as
    // new, and passed as resolved
    match state {
        CheckState::Pass => (4, "Resolved"),
        CheckState::Fail => (1, "New"),
        CheckState::Warning => (0, "Unknown"),
        CheckState::Unknown => (0, "Unknown"),
    }
}

/// Map a CheckState to OCSF (status_id, status label).
pub fn compliance_status(state: &CheckState) -> (u8, &'static str) {
    match state {
        CheckState::Unknown => (0, "Unknown"),
        CheckState::Pass => (1, "Pass"),
        CheckState::Warning => (2, "Warning"),
        CheckState::Fail => (3, "Fail"),
    }
}

/// Map a Severity to OCSF (severity_id, severity label).
pub fn severity(severity: &Severity) -> (u8, String) {
    (*severity as u8, severity.to_string())
}

/// Build OCSF metadata with schema version and product info.
pub fn build_metadata() -> OcsfMetadata {
    OcsfMetadata {
        version: OCSF_VERSION,
        product: OcsfProduct {
            name: "raudit",
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        reporter: None,
    }
}

/// Build report metadata identifying the host that produced the findings.
pub fn build_report_metadata(host: &str) -> OcsfMetadata {
    let mut metadata = build_metadata();
    if !host.is_empty() {
        metadata.reporter = Some(OcsfReporter {
            name: host.to_string(),
            hostname: host.to_string(),
        });
    }
    metadata
}

/// Build audit execution details with the audit interval and user.
pub fn build_audit(start_time: i64, end_time: i64) -> OcsfAudit {
    OcsfAudit {
        start_time,
        end_time,
        duration: end_time.saturating_sub(start_time).max(0),
        username: utils::username(),
    }
}

/// Extract compliance framework standards from check tags.
fn extract_standards(tags: &[String]) -> Vec<String> {
    let mut standards: Vec<String> = Vec::new();
    for (tag, name) in FRAMEWORK_TAGS {
        if tags.iter().any(|t| t == *tag) {
            standards.push(name.to_string());
        }
    }
    if standards.is_empty() {
        standards.push("raudit".to_string());
    }
    standards
}

/// Convert a Check into an OCSF Compliance Finding event.
pub fn check_to_finding(
    check: &Check,
    timestamp: i64,
    metadata: &OcsfMetadata,
    host: &str,
) -> OcsfComplianceFinding {
    let (severity_id, severity) = severity(&check.severity);
    let (status_id, status) = finding_status(&check.state);
    let (compliance_status_id, compliance_status) = compliance_status(&check.state);
    let resources = if host.is_empty() {
        Vec::new()
    } else {
        vec![OcsfResource {
            name: host.to_string(),
            hostname: host.to_string(),
            resource_type: "host",
        }]
    };

    OcsfComplianceFinding {
        activity_id: 1,
        activity_name: "Create",
        category_uid: 2,
        category_name: "Findings",
        class_uid: 2003,
        class_name: "Compliance Finding",
        type_uid: 200301,
        type_name: "Compliance Finding: Create",
        finding_info: OcsfFindingInfo {
            uid: check.id.clone(),
            title: check.title.clone(),
            desc: check.description.clone(),
        },
        compliance: OcsfCompliance {
            standards: extract_standards(&check.tags),
            status_id: compliance_status_id,
            status: compliance_status,
        },
        message: check.message.clone(),
        metadata: metadata.clone(),
        remediation: check.fix.clone().map(|f| OcsfRemediation { desc: f }),
        resources,
        severity_id,
        severity,
        status_id,
        status,
        time: timestamp,
    }
}

/// Build the full OCSF report from checks and stats.
pub fn build_ocsf_report(checks: &[Check], stats: ReportStats, timestamp: i64) -> OcsfReport {
    build_ocsf_report_with_host(checks, stats, timestamp, &utils::hostname())
}

/// Build the full OCSF report with an explicit hostname.
pub fn build_ocsf_report_with_host(
    checks: &[Check],
    stats: ReportStats,
    timestamp: i64,
    host: &str,
) -> OcsfReport {
    let end_time = utils::now_millis();
    let metadata = build_report_metadata(host);
    let audit = build_audit(timestamp, end_time);
    let finding_metadata = build_metadata();
    let findings = checks
        .iter()
        .map(|c| check_to_finding(c, timestamp, &finding_metadata, host))
        .collect();
    OcsfReport {
        findings,
        stats,
        metadata,
        audit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{Check, CheckState, Severity};

    fn dummy_check() -> (CheckState, Option<String>) {
        (CheckState::Fail, Some("details".to_string()))
    }

    fn dummy_pass_check() -> (CheckState, Option<String>) {
        (CheckState::Pass, None)
    }

    #[test]
    fn test_check_to_finding_fail_with_description_and_fix() {
        let mut check = Check::new(
            "TST_001",
            "Test check",
            Severity::High,
            vec![],
            dummy_check,
            vec![],
        )
        .with_description("A test description")
        .with_fix("Apply the fix");
        check.run();

        let metadata = build_metadata();
        let finding = check_to_finding(&check, 1700000000000, &metadata, "test-host");

        assert_eq!(finding.type_name, "Compliance Finding: Create");
        assert_eq!(finding.resources.len(), 1);
        assert_eq!(finding.resources[0].name, "test-host");
        assert_eq!(finding.resources[0].hostname, "test-host");
        assert_eq!(finding.resources[0].resource_type, "host");
        assert_eq!(finding.severity_id, 4);
        assert_eq!(finding.severity, "High");
        assert_eq!(finding.status_id, 1);
        assert_eq!(finding.status, "New");
        assert_eq!(finding.class_uid, 2003);
        assert_eq!(finding.type_uid, 200301);
        assert_eq!(finding.activity_id, 1);
        assert_eq!(finding.activity_name, "Create");
        assert_eq!(finding.category_uid, 2);
        assert_eq!(finding.category_name, "Findings");
        assert_eq!(finding.class_name, "Compliance Finding");
        assert_eq!(finding.finding_info.uid, "TST_001");
        assert_eq!(finding.finding_info.title, "Test check");
        assert_eq!(
            finding.finding_info.desc.as_deref(),
            Some("A test description")
        );
        assert_eq!(
            finding.remediation.as_ref().map(|r| r.desc.as_str()),
            Some("Apply the fix")
        );
        assert_eq!(finding.message.as_deref(), Some("details"));
        assert_eq!(finding.time, 1700000000000);
    }

    #[test]
    fn test_check_to_finding_pass_omits_optional_fields() {
        let mut check = Check::new(
            "TST_002",
            "Pass check",
            Severity::Low,
            vec![],
            dummy_pass_check,
            vec![],
        );
        check.run();

        let metadata = build_metadata();
        let finding = check_to_finding(&check, 1700000000000, &metadata, "test-host");

        assert_eq!(finding.status_id, 4);
        assert_eq!(finding.status, "Resolved");
        assert!(finding.finding_info.desc.is_none());
        assert!(finding.remediation.is_none());
        assert!(finding.message.is_none());
    }

    #[test]
    fn test_check_to_finding_without_host_omits_resources() {
        let mut check = Check::new(
            "TST_004",
            "No host check",
            Severity::Low,
            vec![],
            dummy_pass_check,
            vec![],
        );
        check.run();

        let metadata = build_metadata();
        let finding = check_to_finding(&check, 1700000000000, &metadata, "");
        let json = serde_json::to_string(&finding).unwrap();

        assert!(finding.resources.is_empty());
        assert!(!json.contains("\"resources\""));
    }

    #[test]
    fn test_ocsf_report_serialization_compact() {
        let mut check = Check::new(
            "TST_003",
            "Compact test",
            Severity::Medium,
            vec![],
            dummy_check,
            vec![],
        );
        check.run();

        let stats = ReportStats::default();
        let report = build_ocsf_report(&[check], stats, 1700000000000);
        let json = serde_json::to_string(&report).unwrap();

        assert_eq!(report.metadata.version, OCSF_VERSION);
        assert_eq!(report.findings[0].metadata.version, OCSF_VERSION);
        assert!(json.contains("\"version\":\"1.9.0\""));
        assert!(json.contains("\"type_name\":\"Compliance Finding: Create\""));
        assert!(json.contains("\"findings\""));
        assert!(json.contains("\"stats\""));
        assert!(json.contains("\"metadata\""));
        assert!(json.contains("\"audit\""));
        assert!(json.contains("\"class_uid\":2003"));
        assert!(json.contains("\"start_time\":1700000000000"));
        assert!(json.contains("\"end_time\""));
        assert!(json.contains("\"duration\""));
        assert!(json.contains("\"username\""));
    }

    #[test]
    fn test_build_report_metadata_reporter() {
        let metadata = build_report_metadata("test-host");
        let reporter = metadata.reporter.expect("reporter should be set");

        assert_eq!(reporter.name, "test-host");
        assert_eq!(reporter.hostname, "test-host");
    }

    #[test]
    fn test_build_report_metadata_without_host_omits_reporter() {
        let metadata = build_report_metadata("");

        assert!(metadata.reporter.is_none());
    }

    #[test]
    fn test_build_audit_interval() {
        let audit = build_audit(1_700_000_000_000, 1_700_000_001_250);

        assert_eq!(audit.start_time, 1_700_000_000_000);
        assert_eq!(audit.end_time, 1_700_000_001_250);
        assert_eq!(audit.duration, 1_250);
        assert!(!audit.username.is_empty());
    }

    #[test]
    fn test_build_audit_never_negative_duration() {
        let audit = build_audit(1_700_000_002_000, 1_700_000_001_000);

        assert_eq!(audit.duration, 0);
    }
}
