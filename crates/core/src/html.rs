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

//! Self-contained HTML report generation.
//!
//! The report is built from OCSF Compliance Finding JSON, so the same renderer
//! handles a live audit and one or more files collected from other hosts. Every
//! style and script is embedded in the document: the report opens offline, with
//! no network access and no external asset.

use std::fmt::Write as _;

use serde::Deserialize;

use crate::check::{Check, ReportStats};
use crate::ocsf;
use crate::utils;

/// Embedded stylesheet, there is deliberately no external resource.
const STYLE: &str = r#"
:root {
  color-scheme: light dark;
  --bg: #f5f7fa;
  --surface: #ffffff;
  --surface-alt: #f0f3f7;
  --text: #17212b;
  --muted: #5c6978;
  --border: #d8dee7;
  --accent: #0b63ce;
  --pass: #16733a;
  --pass-bg: #e3f4e8;
  --fail: #b42318;
  --fail-bg: #fde7e5;
  --warning: #8a5a00;
  --warning-bg: #fff2cc;
  --unknown: #4a5566;
  --unknown-bg: #e9edf3;
  --critical: #b42318;
  --high: #c2410c;
  --medium: #9a6700;
  --low: #0b63ce;
  --info: #5c6978;
  --radius: 10px;
  --shadow: 0 1px 2px rgba(16, 24, 40, .06), 0 1px 3px rgba(16, 24, 40, .1);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f141b;
    --surface: #171e27;
    --surface-alt: #1d2631;
    --text: #e7edf5;
    --muted: #9aa7b8;
    --border: #2b3644;
    --accent: #69a7ff;
    --pass: #6fdb95;
    --pass-bg: #12351f;
    --fail: #ff8d82;
    --fail-bg: #3a1614;
    --warning: #f2c94c;
    --warning-bg: #352a0b;
    --unknown: #b3bfce;
    --unknown-bg: #242d39;
    --critical: #ff8d82;
    --high: #ffab73;
    --medium: #f2c94c;
    --low: #69a7ff;
    --info: #b3bfce;
    --shadow: 0 1px 2px rgba(0, 0, 0, .3);
  }
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body {
  margin: 0;
  color: var(--text);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
main { max-width: 1440px; margin: 0 auto; padding: 28px 20px 56px; }
a { color: var(--accent); }
h1 { font-size: 1.9rem; margin: 0 0 4px; letter-spacing: -.02em; }
h2 { font-size: 1.3rem; margin: 0; }
h3 { font-size: 1rem; margin: 0 0 10px; }
.page-header { margin-bottom: 22px; }
.subtitle, .host-meta, .finding-desc, .finding-message, .finding-standards,
.finding-source, footer { color: var(--muted); }
.subtitle { margin: 0; }
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin: 18px 0 26px;
}
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-top: 4px solid var(--border);
  border-radius: var(--radius);
  padding: 14px 16px;
  box-shadow: var(--shadow);
}
.card-pass { border-top-color: var(--pass); }
.card-fail { border-top-color: var(--fail); }
.card-warning { border-top-color: var(--warning); }
.card-unknown { border-top-color: var(--unknown); }
.card-label {
  display: block;
  color: var(--muted);
  font-size: .8rem;
  letter-spacing: .06em;
  text-transform: uppercase;
}
.card-value { display: block; font-size: 1.8rem; font-weight: 700; line-height: 1.15; margin-top: 4px; }
.card-sub { color: var(--muted); font-size: .85rem; }
.table-wrap {
  overflow-x: auto;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
}
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
th {
  background: var(--surface-alt);
  color: var(--muted);
  font-size: .78rem;
  letter-spacing: .05em;
  text-transform: uppercase;
  white-space: nowrap;
}
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: var(--surface-alt); }
.num { text-align: right; }
.percent { color: var(--muted); font-size: .86em; font-weight: 400; }
.summary-total td { background: var(--surface-alt); font-weight: 600; }
.host { margin-top: 30px; }
.host-header {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 10px;
}
.host-meta { margin: 0; font-size: .88rem; }
.host-stats { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0 14px; }
.stat {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border-radius: 999px;
  padding: 4px 10px;
  font-size: .85rem;
  font-weight: 600;
  background: var(--unknown-bg);
  color: var(--unknown);
}
.stat-pass { background: var(--pass-bg); color: var(--pass); }
.stat-fail { background: var(--fail-bg); color: var(--fail); }
.stat-warning { background: var(--warning-bg); color: var(--warning); }
.stat-unknown { background: var(--unknown-bg); color: var(--unknown); }
.toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: end;
  gap: 10px;
  margin: 18px 0;
  padding: 12px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
}
.field {
  display: flex;
  flex-direction: column;
  gap: 4px;
  color: var(--muted);
  font-size: .78rem;
  letter-spacing: .05em;
  text-transform: uppercase;
}
input[type="search"], select, button {
  font: inherit;
  color: var(--text);
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 7px 10px;
}
input[type="search"] { min-width: 240px; }
button { cursor: pointer; letter-spacing: 0; text-transform: none; }
button:hover { border-color: var(--accent); }
#filter-count { margin-left: auto; color: var(--muted); font-size: .85rem; align-self: center; }
.finding-id code { font-size: .86em; }
.finding-title { min-width: 280px; }
.finding-desc { display: block; font-size: .87rem; margin-top: 3px; }
.finding-detail { min-width: 220px; font-size: .9rem; }
.finding-message { font-style: italic; }
.finding-standards { font-size: .85rem; }
.badge {
  display: inline-block;
  border-radius: 999px;
  padding: 2px 9px;
  font-size: .78rem;
  font-weight: 700;
  white-space: nowrap;
}
.status-pass, .status-resolved { background: var(--pass-bg); color: var(--pass); }
.status-fail, .status-new { background: var(--fail-bg); color: var(--fail); }
.status-warning { background: var(--warning-bg); color: var(--warning); }
.status-unknown { background: var(--unknown-bg); color: var(--unknown); }
.severity { font-weight: 600; white-space: nowrap; }
.severity-critical { color: var(--critical); }
.severity-high { color: var(--high); }
.severity-medium { color: var(--medium); }
.severity-low { color: var(--low); }
.severity-informational, .severity-info { color: var(--info); }
.severity-unknown { color: var(--muted); }
details.remediation { margin-top: 6px; }
details.remediation summary { cursor: pointer; color: var(--accent); font-size: .87rem; }
.host[hidden], tr[hidden] { display: none !important; }
.empty { color: var(--muted); padding: 24px; text-align: center; }
footer { margin-top: 34px; font-size: .85rem; text-align: center; }
@media (max-width: 720px) {
  main { padding: 18px 12px 40px; }
  .toolbar { position: static; }
  .finding-title { min-width: 200px; }
}
@media print {
  body { background: #fff; }
  .toolbar, footer, .cards { display: none; }
  .table-wrap, .card { box-shadow: none; }
  .host { break-inside: avoid; }
  a { color: inherit; text-decoration: none; }
}
"#;

/// Embedded script, the filters and expand buttons work without any network.
const SCRIPT: &str = r#"
(function () {
  "use strict";
  var search = document.getElementById("filter-search");
  var status = document.getElementById("filter-status");
  var severity = document.getElementById("filter-severity");
  var host = document.getElementById("filter-host");
  var count = document.getElementById("filter-count");
  var empty = document.getElementById("filter-empty");
  var sections = Array.prototype.slice.call(document.querySelectorAll("section.host"));
  var rows = Array.prototype.slice.call(document.querySelectorAll("tr.finding"));

  function apply() {
    var q = search ? search.value.trim().toLowerCase() : "";
    var s = status ? status.value : "";
    var v = severity ? severity.value : "";
    var h = host ? host.value : "";
    var visible = 0;
    var filtering = q !== "" || s !== "" || v !== "" || h !== "";

    rows.forEach(function (row) {
      var match = (!q || (row.getAttribute("data-search") || "").indexOf(q) !== -1)
        && (!s || row.getAttribute("data-status") === s)
        && (!v || row.getAttribute("data-severity") === v)
        && (!h || row.getAttribute("data-host") === h);
      row.hidden = !match;
      if (match) {
        visible++;
      }
    });

    sections.forEach(function (section) {
      section.hidden = filtering && !section.querySelector("tr.finding:not([hidden])");
    });

    if (count) {
      count.textContent = visible + " / " + rows.length + " findings";
    }
    if (empty) {
      empty.hidden = !(rows.length > 0 && visible === 0);
    }
  }

  [search, status, severity, host].forEach(function (el) {
    if (el) {
      el.addEventListener("input", apply);
      el.addEventListener("change", apply);
    }
  });

  function setDetails(open) {
    document.querySelectorAll("details.remediation").forEach(function (details) {
      details.open = open;
    });
  }

  var expand = document.getElementById("expand-all");
  var collapse = document.getElementById("collapse-all");
  if (expand) { expand.addEventListener("click", function () { setDetails(true); }); }
  if (collapse) { collapse.addEventListener("click", function () { setDetails(false); }); }

  apply();
})();
"#;

/// Reporter of the event.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HtmlReporter {
    /// Reporter name.
    #[serde(default)]
    pub name: String,
    /// Reporter hostname.
    #[serde(default)]
    pub hostname: String,
}

/// Host metadata, extended with the hostname and audit details of raudit.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HtmlMetadata {
    /// OCSF schema version.
    #[serde(default)]
    pub version: String,
    /// Product that produced the findings.
    #[serde(default)]
    pub product: HtmlProduct,
    /// Entity that reported the findings.
    #[serde(default)]
    pub reporter: HtmlReporter,
    /// Hostname extension, absent from older reports.
    #[serde(default)]
    pub host: Option<String>,
    /// Audit start time in epoch milliseconds.
    #[serde(default)]
    pub start_time: Option<i64>,
    /// Audit end time in epoch milliseconds.
    #[serde(default)]
    pub end_time: Option<i64>,
    /// Audit duration in milliseconds.
    #[serde(default)]
    pub elapsed: Option<i64>,
    /// User that started the audit.
    #[serde(default)]
    pub username: Option<String>,
}

/// Audit execution details, stored outside the OCSF metadata object.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HtmlAudit {
    /// Audit start time in epoch milliseconds.
    #[serde(default)]
    pub start_time: Option<i64>,
    /// Audit end time in epoch milliseconds.
    #[serde(default)]
    pub end_time: Option<i64>,
    /// Audit duration in milliseconds.
    #[serde(default)]
    pub duration: Option<i64>,
    /// User that started the audit.
    #[serde(default)]
    pub username: Option<String>,
}

/// Product identification.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HtmlProduct {
    /// Product name.
    #[serde(default)]
    pub name: String,
    /// Product version.
    #[serde(default)]
    pub version: String,
}

/// Aggregate statistics of one host.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HtmlStats {
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

impl HtmlStats {
    fn add(&mut self, other: &HtmlStats) {
        self.total += other.total;
        self.pass += other.pass;
        self.fail += other.fail;
        self.warning += other.warning;
        self.unknown += other.unknown;
        self.fail_critical += other.fail_critical;
        self.fail_high += other.fail_high;
        self.fail_medium += other.fail_medium;
        self.fail_low += other.fail_low;
        self.fail_informational += other.fail_informational;
    }
}

impl From<ReportStats> for HtmlStats {
    fn from(stats: ReportStats) -> Self {
        HtmlStats {
            total: stats.total,
            pass: stats.pass,
            fail: stats.fail,
            warning: stats.warning,
            unknown: stats.unknown,
            fail_critical: stats.fail_critical,
            fail_high: stats.fail_high,
            fail_medium: stats.fail_medium,
            fail_low: stats.fail_low,
            fail_informational: stats.fail_informational,
        }
    }
}

/// Finding identification details.
#[derive(Debug, Clone, Deserialize)]
pub struct HtmlFindingInfo {
    /// Check identifier.
    pub uid: String,
    /// Finding title.
    pub title: String,
    /// Finding description.
    #[serde(default)]
    pub desc: Option<String>,
}

/// Compliance details of a finding.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HtmlCompliance {
    /// Compliance frameworks the finding belongs to.
    #[serde(default)]
    pub standards: Vec<String>,
    /// Compliance status, one of Pass, Fail, Warning or Unknown.
    #[serde(default)]
    pub status: String,
}

/// Remediation guidance.
#[derive(Debug, Clone, Deserialize)]
pub struct HtmlRemediation {
    /// Remediation description.
    pub desc: String,
}

/// One OCSF Compliance Finding.
#[derive(Debug, Clone, Deserialize)]
pub struct HtmlFinding {
    /// Finding identification.
    pub finding_info: HtmlFindingInfo,
    /// Compliance details.
    #[serde(default)]
    pub compliance: Option<HtmlCompliance>,
    /// Runtime result message.
    #[serde(default)]
    pub message: Option<String>,
    /// Remediation guidance.
    #[serde(default)]
    pub remediation: Option<HtmlRemediation>,
    /// Human-readable severity label.
    #[serde(default)]
    pub severity: String,
    /// Human-readable finding status.
    #[serde(default)]
    pub status: String,
    /// Event timestamp in epoch milliseconds.
    #[serde(default)]
    pub time: i64,
}

/// One host report, as serialized by `raudit --json`.
#[derive(Debug, Clone, Deserialize)]
pub struct HtmlReport {
    /// Hostname extension at the envelope level, if present.
    #[serde(default)]
    pub host: Option<String>,
    /// Findings of the host.
    pub findings: Vec<HtmlFinding>,
    /// Aggregate statistics.
    pub stats: HtmlStats,
    /// Report metadata.
    pub metadata: HtmlMetadata,
    /// Audit execution details, absent from older reports.
    #[serde(default)]
    pub audit: Option<HtmlAudit>,
    /// File the report was read from, not part of the JSON.
    #[serde(skip)]
    pub source: Option<String>,
}

impl HtmlReport {
    /// Parse an OCSF JSON report produced by `raudit --json`.
    pub fn from_json(input: &str) -> Result<Self, String> {
        let mut report: Self = serde_json::from_str(input).map_err(|err| err.to_string())?;
        report.normalize_audit();
        Ok(report)
    }

    /// Merge the audit object and reporter hostname into the metadata fields.
    ///
    /// Older reports store the audit details directly in the metadata object
    /// and the hostname in a custom `metadata.host` attribute.
    fn normalize_audit(&mut self) {
        if self
            .metadata
            .host
            .as_deref()
            .is_none_or(|host| host.is_empty())
        {
            let hostname = self.metadata.reporter.hostname.trim().to_string();
            if !hostname.is_empty() {
                self.metadata.host = Some(hostname);
            }
        }

        let Some(audit) = &self.audit else {
            return;
        };

        self.metadata.start_time = self.metadata.start_time.or(audit.start_time);
        self.metadata.end_time = self.metadata.end_time.or(audit.end_time);
        self.metadata.elapsed = self.metadata.elapsed.or(audit.duration);
        self.metadata.username = self
            .metadata
            .username
            .clone()
            .or_else(|| audit.username.clone());
    }

    /// Build a report from the checks currently registered and executed.
    pub fn from_checks(checks: &[Check], stats: ReportStats, host: &str, timestamp: i64) -> Self {
        let report = ocsf::build_ocsf_report_with_host(checks, stats, timestamp, host);
        Self::from_ocsf(report)
    }

    /// Convert an in-memory OCSF report.
    pub fn from_ocsf(report: ocsf::OcsfReport) -> Self {
        let reporter = report
            .metadata
            .reporter
            .map(|reporter| HtmlReporter {
                name: reporter.name,
                hostname: reporter.hostname,
            })
            .unwrap_or_default();
        let host = Some(reporter.hostname.clone()).filter(|host| !host.is_empty());
        let metadata = HtmlMetadata {
            version: report.metadata.version.to_string(),
            product: HtmlProduct {
                name: report.metadata.product.name.to_string(),
                version: report.metadata.product.version,
            },
            reporter,
            host,
            start_time: Some(report.audit.start_time),
            end_time: Some(report.audit.end_time),
            elapsed: Some(report.audit.duration),
            username: Some(report.audit.username),
        };
        let host = metadata.host.clone();
        let findings = report.findings.into_iter().map(HtmlFinding::from).collect();
        let stats = HtmlStats::from(report.stats);

        HtmlReport {
            host,
            findings,
            stats,
            metadata,
            audit: None,
            source: None,
        }
    }

    /// Hostname of the report, from the envelope or its metadata.
    pub fn hostname(&self) -> Option<&str> {
        self.host
            .as_deref()
            .filter(|host| !host.is_empty())
            .or_else(|| {
                self.metadata
                    .host
                    .as_deref()
                    .filter(|host| !host.is_empty())
            })
    }

    /// Set the hostname when the report does not carry one.
    pub fn ensure_host(&mut self, fallback: &str) {
        if self.hostname().is_none() {
            self.host = Some(fallback.to_string());
        }
    }

    /// Time of the first finding, in epoch milliseconds.
    pub fn audited_at(&self) -> Option<i64> {
        self.findings.iter().find(|f| f.time > 0).map(|f| f.time)
    }
}

impl From<ocsf::OcsfComplianceFinding> for HtmlFinding {
    fn from(finding: ocsf::OcsfComplianceFinding) -> Self {
        HtmlFinding {
            finding_info: HtmlFindingInfo {
                uid: finding.finding_info.uid,
                title: finding.finding_info.title,
                desc: finding.finding_info.desc,
            },
            compliance: Some(HtmlCompliance {
                standards: finding.compliance.standards,
                status: finding.compliance.status.to_string(),
            }),
            message: finding.message,
            remediation: finding.remediation.map(|remediation| HtmlRemediation {
                desc: remediation.desc,
            }),
            severity: finding.severity,
            status: finding.status.to_string(),
            time: finding.time,
        }
    }
}

/// Render one or more host reports as a single offline HTML document.
pub fn render(reports: &[HtmlReport], generated_at: i64) -> String {
    let totals = total_stats(reports);
    let products = unique_values(reports, |report| {
        let name = report.metadata.product.name.trim();
        let version = report.metadata.product.version.trim();
        match (name.is_empty(), version.is_empty()) {
            (false, false) => Some(format!("{} {}", name, version)),
            (false, true) => Some(name.to_string()),
            _ => None,
        }
    });
    let schemas = unique_values(reports, |report| {
        let version = report.metadata.version.trim();
        (!version.is_empty()).then(|| version.to_string())
    });

    let host_label = if reports.len() == 1 {
        "1 host".to_string()
    } else {
        format!("{} hosts", reports.len())
    };

    let mut out = String::with_capacity(32 * 1024);
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    out.push_str("<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str("<meta name=\"color-scheme\" content=\"light dark\">\n");
    out.push_str(
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; \
         style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; \
         base-uri 'none'\">\n",
    );
    out.push_str("<title>rAudit Security Report</title>\n<style>");
    out.push_str(STYLE);
    out.push_str("</style>\n</head>\n<body>\n<main>\n");

    let _ = writeln!(
        out,
        "<header class=\"page-header\"><h1>rAudit Security Report</h1>\
         <p class=\"subtitle\">Generated {} &middot; {}{}{}</p></header>",
        escape_html(&format_timestamp(generated_at)),
        host_label,
        if products.is_empty() {
            String::new()
        } else {
            format!(" &middot; {}", escape_html(&products.join(", ")))
        },
        if schemas.is_empty() {
            String::new()
        } else {
            format!(" &middot; OCSF schema {}", escape_html(&schemas.join(", ")))
        },
    );

    out.push_str("<section class=\"cards\" aria-label=\"Overview\">\n");
    stat_card(&mut out, "Pass", totals.pass, totals.total, "pass");
    stat_card(&mut out, "Fail", totals.fail, totals.total, "fail");
    stat_card(&mut out, "Warning", totals.warning, totals.total, "warning");
    stat_card(&mut out, "Unknown", totals.unknown, totals.total, "unknown");
    stat_card(&mut out, "Total", totals.total, totals.total, "unknown");
    out.push_str("</section>\n");

    if totals.fail > 0 {
        out.push_str("<h3>Failed by severity</h3>\n<div class=\"host-stats\">\n");
        severity_pill(&mut out, "Critical", totals.fail_critical);
        severity_pill(&mut out, "High", totals.fail_high);
        severity_pill(&mut out, "Medium", totals.fail_medium);
        severity_pill(&mut out, "Low", totals.fail_low);
        severity_pill(&mut out, "Informational", totals.fail_informational);
        out.push_str("</div>\n");
    }

    let show_source = reports.iter().any(|report| report.source.is_some());
    out.push_str("<h2>Hosts</h2>\n<div class=\"table-wrap\"><table class=\"summary\">\n");
    out.push_str("<thead>\n<tr><th rowspan=\"2\">Host</th>");
    if show_source {
        out.push_str("<th rowspan=\"2\">Source</th>");
    }
    out.push_str(
        "<th rowspan=\"2\">Audited</th><th colspan=\"5\">Checks</th>\
         <th colspan=\"5\">Failed by severity</th></tr>\n<tr>\
         <th class=\"num\">Pass</th><th class=\"num\">Fail</th>\
         <th class=\"num\">Warning</th><th class=\"num\">Unknown</th>\
         <th class=\"num\">Total</th>\
         <th class=\"num severity-critical\">Critical</th>\
         <th class=\"num severity-high\">High</th>\
         <th class=\"num severity-medium\">Medium</th>\
         <th class=\"num severity-low\">Low</th>\
         <th class=\"num severity-informational\">Informational</th></tr>\n</thead>\n<tbody>\n",
    );

    for (index, report) in reports.iter().enumerate() {
        let host = report.hostname().unwrap_or("unknown host");
        let anchor = format!("host-{}", index + 1);
        let audited = report
            .audited_at()
            .map(format_timestamp)
            .unwrap_or_else(|| "&mdash;".to_string());

        let _ = writeln!(
            out,
            "<tr><td><a href=\"#{}\">{}</a></td>",
            anchor,
            escape_html(host)
        );
        if show_source {
            let source = report.source.as_deref().unwrap_or("");
            let _ = writeln!(
                out,
                "<td class=\"finding-source\">{}</td>",
                escape_html(source)
            );
        }
        let _ = writeln!(out, "<td>{}</td>", audited);
        summary_stat_cell(
            &mut out,
            report.stats.pass,
            report.stats.total,
            "status-pass",
        );
        summary_stat_cell(
            &mut out,
            report.stats.fail,
            report.stats.total,
            "status-fail",
        );
        summary_stat_cell(
            &mut out,
            report.stats.warning,
            report.stats.total,
            "status-warning",
        );
        summary_stat_cell(
            &mut out,
            report.stats.unknown,
            report.stats.total,
            "status-unknown",
        );
        let _ = writeln!(
            out,
            "<td class=\"num\"><strong>{}</strong></td>",
            report.stats.total
        );
        summary_severity_cell(&mut out, report.stats.fail_critical, "severity-critical");
        summary_severity_cell(&mut out, report.stats.fail_high, "severity-high");
        summary_severity_cell(&mut out, report.stats.fail_medium, "severity-medium");
        summary_severity_cell(&mut out, report.stats.fail_low, "severity-low");
        summary_severity_cell(
            &mut out,
            report.stats.fail_informational,
            "severity-informational",
        );
        out.push_str("</tr>\n");
    }

    if reports.len() > 1 {
        out.push_str("<tr class=\"summary-total\"><td>All hosts</td>");
        if show_source {
            out.push_str("<td></td>");
        }
        out.push_str("<td>&mdash;</td>");
        summary_stat_cell(&mut out, totals.pass, totals.total, "status-pass");
        summary_stat_cell(&mut out, totals.fail, totals.total, "status-fail");
        summary_stat_cell(&mut out, totals.warning, totals.total, "status-warning");
        summary_stat_cell(&mut out, totals.unknown, totals.total, "status-unknown");
        let _ = writeln!(
            out,
            "<td class=\"num\"><strong>{}</strong></td>",
            totals.total
        );
        summary_severity_cell(&mut out, totals.fail_critical, "severity-critical");
        summary_severity_cell(&mut out, totals.fail_high, "severity-high");
        summary_severity_cell(&mut out, totals.fail_medium, "severity-medium");
        summary_severity_cell(&mut out, totals.fail_low, "severity-low");
        summary_severity_cell(
            &mut out,
            totals.fail_informational,
            "severity-informational",
        );
        out.push_str("</tr>\n");
    }

    if reports.is_empty() {
        let columns = if show_source { 14 } else { 13 };
        let _ = writeln!(
            out,
            "<tr><td colspan=\"{}\" class=\"empty\">No host reports in this document.</td></tr>",
            columns
        );
    }
    out.push_str("</tbody></table></div>\n");

    out.push_str("<div class=\"toolbar\" role=\"search\">\n");
    out.push_str(
        "<label class=\"field\">Search<input id=\"filter-search\" type=\"search\" \
         placeholder=\"ID, title, message...\"></label>\n",
    );
    out.push_str(
        "<label class=\"field\">Status<select id=\"filter-status\">\
         <option value=\"\">All</option><option>Pass</option><option>Fail</option>\
         <option>Warning</option><option>Unknown</option></select></label>\n",
    );
    out.push_str(
        "<label class=\"field\">Severity<select id=\"filter-severity\">\
         <option value=\"\">All</option><option>Critical</option><option>High</option>\
         <option>Medium</option><option>Low</option><option>Informational</option>\
         </select></label>\n",
    );
    if reports.len() > 1 {
        out.push_str(
            "<label class=\"field\">Host<select id=\"filter-host\">\
                      <option value=\"\">All</option>",
        );
        for host in unique_values(reports, |report| report.hostname().map(str::to_string)) {
            let _ = write!(
                out,
                "<option value=\"{}\">{}</option>",
                escape_html(&host),
                escape_html(&host)
            );
        }
        out.push_str("</select></label>\n");
    }
    out.push_str(
        "<button type=\"button\" id=\"expand-all\">Expand fixes</button>\
         <button type=\"button\" id=\"collapse-all\">Collapse fixes</button>\
         <span id=\"filter-count\"></span>\n</div>\n",
    );
    out.push_str(
        "<p id=\"filter-empty\" class=\"empty\" hidden>No findings match the current filters.</p>\n",
    );

    for (index, report) in reports.iter().enumerate() {
        render_host(&mut out, report, index + 1);
    }

    out.push_str(
        "<footer>Generated by <a href=\"https://github.com/deoktr/raudit\">rAudit</a>.</footer>\n",
    );
    out.push_str("</main>\n<script>");
    out.push_str(SCRIPT);
    out.push_str("</script>\n</body>\n</html>\n");
    out
}

fn render_host(out: &mut String, report: &HtmlReport, index: usize) {
    let host = report.hostname().unwrap_or("unknown host");
    let anchor = format!("host-{index}");
    let _ = writeln!(
        out,
        "<section class=\"host\" id=\"{}\" data-host=\"{}\">",
        anchor,
        escape_html(host)
    );

    out.push_str("<div class=\"host-header\"><div>");
    let _ = writeln!(out, "<h2>{}</h2>", escape_html(host));
    let mut meta = Vec::new();
    if !report.metadata.product.name.is_empty() {
        let version = report.metadata.product.version.trim();
        if version.is_empty() {
            meta.push(report.metadata.product.name.clone());
        } else {
            meta.push(format!("{} {}", report.metadata.product.name, version));
        }
    }
    if !report.metadata.version.is_empty() {
        meta.push(format!("OCSF {}", report.metadata.version));
    }
    if let Some(start_time) = report.metadata.start_time {
        meta.push(format!("started {}", format_timestamp(start_time)));
    } else if let Some(audited) = report.audited_at() {
        meta.push(format!("audited {}", format_timestamp(audited)));
    }
    if let Some(end_time) = report.metadata.end_time {
        meta.push(format!("finished {}", format_timestamp(end_time)));
    }
    if let Some(elapsed) = report.metadata.elapsed {
        meta.push(format!("took {}", format_elapsed(elapsed)));
    }
    if let Some(username) = &report.metadata.username {
        if !username.is_empty() {
            meta.push(format!("by {}", username));
        }
    }
    if !meta.is_empty() {
        let _ = writeln!(
            out,
            "<p class=\"host-meta\">{}</p>",
            escape_html(&meta.join(" · "))
        );
    }
    out.push_str("</div>");
    if let Some(source) = &report.source {
        let _ = write!(
            out,
            "<p class=\"finding-source\">Source: {}</p>",
            escape_html(source)
        );
    }
    out.push_str("</div>\n");

    out.push_str("<div class=\"host-stats\">\n");
    stat_pill(out, "Pass", report.stats.pass, report.stats.total, "pass");
    stat_pill(out, "Fail", report.stats.fail, report.stats.total, "fail");
    stat_pill(
        out,
        "Warning",
        report.stats.warning,
        report.stats.total,
        "warning",
    );
    stat_pill(
        out,
        "Unknown",
        report.stats.unknown,
        report.stats.total,
        "unknown",
    );
    out.push_str("</div>\n");

    if report.stats.fail > 0 {
        out.push_str("<div class=\"host-stats\">\n");
        severity_pill(out, "Critical", report.stats.fail_critical);
        severity_pill(out, "High", report.stats.fail_high);
        severity_pill(out, "Medium", report.stats.fail_medium);
        severity_pill(out, "Low", report.stats.fail_low);
        severity_pill(out, "Informational", report.stats.fail_informational);
        out.push_str("</div>\n");
    }

    out.push_str("<div class=\"table-wrap\"><table class=\"findings\">\n");
    out.push_str(
        "<thead><tr><th>ID</th><th>Severity</th><th>Title</th>\
         <th>Status</th><th>Details</th></tr></thead>\n<tbody>\n",
    );

    if report.findings.is_empty() {
        out.push_str(
            "<tr><td colspan=\"5\" class=\"empty\">No findings for this host.</td></tr>\n",
        );
    }

    for finding in &report.findings {
        render_finding(out, finding, host);
    }

    out.push_str("</tbody></table></div>\n</section>\n");
}

fn render_finding(out: &mut String, finding: &HtmlFinding, host: &str) {
    let severity = display_severity(finding);
    let state = display_state(finding);
    let severity_class = class_token(severity);
    let status_class = class_token(state);

    let mut search = vec![
        finding.finding_info.uid.clone(),
        finding.finding_info.title.clone(),
        severity.to_string(),
        state.to_string(),
        host.to_string(),
    ];
    if let Some(desc) = &finding.finding_info.desc {
        search.push(desc.clone());
    }
    if let Some(message) = &finding.message {
        search.push(message.clone());
    }
    if let Some(compliance) = &finding.compliance {
        search.extend(compliance.standards.iter().cloned());
    }
    if let Some(remediation) = &finding.remediation {
        search.push(remediation.desc.clone());
    }

    let _ = writeln!(
        out,
        "<tr class=\"finding status-{} severity-{}\" data-status=\"{}\" \
         data-severity=\"{}\" data-host=\"{}\" data-search=\"{}\">",
        status_class,
        severity_class,
        escape_html(state),
        escape_html(severity),
        escape_html(host),
        escape_html(&search.join(" ").to_lowercase()),
    );

    let _ = writeln!(
        out,
        "<td class=\"finding-id\"><code>{}</code></td>",
        escape_html(&finding.finding_info.uid)
    );
    let _ = writeln!(
        out,
        "<td><span class=\"severity severity-{}\">{}</span></td>",
        severity_class,
        escape_html(severity)
    );
    let _ = write!(
        out,
        "<td class=\"finding-title\"><strong>{}</strong>",
        escape_html(&finding.finding_info.title)
    );
    if let Some(desc) = &finding.finding_info.desc {
        let _ = write!(
            out,
            "<span class=\"finding-desc\">{}</span>",
            escape_html(desc)
        );
    }
    out.push_str("</td>");

    let _ = writeln!(
        out,
        "<td><span class=\"badge status-{}\">{}</span></td>",
        status_class,
        escape_html(state)
    );

    out.push_str("<td class=\"finding-detail\">");
    if let Some(message) = &finding.message {
        let _ = write!(
            out,
            "<div class=\"finding-message\">{}</div>",
            escape_html(message)
        );
    }
    if let Some(compliance) = &finding.compliance {
        if !compliance.standards.is_empty() {
            let standards = compliance
                .standards
                .iter()
                .map(|standard| escape_html(standard))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(
                out,
                "<div class=\"finding-standards\">Standards: {}</div>",
                standards
            );
        }
    }
    if let Some(remediation) = &finding.remediation {
        let _ = write!(
            out,
            "<details class=\"remediation\"><summary>Fix</summary><div>{}</div></details>",
            escape_html(&remediation.desc)
        );
    }
    out.push_str("</td></tr>\n");
}

fn stat_card(out: &mut String, label: &str, value: i32, total: i32, class: &str) {
    let _ = writeln!(
        out,
        "<div class=\"card card-{}\"><span class=\"card-label\">{}</span>\
         <span class=\"card-value\">{}</span><span class=\"card-sub\">{} of {} ({})</span></div>",
        class,
        escape_html(label),
        value,
        value,
        total,
        percentage(value, total),
    );
}

fn stat_pill(out: &mut String, label: &str, value: i32, total: i32, class: &str) {
    let _ = writeln!(
        out,
        "<span class=\"stat stat-{}\">{} <strong>{}</strong> <span>({})</span></span>",
        class,
        escape_html(label),
        value,
        percentage(value, total),
    );
}

fn summary_stat_cell(out: &mut String, value: i32, total: i32, class: &str) {
    let _ = writeln!(
        out,
        "<td class=\"num {}\">{} <span class=\"percent\">({})</span></td>",
        class,
        value,
        percentage(value, total),
    );
}

fn summary_severity_cell(out: &mut String, value: i32, class: &str) {
    let _ = writeln!(out, "<td class=\"num {}\">{}</td>", class, value);
}

fn severity_pill(out: &mut String, label: &str, value: i32) {
    let _ = writeln!(
        out,
        "<span class=\"stat severity-{}\">{} <strong>{}</strong></span>",
        class_token(label),
        escape_html(label),
        value,
    );
}

fn total_stats(reports: &[HtmlReport]) -> HtmlStats {
    let mut total = HtmlStats::default();
    for report in reports {
        total.add(&report.stats);
    }
    total
}

fn unique_values(
    reports: &[HtmlReport],
    value: impl Fn(&HtmlReport) -> Option<String>,
) -> Vec<String> {
    let mut values = Vec::new();
    for report in reports {
        if let Some(value) = value(report) {
            if !values.contains(&value) {
                values.push(value);
            }
        }
    }
    values
}

fn display_severity(finding: &HtmlFinding) -> &str {
    match finding.severity.trim() {
        "" => "Unknown",
        // OCSF uses the short label, the report filters use the full one
        "Info" => "Informational",
        severity => severity,
    }
}

fn display_state(finding: &HtmlFinding) -> &str {
    if let Some(compliance) = &finding.compliance {
        let status = compliance.status.trim();
        if !status.is_empty() {
            return status;
        }
    }

    match finding.status.as_str() {
        "Resolved" => "Pass",
        "New" => "Fail",
        "" => "Unknown",
        status => status,
    }
}

fn class_token(value: &str) -> String {
    let mut token = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            token.push(ch.to_ascii_lowercase());
        } else if !token.ends_with('-') {
            token.push('-');
        }
    }
    let token = token.trim_matches('-');
    if token.is_empty() {
        "unknown".to_string()
    } else {
        token.to_string()
    }
}

fn percentage(value: i32, total: i32) -> String {
    if total > 0 {
        format!("{:.2}%", (value as f64 / total as f64) * 100.0)
    } else {
        "0.00%".to_string()
    }
}

/// Escape a value before inserting it into HTML text or an attribute.
fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Format an audit duration stored in milliseconds.
fn format_elapsed(milliseconds: i64) -> String {
    if milliseconds <= 0 {
        return "0.00 ms".to_string();
    }

    utils::format_duration(std::time::Duration::from_millis(milliseconds as u64))
}

/// Format epoch milliseconds as `YYYY-MM-DD HH:MM:SS UTC`.
fn format_timestamp(milliseconds: i64) -> String {
    let seconds = milliseconds.div_euclid(1000);
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hour, minute, second
    )
}

/// Convert days since the Unix epoch to a civil date.
///
/// Algorithm from Howard Hinnant's `chrono`-compatible `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    if month <= 2 {
        year += 1;
    }

    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(uid: &str, title: &str, severity: &str, status: &str) -> HtmlFinding {
        HtmlFinding {
            finding_info: HtmlFindingInfo {
                uid: uid.to_string(),
                title: title.to_string(),
                desc: Some(format!("Description of {uid}")),
            },
            compliance: Some(HtmlCompliance {
                standards: vec!["raudit".to_string()],
                status: status.to_string(),
            }),
            message: Some(format!("Message of {uid}")),
            remediation: Some(HtmlRemediation {
                desc: format!("Fix {uid}"),
            }),
            severity: severity.to_string(),
            status: if status == "Pass" { "Resolved" } else { "New" }.to_string(),
            time: 1_700_000_000_000,
        }
    }

    fn report(host: &str, findings: Vec<HtmlFinding>) -> HtmlReport {
        let fail = findings
            .iter()
            .filter(|finding| display_state(finding) == "Fail")
            .count() as i32;
        let pass = findings
            .iter()
            .filter(|finding| display_state(finding) == "Pass")
            .count() as i32;
        let total = findings.len() as i32;
        HtmlReport {
            host: Some(host.to_string()),
            findings,
            stats: HtmlStats {
                total,
                pass,
                fail,
                warning: 0,
                unknown: 0,
                fail_critical: 0,
                fail_high: fail,
                fail_medium: 0,
                fail_low: 0,
                fail_informational: 0,
            },
            metadata: HtmlMetadata {
                version: "1.9.0".to_string(),
                product: HtmlProduct {
                    name: "raudit".to_string(),
                    version: "0.39.0".to_string(),
                },
                reporter: HtmlReporter::default(),
                host: Some(host.to_string()),
                start_time: Some(1_700_000_000_000),
                end_time: Some(1_700_000_001_250),
                elapsed: Some(1_250),
                username: Some("tester".to_string()),
            },
            audit: None,
            source: None,
        }
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(
            escape_html("<script>\"a&b\"</script>"),
            "&lt;script&gt;&quot;a&amp;b&quot;&lt;/script&gt;"
        );
    }

    #[test]
    fn test_format_timestamp() {
        assert_eq!(format_timestamp(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(
            format_timestamp(1_700_000_000_000),
            "2023-11-14 22:13:20 UTC"
        );
    }

    #[test]
    fn test_format_elapsed() {
        assert_eq!(format_elapsed(0), "0.00 ms");
        assert_eq!(format_elapsed(-1), "0.00 ms");
        assert_eq!(format_elapsed(1_250), "1.25 s");
    }

    #[test]
    fn test_parse_requires_core_fields() {
        assert!(HtmlReport::from_json(r#"{"findings":[]}"#).is_err());
        assert!(
            HtmlReport::from_json(r#"{"findings":[],"stats":{},"metadata":{"version":"1.9.0"}}"#)
                .is_ok()
        );
    }

    #[test]
    fn test_parse_old_report_without_host() {
        let json = r#"{
            "findings": [],
            "stats": {"total": 0},
            "metadata": {"version": "1.9.0", "product": {"name": "raudit", "version": "0.1.0"}}
        }"#;
        let mut report = HtmlReport::from_json(json).unwrap();
        assert!(report.hostname().is_none());
        report.ensure_host("legacy-host");
        assert_eq!(report.hostname(), Some("legacy-host"));
    }

    #[test]
    fn test_parse_reporter_and_audit() {
        let json = r#"{
            "findings": [],
            "stats": {"total": 0},
            "metadata": {
                "version": "1.9.0",
                "product": {"name": "raudit", "version": "0.1.0"},
                "reporter": {"name": "host-one", "hostname": "host-one"}
            },
            "audit": {
                "start_time": 1700000000000,
                "end_time": 1700000001250,
                "duration": 1250,
                "username": "tester"
            }
        }"#;
        let report = HtmlReport::from_json(json).unwrap();

        assert_eq!(report.hostname(), Some("host-one"));
        assert_eq!(report.metadata.start_time, Some(1_700_000_000_000));
        assert_eq!(report.metadata.end_time, Some(1_700_000_001_250));
        assert_eq!(report.metadata.elapsed, Some(1_250));
        assert_eq!(report.metadata.username.as_deref(), Some("tester"));
    }

    #[test]
    fn test_parse_legacy_metadata_fields() {
        let json = r#"{
            "findings": [],
            "stats": {"total": 0},
            "metadata": {
                "version": "1.9.0",
                "product": {"name": "raudit", "version": "0.1.0"},
                "host": "host-one",
                "start_time": 1700000000000,
                "end_time": 1700000001250,
                "elapsed": 1250,
                "username": "tester"
            }
        }"#;
        let report = HtmlReport::from_json(json).unwrap();

        assert_eq!(report.hostname(), Some("host-one"));
        assert_eq!(report.metadata.start_time, Some(1_700_000_000_000));
        assert_eq!(report.metadata.elapsed, Some(1_250));
        assert_eq!(report.metadata.username.as_deref(), Some("tester"));
    }

    #[test]
    fn test_render_single_host_embeds_everything() {
        let html = render(
            &[report(
                "host-one",
                vec![finding("TST_001", "Test <check>", "High", "Fail")],
            )],
            1_700_000_000_000,
        );

        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("host-one"));
        assert!(html.contains("TST_001"));
        assert!(html.contains("Test &lt;check&gt;"));
        assert!(html.contains("2023-11-14 22:13:20 UTC"));
        assert!(html.contains("started 2023-11-14 22:13:20 UTC"));
        assert!(html.contains("finished 2023-11-14 22:13:21 UTC"));
        assert!(html.contains("took 1.25 s"));
        assert!(html.contains("by tester"));
        assert!(html.contains("Failed by severity"));
        assert!(html.contains("<th colspan=\"5\">Checks</th>"));
        assert!(html.contains(
            "<td class=\"num status-fail\">1 <span class=\"percent\">(100.00%)</span></td>"
        ));
        assert!(html.contains("<td class=\"num severity-high\">1</td>"));
        assert!(html.contains("Content-Security-Policy"));
        assert!(html.contains("<style>"));
        assert!(html.contains("<script>"));
        // no external asset, script, style or font can be needed to open it;
        // ordinary hyperlinks in the footer are allowed
        assert!(!html.contains("<link"));
        assert!(!html.contains("src=\"http"));
        assert!(!html.contains("@import"));
        assert!(!html.contains("url(http"));
    }

    #[test]
    fn test_render_multiple_hosts_and_totals() {
        let html = render(
            &[
                report(
                    "host-one",
                    vec![
                        finding("TST_001", "First", "High", "Fail"),
                        finding("TST_002", "Second", "Low", "Pass"),
                    ],
                ),
                report(
                    "host-two",
                    vec![finding("TST_003", "Third", "Critical", "Fail")],
                ),
            ],
            1_700_000_000_000,
        );

        assert!(html.contains("host-one"));
        assert!(html.contains("host-two"));
        assert!(html.contains("TST_001"));
        assert!(html.contains("TST_003"));
        assert!(html.contains("2 hosts"));
        assert!(html.contains("<option value=\"host-one\">host-one</option>"));
        assert!(html.contains("<td>All hosts</td>"));
        assert!(html.contains("<td class=\"num severity-high\">2</td>"));
    }

    #[test]
    fn test_render_escapes_host_and_finding_data() {
        let mut finding = finding("TST_001", "<script>alert(1)</script>", "High", "Fail");
        finding.message = Some("\"quoted\" & <unsafe>".to_string());
        let mut report = report("<host & one>", vec![finding]);
        report.source = Some("<source>.json".to_string());

        let html = render(&[report], 1_700_000_000_000);

        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<host & one>"));
        assert!(html.contains("&lt;host &amp; one&gt;"));
        assert!(html.contains("&quot;quoted&quot; &amp; &lt;unsafe&gt;"));
    }

    #[test]
    fn test_from_checks() {
        let stats = ReportStats {
            total: 1,
            pass: 1,
            ..ReportStats::default()
        };
        let report = HtmlReport::from_checks(&[], stats, "live-host", 1_700_000_000_000);

        assert_eq!(report.hostname(), Some("live-host"));
        assert_eq!(report.stats.total, 1);
        assert_eq!(report.stats.pass, 1);
        assert_eq!(report.metadata.start_time, Some(1_700_000_000_000));
        assert!(report.metadata.end_time.is_some());
        assert!(report.metadata.elapsed.is_some());
        assert!(
            report
                .metadata
                .username
                .as_deref()
                .is_some_and(|username| !username.is_empty())
        );
    }
}
