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

use super::types::{Check, CheckState, REPORT, ReportStats, Severity};
use crate::{config, consts, ocsf, utils};

/// Maximum width of a printed line.
const OUTPUT_WIDTH: usize = 100;

/// Prefix of every line belonging to a check.
const CHILD_PREFIX: &str = "| ";

/// Width left for the content of a line belonging to a check.
const CHILD_WIDTH: usize = OUTPUT_WIDTH - CHILD_PREFIX.len();

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

/// Print list of available severity levels.
pub fn print_severities() {
    println!("Available severities: informational, low, medium, high, critical.");
}

/// Style `text` with an ANSI attribute, or return it as is when colored output
/// is disabled.
fn styled(attribute: &str, reset: &str, text: &str) -> String {
    if config::is_colored_output_enabled() {
        format!("{}{}{}", attribute, text, reset)
    } else {
        text.to_string()
    }
}

/// Highlight with `CODE_BACKGROUND` the backtick delimited spans of `line`,
/// they wrap commands, file paths and configuration entries.
fn highlight_code(line: &str, in_code: &mut bool) -> String {
    if !config::is_colored_output_enabled() {
        return line.to_string();
    }

    let mut out = String::with_capacity(line.len());
    let mut rest = line;

    if *in_code {
        out.push_str(consts::CODE_STYLE);
    }

    while let Some((before, after)) = rest.split_once('`') {
        out.push_str(before);

        if *in_code {
            out.push('`');
            out.push_str(consts::RESET_CODE_STYLE);
        } else {
            out.push_str(consts::CODE_STYLE);
            out.push('`');
        }

        *in_code = !*in_code;
        rest = after;
    }

    out.push_str(rest);

    if *in_code {
        out.push_str(consts::RESET_CODE_STYLE);
    }

    out
}

/// Print the check header, wrapping the title to the output width.
fn print_check_header(check: &Check) {
    let color = check.state_color();
    let reset = if color.is_empty() {
        ""
    } else {
        consts::RESET_COLOR
    };
    let header = format!("{}{}", check.header_prefix(), check.title);
    let lines = utils::wrap_text(&header, OUTPUT_WIDTH);

    if let Some((first, rest)) = lines.split_first() {
        println!("{}{}", first, reset);

        for line in rest {
            println!("{}{}{}", color, line, reset);
        }
    }
}

/// Print a line belonging to a check, wrapped to the output width.
fn print_check_line(text: &str) {
    let prefix = styled(consts::DIM_COLOR, consts::RESET_COLOR, CHILD_PREFIX);
    let mut in_code = false;

    for line in utils::wrap_text(text, CHILD_WIDTH) {
        println!("{}{}", prefix, highlight_code(&line, &mut in_code));
    }
}

/// Print a check detail, with its label in bold, wrapped to the output width.
fn print_check_detail(label: &str, text: &str) {
    let label = styled(consts::BOLD_STYLE, consts::RESET_BOLD_STYLE, label);
    print_check_line(format!("{} {}", label, text).trim_end());
}

/// Print list of checks, with option to skip passed checks.
pub fn print_checks(skip_passed: bool, no_print_description: bool, no_print_fix: bool) {
    let report = REPORT.lock().expect("Checks not initialized");

    for check in report.checks.iter() {
        if skip_passed && check.state == CheckState::Pass {
            continue;
        }

        print_check_header(check);

        let mut add_new_line = false;

        if let Some(message) = &check.message {
            print_check_detail("Result:", message);
            add_new_line = true;
        }

        if check.state != CheckState::Pass
            && !no_print_description
            && let Some(description) = &check.description
        {
            print_check_detail("Description:", description);
            add_new_line = true;
        }

        if check.state == CheckState::Fail
            && !no_print_fix
            && let Some(fix) = &check.fix
        {
            print_check_detail("Fix:", fix);
            add_new_line = true;
        }

        if check.state == CheckState::Fail && !check.links.is_empty() {
            print_check_detail("Links:", "");
            for link in &check.links {
                print_check_line(link);
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
