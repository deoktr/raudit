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

use clap::Parser;
use raudit_core::html::{self, HtmlReport};
use raudit_core::{check, config, logger, utils};
use raudit_rules as rules;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Extended help printed by `--help` after the list of options.
const LONG_HELP: &str = r#"Selection:

  By default every check runs. Each selection flag narrows that set down, and
  the flags combine with AND: a check has to satisfy --tags, --filters and
  --severity at the same time, and match neither --tags-exclude nor
  --filters-exclude. Inside a single flag the values are alternatives, except
  for the tag groups described below.

  Checks that cannot apply to the host are skipped and hidden from the report,
  use --no-skip to keep them.

  Every selection flag prints the vocabulary it accepts when given no value:

    raudit --tags              list all tags
    raudit --filters           list all ID prefixes
    raudit --severity-exact    list all severity levels

Tags:

  A tag is a free-form label attached to a check, and a check usually carries
  several. They describe the role it targets (server, workstation), its cost
  and applicability (slow, conditional), the subsystem it inspects (sysctl,
  kernel, kconfig, modprobe, sshd, apt, pam, sudo, mount, docker, ...), the
  source (CIS, STIG, KSPP, mozilla, tails).

  Tags are selected with a comma separates list. A '+' joins the tags of a
  group that all have to be present, so it is an intersection. Groups are
  alternatives of each other:

    --tags sysctl,workstation       every sysctl OR every workstation check
    --tags sysctl+workstation       sysctl checks that also target workstations
    --tags sysctl+workstation,apt   that intersection, plus every apt check

  --tags-exclude takes the same grammar, and drops a check only when the whole
  group matches:

    --tags-exclude slow             drop every slow check
    --tags-exclude slow+server      drop the slow checks targeting servers

Filters:

  A filter matches the check ID by prefix, so it selects either a family of
  rules or one exact rule. Matching is a plain string prefix, so the shorter
  the value the more it selects:

    --filters APT                   every apt rule
    --filters SYK,SYN               kernel and network sysctls
    --filters SYK_00                SYK_001 up to SYK_009
    --filters USR_001               one exact rule

  --filters-exclude take the same grammar, and drops checks on match

Severity:

  Five ascending levels, matched case-insensitively: informational, low,
  medium, high, critical. --severity is a floor and keeps everything above it,
  --severity-exact is a closed set, and the two cannot be combined:

    --severity high                 high and critical
    --severity-exact medium,high    exactly those two

Environment:

  Every flag has an env var counterpart accepting the same values:

    TAGS=sysctl+workstation SEVERITY=high raudit

Output:

  By default checks are printed to the terminal. --json emits OCSF Compliance
  Finding JSON, --html emits a self-contained HTML report. Use --output to write
  the HTML report to a file instead of stdout.

  --convert reads one or more OCSF JSON reports, each from a different host, and
  combines them into a single HTML report. Use - as a file name to read a report
  from stdin. The HTML report embeds all of its styles and scripts, so it works
  offline, with no network access.

    raudit --html -o report.html
    raudit --json > host1.json
    raudit --convert host1.json host2.json -o report.html
    raudit --convert - < host1.json > report.html

Examples:

  Audit a workstation, without the noisy or expensive families:

    raudit --severity high \
           --tags workstation \
           --tags-exclude modprobe,kernel_build_conf,sysctl,audit,kernel

  Audit a server, high severity and above, only show failed or warnings:

    raudit --tags server --severity high --no-print-passed

  Kernel modules that a workstation should have disabled:

    raudit --tags modprobe+workstation

  Machine readable report for a single rule:

    raudit --json --filters USR_001"#;

/// Audit Linux systems security configurations
#[derive(Debug, Parser)]
#[command(name = "raudit", version, after_long_help = LONG_HELP)]
struct Cli {
    /// Comma-separated list of tags to include, '+' requires all tags of a group
    #[arg(long, value_delimiter = ',', num_args(0..), env = "TAGS")]
    tags: Option<Vec<String>>,

    /// Comma-separated list of tags to exclude, '+' requires all tags of a group
    #[arg(long, value_delimiter = ',', num_args(0..), env = "TAGS_EXCLUDE")]
    tags_exclude: Option<Vec<String>>,

    /// Comma-separated list of ID prefixes to include
    #[arg(long, value_delimiter = ',', num_args(0..), env = "FILTERS")]
    filters: Option<Vec<String>>,

    /// Comma-separated list of ID prefixes to exclude
    #[arg(long, value_delimiter = ',', num_args(0..), env = "FILTERS_EXCLUDE")]
    filters_exclude: Option<Vec<String>>,

    /// Minimum severity level to include (includes specified level and above)
    #[arg(long, conflicts_with = "severity_exact", env = "SEVERITY")]
    severity: Option<String>,

    /// Comma-separated list of exact severity levels to include
    #[arg(long, value_delimiter = ',', num_args(0..), conflicts_with = "severity", env = "SEVERITY_EXACT")]
    severity_exact: Option<Vec<String>>,

    /// Log level
    #[arg(long, value_enum, default_value_t = logger::DEFAULT_LOG_LEVEL, env = "LOG_LEVEL")]
    log_level: logger::LogLevel,

    /// Disable multi-threading parallelization
    #[arg(long, action = clap::ArgAction::SetTrue, env = "NO_PARALLELIZATION")]
    no_parallelization: bool,

    /// Disable print of individual checks
    #[arg(long, action = clap::ArgAction::SetTrue, env = "NO_PRINT_CHECKS")]
    no_print_checks: bool,

    /// Disable print of passed checks
    #[arg(long, action = clap::ArgAction::SetTrue, env = "NO_PRINT_PASSED")]
    no_print_passed: bool,

    /// Disable print of check description
    #[arg(long, action = clap::ArgAction::SetTrue, env = "NO_PRINT_DESCRIPTION")]
    no_print_description: bool,

    /// Disable print of check fix if it failed
    #[arg(long, action = clap::ArgAction::SetTrue, env = "NO_PRINT_FIX")]
    no_print_fix: bool,

    /// Disable print of stats
    #[arg(long, action = clap::ArgAction::SetTrue, env = "NO_STATS")]
    no_stats: bool,

    /// Disable colored output
    #[arg(long, action = clap::ArgAction::SetTrue, env = "NO_COLORS")]
    no_colors: bool,

    /// Disable timer
    #[arg(long, action = clap::ArgAction::SetTrue, env = "NO_TIME")]
    no_time: bool,

    /// Disable automatic skipping of rules
    #[arg(long, action = clap::ArgAction::SetTrue, env = "NO_SKIP")]
    no_skip: bool,

    /// Generate JSON output
    #[arg(
        long,
        action = clap::ArgAction::SetTrue,
        env = "JSON",
        conflicts_with_all = ["html", "convert"]
    )]
    json: bool,

    /// Generate a self-contained HTML report
    #[arg(
        long,
        action = clap::ArgAction::SetTrue,
        env = "HTML",
        conflicts_with_all = ["json", "convert"]
    )]
    html: bool,

    /// Convert one or more OCSF JSON reports to a single HTML report
    #[arg(
        long,
        value_name = "FILE",
        num_args = 1..,
        env = "CONVERT",
        conflicts_with_all = ["json", "html"]
    )]
    convert: Option<Vec<PathBuf>>,

    /// Write the HTML report to FILE instead of stdout
    #[arg(short = 'o', long, value_name = "FILE", env = "OUTPUT")]
    output: Option<PathBuf>,
}

pub fn cli() {
    let now = Instant::now();
    let timestamp = utils::now_millis();

    let args = Cli::parse();

    if args.output.is_some() && !args.html && args.convert.is_none() {
        eprintln!("--output requires --html or --convert");
        std::process::exit(2);
    }

    if let Some(ref inputs) = args.convert {
        if let Err(err) = convert_reports(inputs, args.output.as_deref(), timestamp) {
            eprintln!("error: {}", err);
            std::process::exit(1);
        }

        if !args.no_time {
            eprintln!("took: {}", utils::format_duration(now.elapsed()));
        }
        return;
    }

    config::set_colored_output(!args.no_colors);

    logger::set_log_level(args.log_level);

    rules::add_all_checks();

    match args.tags {
        None => (),
        Some(ref tags) if tags.is_empty() => {
            check::print_tags();
            return;
        }
        Some(ref tags) => check::filter_tags(check::parse_tag_selector(tags)),
    }

    match args.filters {
        None => (),
        Some(ref filters) if filters.is_empty() => {
            check::print_id_prefixes();
            return;
        }
        Some(filters) => check::filter_id(filters),
    }

    match args.tags_exclude {
        None => (),
        Some(ref tags_exclude) if tags_exclude.is_empty() => {
            check::print_tags();
            return;
        }
        Some(ref tags_exclude) => {
            check::filter_tags_exclude(check::parse_tag_selector(tags_exclude))
        }
    }

    match args.filters_exclude {
        None => (),
        Some(ref filters_exclude) if filters_exclude.is_empty() => {
            check::print_id_prefixes();
            return;
        }
        Some(filters_exclude) => check::filter_id_exclude(filters_exclude),
    }

    match args.severity {
        None => (),
        Some(severity) => match check::Severity::from_str(&severity) {
            Ok(min) => check::filter_severity(min),
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        },
    }

    match args.severity_exact {
        None => (),
        Some(ref severity_exact) if severity_exact.is_empty() => {
            check::print_severities();
            return;
        }
        Some(ref severity_exact) => {
            let mut levels = Vec::new();
            for s in severity_exact {
                match check::Severity::from_str(s) {
                    Ok(level) => {
                        if !levels.contains(&level) {
                            levels.push(level);
                        }
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                }
            }
            check::filter_severity_exact(levels);
        }
    }

    if !args.no_skip {
        check::remove_skipped(!args.no_parallelization);
    }

    check::run_dependencies(!args.no_parallelization);
    check::run_checks(!args.no_parallelization);

    if args.html {
        check::calculate_stats();

        let document = check::build_html(timestamp, &utils::hostname());
        if let Err(err) = write_output(&document, args.output.as_deref()) {
            eprintln!("error: {}", err);
            std::process::exit(1);
        }
    } else if args.json {
        check::calculate_stats();

        check::print_json(timestamp);
    } else {
        if !args.no_print_checks {
            check::print_checks(
                args.no_print_passed,
                args.no_print_description,
                args.no_print_fix,
            );
        }

        if !args.no_stats {
            check::calculate_stats();
            check::print_stats();
        }
    }

    if !args.no_time {
        eprintln!("took: {}", utils::format_duration(now.elapsed()));
    }
}

/// Convert one or more OCSF JSON files into a single HTML report.
fn convert_reports(
    inputs: &[PathBuf],
    output: Option<&Path>,
    timestamp: i64,
) -> Result<(), String> {
    let mut reports = Vec::with_capacity(inputs.len());

    for input in inputs {
        let content = read_input(input)?;
        let mut report = HtmlReport::from_json(&content)
            .map_err(|err| format!("{}: invalid OCSF report: {}", display_input(input), err))?;
        report.ensure_host(&fallback_host(input));
        report.source = Some(display_input(input));
        reports.push(report);
    }

    let document = html::render(&reports, timestamp);
    write_output(&document, output)
}

/// Read a report from a file, or from stdin when the path is `-`.
fn read_input(path: &Path) -> Result<String, String> {
    if path == Path::new("-") {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .map_err(|err| format!("failed to read stdin: {}", err))?;
        Ok(input)
    } else {
        fs::read_to_string(path)
            .map_err(|err| format!("failed to read `{}`: {}", path.display(), err))
    }
}

/// Name to use when a report does not carry a hostname.
fn fallback_host(path: &Path) -> String {
    if path == Path::new("-") {
        return "stdin".to_string();
    }

    path.file_stem()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

/// Human-readable source name shown in the report.
fn display_input(path: &Path) -> String {
    if path == Path::new("-") {
        "stdin".to_string()
    } else {
        path.display().to_string()
    }
}

/// Write an HTML document to a file, or to stdout when no path is given.
fn write_output(content: &str, output: Option<&Path>) -> Result<(), String> {
    match output {
        Some(path) if path == Path::new("-") => {
            print!("{}", content);
            Ok(())
        }
        Some(path) => fs::write(path, content)
            .map_err(|err| format!("failed to write `{}`: {}", path.display(), err)),
        None => {
            print!("{}", content);
            Ok(())
        }
    }
}
