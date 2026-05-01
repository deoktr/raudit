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

use crate::*;
use clap::Parser;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Audit Linux systems security configurations
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Comma-separated list of tags to include
    #[arg(long, value_delimiter = ',', num_args(0..), env = "TAGS")]
    tags: Option<Vec<String>>,

    /// Comma-separated list of tags to exclude
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

    /// Generate JSON output
    #[arg(long, action = clap::ArgAction::SetTrue, env = "JSON")]
    json: bool,
}

pub fn cli() {
    let now = Instant::now();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock before UNIX epoch")
        .as_millis() as i64;

    let args = Cli::parse();

    config::set_colored_output(!args.no_colors);

    logger::set_log_level(args.log_level);

    add_all_checks();

    match args.tags {
        None => (),
        Some(ref tags) if tags.is_empty() => {
            check::print_tags();
            return;
        }
        Some(tags) => check::filter_tags(tags),
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
        Some(tags_exclude) => check::filter_tags_exclude(tags_exclude),
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

    check::remove_skipped(!args.no_parallelization);

    check::run_dependencies(!args.no_parallelization);
    check::run_checks(!args.no_parallelization);

    if !args.json {
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
    } else {
        check::calculate_stats();

        check::print_json(timestamp);
    }

    if !args.no_time {
        eprintln!("took: {}", utils::format_duration(now.elapsed()));
    }
}

// add checks for all modules
fn add_all_checks() {
    rules::apparmor::add_checks();
    rules::apt::add_checks();
    rules::audit::add_checks();
    rules::bin::add_checks();
    rules::clamav::add_checks();
    rules::cron::add_checks();
    rules::docker::add_checks();
    rules::gdm::add_checks();
    rules::group::add_checks();
    rules::grub::add_checks();
    rules::hosts::add_checks();
    rules::kernel::add_checks();
    rules::kernel_params::add_checks();
    rules::login_defs::add_checks();
    rules::malloc::add_checks();
    rules::modprobe::add_checks();
    rules::mount::add_checks();
    rules::nginx::add_checks();
    rules::pam::add_checks();
    rules::podman::add_checks();
    rules::shell::add_checks();
    rules::sshd::add_checks();
    rules::sudo::add_checks();
    rules::sysctl::add_checks();
    rules::system::add_checks();
    rules::systemd::add_checks();
    rules::uptime::add_checks();
    rules::user::add_checks();
}
