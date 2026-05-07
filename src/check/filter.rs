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

use super::types::{REPORT, Severity, SkipFn};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::collections::{HashMap, HashSet};

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

/// Exclude skipped checks.
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
