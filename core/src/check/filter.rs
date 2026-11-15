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

/// Separator intersecting the tags of a single selector group.
const TAG_INTERSECT: char = '+';

type TagSelector = Vec<Vec<String>>;

/// Parse raw tag values into a selector, a list of tag groups.
///
/// A group is a set of tags that must all be present on a check, and groups are
/// alternatives of each other. Values are already split on the comma separator,
/// so each of them becomes a group, and [`TAG_INTERSECT`] adds tags to it. So
/// `["sysctl", "workstation"]` selects the union of both tags, while
/// `["sysctl+workstation"]` selects their intersection (both must be present).
pub fn parse_tag_selector(values: &[String]) -> TagSelector {
    values
        .iter()
        .filter_map(|value| {
            let group: Vec<String> = value
                .split(TAG_INTERSECT)
                .map(|tag| tag.trim())
                .filter(|tag| !tag.is_empty())
                .map(|tag| tag.to_string())
                .collect();
            (!group.is_empty()).then_some(group)
        })
        .collect()
}

/// Return true if `tags` matches at least one group of `selector`.
fn matches_selector(tags: &[String], selector: &[Vec<String>]) -> bool {
    selector
        .iter()
        .any(|group| group.iter().all(|tag| tags.contains(tag)))
}

/// Filter checks by their tags.
pub fn filter_tags(selector: TagSelector) {
    if selector.is_empty() {
        return;
    }

    let mut report = REPORT.lock().unwrap();
    report
        .checks
        .retain(|check| matches_selector(&check.tags, &selector));
}

/// Filter out checks by their tags.
pub fn filter_tags_exclude(selector: TagSelector) {
    if selector.is_empty() {
        return;
    }

    let mut report = REPORT.lock().unwrap();
    report
        .checks
        .retain(|check| !matches_selector(&check.tags, &selector));
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
