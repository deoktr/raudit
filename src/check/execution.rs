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

use super::types::{DependencyFn, REPORT};
use rayon::iter::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};
use std::collections::HashSet;

/// Run checks.
pub fn run_checks(parallel: bool) {
    let mut report = REPORT.lock().unwrap();

    if parallel {
        report.checks.par_iter_mut().for_each(|check| check.run());
    } else {
        report.checks.iter_mut().for_each(|check| check.run());
    }
}

/// Run dependencies.
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
