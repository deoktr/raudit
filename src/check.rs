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

use crate::config;

// static mut CHECKS: Vec<Check> = Vec::new();

pub struct CheckList<'a> {
    pub checks: Vec<&'a mut Check<'a>>,
}

impl CheckList<'_> {
    pub fn run(&mut self) {
        for check in &mut self.checks {
            // ignore any already ran, or skipped tests
            if check.state != CheckState::Waiting {
                continue;
            }
            check.run();
        }
    }

    /// Filter checks by id prefix.
    pub fn filter_id(&mut self, prefixes: Vec<String>) {
        if prefixes.len() == 0 {
            return;
        }

        self.checks
            .retain(|check| prefixes.iter().any(|prefix| check.id.starts_with(prefix)));
    }

    pub fn print(&mut self) {
        for check in &mut self.checks {
            check.print();
        }
    }

    pub fn get_stats(self) -> CheckListStats {
        let mut stats = CheckListStats::default();

        for check in self.checks {
            stats.total += 1;
            match check.state {
                CheckState::Valid => stats.valid += 1,
                CheckState::Invalid => stats.invalid += 1,
                CheckState::Skipped => stats.skipped += 1,
                CheckState::Error => stats.error += 1,
                CheckState::Waiting => stats.waiting += 1,
            }
        }
        return stats;
    }

    pub fn print_stats(self) {
        let stats = self.get_stats();
        stats.print();
    }
}

#[derive(Default)]
pub struct CheckListStats {
    total: i32,
    valid: i32,
    invalid: i32,
    skipped: i32,
    error: i32,
    waiting: i32,
}

impl CheckListStats {
    pub fn print(self) {
        if config::is_colored_output_enabled() {
            println!("\nResult:");
            println!("\x1b[32m  VALID:   {}/{}\x1b[39m", self.valid, self.total);
            println!("\x1b[31m  INVALID: {}/{}\x1b[39m", self.invalid, self.total);
            println!("\x1b[34m  SKIPPED: {}/{}\x1b[39m", self.skipped, self.total);
            println!("\x1b[36m  ERROR:   {}/{}\x1b[39m", self.error, self.total);
            println!("\x1b[36m  WAITING: {}/{}\x1b[39m", self.waiting, self.total);
        } else {
            println!("\nResult:");
            println!("  VALID:   {}/{}", self.valid, self.total);
            println!("  INVALID: {}/{}", self.invalid, self.total);
            println!("  SKIPPED: {}/{}", self.skipped, self.total);
            println!("  ERROR:   {}/{}", self.error, self.total);
            println!("  WAITING: {}/{}", self.waiting, self.total);
        }
    }
}

#[derive(PartialEq)]
pub enum CheckState {
    Valid,
    Invalid,
    #[allow(dead_code)]
    Skipped,
    Error,
    Waiting,
}

/// A security check.
pub struct Check<'a> {
    id: String,
    title: String,
    message: String,
    state: CheckState,
    // the func returns the check state and an optional message
    func: &'a dyn Fn() -> (CheckState, Option<String>),
}

impl Check<'_> {
    pub fn new<'a>(
        id: String,
        title: String,
        func: &'a dyn Fn() -> (CheckState, Option<String>),
    ) -> Check<'a> {
        Check {
            id,
            title,
            message: "".to_string(),
            state: CheckState::Waiting,
            func,
        }
    }

    pub fn run(&mut self) {
        let (state, message) = (self.func)();
        self.state = state;
        match message {
            Some(m) => self.message = m,
            None => (),
        }
    }

    /// Output result to stdout.
    pub fn print(&self) {
        let mut out = format!("[{}] {}", self.id, self.title);
        if !self.message.is_empty() {
            out = format!("{}: ({})", out, self.message);
        }
        if config::is_colored_output_enabled() {
            match self.state {
                CheckState::Valid => println!("\x1b[32m{}\x1b[39m", out),
                CheckState::Invalid => println!("\x1b[31m{}\x1b[39m", out),
                CheckState::Skipped => println!("\x1b[34m{}\x1b[39m", out),
                CheckState::Error => println!("\x1b[36m{}\x1b[39m", out),
                CheckState::Waiting => println!("\x1b[36m{} NOT RAN!\x1b[39m", out),
            }
        } else {
            match self.state {
                CheckState::Waiting => println!("{} NOT RAN!", out),
                _ => println!("{}", out),
            }
        }
    }
}
