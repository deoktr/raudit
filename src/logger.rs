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

use clap::ValueEnum;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, PartialEq, PartialOrd, Clone, ValueEnum)]
pub enum LogLevel {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Info;

static LOG_LEVEL: AtomicU8 = AtomicU8::new(DEFAULT_LOG_LEVEL as u8);

/// Set log level.
pub fn set_log_level(level: LogLevel) {
    LOG_LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Get current log level.
pub fn current_log_level() -> LogLevel {
    match LOG_LEVEL.load(Ordering::Relaxed) {
        1 => LogLevel::Error,
        2 => LogLevel::Warn,
        3 => LogLevel::Info,
        4 => LogLevel::Debug,
        5 => LogLevel::Trace,
        _ => DEFAULT_LOG_LEVEL,
    }
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        if $crate::logger::LogLevel::Error <= $crate::logger::current_log_level() {
            if $crate::config::is_colored_output_enabled() {
                eprintln!("\x1b[31m[!] {}\x1b[0m", format!($($arg)*))
            } else {
                eprintln!("[ERROR] {}", format!($($arg)*))
            }
        }
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        if $crate::logger::LogLevel::Warn <= $crate::logger::current_log_level() {
            if $crate::config::is_colored_output_enabled() {
                eprintln!("\x1b[33m[-] {}\x1b[0m", format!($($arg)*))
            } else {
                eprintln!("[WARN] {}", format!($($arg)*))
            }
        }
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        if $crate::logger::LogLevel::Info <= $crate::logger::current_log_level() {
            if $crate::config::is_colored_output_enabled() {
                eprintln!("\x1b[32m[+] {}\x1b[0m", format!($($arg)*))
            } else {
                eprintln!("[INFO] {}", format!($($arg)*))
            }
        }
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if $crate::logger::LogLevel::Debug <= $crate::logger::current_log_level() {
            if $crate::config::is_colored_output_enabled() {
                eprintln!("\x1b[36m[*] {}\x1b[0m", format!($($arg)*))
            } else {
                eprintln!("[DEBUG] {}", format!($($arg)*))
            }
        }
    };
}

#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => {
        if $crate::logger::LogLevel::Trace <= $crate::logger::current_log_level() {
            if $crate::config::is_colored_output_enabled() {
                eprintln!("\x1b[36m['] {}\x1b[0m", format!($($arg)*))
            } else {
                eprintln!("[TRACE] {}", format!($($arg)*))
            }
        }
    };
}
