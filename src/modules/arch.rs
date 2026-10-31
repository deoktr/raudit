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

use crate::{log_debug, utils};

/// Architecture of the running kernel, from the `machine` name of `uname`.
fn kernel_arch(machine: &str) -> Option<&'static str> {
    match machine {
        "x86_64" => Some("x86_64"),
        "i386" | "i486" | "i586" | "i686" => Some("x86_32"),
        "aarch64" => Some("arm64"),
        machine if machine.starts_with("armv") => Some("arm32"),
        "riscv64" => Some("riscv64"),
        "riscv32" => Some("riscv32"),
        "ppc64le" => Some("ppc64le"),
        "ppc64" => Some("ppc64"),
        "s390x" => Some("s390x"),
        "loongarch64" => Some("loongarch64"),
        "mips" | "mips64" => Some("mips"),
        _ => None,
    }
}

/// Architecture of the running kernel, None when it is not one of
/// [kernel_arch].
fn get_kernel_arch() -> Option<&'static str> {
    match utils::get_arch() {
        Ok(machine) => kernel_arch(&machine),
        Err(err) => {
            log_debug!("machine name not available: {err}");
            None
        }
    }
}

/// Skip a check when the running kernel is not one of `arches`.
pub fn skip_not_arch(arches: &[&str]) -> bool {
    match get_kernel_arch() {
        Some(arch) => !arches.contains(&arch),
        None => {
            log_debug!("unknown kernel architecture, keeping the check");
            false
        }
    }
}

/// Skip a check when the running kernel is one of `arches`.
pub fn skip_arch(arches: &[&str]) -> bool {
    match get_kernel_arch() {
        Some(arch) => arches.contains(&arch),
        None => {
            log_debug!("unknown kernel architecture, keeping the check");
            false
        }
    }
}
