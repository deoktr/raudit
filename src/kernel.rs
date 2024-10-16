/*
 * rAudit, a Linux security auditing toolkit
 * Copyright (C) 2024  deoktr
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

use std::fs;
use std::path::Path;

/// Kenel params from `/proc/cmdline`.
pub type KernelParams = Vec<String>;

/// Parse content for `/proc/cmdline`.
fn parse_kernel_params(cmdline: String) -> KernelParams {
    cmdline
        .replace("\n", "")
        // TODO: use shlex to split arguments, they could contain spaces in them
        .split(" ")
        .map(|line| line.to_string())
        .collect()
}

/// Get kernel params by reading from `/proc/cmdline`.
pub fn init_kernel_params() -> Result<KernelParams, std::io::Error> {
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    Ok(parse_kernel_params(cmdline))
}

/// Get kernel params presence from a collected configuration.
pub fn get_kernel_params(config: &KernelParams, variable: String) -> bool {
    config.contains(&variable)
}

/// Check if system needs a reboot.
pub fn check_reboot_required() -> bool {
    !(Path::new("/var/run/reboot-required.pkgs").exists()
        || Path::new("/var/run/needs_restarting").exists())
}
