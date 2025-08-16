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

use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use crate::{check, log_error};

const CMDLINE_PATH: &str = "/proc/cmdline";

static KERNEL_PARAMS: OnceLock<KernelParams> = OnceLock::new();

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
pub fn init_kernel_params() {
    if KERNEL_PARAMS.get().is_some() {
        return;
    }

    match fs::read_to_string(CMDLINE_PATH) {
        Ok(cmdline) => {
            KERNEL_PARAMS.get_or_init(|| parse_kernel_params(cmdline));
        }
        Err(err) => log_error!("Failed to initialize kernel params: {}", err),
    }
}

/// Get kernel params presence from a collected configuration.
pub fn check_kernel_params(variable: &str) -> check::CheckReturn {
    let kparams = match KERNEL_PARAMS.get() {
        Some(kparams) => kparams,
        None => {
            return (
                check::CheckState::Error,
                Some("kernel params not initialized".to_string()),
            );
        }
    };

    if kparams.contains(&variable.to_string()) {
        (check::CheckState::Passed, None)
    } else {
        (check::CheckState::Failed, None)
    }
}

/// Check if system needs a reboot.
pub fn check_reboot_required() -> check::CheckReturn {
    // TODO: on RHEL use `needs-restarting -r` command, status 0 no reboot
    // required, 1 if it is
    if !(Path::new("/var/run/reboot-required.pkgs").exists()
        || Path::new("/var/run/needs_restarting").exists())
    {
        (check::CheckState::Passed, None)
    } else {
        (check::CheckState::Failed, None)
    }
}
