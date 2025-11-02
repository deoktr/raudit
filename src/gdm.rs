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

use crate::check;

// FIXME: On Ubuntu it is in:
// "/etc/gdm3/custom.conf"
const GDM_CFG_PATH: &str = "/etc/gdm/custom.conf";

/// Ensure no automatic logon to the system via a GUI is possible.
///
/// <https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/finding/V-258018>
pub fn no_gdm_auto_logon() -> check::CheckReturn {
    // TODO: ensure that this is under `[daemon]`, parse with TOML
    match fs::read_to_string(GDM_CFG_PATH) {
        Ok(cfg) => {
            if cfg.lines().any(|l| l == "AutomaticLoginEnable=false") {
                (check::CheckState::Passed, None)
            } else {
                (
                    check::CheckState::Failed,
                    Some("missing AutomaticLoginEnable=false".to_string()),
                )
            }
        }
        Err(err) => (
            check::CheckState::Error,
            Some(format!("failed to read gdm configuration: {}", err)),
        ),
    }
}
