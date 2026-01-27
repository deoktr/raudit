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
use std::sync::OnceLock;

use crate::{check, log_debug, log_error};

const GRUB_CFG_PATH: &str = "/boot/grub/grub.cfg";

static GRUB_CFG: OnceLock<GrubCfg> = OnceLock::new();

/// Raw grub config from `/boot/grub/grub.cfg`.
pub type GrubCfg = String;

/// Get the system's grub config from `/boot/grub/grub.cfg`.
fn get_grub_cfg() -> Result<String, std::io::Error> {
    Ok(fs::read_to_string(GRUB_CFG_PATH)?)
}

/// Init the system's grub config from `/boot/grub/grub.cfg`.
pub fn init_grub_cfg() {
    if GRUB_CFG.get().is_some() {
        return;
    }

    match get_grub_cfg() {
        Ok(c) => {
            GRUB_CFG.get_or_init(|| c);
            log_debug!("initialized grub cfg");
        }
        Err(err) => log_error!("failed to initialize grub configuration: {}", err),
    }
}

/// Verify that grub is configured with a password.
pub fn password_is_set() -> check::CheckReturn {
    let grub_cfg = match GRUB_CFG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("grub configuration not initialized".to_string()),
            );
        }
    };

    // NOTE: "\n" is to ensure they are not commented out
    if grub_cfg.contains(&"\nset superusers".to_string())
        && grub_cfg.contains(&"\npassword".to_string())
    {
        (check::CheckState::Passed, None)
    } else {
        (check::CheckState::Failed, None)
    }
}
