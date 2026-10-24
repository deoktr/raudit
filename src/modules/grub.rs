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

use crate::check::{self, State};

const GRUB_CFG_PATH: &str = "/boot/grub/grub.cfg";

static GRUB_CFG: State<GrubCfg> = State::new("grub config");

/// Raw grub config from `/boot/grub/grub.cfg`.
type GrubCfg = String;

/// Skip if grub is not the bootloader.
pub fn skip_no_grub() -> bool {
    !Path::new("/boot/grub").is_dir() && !Path::new("/boot/grub2").is_dir()
}

/// Get the system's grub config from `/boot/grub/grub.cfg`.
fn get_grub_cfg() -> Result<String, String> {
    fs::read_to_string(GRUB_CFG_PATH)
        .map_err(|err| format!("failed to read {}: {}", GRUB_CFG_PATH, err))
}

/// Init the system's grub config from `/boot/grub/grub.cfg`.
pub fn init_grub_cfg() {
    GRUB_CFG.init(get_grub_cfg);
}

/// Verify that grub is configured with a password.
pub fn password_is_set() -> check::CheckReturn {
    GRUB_CFG.with(|grub_cfg| {
        // NOTE: "\n" is to ensure they are not commented out
        if grub_cfg.contains(&"\nset superusers".to_string())
            && grub_cfg.contains(&"\npassword".to_string())
        {
            (check::CheckState::Pass, None)
        } else {
            (check::CheckState::Fail, None)
        }
    })
}
