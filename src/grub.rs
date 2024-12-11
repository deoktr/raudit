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

const GRUB_CFG_PATH: &str = "/boot/grub/grub.cfg";

/// Raw grub config from `/boot/grub/grub.cfg`.
pub type GrubCfg = String;

/// Get the system's grub config from `/boot/grub/grub.cfg`.
pub fn init_grub_cfg() -> Result<GrubCfg, std::io::Error> {
    let grub_cfg = fs::read_to_string(GRUB_CFG_PATH)?;
    Ok(grub_cfg)
}

/// Verify that grub is configured with a password.
pub fn password_is_set(grub_cfg: &'static GrubCfg) -> bool {
    // NOTE: "\n" is to ensure they are not commented out
    grub_cfg.contains(&"\nset superusers".to_string())
        && grub_cfg.contains(&"\npassword".to_string())
}
