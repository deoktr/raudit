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

/// LD preload configuration from `/etc/ld.so.preload`.
pub type LdSoPreload = String;

/// Get login.defs configuration by reading `/etc/ld.so.preload`.
pub fn init_ld_so_preload() -> Result<LdSoPreload, std::io::Error> {
    // TODO: error errors if it doesn't exist, since it would just mean it's not
    // configured properly

    // FIXME: on NixOS the file is `ld-nix.so.preload`, add a way to detect the
    // OS and change it here based on that
    let ls_so_preload = match fs::read_to_string("/etc/ld-nix.so.preload") {
        Ok(content) => content,
        Err(_) => fs::read_to_string("/etc/ld.so.preload")?,
    };

    // let ls_so_preload = fs::read_to_string("/etc/ld.so.preload")?;
    Ok(ls_so_preload)
}

/// Uses [libhardened_malloc](https://github.com/GrapheneOS/hardened_malloc/).
///
/// `hardened_malloc` is a hardened memory allocator that provides substantial
/// protection from heap memory corruption vulnerabilities. It is heavily based
/// on OpenBSD's malloc design but with numerous improvements.
pub fn has_libhardened_malloc(config: &'static LdSoPreload) -> bool {
    config.contains("libhardened_malloc")
}

/// Uses [scudo](https://llvm.org/docs/ScudoHardenedAllocator.html).
///
/// Scudo Hardened Allocator is a user-mode allocator, originally based on LLVM
/// Sanitizers’ `CombinedAllocator`.
pub fn has_scudo_malloc(config: &'static LdSoPreload) -> bool {
    config.contains("scudo")
}

/// Ensure that an hardened malloc is used. It can either be `scudo` or
/// `libhardened_malloc`.
pub fn has_hardened_malloc(config: &'static LdSoPreload) -> bool {
    return has_libhardened_malloc(config) || has_scudo_malloc(config);
}
