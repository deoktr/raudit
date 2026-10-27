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

use std::{fs, io};

use crate::check::{self, State};

// FIXME: on NixOS the file is `/etc/ld-nix.so.preload`
const LD_SO_PRELOAD_PATH: &str = "/etc/ld.so.preload";

static LD_SO_PRELOAD: State<LdSoPreload> = State::new("ld.so.preload");

/// LD preload configuration from `/etc/ld.so.preload`.
type LdSoPreload = String;

/// Get login.defs configuration by reading `/etc/ld.so.preload`.
fn get_ld_so_preload() -> Result<LdSoPreload, String> {
    match fs::read_to_string(LD_SO_PRELOAD_PATH) {
        Ok(v) => Ok(v),
        Err(e) => match e.kind() {
            io::ErrorKind::NotFound => Ok(String::new()),
            _ => Err(format!("failed to read `{}`: {}", LD_SO_PRELOAD_PATH, e)),
        },
    }
}

/// Init login.defs configuration by reading `/etc/ld.so.preload`.
pub fn init_ld_so_preload() {
    LD_SO_PRELOAD.init(get_ld_so_preload);
}

/// Uses [scudo](https://llvm.org/docs/ScudoHardenedAllocator.html).
///
/// Scudo Hardened Allocator is a user-mode allocator, originally based on LLVM
/// Sanitizers’ `CombinedAllocator`.
pub fn has_scudo_malloc() -> check::CheckReturn {
    LD_SO_PRELOAD.with(|config| {
        if config.contains("scudo") {
            (check::CheckState::Pass, None)
        } else {
            (check::CheckState::Fail, None)
        }
    })
}

// /// Uses [libhardened_malloc](https://github.com/GrapheneOS/hardened_malloc/).
// ///
// /// `hardened_malloc` is a hardened memory allocator that provides substantial
// /// protection from heap memory corruption vulnerabilities. It is heavily based
// /// on OpenBSD's malloc design but with numerous improvements.
// pub fn has_libhardened_malloc() -> check::CheckReturn {
//     match LD_SO_PRELOAD.get() {
//         Some(config) => {
//             if config.contains("libhardened_malloc") {
//                 (check::CheckState::Success, None)
//             } else {
//                 (check::CheckState::Failure, None)
//             }
//         }
//         None => (
//             check::CheckState::Error,
//             Some("ld.so.preload not initialized".to_string()),
//         ),
//     }
// }
