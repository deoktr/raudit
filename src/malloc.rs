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

use crate::check;

// FIXME: on NixOS the file is `/etc/ld-nix.so.preload`
const LD_SO_PRELOAD_PATH: &str = "/etc/ld.so.preload";

static LD_SO_PRELOAD: OnceLock<LdSoPreload> = OnceLock::new();

/// LD preload configuration from `/etc/ld.so.preload`.
pub type LdSoPreload = String;

/// Get login.defs configuration by reading `/etc/ld.so.preload`.
pub fn init_ld_so_preload() {
    if LD_SO_PRELOAD.get().is_some() {
        return;
    }

    LD_SO_PRELOAD.get_or_init(|| match fs::read_to_string(LD_SO_PRELOAD_PATH) {
        Ok(content) => content,
        // TODO: check error type, if the file does not exist then set LD_SO to
        // an empty string, otherwise log error
        Err(_) => "".to_owned(),
    });
}

/// Uses [scudo](https://llvm.org/docs/ScudoHardenedAllocator.html).
///
/// Scudo Hardened Allocator is a user-mode allocator, originally based on LLVM
/// Sanitizers’ `CombinedAllocator`.
pub fn has_scudo_malloc() -> check::CheckReturn {
    match LD_SO_PRELOAD.get() {
        Some(config) => {
            if config.contains("scudo") {
                (check::CheckState::Success, None)
            } else {
                (check::CheckState::Failure, None)
            }
        }
        None => (
            check::CheckState::Error,
            Some("ld.so.preload not initialized".to_string()),
        ),
    }
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
