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

//! Helpers shared by the host data collection modules.

use std::env;
use std::ffi::CStr;
use std::path::PathBuf;

/// Length of a `struct utsname` field, `UTS_LEN` characters plus the null byte.
const UTS_FIELD_LEN: usize = 65;

/// Information about the running kernel, `struct utsname` in C.
#[repr(C)]
struct Utsname {
    sysname: [u8; UTS_FIELD_LEN],
    nodename: [u8; UTS_FIELD_LEN],
    release: [u8; UTS_FIELD_LEN],
    version: [u8; UTS_FIELD_LEN],
    machine: [u8; UTS_FIELD_LEN],
    domainname: [u8; UTS_FIELD_LEN],
}

unsafe extern "C" {
    fn uname(buf: *mut Utsname) -> i32;
}

/// Resolve an executable name against `$PATH`. Returns the first matching
/// absolute path, or None if the binary is not found.
pub fn which(bin: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Get the machine hardware name with the `uname` syscall, like `uname -m`.
///
/// Returns the name reported by the kernel, `x86_64`, `aarch64`, `armv7l`,
/// `riscv64`, `ppc64le`, `s390x` and so on.
pub fn get_arch() -> Result<String, String> {
    let mut buf = Utsname {
        sysname: [0; UTS_FIELD_LEN],
        nodename: [0; UTS_FIELD_LEN],
        release: [0; UTS_FIELD_LEN],
        version: [0; UTS_FIELD_LEN],
        machine: [0; UTS_FIELD_LEN],
        domainname: [0; UTS_FIELD_LEN],
    };

    // SAFETY: `buf` is a zeroed `struct utsname` of the exact size the kernel
    // writes and stays valid for the whole call.
    if unsafe { uname(&mut buf) } != 0 {
        return Err("uname syscall failed".to_string());
    }

    CStr::from_bytes_until_nul(&buf.machine)
        .map(|machine| machine.to_string_lossy().into_owned())
        .map_err(|_| "uname returned an unterminated machine name".to_string())
}
