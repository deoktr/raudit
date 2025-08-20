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

use std::sync::OnceLock;
use std::{collections::HashMap, path::PathBuf};
use std::{fs, io};

use crate::{check, log_debug, log_error};

static KERNEL_BUILD_CONFIG: OnceLock<KernelBuildConfig> = OnceLock::new();

/// Kernel build configuration from `/lib/modules/$(uname -r)/build/.config`.
pub type KernelBuildConfig = HashMap<String, String>;

/// Get path `/lib/modules/$(uname -r)/build/.config`.
fn get_kernel_build_config_path() -> Result<PathBuf, io::Error> {
    let kernel_version = fs::read_to_string("/proc/sys/kernel/osrelease")?
        .trim()
        .to_string();

    Ok(PathBuf::from("/lib/modules")
        .join(kernel_version)
        .join("build/.config"))
}

/// Parse content of `/lib/modules/$(uname -r)/build/.config`.
fn parse_kernel_build_config(cmdline: String) -> KernelBuildConfig {
    cmdline
        .lines()
        .filter(|line| !line.is_empty())
        // comments are usefull and gives informations about what flags where
        // not set, ex: `# CONFIG_EARLY_PRINTK_USB_XDBC is not set`
        .filter(|line| {
            !(line.starts_with("#")
                && !(line.starts_with("# CONFIG_") && line.ends_with(" is not set")))
        })
        .map(|line| -> String {
            line.replacen("# CONFIG_", "CONFIG_", 1)
                .replacen(" is not set", "=is not set", 1)
                .to_string()
        })
        .filter_map(|line| match line.split_once("=") {
            Some((key, value)) => Some((key.to_string(), value.trim_start().to_string())),
            // should never happen, don't even log it
            None => None,
        })
        .collect()
}

/// Get kernel build configuration by reading
/// `/lib/modules/$(uname -r)/build/.config` or by reading `/proc/config.gz`.
///
/// [view_kernel_conf](https://docs.rockylinux.org/gemstones/core/view_kernel_conf/)
/// The file may not exist, it is only present if the kernel was compiled with
/// `CONFIG_IKCONFIG_PROC=y`.
pub fn init_kernel_build_config() {
    if KERNEL_BUILD_CONFIG.get().is_some() {
        return;
    }

    // TODO: if `/lib/modules/.../build/.config` is not present, get it from
    // another source

    let kernel_build_config_path = match get_kernel_build_config_path() {
        Ok(p) => p,
        Err(err) => {
            log_error!(
                "Failed to initialize kernel build config, error while building path: {}",
                err.to_string()
            );
            return;
        }
    };

    match fs::read_to_string(&kernel_build_config_path) {
        Ok(content) => KERNEL_BUILD_CONFIG.get_or_init(|| parse_kernel_build_config(content)),
        Err(err) => {
            log_error!(
                "Failed to initialize kernel build config, error while reading {}: {}",
                kernel_build_config_path.to_string_lossy(),
                err.to_string()
            );
            return;
        }
    };

    log_debug!("initialized kernel build config");
}

/// Ensure kernel build parameter is set.
pub fn check_option_is_set(param: &str) -> check::CheckReturn {
    let config = match KERNEL_BUILD_CONFIG.get() {
        Some(config) => config,
        None => {
            return (
                check::CheckState::Error,
                Some("kcompile config not initialized".to_string()),
            );
        }
    };

    match config.get(param) {
        Some(val) => {
            if *val != "is not set".to_string() {
                (check::CheckState::Passed, None)
            } else {
                (check::CheckState::Failed, Some("param not set".to_string()))
            }
        }
        None => (
            check::CheckState::Error,
            Some("param not present".to_string()),
        ),
    }
}

/// Ensure kernel parameter is not set.
pub fn check_option_is_not_set(param: &str) -> check::CheckReturn {
    let config = match KERNEL_BUILD_CONFIG.get() {
        Some(config) => config,
        None => {
            return (
                check::CheckState::Error,
                Some("kcompile config not initialized".to_string()),
            );
        }
    };

    match config.get(param) {
        Some(val) => {
            if *val == "is not set".to_string() {
                (check::CheckState::Passed, None)
            } else {
                (check::CheckState::Failed, Some("param set".to_string()))
            }
        }
        None => (
            check::CheckState::Error,
            Some("param not present".to_string()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pam_rule() {
        let r = parse_kernel_build_config(
            "#
# x86 Debugging
#
CONFIG_EARLY_PRINTK_USB=y
CONFIG_X86_VERBOSE_BOOTUP=y
CONFIG_EARLY_PRINTK=y
CONFIG_EARLY_PRINTK_DBGP=y
# CONFIG_EARLY_PRINTK_USB_XDBC is not set
# CONFIG_EFI_PGT_DUMP is not set
# CONFIG_DEBUG_TLBFLUSH is not set
CONFIG_HAVE_MMIOTRACE_SUPPORT=y
# CONFIG_X86_DECODER_SELFTEST is not set
CONFIG_IO_DELAY_0X80=y
# CONFIG_IO_DELAY_0XED is not set
# CONFIG_IO_DELAY_UDELAY is not set
# CONFIG_IO_DELAY_NONE is not set
CONFIG_DEBUG_BOOT_PARAMS=y
# CONFIG_CPA_DEBUG is not set
CONFIG_DEBUG_ENTRY=y
# CONFIG_DEBUG_NMI_SELFTEST is not set
CONFIG_X86_DEBUG_FPU=y
CONFIG_PUNIT_ATOM_DEBUG=m
CONFIG_UNWINDER_ORC=y
# CONFIG_UNWINDER_FRAME_POINTER is not set
# end of x86 Debugging
"
            .to_string(),
        );
        assert_eq!(r.len(), 21);
        assert!(r.contains_key("CONFIG_EARLY_PRINTK_USB"));
        assert_eq!(r.get("CONFIG_EARLY_PRINTK_USB").unwrap(), "y");
        assert!(r.contains_key("CONFIG_EARLY_PRINTK_USB_XDBC"));
        assert_eq!(r.get("CONFIG_EARLY_PRINTK_USB_XDBC").unwrap(), "is not set");
        assert!(r.contains_key("CONFIG_UNWINDER_ORC"));
        assert_eq!(r.get("CONFIG_UNWINDER_ORC").unwrap(), "y");
        assert!(r.contains_key("CONFIG_UNWINDER_FRAME_POINTER"));
        assert_eq!(
            r.get("CONFIG_UNWINDER_FRAME_POINTER").unwrap(),
            "is not set"
        );
    }
}
