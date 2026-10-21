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

use std::io::Read;
use std::sync::OnceLock;
use std::{collections::HashMap, fs, io, path::Path, path::PathBuf};

use flate2::read::GzDecoder;

use crate::{check, log_debug, log_error};

static KERNEL_BUILD_CONFIG: OnceLock<KernelBuildConfig> = OnceLock::new();

/// Kernel build configuration, parsed from the first available source of
/// [get_kernel_build_config_paths].
pub type KernelBuildConfig = HashMap<String, String>;

/// Skip a check when the running kernel's build config is not available.
pub fn skip_no_kbuild_config() -> bool {
    match get_kernel_build_config_paths() {
        Ok(paths) => !paths.iter().any(|path| path.is_file()),
        Err(_) => true,
    }
}

/// Get the running kernel release from `/proc/sys/kernel/osrelease`.
fn get_kernel_release() -> Result<String, io::Error> {
    Ok(fs::read_to_string("/proc/sys/kernel/osrelease")?
        .trim()
        .to_string())
}

/// Get the kernel build configuration sources, in order of preference:
///
/// - `/lib/modules/$(uname -r)/build/.config`
/// - `/boot/config-$(uname -r)`
/// - `/proc/config.gz` present if the kernel had `CONFIG_IKCONFIG_PROC=y`
///
/// [view_kernel_conf](https://docs.rockylinux.org/gemstones/core/view_kernel_conf/)
fn get_kernel_build_config_paths() -> Result<Vec<PathBuf>, io::Error> {
    let kernel_version = get_kernel_release()?;

    Ok(vec![
        PathBuf::from("/lib/modules")
            .join(&kernel_version)
            .join("build/.config"),
        PathBuf::from(format!("/boot/config-{kernel_version}")),
        PathBuf::from("/proc/config.gz"),
    ])
}

/// Read a kernel build configuration file, gunzipping it when needed.
fn read_kernel_build_config(path: &Path) -> Result<String, io::Error> {
    if !path.extension().is_some_and(|ext| ext == "gz") {
        return fs::read_to_string(path);
    }

    let mut content = String::new();
    GzDecoder::new(fs::File::open(path)?).read_to_string(&mut content)?;

    Ok(content)
}

/// Parse content of a kernel build configuration file.
fn parse_kernel_build_config(cmdline: String) -> KernelBuildConfig {
    cmdline
        .lines()
        .filter(|line| !line.is_empty())
        // comments are useful and gives information about what flags where
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
        .filter_map(|line| {
            line.split_once("=")
                .map(|(key, value)| (key.to_string(), value.trim_start().to_string()))
        })
        .collect()
}

/// Get kernel build configuration from the first readable source of
/// [get_kernel_build_config_paths].
fn get_kernel_build_config() -> Result<KernelBuildConfig, io::Error> {
    let mut err = io::Error::new(
        io::ErrorKind::NotFound,
        "no kernel build config source available",
    );

    for path in get_kernel_build_config_paths()? {
        match read_kernel_build_config(&path) {
            Ok(content) => {
                log_debug!("kernel build config read from {}", path.display());
                return Ok(parse_kernel_build_config(content));
            }
            Err(e) => err = e,
        }
    }

    Err(err)
}

/// Init kernel build configuration from the first readable source of
/// [get_kernel_build_config_paths].
///
/// [view_kernel_conf](https://docs.rockylinux.org/gemstones/core/view_kernel_conf/)
pub fn init_kernel_build_config() {
    if KERNEL_BUILD_CONFIG.get().is_some() {
        return;
    }

    match get_kernel_build_config() {
        Ok(c) => {
            KERNEL_BUILD_CONFIG.get_or_init(|| c);
            log_debug!("initialized kernel build config");
        }
        Err(err) => log_error!("failed to initialize kernel build config: {}", err),
    }
}

/// Ensure kernel build parameter is set.
pub fn check_option_is_set(param: &str) -> check::CheckReturn {
    let config = match KERNEL_BUILD_CONFIG.get() {
        Some(config) => config,
        None => {
            return (
                check::CheckState::Warning,
                Some("kcompile config not initialized".to_string()),
            );
        }
    };

    match config.get(param) {
        Some(val) => {
            if val != "is not set" {
                (check::CheckState::Pass, None)
            } else {
                (check::CheckState::Fail, Some("param not set".to_string()))
            }
        }
        None => (
            check::CheckState::Warning,
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
                check::CheckState::Warning,
                Some("kcompile config not initialized".to_string()),
            );
        }
    };

    match config.get(param) {
        Some(val) => {
            if val == "is not set" {
                (check::CheckState::Pass, None)
            } else {
                (check::CheckState::Fail, Some("param set".to_string()))
            }
        }
        None => (
            check::CheckState::Warning,
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
