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

use std::collections::HashMap;
use std::process;
use std::process::Stdio;

/// Kenel compilation config from `/proc/config.gz`.
pub type KcompilConfig = HashMap<String, String>;

/// Parse content for `/proc/config.gz`.
fn parse_kcompile_config(cmdline: String) -> KcompilConfig {
    cmdline
        .lines()
        .filter(|line| !line.is_empty())
        // come comments are usefull and gives informations about what flags
        // where not set, ex: `# CONFIG_EARLY_PRINTK_USB_XDBC is not set`
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

/// Get kernel compilation config by reading from `/proc/config.gz`.
///
/// The file may not exist, it is only present if the kernel was compiled with
/// `CONFIG_IKCONFIG_PROC=y`
pub fn init_kcompile_config() -> Result<KcompilConfig, std::io::Error> {
    // TODO: decompress first, would require a dependancy, so maybe not?
    // let kconfig = fs::read_to_string("/proc/config.gz")?;

    let mut cmd = process::Command::new("zcat");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["/proc/config.gz"]);

    let output = cmd.output()?;

    // TODO: error if not 0
    // match output.status.code() {
    //     Some(c) => c,
    //     None => 0,
    // }

    Ok(parse_kcompile_config(
        String::from_utf8_lossy(&output.stdout).to_string(),
    ))
}

/// Get kernel compilation flag from a collected configuration.
pub fn get_kcompile_config(config: &'static KcompilConfig, flag: String) -> Result<String, String> {
    match config.get(&flag) {
        Some(val) => {
            if *val == "is not set".to_string() {
                Err("flag is not set".to_string())
            } else {
                Ok(val.to_string())
            }
        }
        None => Err("flag not present".to_string()),
    }
}

/// Check if kernel compilation flag is not set.
pub fn get_kcompile_not_set_config(
    config: &'static KcompilConfig,
    flag: String,
) -> Result<bool, String> {
    match config.get(&flag) {
        Some(val) => Ok(*val == "is not set".to_string()),
        None => Err("flag not present".to_string()),
    }
}

// /// Check if any stack protector flag is activated.
// pub fn has_stack_protector(config: &'static KcompilConfig) -> bool {
//     vec![
//         get_kcompile_config(config, "CONFIG_STACKPROTECTOR".to_string()),
//         get_kcompile_config(config, "CONFIG_CC_STACKPROTECTOR".to_string()),
//         get_kcompile_config(config, "CONFIG_CC_STACKPROTECTOR_REGULAR".to_string()),
//         get_kcompile_config(config, "CONFIG_CC_STACKPROTECTOR_AUTO".to_string()),
//         get_kcompile_config(config, "CONFIG_CC_STACKPROTECTOR_STRONG".to_string()),
//     ]
//     .into_iter()
//     .filter(|r| r.is_err())
//     .any(|r| r.unwrap() == "y".to_string())
// }
//
// /// Check if any stack protector strong flag is activated.
// pub fn has_stack_protector_strong(config: &'static KcompilConfig) -> bool {
//     vec![
//         get_kcompile_config(config, "STACKPROTECTOR_STRONG".to_string()),
//         get_kcompile_config(config, "CC_STACKPROTECTOR_STRONG".to_string()),
//     ]
//     .into_iter()
//     .filter(|r| r.is_err())
//     .any(|r| r.unwrap() == "y".to_string())
// }
//
// pub fn has_strict_kernel_rwx(config: &'static KcompilConfig) -> bool {
//     vec![
//         get_kcompile_config(config, "STRICT_KERNEL_RWX".to_string()),
//         get_kcompile_config(config, "DEBUG_RODATA".to_string()),
//     ]
//     .into_iter()
//     .filter(|r| r.is_err())
//     .any(|r| r.unwrap() == "y".to_string())
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pam_rule() {
        let r = parse_kcompile_config(
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
