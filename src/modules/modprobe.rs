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

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::check::State;
use crate::{check, log_debug};

const OSRELEASE_PATH: &str = "/proc/sys/kernel/osrelease";

/// Modprobe configuration directories, in kmod precedence order. A file in an
/// earlier directory shadows a file with the same name in a later one.
const MODPROBE_DIRS: [&str; 5] = [
    "/etc/modprobe.d",
    "/run/modprobe.d",
    "/usr/local/lib/modprobe.d",
    "/usr/lib/modprobe.d",
    "/lib/modprobe.d",
];

static MODPROBE_CONFIG: State<ModprobeConfig> = State::new("modprobe config");
static MODPROBE_BLACKLIST: State<ModprobeBlacklist> = State::new("modprobe blacklisted");
static MODPROBE_DISABLED: State<ModprobeDisabled> = State::new("modprobe disabled");
static LOADED_MODULES: State<LoadedModules> = State::new("loaded kernel modules");

/// Available modules are the list of modules present on disk.
static AVAILABLE_MODULES: State<AvailableModules> = State::new("available kernel modules");

/// Compiled-in modules cannot be unloaded, but they are present.
static COMPILED_IN_MODULES: State<CompiledInModules> = State::new("compiled-in kernel modules");

/// Modprobe directives, in the order kmod parses them.
type ModprobeConfig = Vec<Directive>;

// NOTE: disabled and blacklisted are two different things, blacklist means the
// module won't start automatically, and disabled means it will never be able
// to start

/// Set of blacklisted kernel modules.
type ModprobeBlacklist = HashSet<String>;

/// `install` directives of the modprobe configuration, in kmod parse order.
///
/// kmod only runs the first directive matching a module, the following ones are
/// ignored, which is why the order matters.
type ModprobeDisabled = Vec<InstallDirective>;

/// Set of loaded kernel modules.
type LoadedModules = HashSet<String>;

/// Set of kernel modules loadable for the running kernel.
type AvailableModules = HashSet<String>;

/// Set of kernel modules compiled-in the running kernel.
type CompiledInModules = HashSet<String>;

/// A modprobe configuration directive.
struct Directive {
    /// Keyword starting the directive, e.g. `blacklist` or `install`.
    cmd: String,
    /// Module name, normalized.
    module: String,
    /// Remainder of the line.
    arg: String,
}

/// An `install` directive, kmod runs `command` instead of loading the module.
struct InstallDirective {
    /// Module name, normalized.
    module: String,
    /// Command run instead of loading the module.
    command: String,
}

/// Get modprobe configuration file paths, in the order kmod parses them.
///
/// kmod sorts the files of every directory by name, and ignores a file whose
/// name was already found in a directory with a higher precedence.
fn get_modprobe_config_paths() -> Vec<PathBuf> {
    let mut files: Vec<(String, usize, PathBuf)> = Vec::new();

    for (precedence, dir) in MODPROBE_DIRS.iter().enumerate() {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            // kmod ignores hidden files and anything but `.conf` files
            if name.starts_with('.') || !name.ends_with(".conf") {
                continue;
            }

            let path = entry.path();
            if path.is_dir() {
                continue;
            }

            files.push((name, precedence, path));
        }
    }

    files.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));

    // names are now sorted, keep only the first occurrence of each one
    files.dedup_by(|a, b| a.0 == b.0);

    files.into_iter().map(|(_, _, path)| path).collect()
}

/// Parse a single modprobe configuration line.
///
/// Lines are tokenized like kmod does: leading whitespace is ignored, the first
/// token is the directive keyword, the second is the module name and the rest
/// of the line is kept as the directive argument.
fn parse_line(line: &str) -> Option<Directive> {
    let line = line.trim_start();

    // only full line comments are supported, like kmod
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // a directive without argument is a syntax error for kmod
    let cmd_end = line.find(char::is_whitespace)?;
    let cmd = &line[..cmd_end];
    let rest = line[cmd_end..].trim_start();

    let module_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let module = &rest[..module_end];
    if module.is_empty() {
        return None;
    }

    Some(Directive {
        cmd: cmd.to_string(),
        module: normalize_module_name(module),
        arg: rest[module_end..].trim_start().to_string(),
    })
}

/// Parse en content of a modprobe configuration file.
fn parse_modprobe(content: &str) -> ModprobeConfig {
    content.lines().filter_map(parse_line).collect()
}

/// Get modprobe configuration by reading files.
fn get_modprobe_config() -> Result<ModprobeConfig, String> {
    Ok(get_modprobe_config_paths()
        .into_iter()
        .flat_map(fs::read_to_string)
        .flat_map(|content| parse_modprobe(&content))
        .collect())
}

/// Init modprobe configuration by reading files.
fn init_modprobe_config() {
    MODPROBE_CONFIG.init(get_modprobe_config);
}

/// Get modprobe blacklisted modules from modprobe config.
fn get_modprobe_blacklist() -> Result<ModprobeBlacklist, String> {
    Ok(MODPROBE_CONFIG
        .try_get()?
        .iter()
        .filter(|directive| directive.cmd == "blacklist")
        .map(|directive| directive.module.clone())
        .collect())
}

/// Get modprobe blacklisted modules from modprobe config.
fn init_modprobe_blacklist() {
    MODPROBE_BLACKLIST.init(get_modprobe_blacklist);
}

/// Get modprobe `install` directives from modprobe config.
fn get_modprobe_disabled() -> Result<ModprobeDisabled, String> {
    Ok(MODPROBE_CONFIG
        .try_get()?
        .iter()
        .filter(|directive| directive.cmd == "install")
        .map(|directive| InstallDirective {
            module: directive.module.clone(),
            command: directive.arg.clone(),
        })
        .collect())
}

/// Init modprobe disabled modules from modprobe config.
fn init_modprobe_disabled() {
    MODPROBE_DISABLED.init(get_modprobe_disabled);
}

/// Parse the content of `/proc/modules` to extract module names.
fn parse_proc_modules(proc_modules: &str) -> LoadedModules {
    proc_modules
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(normalize_module_name)
        .collect()
}

/// Init currently loaded kernel modules by reading `/proc/modules`.
fn get_loaded_modules() -> Result<LoadedModules, String> {
    let content = fs::read_to_string("/proc/modules")
        .map_err(|err| format!("failed to open /proc/modules: {}", err))?;
    Ok(parse_proc_modules(&content))
}

/// Init currently loaded kernel modules by reading `/proc/modules`.
fn init_loaded_modules() {
    LOADED_MODULES.init(get_loaded_modules);
}

/// Normalize a module name, kernel module names always use `_` but file names
/// may use `-`.
fn normalize_module_name(module: &str) -> String {
    module.replace('-', "_")
}

/// Parse content of `modules.dep` or `modules.builtin` to extract available
/// module names.
fn parse_available_modules(content: &str) -> Vec<String> {
    content
        .lines()
        .filter(|line| !line.is_empty())
        // `modules.dep` lines are `<path>.ko: <dep>.ko ...`, only keep the
        // first field, which also strips the trailing `:`
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|path| path.rsplit('/').next())
        // strip the `.ko` extension and any compression suffix (.ko.zst,
        // .ko.xz, .ko.gz)
        .filter_map(|file| file.find(".ko").map(|idx| &file[..idx]))
        .map(normalize_module_name)
        .collect()
}

/// Get available kernel modules for the running kernel by reading
/// `/lib/modules/$(uname -r)/modules.dep`.
fn get_available_modules() -> Result<AvailableModules, String> {
    let kernel_release = fs::read_to_string(OSRELEASE_PATH)
        .map_err(|err| format!("failed to open {}: {}", OSRELEASE_PATH, err))?
        .trim()
        .to_string();

    let content = fs::read_to_string(
        PathBuf::from("/lib/modules")
            .join(&kernel_release)
            .join("modules.dep"),
    )
    .map_err(|err| {
        format!(
            "failed to read /lib/modules/{}/modules.dep: {}",
            kernel_release, err
        )
    })?;

    Ok(parse_available_modules(&content).into_iter().collect())
}

/// Init available kernel modules for the running kernel.
fn init_available_modules() {
    AVAILABLE_MODULES.init(get_available_modules);
}

/// Get compiled-in kernel modules by reading `modules.builtin`.
fn get_compiled_in_modules() -> Result<CompiledInModules, String> {
    let kernel_release = fs::read_to_string(OSRELEASE_PATH)
        .map_err(|err| format!("failed to open {}: {}", OSRELEASE_PATH, err))?
        .trim()
        .to_string();

    let content = fs::read_to_string(
        PathBuf::from("/lib/modules")
            .join(&kernel_release)
            .join("modules.builtin"),
    )
    .map_err(|err| {
        format!(
            "failed to read /lib/modules/{}/modules.builtin: {}",
            kernel_release, err
        )
    })?;

    Ok(parse_available_modules(&content).into_iter().collect())
}

/// Init compiled-in kernel modules for the running kernel.
fn init_compiled_in_modules() {
    COMPILED_IN_MODULES.init(get_compiled_in_modules);
}

/// Init modprobe configuration, disabled and blacklist.
pub fn init_modprobe() {
    init_modprobe_config();
    init_modprobe_disabled();
    init_modprobe_blacklist();
    init_loaded_modules();
    init_available_modules();
    init_compiled_in_modules();

    log_debug!("initialized modprobe");
}

/// Decide the checks that only depend on the state of a module for the running
/// kernel, returns `None` when the module is present and can be loaded.
///
/// `modules.builtin` is the list kmod itself uses to know that a module is
/// compiled-in, and `modules.dep` the list of modules it can load. A module
/// absent from both cannot be loaded, but without `modules.builtin` an absent
/// module is indistinguishable from a compiled-in one.
///
/// `action` is the verb used in the compiled-in failure message, `blacklist` or
/// `disable`.
fn check_module_state(module: &str, action: &str) -> Option<check::CheckReturn> {
    let module = normalize_module_name(module);

    match (
        COMPILED_IN_MODULES.get().map(|m| m.contains(&module)),
        AVAILABLE_MODULES.get().map(|m| m.contains(&module)),
    ) {
        // a compiled-in module is always active, it cannot be blacklisted nor
        // disabled
        (Ok(true), _) => Some((
            check::CheckState::Fail,
            Some(format!(
                "module is compiled-in in the kernel, you must recompile the kernel without it to be able to {} it",
                action
            )),
        )),
        // a module on disk cannot be compiled-in, even if `modules.builtin`
        // could not be read
        (_, Ok(true)) => None,
        (Ok(false), Ok(false)) => Some((
            check::CheckState::Pass,
            Some("module not present".to_string()),
        )),
        (Err(warning), Ok(false)) => Some(warning),
        (_, Err(warning)) => Some(warning),
    }
}

/// Match a module name against an `install` directive pattern.
///
/// kmod matches those with `fnmatch(pattern, modname, 0)`, so a single
/// directive can cover a whole module family (e.g. `install usb* /bin/false`).
/// Only `*` and `?` are supported, other patterns are compared literally, which
/// fails the check instead of silently passing it.
fn pattern_matches(pattern: &str, module: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let module: Vec<char> = module.chars().collect();
    let (mut p, mut m) = (0, 0);
    // position of the last `*` and of the module character it matched
    let mut star: Option<(usize, usize)> = None;

    while m < module.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, m));
                p += 1;
            }
            Some('?') => {
                p += 1;
                m += 1;
            }
            Some(&c) if c == module[m] => {
                p += 1;
                m += 1;
            }
            // on mismatch, let the last `*` consume one more character
            _ => match star {
                Some((star_p, star_m)) => {
                    p = star_p + 1;
                    m = star_m + 1;
                    star = Some((star_p, m));
                }
                None => return false,
            },
        }
    }

    pattern[p..].iter().all(|&c| c == '*')
}

/// Get the `install` directive kmod would run for a module, the first matching
/// directive in parse order wins.
fn get_install_directive<'a>(
    installs: &'a ModprobeDisabled,
    module: &str,
) -> Option<&'a InstallDirective> {
    installs
        .iter()
        .find(|install| pattern_matches(&install.module, module))
}

/// Returns `true` when an `install` command prevents the module from loading.
///
/// The command is run by `/bin/sh -c`, so anything after a `#` is a comment.
fn install_command_blocks(command: &str) -> bool {
    let command = command.split('#').next().unwrap_or_default();

    match command.split_whitespace().next() {
        Some(exe) => matches!(
            Path::new(exe).file_name().and_then(|name| name.to_str()),
            Some("false") | Some("true")
        ),
        None => false,
    }
}

/// Ensure that kernel module is blacklisted.
pub fn check_module_blacklist(module: &str) -> check::CheckReturn {
    if let Some(result) = check_module_state(module, "blacklist") {
        return result;
    }

    let m_blacklist = match MODPROBE_BLACKLIST.get() {
        Ok(m_blacklist) => m_blacklist,
        Err(warning) => return warning,
    };

    let loaded = match LOADED_MODULES.get() {
        Ok(loaded) => loaded,
        Err(warning) => return warning,
    };

    let module = normalize_module_name(module);

    if !m_blacklist.contains(&module) {
        return (
            check::CheckState::Fail,
            Some("module not blacklisted".to_string()),
        );
    }

    if loaded.contains(&module) {
        return (
            check::CheckState::Fail,
            Some("module blacklisted but loaded".to_string()),
        );
    }
    (check::CheckState::Pass, None)
}

/// Ensure that kernel module is disabled.
pub fn check_module_disabled(module: &str) -> check::CheckReturn {
    if let Some(result) = check_module_state(module, "disable") {
        return result;
    }

    let m_disabled = match MODPROBE_DISABLED.get() {
        Ok(m_disabled) => m_disabled,
        Err(warning) => return warning,
    };

    let loaded = match LOADED_MODULES.get() {
        Ok(loaded) => loaded,
        Err(warning) => return warning,
    };

    let module = normalize_module_name(module);

    let install = match get_install_directive(m_disabled, &module) {
        Some(install) => install,
        None => {
            return (
                check::CheckState::Fail,
                Some("module not disabled".to_string()),
            );
        }
    };

    if !install_command_blocks(&install.command) {
        return (
            check::CheckState::Fail,
            Some(format!(
                "install command does not prevent loading: {}",
                install.command
            )),
        );
    }

    if loaded.contains(&module) {
        return (
            check::CheckState::Fail,
            Some("module disabled but loaded".to_string()),
        );
    }
    (check::CheckState::Pass, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_available_modules() {
        let modules = parse_available_modules(
            "kernel/arch/x86/events/amd/amd-uncore.ko.zst:
kernel/drivers/usb/misc/usbtest.ko.xz: kernel/drivers/usb/core/usbcore.ko
kernel/arch/x86/events/intel/intel-uncore.ko
",
        );
        assert_eq!(modules.len(), 3);
        assert!(modules.contains(&"amd_uncore".to_string()));
        assert!(modules.contains(&"usbtest".to_string()));
        assert!(modules.contains(&"intel_uncore".to_string()));
    }

    #[test]
    fn test_normalize_module_name() {
        assert_eq!(normalize_module_name("snd-intel8x0"), "snd_intel8x0");
        assert_eq!(normalize_module_name("snd_intel8x0"), "snd_intel8x0");
    }

    #[test]
    fn test_parse_directive() {
        // keyword must be a full token, module names are normalized, the rest
        // of the line is kept as the argument
        let directive = parse_line("install snd-pcm-oss /bin/false").unwrap();
        assert_eq!(directive.cmd, "install");
        assert_eq!(directive.module, "snd_pcm_oss");
        assert_eq!(directive.arg, "/bin/false");

        // kmod ignores leading whitespace
        assert_eq!(
            parse_line("\t  blacklist snd-pcm-oss").unwrap().module,
            "snd_pcm_oss"
        );

        // comments and empty lines
        assert!(parse_line("# blacklist foo").is_none());
        assert!(parse_line("   ").is_none());

        // directives without module name or keyword
        assert!(parse_line("blacklist").is_none());
        assert_eq!(parse_line("blacklistx foo").unwrap().cmd, "blacklistx");

        // a directive with no argument is still valid, e.g. `blacklist foo`
        let directive = parse_line("blacklist foo").unwrap();
        assert!(directive.arg.is_empty());
    }

    #[test]
    fn test_parse_modprobe() {
        let config = parse_modprobe(
            "# comment
blacklist snd-pcm-oss
options snd-hda-intel index=0
install snd_pcm /sbin/modprobe --ignore-install snd_pcm

blacklist usb-midi
",
        );
        assert_eq!(config.len(), 4);
        assert_eq!(config[0].cmd, "blacklist");
        assert_eq!(config[0].module, "snd_pcm_oss");
        assert_eq!(config[3].module, "usb_midi");
    }

    #[test]
    fn test_install_command_blocks() {
        assert!(install_command_blocks("/bin/false"));
        assert!(install_command_blocks("/usr/bin/false"));
        assert!(install_command_blocks("true"));
        // the command is run by `/bin/sh -c`
        assert!(install_command_blocks("/bin/false # CIS 4.4.2"));
        assert!(install_command_blocks("  /bin/true  "));

        assert!(!install_command_blocks(
            "/sbin/modprobe --ignore-install snd_pcm"
        ));
        assert!(!install_command_blocks(""));
        assert!(!install_command_blocks("/bin/falsey"));
    }

    #[test]
    fn test_pattern_matches() {
        assert!(pattern_matches("usb_storage", "usb_storage"));
        assert!(!pattern_matches("usb_storage", "usb_storag"));
        assert!(pattern_matches("usb*", "usb_storage"));
        assert!(pattern_matches("*", "usb_storage"));
        assert!(pattern_matches("*storage", "usb_storage"));
        assert!(pattern_matches("usb_*age", "usb_storage"));
        assert!(pattern_matches("usb_storag?", "usb_storage"));
        assert!(!pattern_matches("usb?", "usb_storage"));
        assert!(!pattern_matches("snd*", "usb_storage"));
        assert!(!pattern_matches("usb_storage", "usb_storagex"));
    }

    #[test]
    fn test_parse_proc_modules() {
        let modules = parse_proc_modules(
            "nf_conntrack_netlink 61440 0 - Live 0x0000000000000000
snd_hda_intel 61440 2 - Live 0x0000000000000000
usb_storage 61440 0 - Live 0x0000000000000000
",
        );
        assert_eq!(modules.len(), 3);
        assert!(modules.contains(&"nf_conntrack_netlink".to_string()));
        assert!(modules.contains(&"snd_hda_intel".to_string()));
    }
}
