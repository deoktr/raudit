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
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::{check, log_debug, log_error};

static MODPROBE_CONFIG: OnceLock<ModprobeConfig> = OnceLock::new();
static MODPROBE_BLACKLIST: OnceLock<ModprobeBlacklist> = OnceLock::new();
static MODPROBE_DISABLED: OnceLock<ModprobeDisabled> = OnceLock::new();
static LOADED_MODULES: OnceLock<LoadedModules> = OnceLock::new();

/// Modprobe configuration.
pub type ModprobeConfig = Vec<String>;

// NOTE: disabled and blacklisted are two different things, blacklist means the
// module won't start automatically, and disabled means it will never be able
// to start

/// List of blacklisted kernel modules.
pub type ModprobeBlacklist = Vec<String>;

/// List of disabled kernel modules.
pub type ModprobeDisabled = Vec<String>;

/// List of loaded kernel modules.
pub type LoadedModules = Vec<String>;

/// Parse en content of a modprobe configuration file.
fn parse_modprobe(content: String) -> ModprobeConfig {
    content
        .lines()
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("#"))
        .map(|module| module.to_string())
        .collect()
}

/// Initialize modprobe configuration by reading files.
fn init_modprobe_config() {
    if MODPROBE_CONFIG.get().is_some() {
        return;
    }

    // get all modprob configuration file paths
    let paths: Vec<PathBuf> = vec![
        fs::read_dir("/lib/modprobe.d/"),
        fs::read_dir("/usr/local/lib/modprobe.d/"),
        fs::read_dir("/run/modprobe.d/"),
        fs::read_dir("/etc/modprobe.d/"),
    ]
    .into_iter()
    .filter(|dir| dir.is_ok())
    .map(|dir| dir.unwrap())
    .map(|dir| {
        dir.filter(|dentry| dentry.is_ok())
            .map(|dentry| dentry.unwrap())
            // only keep `.conf` files
            .filter(|dentry| dentry.file_name().to_string_lossy().ends_with(".conf"))
            .map(|dentry| dentry.path())
            .filter(|path| !path.is_dir())
            .collect::<Vec<PathBuf>>()
    })
    .flatten()
    .collect();

    // get the configuration from all config paths
    let config: ModprobeConfig = paths
        .into_iter()
        .map(|path| fs::read_to_string(path))
        .filter(|rcontent| rcontent.is_ok())
        .map(|rcontent| rcontent.unwrap())
        .map(|content| parse_modprobe(content))
        .flatten()
        .collect();

    MODPROBE_CONFIG.get_or_init(|| config);

    log_debug!("initialized modprobe config");
}

/// Initialize modprobe blacklisted modules from modprobe config.
fn init_modprobe_blacklist() {
    if MODPROBE_BLACKLIST.get().is_some() {
        return;
    }

    let modprobe = match MODPROBE_CONFIG.get() {
        Some(c) => c,
        None => {
            log_error!("Failed to initialize modprobe blacklist: Modprobe is not initialized");
            return;
        }
    };

    MODPROBE_BLACKLIST.get_or_init(|| {
        modprobe
            .into_iter()
            .filter(|line| {
                // `blacklist mod_name`
                line.starts_with("blacklist")
            })
            .filter_map(|line| line.split_whitespace().nth(1))
            .map(|line| line.to_string())
            .collect()
    });

    log_debug!("initialized modprobe blacklist");
}

/// Initialize modprobe disabled modules from modprobe config.
fn init_modprobe_disabled() {
    if MODPROBE_DISABLED.get().is_some() {
        return;
    }

    let modprobe = match MODPROBE_CONFIG.get() {
        Some(c) => c,
        None => {
            log_error!("Failed to initialize modprobe blacklist: Modprobe is not initialized");
            return;
        }
    };

    MODPROBE_DISABLED.get_or_init(|| {
        modprobe
            .into_iter()
            .filter(|line| {
                // `install mod_name /bin/false`
                // OR
                // `install mod_name /bin/true`
                // NOTE: technically it can be any other executable other then the
                // actuall module
                // You could for example add a custom executable to log every
                // loading attempts
                line.starts_with("install")
                    && (line.ends_with("/bin/false") || line.ends_with("/bin/true"))
            })
            .filter_map(|line| line.split_whitespace().nth(1))
            .map(|line| line.to_string())
            .collect()
    });

    log_debug!("initialized modprobe disabled");
}

/// Parse the output of `lsmod` to extract modules.
fn parse_lsmod_modules(lsmod: String) -> Vec<String> {
    lsmod
        .lines()
        // skip first line
        .skip(1)
        .map(|line| {
            line.split_whitespace()
                .nth(0)
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

/// Initialize currently loaded kernel modules by reading `/proc/modules`.
fn init_loaded_modules() {
    if LOADED_MODULES.get().is_some() {
        return;
    }

    match fs::read_to_string("/proc/modules") {
        Ok(content) => {
            LOADED_MODULES.get_or_init(|| parse_lsmod_modules(content));
        }
        Err(err) => {
            log_error!("failed to initialize loaded kernel modules: {}", err);
            return;
        }
    };

    log_debug!("initialized modprobe loaded kernel modules");
}

/// Initialize modprobe configuration, disabled and blacklist.
pub fn init_modprobe() {
    init_modprobe_config();
    init_modprobe_disabled();
    init_modprobe_blacklist();
    init_loaded_modules();

    log_debug!("initialized modprobe");
}

/// Ensure that kernel module is blacklisted.
pub fn check_module_blacklist(module: &str) -> check::CheckReturn {
    let m_blacklist = match MODPROBE_BLACKLIST.get() {
        Some(m_blacklist) => m_blacklist,
        None => {
            return (
                check::CheckState::Error,
                Some("modprobe blacklist not initialized".to_string()),
            );
        }
    };

    let loaded = match LOADED_MODULES.get() {
        Some(loaded) => loaded,
        None => {
            return (
                check::CheckState::Error,
                Some("loaded modules not initialized".to_string()),
            );
        }
    };

    if m_blacklist.contains(&module.to_string()) {
        if !loaded.contains(&module.to_string()) {
            (check::CheckState::Passed, None)
        } else {
            (
                check::CheckState::Failed,
                Some("module blacklisted but loaded".to_string()),
            )
        }
    } else {
        (
            check::CheckState::Failed,
            Some("module not blacklisted".to_string()),
        )
    }
}

/// Ensure that kernel module is disabled.
pub fn check_module_disabled(module: &str) -> check::CheckReturn {
    let m_disabled = match MODPROBE_DISABLED.get() {
        Some(m_disabled) => m_disabled,
        None => {
            return (
                check::CheckState::Error,
                Some("modprobe disabled not initialized".to_string()),
            );
        }
    };

    let loaded = match LOADED_MODULES.get() {
        Some(loaded) => loaded,
        None => {
            return (
                check::CheckState::Error,
                Some("loaded modules not initialized".to_string()),
            );
        }
    };

    if m_disabled.contains(&module.to_string()) {
        // TODO: should we even care about it being loaded since it's disabled
        if !loaded.contains(&module.to_string()) {
            (check::CheckState::Passed, None)
        } else {
            (
                check::CheckState::Failed,
                Some("module disabled but loaded".to_string()),
            )
        }
    } else {
        (
            check::CheckState::Failed,
            Some("module not disabled".to_string()),
        )
    }
}

/// Add checks from a list of modules.
macro_rules! add_module_blacklisted_check_list {
    ($($module:expr),* $(,)?) => {
        let mut __i_add_module_blacklisted_check_list = 0;
        $(
            $crate::check::add_check(
                format!("KMD_{:03}", __i_add_module_blacklisted_check_list).as_str(),
                format!("Ensure that kernel module \"{}\" is blacklisted", $module).as_str(),
                vec!["modprobe"],
                || $crate::modprobe::check_module_blacklist($module),
                vec![$crate::modprobe::init_modprobe],
            );
            __i_add_module_blacklisted_check_list += 1;
        )*
    };
}

pub(crate) use add_module_blacklisted_check_list;

/// Add checks from a list of modules.
macro_rules! add_module_disabled_check_list {
    ($($module:expr),* $(,)?) => {
        let mut __i_add_module_disabled_check_list = 1;
        $(
            $crate::check::add_check(
                format!("KMD_{:03}", __i_add_module_disabled_check_list).as_str(),
                format!("Ensure that kernel module \"{}\" is disabled", $module).as_str(),
                vec!["modprobe"],
                || $crate::modprobe::check_module_disabled($module),
                vec![$crate::modprobe::init_modprobe],
            );
            __i_add_module_disabled_check_list += 1;
        )*
    };
}

pub(crate) use add_module_disabled_check_list;
