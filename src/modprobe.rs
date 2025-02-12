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
use std::process;
use std::process::Stdio;

/// Modprobe configuration.
pub type ModprobeConfig = Vec<String>;

// NOTE: disabled and blacklisted are two different things, blacklist means the
// module won't start automatically, and disabled means it will never be able
// to start

/// List of blacklisted kernel modules.
pub type ModprobeBlacklist = Vec<String>;

/// List of disabled kernel modules.
pub type ModprobeDisabled = Vec<String>;

/// Parse en content of a modprobe configuration file.
fn parse_modprobe(content: String) -> ModprobeConfig {
    content
        .lines()
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("#"))
        .map(|module| module.to_string())
        .collect()
}

/// Get modprobe configuration by reading files.
pub fn init_modprobe() -> Result<ModprobeConfig, std::io::Error> {
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

    Ok(config)
}

/// Get modprobe blacklisted modules from modprobe config.
pub fn init_modprobe_blacklist(modprobe: &ModprobeConfig) -> ModprobeBlacklist {
    modprobe
        .into_iter()
        .filter(|line| {
            // `blacklist mod_name`
            line.starts_with("blacklist")
        })
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(|line| line.to_string())
        .collect()
}

/// Get modprobe disabled modules from modprobe config.
pub fn init_modprobe_disabled(modprobe: &ModprobeConfig) -> ModprobeDisabled {
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

/// Get currently loaded kernel modules by running `lsmod`.
pub fn init_loaded_modules() -> Result<Vec<String>, std::io::Error> {
    // TODO: read from `/proc/modules` instead of using `lsmod`
    let mut cmd = process::Command::new("lsmod");
    cmd.stdin(Stdio::null());

    let output = cmd.output()?;

    // TODO: error if not 0
    // match output.status.code() {
    //     Some(c) => c,
    //     None => 0,
    // }

    Ok(parse_lsmod_modules(
        String::from_utf8_lossy(&output.stdout).to_string(),
    ))
}
