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

use crate::utils::run;

use std::collections::HashMap;
use std::fs;

const KOSTYPE_PATH: &str = "/proc/sys/kernel/ostype";

const KOSRELEASE_PATH: &str = "/proc/sys/kernel/osrelease";

const OS_RELEASE_PATH: &str = "/etc/os-release";

/// OS.
#[derive(Debug)]
pub struct OS {
    os: String,
    name: String,
    version: String,
    full_name: String,
}

/// OS release.
pub type OSRelease = HashMap<String, String>;

/// Init system OS type by reading `/proc/sys/kernel/ostype`.
pub fn init_kernel_os_type() -> Result<String, std::io::Error> {
    let content = fs::read_to_string(KOSTYPE_PATH)?;
    Ok(content.trim_end().to_string())
}

/// Init system OS release by reading `/proc/sys/kernel/osrelease`.
pub fn init_kernel_os_release() -> Result<String, std::io::Error> {
    let content = fs::read_to_string(KOSRELEASE_PATH)?;
    Ok(content.trim_end().to_string())
}

/// Parse content of `/etc/os-release`.
fn parse_os_release(content: String) -> OSRelease {
    content
        .lines()
        .filter_map(|line| match line.split_once("=") {
            Some((key, value)) => Some((
                key.to_string(),
                // parse the value, can be inside quotes single or double
                value.to_string().replace("'", "").replace("\"", ""),
            )),
            // should never happen, don't even log it
            None => None,
        })
        .collect()
}

/// Get OS release info from `/etc/os-release`.
pub fn init_os_release() -> Result<OSRelease, std::io::Error> {
    let content = fs::read_to_string(OS_RELEASE_PATH)?;
    Ok(parse_os_release(content))
}

pub fn detect_os() -> Result<OS, std::io::Error> {
    let uname = run!("uname");

    Ok(match uname.as_str() {
        "AIX" => OS {
            os: "AIX".to_string(),
            name: "AIX".to_string(),
            version: run!("oslevel"),
            // FIXME: get the full name from the version
            full_name: format!("AIX {}", "foo"),
        },

        "Darwin" => OS {
            os: "macOS".to_string(),
            name: "macOS".to_string(),
            // version: run!("/usr/bin/sw_vers", "-productVersion"),
            version: run!("uname", "-r"),
            full_name: run!("uname", "-s", "-r"),
        },

        "DragonFly" => OS {
            os: "DragonFly".to_string(),
            name: "DragonFly BSD".to_string(),
            version: run!("uname", "-r"),
            full_name: run!("uname", "-s", "-r"),
        },

        "FreeBSD" => OS {
            os: "FreeBSD".to_string(),
            name: "FreeBSD".to_string(),
            version: run!("uname", "-r"),
            full_name: run!("uname", "-s", "-r"),
        },

        "HP-UX" => OS {
            os: "HP-UX".to_string(),
            name: "HP-UX".to_string(),
            version: run!("uname", "-r"),
            full_name: run!("uname", "-s", "-r"),
        },

        // TODO: handle the different distro
        "Linux" => OS {
            os: "Linux".to_string(),
            name: "Linux".to_string(),
            version: run!("uname", "-r"),
            full_name: run!("uname", "-s", "-r"),
        },

        "NetBSD" => OS {
            os: "NetBSD".to_string(),
            name: "NetBSD".to_string(),
            version: run!("uname", "-r"),
            full_name: run!("uname", "-s", "-r"),
        },

        "OpenBSD" => OS {
            os: "OpenBSD".to_string(),
            name: "OpenBSD".to_string(),
            version: run!("uname", "-r"),
            full_name: run!("uname", "-s", "-r"),
        },

        "SunOS" => OS {
            os: "Solaris".to_string(),
            name: "Solaris".to_string(),
            version: run!("uname", "-r"),
            full_name: run!("uname", "-s", "-r"),
        },

        "VMkernel" => OS {
            os: "VMkernel".to_string(),
            name: "VMware ESXI".to_string(),
            version: run!("uname", "-r"),
            // FIXME: read with a macro
            full_name: run!("cat", "/etc/vmware-release"),
        },

        _ => {
            if uname != "" {
                println!("OS {} not supported", uname)
            } else {
                println!("Failed to detect OS with command `uname`")
            }
            OS {
                os: "unkown".to_string(),
                name: "unkown".to_string(),
                version: "unkown".to_string(),
                full_name: "unkown".to_string(),
            }
        }
    })
}
