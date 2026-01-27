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

use crate::{check, log_debug, log_error};

const HOSTS_PATH: &str = "/etc/hosts";

static HOSTS: OnceLock<Hosts> = OnceLock::new();

pub struct Host {
    addr: String,
    value: String,
}

/// Raw grub config from `/etc/hosts`.
pub type Hosts = Vec<Host>;

/// Parse content of `/etc/hosts`.
fn parse_hosts(hosts: String) -> Hosts {
    hosts
        .lines()
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("#"))
        .filter_map(|line| match line.split_once(char::is_whitespace) {
            Some((addr, value)) => Some(Host {
                addr: addr.to_string(),
                value: value.trim_start().to_string(),
            }),
            // should never happen, don't even log it
            None => None,
        })
        .collect()
}

/// Get the system's hosts config from `/boot/grub/grub.cfg`.
fn get_hosts() -> Result<Hosts, std::io::Error> {
    Ok(parse_hosts(fs::read_to_string(HOSTS_PATH)?))
}

/// Init the system's hosts config from `/boot/grub/grub.cfg`.
pub fn init_hosts() {
    if HOSTS.get().is_some() {
        return;
    }

    match get_hosts() {
        Ok(h) => {
            HOSTS.get_or_init(|| h);
            log_debug!("initialized hosts");
        }
        Err(err) => log_error!("failed to initialize hosts: {}", err),
    }
}

/// Ensure that hosts entry is present.
pub fn entry_present(addr: &str, value: &str) -> check::CheckReturn {
    let hosts = match HOSTS.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("hosts configuration not initialized".to_string()),
            );
        }
    };

    for host in hosts {
        if host.addr == addr && host.value == value {
            return (check::CheckState::Passed, None);
        }
    }

    (check::CheckState::Failed, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hosts() {
        let lines = parse_hosts(
            "# comment

#
127.0.0.1        localhost
::1              localhost
255.255.255.255 broadcasthost
fe80::1%lo0   localhost
ff00::0  ip6-localnet
0.0.0.0    foo.com
0.0.0.0     bar.com
"
            .to_string(),
        );

        assert_eq!(lines.len(), 7);
        assert_eq!(lines[0].addr, "127.0.0.1".to_string());
        assert_eq!(lines[0].value, "localhost".to_string());
        assert_eq!(lines[1].addr, "::1".to_string());
        assert_eq!(lines[1].value, "localhost".to_string());
        assert_eq!(lines[2].addr, "255.255.255.255".to_string());
        assert_eq!(lines[2].value, "broadcasthost".to_string());
        assert_eq!(lines[3].addr, "fe80::1%lo0".to_string());
        assert_eq!(lines[3].value, "localhost".to_string());
        assert_eq!(lines[4].addr, "ff00::0".to_string());
        assert_eq!(lines[4].value, "ip6-localnet".to_string());
        assert_eq!(lines[5].addr, "0.0.0.0".to_string());
        assert_eq!(lines[5].value, "foo.com".to_string());
        assert_eq!(lines[6].addr, "0.0.0.0".to_string());
        assert_eq!(lines[6].value, "bar.com".to_string());
    }
}
