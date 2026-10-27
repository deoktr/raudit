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

use crate::check::{self, State};

const HOSTS_PATH: &str = "/etc/hosts";

static HOSTS: State<Hosts> = State::new("hosts");

struct Host {
    addr: String,
    value: String,
}

/// Hosts config from `/etc/hosts`.
type Hosts = Vec<Host>;

/// Parse content of `/etc/hosts`.
fn parse_hosts(hosts: String) -> Hosts {
    let mut entries = Vec::new();
    for line in hosts.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut fields = line.split_whitespace();
        let Some(addr) = fields.next() else {
            continue;
        };
        // every remaining field is a hostname mapped to that address, so each
        // one becomes its own entry, an address may repeat within a line or
        // across lines
        for value in fields {
            entries.push(Host {
                addr: addr.to_string(),
                value: value.to_string(),
            });
        }
    }
    entries
}

/// Get the system's hosts config from `/etc/hosts`.
fn get_hosts() -> Result<Hosts, String> {
    let content = fs::read_to_string(HOSTS_PATH)
        .map_err(|err| format!("failed to read `{}`: {}", HOSTS_PATH, err))?;
    Ok(parse_hosts(content))
}

/// Init the system's hosts config from `/etc/hosts`.
pub fn init_hosts() {
    HOSTS.init(get_hosts);
}

/// Ensure that hosts entry is present.
pub fn entry_present(addr: &str, value: &str) -> check::CheckReturn {
    HOSTS.with(|hosts| {
        for host in hosts {
            if host.addr == addr && host.value == value {
                return (check::CheckState::Pass, None);
            }
        }
        (check::CheckState::Fail, None)
    })
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
        assert_eq!(lines[0].addr, "127.0.0.1");
        assert_eq!(lines[0].value, "localhost");
        assert_eq!(lines[1].addr, "::1");
        assert_eq!(lines[1].value, "localhost");
        assert_eq!(lines[2].addr, "255.255.255.255");
        assert_eq!(lines[2].value, "broadcasthost");
        assert_eq!(lines[3].addr, "fe80::1%lo0");
        assert_eq!(lines[3].value, "localhost");
        assert_eq!(lines[4].addr, "ff00::0");
        assert_eq!(lines[4].value, "ip6-localnet");
        assert_eq!(lines[5].addr, "0.0.0.0");
        assert_eq!(lines[5].value, "foo.com");
        assert_eq!(lines[6].addr, "0.0.0.0");
        assert_eq!(lines[6].value, "bar.com");
    }

    #[test]
    fn test_parse_hosts_multiple_hostnames() {
        let lines = parse_hosts(
            "::1   ip6-localhost   ip6-loopback
127.0.0.1\tlocalhost localhost.localdomain   # trailing comment
   # indented full-line comment
10.0.0.5
"
            .to_string(),
        );

        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0].addr, "::1");
        assert_eq!(lines[0].value, "ip6-localhost");
        assert_eq!(lines[1].addr, "::1");
        assert_eq!(lines[1].value, "ip6-loopback");
        assert_eq!(lines[2].addr, "127.0.0.1");
        assert_eq!(lines[2].value, "localhost");
        assert_eq!(lines[3].addr, "127.0.0.1");
        assert_eq!(lines[3].value, "localhost.localdomain");
    }
}
