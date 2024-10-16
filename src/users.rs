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

use std::fs;

/// Passwd configuration from `/etc/passwd`.
pub type PasswdConfig = Vec<Passwd>;

/// Shadow configuration from `/etc/shadow`.
pub type ShadowConfig = Vec<Shadow>;

/// Passwd entry.
#[allow(dead_code)]
pub struct Passwd {
    username: String,
    password: String,
    uid: u32,
    gid: u32,
    gecos: String,
    home: String,
    shell: String,
}

/// Shadow entry.
#[allow(dead_code)]
pub struct Shadow {
    username: String,
    password: String,
    last_change: u64,
    min_age: u32,
    max_age: u32,
    warn_period: u32,
    inactivity_period: Option<u32>,
    expiration_date: Option<u32>,
    unused: String,
}

/// Parse the content of passwd.
pub fn parse_passwd(content: String) -> PasswdConfig {
    content
        .lines()
        .map(|line| {
            let mut kvs = line.splitn(7, ":");
            let username = kvs.next().unwrap_or_default().to_string();
            let password = kvs.next().unwrap_or_default().to_string();
            let uid = kvs
                .next()
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or_default();
            let gid = kvs
                .next()
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or_default();
            let gecos = kvs.next().unwrap_or_default().to_string();
            let home = kvs.next().unwrap_or_default().to_string();
            let shell = kvs.next().unwrap_or_default().to_string();
            Passwd {
                username,
                password,
                uid,
                gid,
                gecos,
                home,
                shell,
            }
        })
        .collect()
}

/// Get the system's users from `/etc/passwd`.
pub fn init_passwd() -> Result<PasswdConfig, std::io::Error> {
    let passwd = fs::read_to_string("/etc/passwd")?;
    Ok(parse_passwd(passwd))
}

/// Parse the content of `/etc/passwd`.
pub fn parse_shadow(content: String) -> ShadowConfig {
    content
        .lines()
        .map(|line| {
            let mut kvs = line.splitn(9, ":");
            // TODO: log errors
            let username = kvs.next().unwrap_or_default().to_string();
            let password = kvs.next().unwrap_or_default().to_string();
            let last_change = kvs
                .next()
                .unwrap_or_default()
                .parse::<u64>()
                .unwrap_or_default();
            let min_age = kvs
                .next()
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or_default();
            let max_age = kvs
                .next()
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or_default();
            let warn_period = kvs
                .next()
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or_default();
            let inactivity_period = match kvs.next() {
                Some(v) => {
                    if v.len() == 0 {
                        None
                    } else {
                        match v.parse::<u32>() {
                            Ok(i) => Some(i),
                            Err(_) => None,
                        }
                    }
                }
                None => None,
            };
            let expiration_date = match kvs.next() {
                Some(v) => {
                    if v.len() == 0 {
                        None
                    } else {
                        match v.parse::<u32>() {
                            Ok(i) => Some(i),
                            Err(_) => None,
                        }
                    }
                }
                None => None,
            };
            let unused = kvs.next().unwrap_or_default().to_string();
            Shadow {
                username,
                password,
                last_change,
                min_age,
                max_age,
                warn_period,
                inactivity_period,
                expiration_date,
                unused,
            }
        })
        .collect()
}

/// Get the system's users from `/etc/shadow`.
pub fn init_shadow() -> Result<ShadowConfig, std::io::Error> {
    let shadow = fs::read_to_string("/etc/shadow")?;
    Ok(parse_shadow(shadow))
}

/// Verify if any user has a password in passwd (not equal to `x`).
pub fn password_in_passwd(passwd: &PasswdConfig) -> bool {
    passwd.iter().any(|user| user.password != "x".to_string())
}

/// Verify that only root has UID 0.
pub fn no_uid_zero(passwd: &PasswdConfig) -> bool {
    passwd.iter().filter(|user| user.uid == 0).count() == 1
}

// TODO:
/// Ensure no accounts are locked, delete them.
// pub fn locked_account(passwd: &PasswdConfig) -> bool { }

// TODO:
/// Ensure that all home directories exist.

// TODO: Ensure all groups in /etc/passwd exist in /etc/group
// TODO: Ensure no duplicate GIDs exist
// TODO: Ensure that root account is locked (paranoid)

/// Ensure no duplicate UIDs exist.
///
/// Returns true if NO duplicate is found.
pub fn no_dup_uid(passwd: &PasswdConfig) -> bool {
    !passwd
        .iter()
        .any(|user| passwd.iter().filter(|u| u.uid == user.uid).count() > 1)
}

/// Ensure no duplicate user names exist.
///
/// Returns true if NO duplicate is found.
pub fn no_dup_username(passwd: &PasswdConfig) -> bool {
    !passwd.iter().any(|user| {
        passwd
            .iter()
            .filter(|u| u.username == user.username)
            .count()
            > 1
    })
}

// TODO: Ensure no login is available on account with UID < 1000 ?

/// Ensure `/etc/securetty` is kept empty or missing.
///
/// The file, `/etc/securetty` specifies where you are allowed to login as root
/// from. This file should be kept empty so that nobody can do so from a
/// terminal.
pub fn empty_securetty() -> Result<bool, std::io::Error> {
    match fs::metadata("/etc/securetty") {
        Ok(m) => Ok(m.len() == 0),
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => Ok(true),
            _ => Err(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_passwd() {
        let lines = parse_passwd(
            "systemd-timesync:x:996:996:systemd Time Synchronization:/:/usr/sbin/nologin"
                .to_string(),
        );
        assert_eq!(lines.len(), 1);
        assert!(lines.get(0).is_some());
        let line = lines.get(0).unwrap();
        assert_eq!(line.username, "systemd-timesync".to_string());
        assert_eq!(line.password, "x".to_string());
        assert_eq!(line.uid, 996);
        assert_eq!(line.gid, 996);
        assert_eq!(line.gecos, "systemd Time Synchronization".to_string());
        assert_eq!(line.home, "/".to_string());
        assert_eq!(line.shell, "/usr/sbin/nologin".to_string());

        let lines = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:996:996:systemd Time Synchronization:/:/usr/sbin/nologin
"
            .to_string(),
        );
        assert_eq!(lines.len(), 20);
        assert!(lines.get(0).is_some());
        let line = lines.get(0).unwrap();
        assert_eq!(line.username, "root".to_string());
        assert_eq!(line.password, "x".to_string());
        assert_eq!(line.uid, 0);
        assert_eq!(line.gid, 0);
        assert_eq!(line.gecos, "root".to_string());
        assert_eq!(line.home, "/root".to_string());
        assert_eq!(line.shell, "/bin/bash".to_string());

        assert!(lines.get(12).is_some());
        let line = lines.get(12).unwrap();
        assert_eq!(line.username, "www-data".to_string());
        assert_eq!(line.password, "x".to_string());
        assert_eq!(line.uid, 33);
        assert_eq!(line.gid, 33);
        assert_eq!(line.gecos, "www-data".to_string());
        assert_eq!(line.home, "/var/www".to_string());
        assert_eq!(line.shell, "/usr/sbin/nologin".to_string());

        assert!(lines.get(19).is_some());
        let line = lines.get(19).unwrap();
        assert_eq!(line.username, "systemd-timesync".to_string());
        assert_eq!(line.password, "x".to_string());
        assert_eq!(line.uid, 996);
        assert_eq!(line.gid, 996);
        assert_eq!(line.gecos, "systemd Time Synchronization".to_string());
        assert_eq!(line.home, "/".to_string());
        assert_eq!(line.shell, "/usr/sbin/nologin".to_string());
    }

    #[test]
    fn test_parse_shadow() {
        let lines = parse_shadow("foo:$6$zHvrJMa5Y690smbQ$z5zdL:18009:0:120:7:14::".to_string());
        assert_eq!(lines.len(), 1);
        assert!(lines.get(0).is_some());
        let line = lines.get(0).unwrap();
        assert_eq!(line.username, "foo".to_string());
        assert_eq!(line.password, "$6$zHvrJMa5Y690smbQ$z5zdL".to_string());
        assert_eq!(line.last_change, 18009);
        assert_eq!(line.min_age, 0);
        assert_eq!(line.max_age, 120);
        assert_eq!(line.warn_period, 7);
        assert_eq!(line.inactivity_period, Some(14));
        assert_eq!(line.expiration_date, None);
        assert_eq!(line.unused, "".to_string());

        let lines = parse_shadow(
            "daemon:*:19837:0:99999:7:::
bin:*:19837:0:99999:7:::
sys:*:19837:0:99999:7:::
sync:*:19837:0:99999:7:::
games:*:19837:0:99999:7:::
man:*:19837:0:99999:7:::
lp:*:19837:0:99999:7:::
mail:*:19837:0:99999:7:::
news:*:19837:0:99999:7:::
uucp:*:19837:0:99999:7:::
proxy:*:19837:0:99999:7:::
"
            .to_string(),
        );
        assert_eq!(lines.len(), 11);
        assert!(lines.get(0).is_some());
        let line = lines.get(0).unwrap();
        assert_eq!(line.username, "daemon".to_string());
        assert_eq!(line.password, "*".to_string());
        assert_eq!(line.last_change, 19837);
        assert_eq!(line.min_age, 0);
        assert_eq!(line.max_age, 99999);
        assert_eq!(line.warn_period, 7);
        assert_eq!(line.inactivity_period, None);
        assert_eq!(line.expiration_date, None);
        assert_eq!(line.unused, "".to_string());

        assert!(lines.get(1).is_some());
        let line = lines.get(1).unwrap();
        assert_eq!(line.username, "bin".to_string());
        assert_eq!(line.password, "*".to_string());
        assert_eq!(line.last_change, 19837);
        assert_eq!(line.min_age, 0);
        assert_eq!(line.max_age, 99999);
        assert_eq!(line.warn_period, 7);
        assert_eq!(line.inactivity_period, None);
        assert_eq!(line.expiration_date, None);
        assert_eq!(line.unused, "".to_string());

        assert!(lines.get(10).is_some());
        let line = lines.get(10).unwrap();
        assert_eq!(line.username, "proxy".to_string());
        assert_eq!(line.password, "*".to_string());
        assert_eq!(line.last_change, 19837);
        assert_eq!(line.min_age, 0);
        assert_eq!(line.max_age, 99999);
        assert_eq!(line.warn_period, 7);
        assert_eq!(line.inactivity_period, None);
        assert_eq!(line.expiration_date, None);
        assert_eq!(line.unused, "".to_string());
    }

    #[test]
    fn test_no_dup_username() {
        let passwd: PasswdConfig = vec![
            Passwd {
                username: "foo".to_string(),
                password: "x".to_string(),
                uid: 1,
                gid: 1,
                gecos: "foo".to_string(),
                home: "/home/foo".to_string(),
                shell: "/".to_string(),
            },
            Passwd {
                username: "bar".to_string(),
                password: "x".to_string(),
                uid: 1,
                gid: 1,
                gecos: "foo".to_string(),
                home: "/home/foo".to_string(),
                shell: "/".to_string(),
            },
            Passwd {
                username: "baz".to_string(),
                password: "x".to_string(),
                uid: 1,
                gid: 1,
                gecos: "foo".to_string(),
                home: "/home/foo".to_string(),
                shell: "/".to_string(),
            },
        ];
        let r = no_dup_username(&passwd);
        assert!(r);

        let passwd_dup: PasswdConfig = vec![
            Passwd {
                username: "foo".to_string(),
                password: "x".to_string(),
                uid: 1,
                gid: 1,
                gecos: "foo".to_string(),
                home: "/home/foo".to_string(),
                shell: "/".to_string(),
            },
            Passwd {
                username: "foo".to_string(),
                password: "x".to_string(),
                uid: 1,
                gid: 1,
                gecos: "foo".to_string(),
                home: "/home/foo".to_string(),
                shell: "/".to_string(),
            },
            Passwd {
                username: "baz".to_string(),
                password: "x".to_string(),
                uid: 1,
                gid: 1,
                gecos: "foo".to_string(),
                home: "/home/foo".to_string(),
                shell: "/".to_string(),
            },
        ];
        let r = no_dup_username(&passwd_dup);
        assert!(!r);
    }
}
