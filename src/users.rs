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
use std::path::Path;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::check;
use crate::{base, log_error};

const PASSWD_PATH: &str = "/etc/passwd";

const SHADOW_PATH: &str = "/etc/shadow";

const SECURETTY_PATH: &str = "/etc/securetty";

/// UID_MIN as defined in `/etc/login.defs`.
const UID_MIN: u32 = 1000;

static PASSWD_CONFIG: OnceLock<PasswdConfig> = OnceLock::new();

static SHADOW_CONFIG: OnceLock<ShadowConfig> = OnceLock::new();

/// Passwd configuration from `/etc/passwd`.
pub type PasswdConfig = Vec<Passwd>;

/// Shadow configuration from `/etc/shadow`.
pub type ShadowConfig = Vec<Shadow>;

/// Passwd entry.
#[allow(dead_code)]
pub struct Passwd {
    /// login name
    username: String,
    /// optional encrypted password
    password: String,
    /// numerical user ID
    uid: u32,
    /// numerical group ID
    gid: u32,
    /// user name or comment field
    gecos: String,
    /// user home directory
    home: String,
    /// optional user command interpreter
    shell: String,
}

/// Shadow entry.
#[allow(dead_code)]
pub struct Shadow {
    /// login name
    username: String,
    /// encrypted password
    password: String,
    /// date of last password change
    last_change: u64,
    /// minimum password age
    min_age: u32,
    /// maximum password age
    max_age: u32,
    /// password warning period
    warn_period: u32,
    /// password inactivity period
    inactivity_period: Option<u32>,
    /// account expiration date
    expiration_date: Option<u32>,
    /// reserved field
    reserved: String,
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
pub fn init_passwd() {
    if PASSWD_CONFIG.get().is_some() {
        return;
    }

    match fs::read_to_string(PASSWD_PATH) {
        Ok(content) => {
            PASSWD_CONFIG.get_or_init(|| parse_passwd(content));
        }
        Err(err) => log_error!("Failed to initialize passwd: {}", err),
    }
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
            let reserved = kvs.next().unwrap_or_default().to_string();
            Shadow {
                username,
                password,
                last_change,
                min_age,
                max_age,
                warn_period,
                inactivity_period,
                expiration_date,
                reserved,
            }
        })
        .collect()
}

/// Get the system's users from `/etc/shadow`.
pub fn init_shadow() {
    if SHADOW_CONFIG.get().is_some() {
        return;
    }

    match fs::read_to_string(SHADOW_PATH) {
        Ok(content) => {
            SHADOW_CONFIG.get_or_init(|| parse_shadow(content));
        }
        Err(err) => log_error!("Failed to initialize shadow: {}", err),
    }
}

/// Verify if any user has a password in passwd (not equal to `x`).
pub fn no_password_in_passwd() -> check::CheckReturn {
    let passwd = match PASSWD_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("passwd configuration not initialized".to_string()),
            )
        }
    };

    let g: Vec<String> = passwd
        .iter()
        .filter(|entry| entry.password != "x")
        .map(|entry| entry.username.clone())
        .collect();

    if g.len() != 0 {
        (check::CheckState::Failed, Some(g.join(", ")))
    } else {
        (check::CheckState::Passed, None)
    }
}

/// Verify that only root has UID 0.
pub fn no_uid_zero() -> check::CheckReturn {
    let passwd = match PASSWD_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("passwd configuration not initialized".to_string()),
            )
        }
    };

    let g: Vec<String> = passwd
        .iter()
        .filter(|entry| entry.uid == 0 && entry.username != "root")
        .map(|entry| entry.username.clone())
        .collect();

    if g.len() != 0 {
        (check::CheckState::Failed, Some(g.join(", ")))
    } else {
        (check::CheckState::Passed, None)
    }
}

/// Ensure all passwords are hashed with yescrypt.
pub fn yescrypt_hashes() -> check::CheckReturn {
    let shadow = match SHADOW_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("shadow configuration not initialized".to_string()),
            )
        }
    };

    // the full yescrypt format is:
    // \$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{,86}\$[./A-Za-z0-9]{43}
    let usernames: Vec<String> = shadow
        .iter()
        .filter(|entry| entry.password.starts_with("$y$") || entry.password == "!")
        .map(|entry| entry.username.clone())
        .collect();

    if usernames.len() != 0 {
        (check::CheckState::Failed, Some(usernames.join(", ")))
    } else {
        (check::CheckState::Passed, None)
    }
}

/// Ensure no accounts are locked, delete them.
///
/// Return true if NO account is locked.
pub fn no_locked_account() -> check::CheckReturn {
    let shadow = match SHADOW_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("shadow configuration not initialized".to_string()),
            )
        }
    };

    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(c) => c,
        Err(err) => return (check::CheckState::Error, Some(format!("{}", err))),
    };

    let days_since_epoch = now.as_secs() / 86400;

    let usernames: Vec<String> = shadow
        .iter()
        .filter(|entry| match entry.expiration_date {
            Some(expiration_date) => u64::from(expiration_date) <= days_since_epoch,
            None => false,
        })
        .map(|entry| entry.username.clone())
        .collect();

    if usernames.len() != 0 {
        (check::CheckState::Failed, Some(usernames.join(", ")))
    } else {
        (check::CheckState::Passed, None)
    }
}

/// Ensure that all home directories exist.
pub fn no_missing_home() -> check::CheckReturn {
    let passwd = match PASSWD_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("passwd configuration not initialized".to_string()),
            )
        }
    };

    let mut usernames: Vec<String> = vec![];
    for user in passwd.iter() {
        if (user.uid > 0 && user.uid < UID_MIN)
            || user.shell.ends_with("/nologin")
            || user.shell.ends_with("/false")
        {
            continue;
        }

        let p = Path::new(&user.home);
        if !p.exists() || !p.is_dir() {
            usernames.push(user.username.clone());
        }
    }

    if usernames.len() != 0 {
        (check::CheckState::Failed, Some(usernames.join(", ")))
    } else {
        (check::CheckState::Passed, None)
    }
}

// TODO: Ensure all groups in /etc/passwd exist in /etc/group
// pub fn no_missing_passwd_groups(passwd: &PasswdConfig, group: &GroupConfig) -> bool { }

// TODO: Ensure that root account is locked

/// Ensure no duplicate UIDs exist.
pub fn no_dup_uid() -> check::CheckReturn {
    let passwd = match PASSWD_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("passwd configuration not initialized".to_string()),
            )
        }
    };

    let usernames: Vec<String> = passwd
        .iter()
        .filter(|entry| passwd.iter().filter(|u| u.uid == entry.uid).count() > 1)
        .map(|entry| entry.username.clone())
        .collect();

    if usernames.len() != 0 {
        (check::CheckState::Failed, Some(usernames.join(", ")))
    } else {
        (check::CheckState::Passed, None)
    }
}

/// Ensure no duplicate user names exist.
pub fn no_dup_username() -> check::CheckReturn {
    let passwd = match PASSWD_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("passwd configuration not initialized".to_string()),
            )
        }
    };

    let usernames: Vec<String> = passwd
        .iter()
        .filter(|entry| {
            passwd
                .iter()
                .filter(|u| u.username == entry.username)
                .count()
                > 1
        })
        .map(|entry| entry.username.clone())
        .collect();

    if usernames.len() != 0 {
        (check::CheckState::Failed, Some(usernames.join(", ")))
    } else {
        (check::CheckState::Passed, None)
    }
}

/// Ensure no login is available on system accounts
///
/// Ensure that all system users (UID < 1000) can't login with a shell, either
/// have `nologin`, or `false` as shell.
pub fn no_login_sys_users() -> check::CheckReturn {
    let config = match PASSWD_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("passwd configuration not initialized".to_string()),
            )
        }
    };

    let usernames: Vec<String> = config
        .iter()
        .filter(|user| {
            (user.uid > 0 && user.uid < UID_MIN)
                && !(user.shell.ends_with("/nologin")
                || user.shell.ends_with("/false")
                // on some distro user `sync` as `/bin/sync` shell
                || user.shell.ends_with("/sync"))
        })
        .map(|entry| entry.username.clone())
        .collect();

    if usernames.len() != 0 {
        (check::CheckState::Failed, Some(usernames.join(", ")))
    } else {
        (check::CheckState::Passed, None)
    }
}

/// Ensure /etc/shadow password fields are not empty.
///
/// An account with an empty password field means that anybody may log in as
/// that user without providing a password.
pub fn no_empty_shadow_password() -> check::CheckReturn {
    let shadow = match SHADOW_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("shadow configuration not initialized".to_string()),
            )
        }
    };

    let usernames: Vec<String> = shadow
        .iter()
        .filter(|user| user.password == "")
        .map(|entry| entry.username.clone())
        .collect();

    if usernames.len() != 0 {
        (check::CheckState::Failed, Some(usernames.join(", ")))
    } else {
        (check::CheckState::Passed, None)
    }
}

/// Ensure /etc/passwd password fields are not empty.
///
/// An account with an empty password field means that anybody may log in as
/// that user without providing a password.
pub fn no_empty_passwd_password() -> check::CheckReturn {
    let passwd = match PASSWD_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Error,
                Some("passwd configuration not initialized".to_string()),
            )
        }
    };

    let usernames: Vec<String> = passwd
        .iter()
        .filter(|user| user.password == "")
        .map(|entry| entry.username.clone())
        .collect();

    if usernames.len() != 0 {
        (check::CheckState::Failed, Some(usernames.join(", ")))
    } else {
        (check::CheckState::Passed, None)
    }
}

/// Ensure `/etc/securetty` is empty or missing.
///
/// The file, `/etc/securetty` specifies where you are allowed to login as root
/// from. This file should be kept empty so that nobody can do so from a
/// terminal.
pub fn empty_securetty() -> check::CheckReturn {
    base::empty_or_missing_file(SECURETTY_PATH)
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
        assert_eq!(line.reserved, "".to_string());

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
        assert_eq!(line.reserved, "".to_string());

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
        assert_eq!(line.reserved, "".to_string());

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
        assert_eq!(line.reserved, "".to_string());
    }
}
