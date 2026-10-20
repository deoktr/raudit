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

use regex::Regex;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::{check, log_trace};

/// Check if file is either empty or not present.
pub fn empty_or_missing_file(path: &str) -> check::CheckReturn {
    match fs::metadata(path) {
        Ok(meta) => {
            if meta.len() == 0 {
                (check::CheckState::Pass, None)
            } else {
                (check::CheckState::Fail, Some("file not empty".to_string()))
            }
        }
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => (check::CheckState::Pass, None),
            _ => (check::CheckState::Warning, Some(err.to_string())),
        },
    }
}

/// Check if file exist and is empty.
#[allow(dead_code)]
pub fn empty_file(path: &str) -> check::CheckReturn {
    match fs::metadata(path) {
        Ok(meta) => {
            if meta.len() == 0 {
                (check::CheckState::Pass, None)
            } else {
                (check::CheckState::Fail, Some("file not empty".to_string()))
            }
        }
        Err(err) => (check::CheckState::Warning, Some(err.to_string())),
    }
}

/// Check if a directory exist.
#[allow(dead_code)]
pub fn directory_exist(path: &str) -> check::CheckReturn {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        (check::CheckState::Pass, None)
    } else {
        (check::CheckState::Fail, None)
    }
}

/// How an entry mode relates to the target permissions.
#[derive(Clone, Copy)]
enum ModeMatch {
    /// The mode must be exactly the target mode.
    Exact,

    /// The mode must not grant any bit outside the target mode, eg. `0600` is
    /// accepted for a target of `0644`.
    ///
    /// A stricter file is not a security issue and some distros ship stricter
    /// defaults, only use when a stricter mode cannot break the file consumers
    /// otherwise it could be a security issue for example DOS.
    OrStricter,
}

impl ModeMatch {
    /// Permissions should be defined like: 0o644.
    /// <https://doc.rust-lang.org/std/os/unix/fs/trait.MetadataExt.html#tymethod.mode>
    fn is_satisfied_by(self, mode: u32, perms: u32) -> bool {
        match self {
            ModeMatch::Exact => mode == perms,
            ModeMatch::OrStricter => mode & !perms == 0,
        }
    }

    fn hint(self) -> &'static str {
        match self {
            ModeMatch::Exact => "",
            ModeMatch::OrStricter => " or stricter",
        }
    }
}

/// Kind of entry expected at the audited path, anything else is a warning.
#[derive(Clone, Copy)]
enum EntryKind {
    File,
    Dir,
    Socket,
}

impl EntryKind {
    fn matches(self, metadata: &fs::Metadata) -> bool {
        match self {
            EntryKind::File => metadata.is_file(),
            EntryKind::Dir => metadata.is_dir(),
            EntryKind::Socket => metadata.file_type().is_socket(),
        }
    }

    fn label(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Dir => "directory",
            EntryKind::Socket => "socket",
        }
    }
}

/// Compare an entry mode with the target permissions.
fn check_mode(mode: u32, perms: u32, matching: ModeMatch) -> check::CheckReturn {
    if matching.is_satisfied_by(mode, perms) {
        (check::CheckState::Pass, None)
    } else {
        (
            check::CheckState::Fail,
            Some(format!(
                "wanted \"{:o}\"{} got \"{:o}\"",
                perms,
                matching.hint(),
                mode
            )),
        )
    }
}

/// Compare an entry owner uid and gid with the expected ones.
fn check_owner(muid: u32, mgid: u32, uid: u32, gid: u32) -> check::CheckReturn {
    if muid != uid || mgid != gid {
        (
            check::CheckState::Fail,
            Some(format!(
                "wanted \"{}:{}\" got \"{}:{}\"",
                uid, gid, muid, mgid
            )),
        )
    } else {
        (check::CheckState::Pass, None)
    }
}

/// Check an entry mode against the target permissions.
fn entry_mode(
    metadata: &fs::Metadata,
    path: &Path,
    perms: u32,
    matching: ModeMatch,
) -> check::CheckReturn {
    let mode = metadata.mode() & 0o777;

    log_trace!("checking entry mode for {:?}, got: {:o}", path, mode);

    check_mode(mode, perms, matching)
}

// TODO: have an alternative function that takes in a username and group name
/// Check an entry owner uid and gid.
fn entry_owner(metadata: &fs::Metadata, path: &Path, uid: u32, gid: u32) -> check::CheckReturn {
    let muid = metadata.uid();
    let mgid = metadata.gid();

    log_trace!(
        "checking entry owner for {:?}, got: {}:{}",
        path,
        muid,
        mgid
    );

    check_owner(muid, mgid, uid, gid)
}

/// Stat `path`, verify the entry kind, then run `check` on its metadata.
///
/// A missing path is a warning, unless `ignore_missing` is set, for rules about
/// optional files.
fn with_entry<F>(path: &str, kind: EntryKind, ignore_missing: bool, check: F) -> check::CheckReturn
where
    F: FnOnce(&fs::Metadata) -> check::CheckReturn,
{
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            return match err.kind() {
                std::io::ErrorKind::NotFound if ignore_missing => {
                    (check::CheckState::Pass, Some("file missing".to_string()))
                }
                _ => (check::CheckState::Warning, Some(err.to_string())),
            };
        }
    };

    if !kind.matches(&metadata) {
        return (
            check::CheckState::Warning,
            Some(format!("path is not a {}", kind.label())),
        );
    }

    check(&metadata)
}

/// Implementation shared by every `check_*_permission*` function.
fn check_permission(
    path: &str,
    kind: EntryKind,
    matching: ModeMatch,
    ignore_missing: bool,
    perms: u32,
) -> check::CheckReturn {
    with_entry(path, kind, ignore_missing, |metadata| {
        entry_mode(metadata, Path::new(path), perms, matching)
    })
}

/// Implementation shared by every `check_*_owner_id` function.
fn check_owner_id(
    path: &str,
    kind: EntryKind,
    ignore_missing: bool,
    uid: u32,
    gid: u32,
) -> check::CheckReturn {
    with_entry(path, kind, ignore_missing, |metadata| {
        entry_owner(metadata, Path::new(path), uid, gid)
    })
}

/// Run `check` on every regular file of the directory `path`, stopping at the
/// first entry that does not pass.
fn check_dir_files<F>(path: &str, mut check: F) -> check::CheckReturn
where
    F: FnMut(&Path, &fs::Metadata) -> check::CheckReturn,
{
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(err) => {
            return (
                check::CheckState::Warning,
                Some(format!("failed to open directory {}: {}", path, err)),
            );
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                return (
                    check::CheckState::Warning,
                    Some(format!("error on path {:?}: {}", path, err)),
                );
            }
        };

        let file = entry.path();
        if !file.is_file() {
            continue;
        }

        if let Ok(metadata) = fs::metadata(&file) {
            let (state, message) = check(&file, &metadata);
            if state != check::CheckState::Pass {
                return (state, message);
            }
        }
    }

    (check::CheckState::Pass, None)
}

fn check_dir_files_permission_common(
    path: &str,
    perms: u32,
    matching: ModeMatch,
) -> check::CheckReturn {
    check_dir_files(path, |file, metadata| {
        let (state, message) = entry_mode(metadata, file, perms, matching);
        match message {
            Some(message) => (
                state,
                Some(format!("file {:?} permission: {}", file, message)),
            ),
            None => (state, None),
        }
    })
}

/// Check a file permissions.
///
/// Permissions should be defined like: 0o644.
pub fn check_file_permission(path: &str, perms: u32) -> check::CheckReturn {
    check_permission(path, EntryKind::File, ModeMatch::Exact, false, perms)
}

/// Check a file permissions are equal or stricter than the target mode.
///
/// Permissions should be defined like: 0o644.
pub fn check_file_permission_or_stricter(path: &str, perms: u32) -> check::CheckReturn {
    check_permission(path, EntryKind::File, ModeMatch::OrStricter, false, perms)
}

/// Check a file permissions, and ignore error if file is missing.
///
/// Permissions should be defined like: 0o644.
pub fn check_file_permission_ignore_missing(path: &str, perms: u32) -> check::CheckReturn {
    check_permission(path, EntryKind::File, ModeMatch::Exact, true, perms)
}

/// Check a file permissions are equal or stricter than the target mode, and
/// ignore error if file is missing.
///
/// Permissions should be defined like: 0o644.
pub fn check_file_permission_or_stricter_ignore_missing(
    path: &str,
    perms: u32,
) -> check::CheckReturn {
    check_permission(path, EntryKind::File, ModeMatch::OrStricter, true, perms)
}

/// Check a directory permissions.
///
/// Permissions should be defined like: 0o644.
pub fn check_dir_permission(path: &str, perms: u32) -> check::CheckReturn {
    check_permission(path, EntryKind::Dir, ModeMatch::Exact, false, perms)
}

/// Check a directory permissions are equal or stricter than the target mode.
///
/// Permissions should be defined like: 0o644.
pub fn check_dir_permission_or_stricter(path: &str, perms: u32) -> check::CheckReturn {
    check_permission(path, EntryKind::Dir, ModeMatch::OrStricter, false, perms)
}

/// Check a socket file permissions.
///
/// Permissions should be defined like: 0o644.
pub fn check_socket_permission(path: &str, perms: u32) -> check::CheckReturn {
    check_permission(path, EntryKind::Socket, ModeMatch::Exact, false, perms)
}

/// Check a socket file permissions are equal or stricter than the target mode.
///
/// Permissions should be defined like: 0o644.
pub fn check_socket_permission_or_stricter(path: &str, perms: u32) -> check::CheckReturn {
    check_permission(path, EntryKind::Socket, ModeMatch::OrStricter, false, perms)
}

/// Check permissions of all the files inside a directory.
///
/// Permissions should be defined like: 0o644.
pub fn check_dir_files_permission(path: &str, perms: u32) -> check::CheckReturn {
    check_dir_files_permission_common(path, perms, ModeMatch::Exact)
}

/// Check permissions of all the files inside a directory are equal or stricter
/// than the target mode.
///
/// Permissions should be defined like: 0o644.
pub fn check_dir_files_permission_or_stricter(path: &str, perms: u32) -> check::CheckReturn {
    check_dir_files_permission_common(path, perms, ModeMatch::OrStricter)
}

/// Check a file owner uid and gid.
pub fn check_file_owner_id(path: &str, uid: u32, gid: u32) -> check::CheckReturn {
    check_owner_id(path, EntryKind::File, false, uid, gid)
}

/// Check a file owner uid and gid, and ignore error if file is missing.
pub fn check_file_owner_id_ignore_missing(path: &str, uid: u32, gid: u32) -> check::CheckReturn {
    check_owner_id(path, EntryKind::File, true, uid, gid)
}

/// Check a directory owner uid and gid.
pub fn check_dir_owner_id(path: &str, uid: u32, gid: u32) -> check::CheckReturn {
    check_owner_id(path, EntryKind::Dir, false, uid, gid)
}

/// Check a socket file owner uid and gid.
pub fn check_socket_owner_id(path: &str, uid: u32, gid: u32) -> check::CheckReturn {
    check_owner_id(path, EntryKind::Socket, false, uid, gid)
}

/// Check all directory files owner uid and gid.
pub fn check_dir_files_owner_id(path: &str, uid: u32, gid: u32) -> check::CheckReturn {
    check_dir_files(path, |file, metadata| {
        let (state, message) = entry_owner(metadata, file, uid, gid);
        match message {
            Some(message) => (state, Some(format!("file: {:?}: {}", file, message))),
            None => (state, None),
        }
    })
}

/// Check if the file content matches the pattern.
pub fn check_file_content_regex(path: &str, pattern: &str) -> check::CheckReturn {
    let re = match Regex::new(pattern) {
        Ok(re) => re,
        Err(err) => {
            return (
                check::CheckState::Warning,
                Some(format!("failed to compile shell timeout regex: {}", err)),
            );
        }
    };

    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => {
                return (check::CheckState::Fail, Some("file not found".to_string()));
            }
            _ => {
                return (
                    check::CheckState::Warning,
                    Some(format!("failed to read file: {}", err)),
                );
            }
        },
    };

    if re.is_match(&content) {
        (check::CheckState::Pass, None)
    } else {
        (check::CheckState::Fail, Some("no match".to_string()))
    }
}
