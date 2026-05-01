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

// TODO: check permission to be at most the value

use regex::Regex;
use std::fs;
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
pub fn directory_exist(path: &str) -> check::CheckReturn {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        (check::CheckState::Pass, None)
    } else {
        (check::CheckState::Fail, None)
    }
}

// TODO: have an alternative function that takes in a username and group name
/// Check a file owner uid and gid.
pub fn check_file_owner_id(path: &str, uid: u32, gid: u32) -> check::CheckReturn {
    let metadata = match fs::metadata(path) {
        Ok(v) => v,
        Err(err) => {
            return (check::CheckState::Warning, Some(err.to_string()));
        }
    };

    if !metadata.is_file() {
        return (
            check::CheckState::Warning,
            Some("path is not a file".to_string()),
        );
    }

    let muid = metadata.uid();
    let mgid = metadata.gid();

    log_trace!("checking file owner for {:?}, got: {}:{}", path, muid, mgid);

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

// TODO: have an alternative function that takes in a username and group name
/// Check a directory owner uid and gid.
pub fn check_dir_owner_id(path: &str, uid: u32, gid: u32) -> check::CheckReturn {
    let metadata = match fs::metadata(path) {
        Ok(v) => v,
        Err(err) => {
            return (check::CheckState::Warning, Some(err.to_string()));
        }
    };

    if !metadata.is_dir() {
        return (
            check::CheckState::Warning,
            Some("path is not a directory".to_string()),
        );
    }

    let muid = metadata.uid();
    let mgid = metadata.gid();

    log_trace!("checking file owner for {:?}, got: {}:{}", path, muid, mgid);

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

/// Check all directory files owner uid and gid.
pub fn check_dir_files_owner_id(path: &str, uid: u32, gid: u32) -> check::CheckReturn {
    match fs::read_dir(&path) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        let path = entry.path();
                        if !path.is_file() {
                            continue;
                        }

                        if let Ok(metadata) = fs::metadata(&path) {
                            let muid = metadata.uid();
                            let mgid = metadata.gid();

                            if muid != uid || mgid != gid {
                                return (
                                    check::CheckState::Fail,
                                    Some(format!(
                                        "file: {:?}: wanted \"{}:{}\" got \"{}:{}\"",
                                        path, uid, gid, muid, mgid
                                    )),
                                );
                            }
                        }
                    }
                    Err(err) => {
                        return (
                            check::CheckState::Warning,
                            Some(format!("error on path {:?}: {}", path, err)),
                        );
                    }
                }
            }
            (check::CheckState::Pass, None)
        }
        Err(err) => (
            check::CheckState::Warning,
            Some(format!("failed to open directory {}: {}", path, err)),
        ),
    }
}

/// Check a file owner uid and gid, and ignore error if file is missing.
pub fn check_file_owner_id_ignore_missing(path: &str, uid: u32, gid: u32) -> check::CheckReturn {
    match fs::metadata(path) {
        Ok(_) => check_file_owner_id(path, uid, gid),
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => {
                (check::CheckState::Pass, Some("file missing".to_string()))
            }
            _ => (check::CheckState::Warning, Some(err.to_string())),
        },
    }
}

/// Check a file permissions.
///
/// Permissions should be defined like: 0o644.
/// <https://doc.rust-lang.org/std/os/unix/fs/trait.MetadataExt.html#tymethod.mode>
pub fn check_file_permission(path: &str, perms: u32) -> check::CheckReturn {
    let metadata = match fs::metadata(path) {
        Ok(v) => v,
        Err(err) => {
            return (check::CheckState::Warning, Some(err.to_string()));
        }
    };

    if !metadata.is_file() {
        return (
            check::CheckState::Warning,
            Some("path is not a file".to_string()),
        );
    }

    let mode = metadata.mode() & 0o777;

    log_trace!("checking file mode for {:?}, got: {:o}", path, mode);

    if mode != perms {
        (
            check::CheckState::Fail,
            Some(format!("wanted \"{:o}\" got \"{:o}\"", perms, mode)),
        )
    } else {
        (check::CheckState::Pass, None)
    }
}

/// Check a directory permissions.
///
/// Permissions should be defined like: 0o644.
/// <https://doc.rust-lang.org/std/os/unix/fs/trait.MetadataExt.html#tymethod.mode>
pub fn check_dir_permission(path: &str, perms: u32) -> check::CheckReturn {
    let metadata = match fs::metadata(path) {
        Ok(v) => v,
        Err(err) => {
            return (check::CheckState::Warning, Some(err.to_string()));
        }
    };

    if !metadata.is_dir() {
        return (
            check::CheckState::Warning,
            Some("path is not a directory".to_string()),
        );
    }

    let mode = metadata.mode() & 0o777;

    log_trace!("checking dir mode for {:?}, got: {:o}", path, mode);

    if mode != perms {
        (
            check::CheckState::Fail,
            Some(format!("wanted \"{:o}\" got \"{:o}\"", perms, mode)),
        )
    } else {
        (check::CheckState::Pass, None)
    }
}

/// Check permissions of all the files inside a directory.
pub fn check_dir_files_permission(path: &str, perms: u32) -> check::CheckReturn {
    match fs::read_dir(&path) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        let path = entry.path();
                        if !path.is_file() {
                            continue;
                        }

                        if let Ok(metadata) = fs::metadata(&path) {
                            let mode = metadata.mode() & 0o777;
                            log_trace!("checking file mode for {:?}, got: {:o}", path, mode);

                            if mode != perms {
                                return (
                                    check::CheckState::Fail,
                                    Some(format!(
                                        "file {:?} permission: wanted \"{:o}\" got \"{:o}\"",
                                        path, perms, mode
                                    )),
                                );
                            }
                        }
                    }
                    Err(err) => {
                        return (
                            check::CheckState::Warning,
                            Some(format!("error on path {:?}: {}", path, err)),
                        );
                    }
                }
            }
            (check::CheckState::Pass, None)
        }
        Err(err) => (
            check::CheckState::Warning,
            Some(format!("failed to open directory {}: {}", path, err)),
        ),
    }
}

/// Check a file owner uid and gid, and ignore error if file is missing.
pub fn check_file_permission_ignore_missing(path: &str, perms: u32) -> check::CheckReturn {
    match fs::metadata(path) {
        Ok(_) => check_file_permission(path, perms),
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => {
                (check::CheckState::Pass, Some("file missing".to_string()))
            }
            _ => (check::CheckState::Warning, Some(err.to_string())),
        },
    }
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
