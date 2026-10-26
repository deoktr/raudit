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

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

/// Maximum length of an ANSI escape sequence.
const MAX_ANSI_ESCAPE_LEN: usize = 16;

/// Resolve an executable name against `$PATH`. Returns the first matching
/// absolute path, or None if the binary is not found.
pub fn which(bin: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn id_from_name(path: &str, name: &str) -> Option<u32> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let mut fields = line.splitn(4, ':');
        if fields.next()? != name {
            continue;
        }
        fields.next()?;
        return fields.next()?.parse::<u32>().ok();
    }
    None
}

/// Resolve UID from a username by reading `/etc/passwd`.
///
/// Returns `None` if the file cannot be read or the user is not found.
pub fn uid_from_name(username: &str) -> Option<u32> {
    id_from_name("/etc/passwd", username)
}

/// Resolve GID from a group name by reading `/etc/group`.
///
/// Returns `None` if the file cannot be read or the group is not found.
pub fn gid_from_name(group: &str) -> Option<u32> {
    id_from_name("/etc/group", group)
}

/// Format short duration, under an hour.
pub fn format_duration(dur: Duration) -> String {
    let total_secs = dur.as_secs_f64();
    if total_secs >= 60.0 {
        format!("{:.2} m", total_secs / 60.0)
    } else if total_secs >= 1.0 {
        format!("{:.2} s", total_secs)
    } else {
        let millis = total_secs * 1000.0;
        if millis >= 1.0 {
            format!("{:.2} ms", millis)
        } else {
            let micros = total_secs * 1_000_000.0;
            format!("{:.2} μs", micros)
        }
    }
}

/// Length of the ANSI escape sequence starting `text`, None if there is none.
fn escape_len(text: &str) -> Option<usize> {
    if !text.starts_with("\x1b[") {
        return None;
    }

    let len = text[2..].find(|c: char| c.is_ascii_alphabetic())? + 3;
    (len <= MAX_ANSI_ESCAPE_LEN).then_some(len)
}

/// Split `text` on whitespaces into words with their displayed width.
///
/// ANSI escape sequences are zero width and stay in the word they precede,
/// words wider than `max_width` are broken into chunks of `max_width` chars.
fn split_words(text: &str, max_width: usize) -> Vec<(String, usize)> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut width = 0;
    let mut rest = text;

    while let Some(ch) = rest.chars().next() {
        let (token, tail) = match escape_len(rest) {
            Some(len) => rest.split_at(len),
            None => rest.split_at(ch.len_utf8()),
        };
        rest = tail;

        if token.starts_with("\x1b") {
            word.push_str(token);
        } else if ch.is_whitespace() {
            if !word.is_empty() {
                words.push((std::mem::take(&mut word), width));
                width = 0;
            }
        } else {
            word.push_str(token);
            width += 1;

            if width == max_width {
                words.push((std::mem::take(&mut word), width));
                width = 0;
            }
        }
    }

    if !word.is_empty() {
        words.push((word, width));
    }

    words
}

/// Format text and wrap it on words at a specific width.
///
/// ANSI escape sequences are zero width and words wider than `max_width` are
/// hard-broken.
pub fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();

    if max_width == 0 {
        return lines;
    }

    for paragraph in text.split("\n") {
        let mut line = String::new();
        let mut width = 0;

        for (word, word_width) in split_words(paragraph, max_width) {
            if width > 0 && width + word_width + 1 > max_width {
                lines.push(std::mem::take(&mut line));
                width = 0;
            }

            if width > 0 {
                line.push(' ');
                width += 1;
            }

            line.push_str(&word);
            width += word_width;
        }

        if !line.is_empty() {
            lines.push(line);
        }
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts;

    #[test]
    fn test_wrap_text_on_words() {
        assert_eq!(
            wrap_text("Ensure apt is configured with false", 12),
            vec!["Ensure apt", "is", "configured", "with false"]
        );
    }

    #[test]
    fn test_wrap_text_counts_chars_not_bytes() {
        assert_eq!(wrap_text("héllo wörld", 6), vec!["héllo", "wörld"]);
    }

    #[test]
    fn test_wrap_text_hard_break_long_words() {
        assert_eq!(wrap_text("abcdef", 2), vec!["ab", "cd", "ef"]);
        assert_eq!(wrap_text("x abcdefg y", 3), vec!["x", "abc", "def", "g y"]);
    }

    #[test]
    fn test_wrap_text_escapes_are_zero_width() {
        let text = format!(
            "{}one two three{}",
            consts::CHK_FAIL_COLOR,
            consts::RESET_COLOR
        );
        assert_eq!(
            wrap_text(&text, 8),
            vec![
                format!("{}one two", consts::CHK_FAIL_COLOR),
                format!("three{}", consts::RESET_COLOR),
            ]
        );
    }

    #[test]
    fn test_wrap_text_stops_bold() {
        let text = format!(
            "{}bold{} normal text here",
            consts::BOLD_COLOR,
            consts::RESET_BOLD_COLOR
        );
        assert_eq!(
            wrap_text(&text, 12),
            vec![
                format!(
                    "{}bold{} normal",
                    consts::BOLD_COLOR,
                    consts::RESET_BOLD_COLOR
                ),
                "text here".to_string(),
            ]
        );
    }

    #[test]
    fn test_wrap_text_on_new_lines() {
        assert_eq!(
            wrap_text("On Debian: chmod 640\nOn other: chmod 600", 80),
            vec!["On Debian: chmod 640", "On other: chmod 600"]
        );
    }

    #[test]
    fn test_wrap_text_zero_width() {
        assert!(wrap_text("anything", 0).is_empty());
    }
}
