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

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// PAM configuration.
///
/// The key of the HashMap is the name of the service (name of the file).
/// The value is a list of rules found in that file.
pub type PamConfig = HashMap<String, Vec<PamRule>>;

/// A single PAM rule (line).
#[derive(Debug)]
pub struct PamRule {
    // ex: `session`
    pub rule_type: String,

    // ex: `required`
    // NOTE: pam control cannot be an enum since it can have complicated valid
    // syntax such as: `[value1=action1 value2=action2 ...]`
    pub control: String,

    // ex: `pam_[...]` (without the `.so` at the end)
    pub module: String,

    // library parameters the key and the value are separated by `=`
    // if it has no value (is just a flag) then the value is empty
    pub settings: HashMap<String, String>,
}

/// Parse PAM rule line.
fn parse_pam_rule(line: &str) -> Result<PamRule, String> {
    // TODO: make it cleaner

    // can't parse includes here, just rules
    if line.starts_with("@") {
        return Err("line starts with @".to_string());
    }

    // remove potential comments at the end of the line
    let clean_line = match line.splitn(2, "#").nth(0) {
        Some(l) => l,
        None => return Err("failed to split the comment when parsing PAM rule".to_string()),
    };

    let mut ws_split = clean_line.split_whitespace();

    let rule_type = match ws_split.next() {
        Some(t) => t.to_string(),
        None => return Err("Failed to split PAM rule".to_string()),
    };

    let mut control = match ws_split.next() {
        Some(n) => n.to_string(),
        None => return Err("Failed to split PAM control".to_string()),
    };

    // match control, basically what we want is to match until ] if it start
    // with [ or until whitespace if it start without [
    if control.starts_with("[") && !control.ends_with("]") {
        loop {
            let n = match ws_split.next() {
                Some(n) => n.to_string(),
                None => return Err("Failed to split PAM control".to_string()),
            };
            control += " ";
            control += &n;
            if control.ends_with("]") {
                break;
            }
        }
    }

    let module = match ws_split.next() {
        Some(n) => match n.to_string().strip_suffix(".so") {
            Some(lib) => lib.to_string(),
            None => n.to_string(),
        },
        None => return Err("Failed to match PAM module".to_string()),
    };

    let mut settings: HashMap<String, String> = HashMap::new();
    ws_split.for_each(|s| {
        let mut sp = s.splitn(2, "=");
        settings.insert(
            sp.next().unwrap_or_default().to_string(),
            sp.next().unwrap_or_default().to_string(),
        );
    });

    Ok(PamRule {
        rule_type,
        control,
        module,
        settings,
    })
}

/// Parse PAM file.
fn parse_pam(content: String) -> Vec<PamRule> {
    content
        .lines()
        .filter(|line| !line.starts_with("#"))
        // ignore includes (`@include ...`)
        .filter(|line| !line.starts_with("@"))
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            match parse_pam_rule(line) {
                Ok(p) => Ok(p),
                Err(error) => {
                    // TODO: send to a proper logger
                    println!("Error parsing PAM rule {}: {}", line.to_string(), error);
                    Err(error)
                }
            }
            .ok()
        })
        .collect()
}

/// Get PAM configuration by reading files in `/etc/pam.d/`.
pub fn init_pam() -> Result<PamConfig, std::io::Error> {
    let paths: Vec<PathBuf> = fs::read_dir("/etc/pam.d/")?
        .filter_map(|dentry| dentry.ok())
        .map(|dentry| dentry.path())
        .filter(|path| !path.is_dir())
        .collect();

    let mut config: PamConfig = HashMap::new();
    for path in paths {
        let content = match fs::read_to_string(path.clone()) {
            Ok(p) => p,
            Err(error) => {
                println!(
                    "Error opening {}: {}",
                    path.to_string_lossy(),
                    error.to_string()
                );
                continue;
            }
        };

        let rules = parse_pam(content);

        config.insert(
            // get the file name, it represent the configured app
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            rules,
        );
    }

    Ok(config)
}

/// Get PAM rule from a collected configuration.
///
/// The `service` being the name of the file containing the rule, ex: `su`.
/// The `rule_type` being the PAM type, ex: `session` or `auth`.
/// The `module` being lib (.so), ex: `pam_limits`.
pub fn get_pam_rule<'a>(
    config: &'a PamConfig,
    service: &'a str,
    rule_type: &'a str,
    module: &'a str,
) -> Result<Option<&'a PamRule>, String> {
    // TODO: add tests

    if !config.contains_key(service) {
        return Err("services not configured with pam".to_string());
    }
    for rule in config.get(service).unwrap() {
        // if rule.module == module && rule.rule_type == rule_type {
        // NOTE: on NixOS external lib have a full path, ex:
        // `/nix/store/.../lib/security/pam_....so` that's why we only
        // check the end of the module (it's name) and not the whole
        // thing
        // TODO: this is still not perfect, since a malicious
        // configuration could point to an attacker controled PAM module
        if rule.module.ends_with(module) && rule.rule_type == rule_type {
            return Ok(Some(rule));
        }
    }
    return Err("rule not found for service".to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pam_rule() {
        let r = parse_pam_rule("session    required   pam_limits.so");
        assert!(r.is_ok());
        let rule = r.unwrap();
        assert_eq!(rule.rule_type, "session");
        assert_eq!(rule.control, "required".to_string());
        assert_eq!(rule.module, "pam_limits".to_string());

        // test settings
        let r = parse_pam_rule("session    required   pam_limits.so debug");
        assert!(r.is_ok());
        let rule = r.unwrap();
        assert_eq!(rule.rule_type, "session");
        assert_eq!(rule.control, "required".to_string());
        assert_eq!(rule.module, "pam_limits".to_string());
        assert_eq!(rule.settings.len(), 1);
        assert!(rule.settings.contains_key("debug"));

        // test settings values
        let r = parse_pam_rule(
            "session       required   pam_env.so readenv=1 envfile=/etc/default/locale",
        );
        assert!(r.is_ok());
        let rule = r.unwrap();
        assert_eq!(rule.rule_type, "session");
        assert_eq!(rule.control, "required".to_string());
        assert_eq!(rule.module, "pam_env".to_string());
        assert_eq!(rule.settings.len(), 2);
        assert!(rule.settings.contains_key("readenv"));
        assert_eq!(rule.settings.get("readenv").unwrap(), "1");
        assert!(rule.settings.contains_key("envfile"));
        assert_eq!(rule.settings.get("envfile").unwrap(), "/etc/default/locale");

        // test comments
        let r = parse_pam_rule("session    required   pam_limits.so debug # this is a test");
        assert!(r.is_ok());
        let rule = r.unwrap();
        assert_eq!(rule.rule_type, "session");
        assert_eq!(rule.control, "required".to_string());
        assert_eq!(rule.module, "pam_limits".to_string());
        assert_eq!(rule.settings.len(), 1);
        assert!(rule.settings.contains_key("debug"));

        let r = parse_pam_rule(
            "session optional pam_xauth.so systemuser=99 xauthpath=/the/path/to/the/lib/bin/xauth # xauth (a comment)",
        );
        assert!(r.is_ok());
        let rule = r.unwrap();
        assert_eq!(rule.rule_type, "session");
        assert_eq!(rule.control, "optional".to_string());
        assert_eq!(rule.module, "pam_xauth".to_string());
        assert_eq!(rule.settings.len(), 2);
        assert!(rule.settings.contains_key("systemuser"));
        assert_eq!(rule.settings.get("systemuser").unwrap(), "99");
        assert!(rule.settings.contains_key("xauthpath"));
        assert_eq!(
            rule.settings.get("xauthpath").unwrap(),
            "/the/path/to/the/lib/bin/xauth"
        );

        // test complex control
        let r = parse_pam_rule("session [default=1]        pam_permit.so");
        assert!(r.is_ok());
        let rule = r.unwrap();
        assert_eq!(rule.rule_type, "session");
        assert_eq!(rule.control, "[default=1]".to_string());
        assert_eq!(rule.module, "pam_permit".to_string());
        assert_eq!(rule.settings.len(), 0);

        // test complex control
        let r = parse_pam_rule(
            "session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open",
        );
        assert!(r.is_ok());
        let rule = r.unwrap();
        assert_eq!(rule.rule_type, "session");
        assert_eq!(
            rule.control,
            "[success=ok ignore=ignore module_unknown=ignore default=bad]".to_string()
        );
        assert_eq!(rule.module, "pam_selinux".to_string());
        assert_eq!(rule.settings.len(), 1);
        assert!(rule.settings.contains_key("open"));
        assert_eq!(rule.settings.get("open").unwrap(), "");

        // multiple settings
        let r = parse_pam_rule(
            "auth    required pam_faillock.so deny=5 unlock_time=5 fail_interval=5 # and a comment",
        );
        assert!(r.is_ok());
        let rule = r.unwrap();
        assert_eq!(rule.rule_type, "auth");
        assert_eq!(rule.control, "required".to_string());
        assert_eq!(rule.module, "pam_faillock".to_string());
        assert_eq!(rule.settings.len(), 3);
        assert!(rule.settings.contains_key("deny"));
        assert_eq!(rule.settings.get("deny").unwrap(), "5");
        assert!(rule.settings.contains_key("unlock_time"));
        assert_eq!(rule.settings.get("unlock_time").unwrap(), "5");
        assert!(rule.settings.contains_key("fail_interval"));
        assert_eq!(rule.settings.get("fail_interval").unwrap(), "5");

        // TODO: add test of invalid PAM rules
    }

    #[test]
    fn test_parse_pam() {
        let r = parse_pam(
            "session    required   pam_limits.so

# this is a comment
session    required   pam_limits.so debug

# This allows root to su without passwords (normal operation)
auth       sufficient pam_rootok.so

# The standard Unix authentication modules, used with
# NIS (man nsswitch) as well as normal /etc/passwd and
# /etc/shadow entries.
@include common-auth
@include common-account
@include common-session
"
            .to_string(),
        );
        assert_eq!(r.len(), 3);
        let rule = r.get(0).unwrap();
        assert_eq!(rule.rule_type, "session");
        assert_eq!(rule.control, "required".to_string());
        assert_eq!(rule.module, "pam_limits".to_string());
        let rule = r.get(2).unwrap();
        assert_eq!(rule.rule_type, "auth");
        assert_eq!(rule.control, "sufficient".to_string());
        assert_eq!(rule.module, "pam_rootok".to_string());
    }
}
