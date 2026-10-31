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

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::check::{self, State};
use crate::{log_error, log_trace, log_warn};

const PAM_DIR_PATH: &str = "/etc/pam.d/";

/// Maximum import resolution depth, protects against include cycles.
const MAX_INCLUDE_DEPTH: u32 = 16;

static PAM_RULES: State<PamRules> = State::new("pam rules");

/// PAM rules.
///
/// The key of the HashMap is the name of the service (name of the file).
/// The value is a list of rules found in that file, or imported by it.
type PamRules = HashMap<String, Vec<PamRule>>;

/// A single PAM rule (line).
#[derive(Debug)]
struct PamRule {
    /// rule interface, `auth|account|password|session`
    rule_type: String,

    /// control flag, `required|requisite|sufficient|optional` or a bracketed
    /// list such as `[value1=action1 value2=action2 ...]`
    ///
    /// The `include` and `substack` controls are import directives, they are
    /// resolved into the rules they pull in and never stored here.
    control: String,

    /// PAM module name, without the `.so` at the end
    module: String,

    /// library parameters the key and the value are separated by `=`
    /// if it has no value (is just a flag) then the value is empty
    settings: HashMap<String, String>,

    /// file the rule was read from, import resolution flattens the rules of
    /// the imported files into the importing service, so a rule of a service
    /// can come from another file than the one configuring it
    file: PathBuf,
}

/// The kind of a PAM configuration line.
///
/// PAM builds a stack by reading a service file line by line, each line is
/// either a module rule or an import of another file. Both import forms are
/// supported, the Debian/Ubuntu `@include` extension and the standard
/// `include`/`substack` controls (used by Arch, RHEL, SUSE...).
#[derive(Debug)]
enum ParsedLine {
    /// `@include <file>`, the Debian/Ubuntu extension, it pulls in every rule
    /// type of `<file>`.
    IncludeAll { file: String },

    /// `<type> include <file>` or `<type> substack <file>`, the standard
    /// controls, they pull in only the `<type>` rules of `<file>`.
    ///
    /// `substack` also isolates the control flow of the imported rules from the
    /// importing stack, but raudit never evaluates the jumps of a stack, only
    /// which rules apply and their flags, so both are flattened the same way.
    Include { rule_type: String, file: String },

    /// A module rule, `<type> <control> <module> [settings...]`.
    Rule(PamRule),
}

/// Remove the trailing comment of a line and trim it.
///
/// `#` starts a comment that runs to the end of the line, PAM also allows
/// leading whitespace before a rule or a comment. `None` is returned for the
/// empty and comment only lines, they carry no configuration.
fn strip_comment(line: &str) -> Option<&str> {
    let content = match line.split_once('#') {
        Some((before, _)) => before,
        None => line,
    };
    match content.trim() {
        "" => None,
        trimmed => Some(trimmed),
    }
}

/// Read the control field of a rule from `tokens`.
///
/// The control is either a single word (`required`, `include`...) or a
/// bracketed list that PAM allows to be written with inner spaces
/// (`[success=1 default=ignore]`), in that case the tokens are joined back
/// until the closing `]`.
fn parse_control(tokens: &mut std::str::SplitWhitespace<'_>) -> Result<String, String> {
    let first = match tokens.next() {
        Some(token) => token,
        None => return Err("missing control field".to_string()),
    };

    if !first.starts_with('[') || first.ends_with(']') {
        return Ok(first.to_string());
    }

    let mut control = first.to_string();
    for token in tokens {
        control.push(' ');
        control.push_str(token);
        if control.ends_with(']') {
            return Ok(control);
        }
    }
    Err("unterminated '[' in the control field".to_string())
}

/// Parse a single comment stripped PAM line into a [`ParsedLine`].
fn parse_line(clean: &str) -> Result<ParsedLine, String> {
    // Debian/Ubuntu `@include <file>` extension, imports every rule type.
    if let Some(rest) = clean.strip_prefix('@') {
        let mut tokens = rest.split_whitespace();
        match tokens.next() {
            Some("include") => {}
            Some(other) => return Err(format!("unknown directive `@{other}`")),
            None => return Err("empty `@` directive".to_string()),
        }
        let file = match tokens.next() {
            Some(file) => file,
            None => return Err("`@include` without a file".to_string()),
        };
        return Ok(ParsedLine::IncludeAll {
            file: file.to_string(),
        });
    }

    let mut tokens = clean.split_whitespace();
    let type_token = match tokens.next() {
        Some(token) => token,
        None => return Err("missing rule type".to_string()),
    };
    // A leading `-` asks PAM to not log a failure to load the module, it does
    // not change the rule type (`-auth` is an `auth` rule).
    let rule_type = type_token
        .strip_prefix('-')
        .unwrap_or(type_token)
        .to_string();

    let control = parse_control(&mut tokens)?;

    // The standard import controls, the token after them is a file to import,
    // not a module, and only the rules of `rule_type` are pulled in.
    if control == "include" || control == "substack" {
        let file = match tokens.next() {
            Some(file) => file,
            None => return Err(format!("`{control}` without a file")),
        };
        return Ok(ParsedLine::Include {
            rule_type,
            file: file.to_string(),
        });
    }

    let module_token = match tokens.next() {
        Some(token) => token,
        None => return Err("missing module".to_string()),
    };
    // The module is a path to a `.so`, keep only the name, NixOS and other
    // distros store them outside of the default search path.
    let module = module_token
        .strip_suffix(".so")
        .unwrap_or(module_token)
        .to_string();

    let mut settings: HashMap<String, String> = HashMap::new();
    for arg in tokens {
        // A `key=value` argument, or a bare flag whose value stays empty.
        let (key, value) = arg.split_once('=').unwrap_or((arg, ""));
        settings.insert(key.to_string(), value.to_string());
    }

    Ok(ParsedLine::Rule(PamRule {
        rule_type,
        control,
        module,
        settings,
        // `parse_pam_file` sets the file the rule was read from
        file: PathBuf::new(),
    }))
}

/// Resolve one import (`@include`, `include` or `substack`) into `rules`.
///
/// `dir` is the directory the import is resolved against, `target` the file to
/// import and `filter` the rule type to keep (`None` keeps every type). `from`
/// is the importing file, used in the messages, `stack` holds the files of the
/// current import branch and `depth` the current import depth, together they
/// stop cycles and runaway nesting. The file is read here and parsed by
/// [`parse_pam_file`].
fn import_file(
    dir: &Path,
    target: &str,
    filter: Option<&str>,
    from: &Path,
    stack: &mut Vec<PathBuf>,
    depth: u32,
    rules: &mut Vec<PamRule>,
) {
    if depth >= MAX_INCLUDE_DEPTH {
        log_warn!(
            "PAM include depth limit ({}) reached in {}, ignoring deeper includes",
            MAX_INCLUDE_DEPTH,
            from.display()
        );
        return;
    }

    // A relative import is resolved against the directory of the PAM files, an
    // absolute one is used as is (`Path::join` replaces on an absolute argument).
    let path = dir.join(target);

    // `stack` holds the files of the current import branch, a file already in
    // it is an import cycle, PAM would loop forever on it. Unlike a plain
    // visited set this still lets one file be imported several times, which the
    // `<type> include` controls of a same service do (Arch, RHEL, SUSE...).
    if stack.contains(&path) {
        log_trace!("PAM include cycle skipped: {:?}", path);
        return;
    }

    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(err) => {
            log_error!("Error opening {}: {}", path.display(), err);
            return;
        }
    };

    log_trace!("PAM including: {:?}", path);
    stack.push(path.clone());
    rules.extend(parse_pam_file(&path, &content, filter, stack, depth + 1));
    stack.pop();
}

/// Parse a PAM file into the flat list of rules that apply to a service.
///
/// The lines are parsed one by one, the module rules are collected and the
/// imports are resolved recursively. `filter` restricts the collected rules to
/// one type, it is set when the file is imported by a standard
/// `<type> include` control and only the rules of that type then apply to the
/// importing stack. `stack` holds the files of the current import branch to
/// stop cycles and `depth` the current import depth to stop runaway nesting.
fn parse_pam_file(
    path: &Path,
    content: &str,
    filter: Option<&str>,
    stack: &mut Vec<PathBuf>,
    depth: u32,
) -> Vec<PamRule> {
    if depth == 0 {
        log_trace!("PAM parsing {}", path.display());
    }

    let dir = path.parent().unwrap_or(path);
    let mut rules: Vec<PamRule> = vec![];

    for line in content.lines() {
        let clean = match strip_comment(line) {
            Some(clean) => clean,
            None => continue,
        };

        match parse_line(clean) {
            Ok(ParsedLine::IncludeAll { file }) => {
                // `@include` pulls in every type, the current filter is kept so
                // an import already restricted to one type stays restricted.
                import_file(dir, &file, filter, path, stack, depth, &mut rules);
            }
            Ok(ParsedLine::Include { rule_type, file }) => {
                // A `<type> include` only applies while its type is collected, it
                // then restricts the imported file to that one type.
                if filter.is_none_or(|kept| kept == rule_type) {
                    import_file(
                        dir,
                        &file,
                        Some(rule_type.as_str()),
                        path,
                        stack,
                        depth,
                        &mut rules,
                    );
                }
            }
            Ok(ParsedLine::Rule(mut rule)) => {
                if filter.is_none_or(|kept| kept == rule.rule_type) {
                    rule.file = path.to_path_buf();
                    rules.push(rule);
                }
            }
            Err(err) => {
                log_warn!("Error parsing PAM rule {}: {}", clean, err);
            }
        }
    }

    rules
}

/// Get PAM configuration by reading files in `/etc/pam.d/`.
fn get_pam() -> Result<PamRules, String> {
    let paths: Vec<PathBuf> = fs::read_dir(PAM_DIR_PATH)
        .map_err(|err| format!("failed to open {}: {}", PAM_DIR_PATH, err))?
        .filter_map(|dentry| dentry.ok())
        .map(|dentry| dentry.path())
        .filter(|path| !path.is_dir())
        .collect();

    let mut config: PamRules = HashMap::new();
    for path in paths {
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(err) => {
                return Err(format!("failed to open {}: {}", path.display(), err));
            }
        };

        // each service resolves its imports independently, the stack is scoped
        // to this file and seeded with it to stop a direct self import
        let mut stack: Vec<PathBuf> = vec![path.clone()];
        let rules = parse_pam_file(&path, &content, None, &mut stack, 0);

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

/// Init pam rules.
pub fn init_pam() {
    PAM_RULES.init(get_pam);
}

/// Match a rule control against the expected one.
///
/// An exact match always wins. Additionally, when the check expects `required`,
/// the other enforcing controls are accepted: `requisite` (fails the stack
/// immediately instead of at the end) and the bracketed forms like
/// `[success=1 new_authtok_reqd=done default=ignore]` that the Debian/Ubuntu
/// stock stacks use for the same intent. Without this a correctly hardened
/// Debian/Ubuntu can never satisfy the `required` checks.
fn control_matches(rule_control: &str, expected: &str) -> bool {
    if rule_control == expected {
        return true;
    }
    expected == "required" && (rule_control == "requisite" || rule_control.starts_with('['))
}

/// Match a rule against a selector.
///
/// NOTE: on NixOS external lib have a full path, ex:
/// `/nix/store/.../lib/security/pam_....so` that's why we only check the end of
/// the module (it's name) and not the whole thing
/// TODO: this is far from perfect
fn rule_matches(rule: &PamRule, rule_type: &str, control: &str, module: &str) -> bool {
    rule.rule_type == rule_type
        && control_matches(&rule.control, control)
        && rule.module.ends_with(module)
}

/// Rules of a service matching a selector, in the order PAM runs them.
fn matching_rules<'a>(
    rules: &'a [PamRule],
    rule_type: &str,
    control: &str,
    module: &str,
) -> impl Iterator<Item = &'a PamRule> {
    rules
        .iter()
        .filter(move |rule| rule_matches(rule, rule_type, control, module))
}

/// Get PAM rule from a collected configuration.
///
/// The `service` being the name of the file containing the rule, ex: `su`.
/// The `rule_type` being the PAM type, ex: `session` or `auth`.
/// The `module` being lib (.so), ex: `pam_limits`.
fn get_pam_rule(
    config: &PamRules,
    service: &str,
    rule_type: &str,
    control: &str,
    module: &str,
) -> Result<(), String> {
    match config.get(service) {
        Some(rules) => {
            if matching_rules(rules, rule_type, control, module)
                .next()
                .is_some()
            {
                Ok(())
            } else {
                Err("rule not found".to_string())
            }
        }
        None => Err("services not configured with pam".to_string()),
    }
}

pub fn check_rule(
    service: &str,
    rule_type: &str,
    control: &str,
    module: &str,
) -> check::CheckReturn {
    PAM_RULES.with(
        |config| match get_pam_rule(config, service, rule_type, control, module) {
            Ok(()) => (check::CheckState::Pass, None),
            Err(err) => (check::CheckState::Fail, Some(err.to_string())),
        },
    )
}

/// Get the relative order of two rules in the stack of a service.
///
/// PAM runs the rules of a type in the written order, imports flattened in
/// place, and the collected stack keeps that order, so comparing the position
/// of the first rule matching each selector decides which one runs first.
/// Both selectors share `rule_type`, the rules of the other types never match.
///
/// A missing second rule is accepted, there is nothing to run before, a
/// missing first rule is reported like [`get_pam_rule`] does.
fn get_pam_rule_order(
    config: &PamRules,
    service: &str,
    rule_type: &str,
    first_control: &str,
    first_module: &str,
    second_control: &str,
    second_module: &str,
) -> Result<(), String> {
    let rules = match config.get(service) {
        Some(rules) => rules,
        None => return Err("services not configured with pam".to_string()),
    };

    let first = rules
        .iter()
        .position(|rule| rule_matches(rule, rule_type, first_control, first_module));
    let second = rules
        .iter()
        .position(|rule| rule_matches(rule, rule_type, second_control, second_module));

    match (first, second) {
        (None, _) => Err(format!(
            "no `{rule_type} {first_control} {first_module}` rule found"
        )),
        (Some(first), Some(second)) if second <= first => Err(format!(
            "`{first_module}` is placed after `{second_module}`"
        )),
        _ => Ok(()),
    }
}

/// Ensure one rule of a service runs before another one.
///
/// The selectors are the ones of [`check_rule`], shared `rule_type` included.
/// Some rules only make sense at a given place of the stack, ex: a password
/// check like `pam_pwhistory` must run before `pam_unix` writes the new hash,
/// placed after it the password is already changed when the module reports
/// its rejection.
pub fn check_rule_before(
    service: &str,
    rule_type: &str,
    first_control: &str,
    first_module: &str,
    second_control: &str,
    second_module: &str,
) -> check::CheckReturn {
    PAM_RULES.with(|config| {
        match get_pam_rule_order(
            config,
            service,
            rule_type,
            first_control,
            first_module,
            second_control,
            second_module,
        ) {
            Ok(()) => (check::CheckState::Pass, None),
            Err(err) => (check::CheckState::Fail, Some(err)),
        }
    })
}

/// Get the value of a flag from a collected configuration.
///
/// The selector is the one of [`get_pam_rule`], `None` is returned when the
/// service is not configured or when none of its matching rules sets `flag`.
/// When several rules set it the last one wins, PAM runs them in order and a
/// later rule is the one deciding the outcome of the stack.
fn get_pam_rule_flag(
    config: &PamRules,
    service: &str,
    rule_type: &str,
    control: &str,
    module: &str,
    flag: &str,
) -> Option<String> {
    matching_rules(config.get(service)?, rule_type, control, module)
        .filter_map(|rule| rule.settings.get(flag))
        .last()
        .cloned()
}

/// Files where a rule of `rule_type` using `module` sets `flag`.
///
/// Includes are flattened per service, so a file included by several services
/// is only reported once. The result is sorted, `config` is a HashMap and its
/// iteration order is not stable.
fn find_rule_flag_files(
    config: &PamRules,
    rule_type: &str,
    module: &str,
    flag: &str,
) -> Vec<String> {
    let mut files: Vec<String> = config
        .values()
        .flatten()
        .filter(|rule| {
            rule.rule_type == rule_type
                && rule.module.ends_with(module)
                && rule.settings.contains_key(flag)
        })
        .map(|rule| rule.file.to_string_lossy().to_string())
        .collect();

    files.sort();
    files.dedup();
    files
}

/// Get the value of a flag of a PAM rule from the collected configuration.
///
/// The selector is the one of [`check_rule`], `Ok(None)` means that no rule of
/// the service sets `flag`, `Err` that the configuration is unavailable.
pub fn get_rule_flag(
    service: &str,
    rule_type: &str,
    control: &str,
    module: &str,
    flag: &str,
) -> Result<Option<String>, String> {
    Ok(get_pam_rule_flag(
        PAM_RULES.try_get()?,
        service,
        rule_type,
        control,
        module,
        flag,
    ))
}

/// Ensure no rule of `rule_type` using `module` sets `flag`, in any service.
///
/// The whole `/etc/pam.d/` is scanned, a flag in an included file weakens every
/// service including it.
pub fn check_no_rule_flag(rule_type: &str, module: &str, flag: &str) -> check::CheckReturn {
    PAM_RULES.with(|config| {
        let files = find_rule_flag_files(config, rule_type, module, flag);

        if files.is_empty() {
            (check::CheckState::Pass, None)
        } else {
            (
                check::CheckState::Fail,
                Some(format!("`{}` set in {}", flag, files.join(", "))),
            )
        }
    })
}

/// Password hashing algorithms `pam_unix` accepts, strongest first.
const PAM_UNIX_CRYPT_FLAGS: [&str; 7] = [
    "yescrypt",
    "gost_yescrypt",
    "blowfish",
    "sha512",
    "sha256",
    "bigcrypt",
    "md5",
];

/// Get the password hashing algorithm the matching rules of a service ask
/// `pam_unix` for.
///
/// `None` means no algorithm flag is set, `pam_unix` then takes the default
/// from `ENCRYPT_METHOD` in `/etc/login.defs`.
fn get_pam_crypt_flag(
    config: &PamRules,
    service: &str,
    rule_type: &str,
    control: &str,
    module: &str,
) -> Option<String> {
    PAM_UNIX_CRYPT_FLAGS
        .into_iter()
        .find(|flag| get_pam_rule_flag(config, service, rule_type, control, module, flag).is_some())
        .map(str::to_string)
}

/// Ensure new passwords are hashed with yescrypt.
///
/// A rule setting no algorithm flag is accepted, `pam_unix` then uses
/// `ENCRYPT_METHOD` from `/etc/login.defs`, which `LDF_001` checks. An explicit
/// weaker algorithm overrides that default and fails.
pub fn check_yescrypt(
    service: &str,
    rule_type: &str,
    control: &str,
    module: &str,
) -> check::CheckReturn {
    PAM_RULES.with(|config| {
        if let Err(err) = get_pam_rule(config, service, rule_type, control, module) {
            return (check::CheckState::Fail, Some(err));
        }

        match get_pam_crypt_flag(config, service, rule_type, control, module) {
            None => (
                check::CheckState::Pass,
                Some(
                    "no algorithm flag, `ENCRYPT_METHOD` from `/etc/login.defs` is used"
                        .to_string(),
                ),
            ),
            Some(flag) if flag == "yescrypt" => (check::CheckState::Pass, None),
            Some(flag) => (
                check::CheckState::Fail,
                Some(format!("`{}` is used instead of `yescrypt`", flag)),
            ),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    /// Run the full line pipeline, strip the comment then classify, like
    /// [`parse_pam_file`] does for every line.
    fn classify(raw: &str) -> Result<ParsedLine, String> {
        match strip_comment(raw) {
            Some(clean) => parse_line(clean),
            None => Err("empty or comment only line".to_string()),
        }
    }

    /// Parse a raw line and require it to be a module rule.
    fn parse_rule(raw: &str) -> PamRule {
        match classify(raw) {
            Ok(ParsedLine::Rule(rule)) => rule,
            Ok(other) => panic!("expected a rule from {raw:?}, got {other:?}"),
            Err(err) => panic!("failed to parse {raw:?}: {err}"),
        }
    }

    #[test]
    fn test_strip_comment() {
        assert_eq!(
            strip_comment("auth required pam_unix.so"),
            Some("auth required pam_unix.so")
        );
        // leading and trailing whitespace is trimmed
        assert_eq!(
            strip_comment("  auth required pam_unix.so  "),
            Some("auth required pam_unix.so")
        );
        // a trailing comment is removed
        assert_eq!(
            strip_comment("auth required pam_unix.so # note"),
            Some("auth required pam_unix.so")
        );
        // full line comments and empty lines carry no configuration
        assert_eq!(strip_comment("# full comment"), None);
        assert_eq!(strip_comment("   # indented comment"), None);
        assert_eq!(strip_comment(""), None);
        assert_eq!(strip_comment("   "), None);
    }

    #[test]
    fn test_parse_pam_rule() {
        let rule = parse_rule("session    required   pam_limits.so");
        assert_eq!(rule.rule_type, "session");
        assert_eq!(rule.control, "required".to_string());
        assert_eq!(rule.module, "pam_limits".to_string());

        // test settings
        let rule = parse_rule("session    required   pam_limits.so debug");
        assert_eq!(rule.rule_type, "session");
        assert_eq!(rule.control, "required".to_string());
        assert_eq!(rule.module, "pam_limits".to_string());
        assert_eq!(rule.settings.len(), 1);
        assert!(rule.settings.contains_key("debug"));

        // test settings values
        let rule =
            parse_rule("session       required   pam_env.so readenv=1 envfile=/etc/default/locale");
        assert_eq!(rule.rule_type, "session");
        assert_eq!(rule.control, "required".to_string());
        assert_eq!(rule.module, "pam_env".to_string());
        assert_eq!(rule.settings.len(), 2);
        assert!(rule.settings.contains_key("readenv"));
        assert_eq!(rule.settings.get("readenv").unwrap(), "1");
        assert!(rule.settings.contains_key("envfile"));
        assert_eq!(rule.settings.get("envfile").unwrap(), "/etc/default/locale");

        // test comments
        let rule = parse_rule("session    required   pam_limits.so debug # this is a test");
        assert_eq!(rule.rule_type, "session");
        assert_eq!(rule.control, "required".to_string());
        assert_eq!(rule.module, "pam_limits".to_string());
        assert_eq!(rule.settings.len(), 1);
        assert!(rule.settings.contains_key("debug"));

        let rule = parse_rule(
            "session optional pam_xauth.so systemuser=99 xauthpath=/the/path/to/the/lib/bin/xauth # xauth (a comment)",
        );
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
        let rule = parse_rule("session [default=1]        pam_permit.so");
        assert_eq!(rule.rule_type, "session");
        assert_eq!(rule.control, "[default=1]".to_string());
        assert_eq!(rule.module, "pam_permit".to_string());
        assert_eq!(rule.settings.len(), 0);

        // a bracketed control written with inner spaces is joined back
        let rule = parse_rule(
            "session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open",
        );
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
        let rule = parse_rule(
            "auth    required pam_faillock.so deny=5 unlock_time=5 fail_interval=5 # and a comment",
        );
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

        // a leading `-` is the "do not log a missing module" prefix, it does
        // not change the rule type
        let rule = parse_rule("-auth required pam_unix.so");
        assert_eq!(rule.rule_type, "auth");
        assert_eq!(rule.module, "pam_unix".to_string());

        // a NixOS style full module path only loses its `.so` suffix
        let rule = parse_rule("auth required /nix/store/hash/lib/security/pam_unix.so");
        assert_eq!(
            rule.module,
            "/nix/store/hash/lib/security/pam_unix".to_string()
        );
    }

    #[test]
    fn test_parse_line_imports() {
        // Debian/Ubuntu `@include`, pulls in every rule type
        match classify("@include common-auth").unwrap() {
            ParsedLine::IncludeAll { file } => assert_eq!(file, "common-auth"),
            other => panic!("expected `@include`, got {other:?}"),
        }
        // leading whitespace is allowed
        match classify("  @include common-session").unwrap() {
            ParsedLine::IncludeAll { file } => assert_eq!(file, "common-session"),
            other => panic!("expected `@include`, got {other:?}"),
        }

        // standard `include`, one rule type (Arch, RHEL, SUSE), tab separated
        match classify("auth\t\tinclude\t\tsystem-auth").unwrap() {
            ParsedLine::Include { rule_type, file } => {
                assert_eq!(rule_type, "auth");
                assert_eq!(file, "system-auth");
            }
            other => panic!("expected `include`, got {other:?}"),
        }
        // standard `substack`
        match classify("password substack system-auth").unwrap() {
            ParsedLine::Include { rule_type, file } => {
                assert_eq!(rule_type, "password");
                assert_eq!(file, "system-auth");
            }
            other => panic!("expected `substack`, got {other:?}"),
        }

        // malformed lines
        assert!(classify("@include").is_err());
        assert!(classify("@unknown foo").is_err());
        assert!(classify("auth include").is_err());
        assert!(classify("auth required").is_err());
        assert!(classify("session [default=1").is_err());
    }

    #[test]
    fn test_parse_pam() {
        let path = PathBuf::from("/etc/pam.d/login");
        let content = "session    required   pam_limits.so

# this is a comment
session    required   pam_limits.so debug

# This allows root to su without passwords (normal operation)
auth       sufficient pam_rootok.so

# The standard Unix authentication modules, used with
# NIS (man nsswitch) as well as normal /etc/passwd and
# /etc/shadow entries.
# @include common-auth
# @include common-account
# @include common-session
";
        let mut stack = vec![path.clone()];
        let r = parse_pam_file(&path, content, None, &mut stack, 0);
        assert_eq!(r.len(), 3);
        let rule = r.first().unwrap();
        assert_eq!(rule.rule_type, "session");
        assert_eq!(rule.control, "required".to_string());
        assert_eq!(rule.module, "pam_limits".to_string());
        assert_eq!(rule.file, PathBuf::from("/etc/pam.d/login"));
        let rule = r.get(2).unwrap();
        assert_eq!(rule.rule_type, "auth");
        assert_eq!(rule.control, "sufficient".to_string());
        assert_eq!(rule.module, "pam_rootok".to_string());
    }

    /// Hardened Debian/Ubuntu style password stack, the controls are the ones
    /// the stock files use.
    const PASSWORD_STACK: &str = "password requisite pam_pwquality.so retry=3 minlen=14
password required pam_pwhistory.so remember=5 use_authtok
password [success=1 default=ignore] pam_unix.so obscure use_authtok yescrypt
password requisite pam_deny.so
";

    /// Build a PAM configuration from `(service, content)` pairs, each service
    /// is parsed as the file `/etc/pam.d/<service>` like [`get_pam`] does.
    fn test_config(services: &[(&str, &str)]) -> PamRules {
        services
            .iter()
            .map(|(service, content)| {
                let path = PathBuf::from(PAM_DIR_PATH).join(service);
                let mut stack = vec![path.clone()];
                (
                    service.to_string(),
                    parse_pam_file(&path, content, None, &mut stack, 0),
                )
            })
            .collect()
    }

    #[test]
    fn test_get_pam_rule() {
        let config = test_config(&[("passwd", PASSWORD_STACK)]);

        assert!(get_pam_rule(&config, "passwd", "password", "required", "pam_unix").is_ok());
        // `requisite` enforces like the expected `required`
        assert!(get_pam_rule(&config, "passwd", "password", "required", "pam_pwquality").is_ok());
        // `sufficient` does not
        assert_eq!(
            get_pam_rule(&config, "passwd", "password", "sufficient", "pam_unix").unwrap_err(),
            "rule not found"
        );
        // unknown module, rule type, control and service
        assert_eq!(
            get_pam_rule(&config, "passwd", "password", "required", "pam_wheel").unwrap_err(),
            "rule not found"
        );
        assert_eq!(
            get_pam_rule(&config, "passwd", "auth", "required", "pam_unix").unwrap_err(),
            "rule not found"
        );
        assert_eq!(
            get_pam_rule(&config, "passwd", "password", "optional", "pam_unix").unwrap_err(),
            "rule not found"
        );
        assert_eq!(
            get_pam_rule(&config, "su", "password", "required", "pam_unix").unwrap_err(),
            "services not configured with pam"
        );

        // a NixOS style full module path matches on the module name
        let config = test_config(&[(
            "passwd",
            "password required /nix/store/hash/lib/security/pam_unix.so yescrypt",
        )]);
        assert!(get_pam_rule(&config, "passwd", "password", "required", "pam_unix").is_ok());
    }

    #[test]
    fn test_get_pam_rule_flag() {
        let config = test_config(&[("passwd", PASSWORD_STACK)]);

        // a flag without value has an empty one
        assert_eq!(
            get_pam_rule_flag(
                &config, "passwd", "password", "required", "pam_unix", "yescrypt"
            ),
            Some("".to_string())
        );
        // a bracketed control enforces like the expected `required`
        assert_eq!(
            get_pam_rule_flag(
                &config, "passwd", "password", "required", "pam_unix", "obscure"
            ),
            Some("".to_string())
        );
        // a flag with a value, on a `requisite` rule
        assert_eq!(
            get_pam_rule_flag(
                &config,
                "passwd",
                "password",
                "required",
                "pam_pwquality",
                "minlen"
            ),
            Some("14".to_string())
        );
        // unset flag, another module, another rule type, another service, a
        // control that does not match and a service that is not configured
        assert_eq!(
            get_pam_rule_flag(
                &config, "passwd", "password", "required", "pam_unix", "remember"
            ),
            None
        );
        assert_eq!(
            get_pam_rule_flag(
                &config,
                "passwd",
                "password",
                "required",
                "pam_pwhistory",
                "yescrypt"
            ),
            None
        );
        assert_eq!(
            get_pam_rule_flag(
                &config, "passwd", "auth", "required", "pam_unix", "yescrypt"
            ),
            None
        );
        assert_eq!(
            get_pam_rule_flag(
                &config, "su", "password", "required", "pam_unix", "yescrypt"
            ),
            None
        );
        assert_eq!(
            get_pam_rule_flag(
                &config, "passwd", "password", "optional", "pam_unix", "yescrypt"
            ),
            None
        );

        // the last rule of the stack wins
        let config = test_config(&[(
            "passwd",
            "password required pam_unix.so remember=3
password required pam_unix.so remember=8
",
        )]);
        assert_eq!(
            get_pam_rule_flag(
                &config, "passwd", "password", "required", "pam_unix", "remember"
            ),
            Some("8".to_string())
        );
    }

    #[test]
    fn test_get_pam_rule_order() {
        // `PASSWORD_STACK` places `pam_pwhistory` before `pam_unix`, the
        // bracketed control of `pam_unix` enforces like `required`
        let config = test_config(&[("passwd", PASSWORD_STACK)]);
        assert!(
            get_pam_rule_order(
                &config,
                "passwd",
                "password",
                "required",
                "pam_pwhistory",
                "required",
                "pam_unix"
            )
            .is_ok()
        );

        // the reversed stack, the password would be changed before the
        // history is checked
        let config = test_config(&[(
            "passwd",
            "password required pam_unix.so use_authtok
password required pam_pwhistory.so remember=5 use_authtok
",
        )]);
        assert_eq!(
            get_pam_rule_order(
                &config,
                "passwd",
                "password",
                "required",
                "pam_pwhistory",
                "required",
                "pam_unix"
            )
            .unwrap_err(),
            "`pam_pwhistory` is placed after `pam_unix`"
        );

        // the rules of another type never match, the `auth` rule using
        // `pam_unix` placed first does not count
        let config = test_config(&[(
            "passwd",
            "auth required pam_unix.so
password required pam_pwhistory.so remember=5 use_authtok
password required pam_unix.so use_authtok
",
        )]);
        assert!(
            get_pam_rule_order(
                &config,
                "passwd",
                "password",
                "required",
                "pam_pwhistory",
                "required",
                "pam_unix"
            )
            .is_ok()
        );

        // no second rule to run before, the order is accepted
        let config = test_config(&[(
            "passwd",
            "password required pam_pwhistory.so remember=5 use_authtok",
        )]);
        assert!(
            get_pam_rule_order(
                &config,
                "passwd",
                "password",
                "required",
                "pam_pwhistory",
                "required",
                "pam_unix"
            )
            .is_ok()
        );

        // a missing first rule or a missing service is reported
        let config = test_config(&[("passwd", "password required pam_unix.so use_authtok")]);
        assert_eq!(
            get_pam_rule_order(
                &config,
                "passwd",
                "password",
                "required",
                "pam_pwhistory",
                "required",
                "pam_unix"
            )
            .unwrap_err(),
            "no `password required pam_pwhistory` rule found"
        );
        assert_eq!(
            get_pam_rule_order(
                &config,
                "su",
                "password",
                "required",
                "pam_pwhistory",
                "required",
                "pam_unix"
            )
            .unwrap_err(),
            "services not configured with pam"
        );
    }

    #[test]
    fn test_get_pam_crypt_flag() {
        let config = test_config(&[("passwd", PASSWORD_STACK)]);
        assert_eq!(
            get_pam_crypt_flag(&config, "passwd", "password", "required", "pam_unix"),
            Some("yescrypt".to_string())
        );

        // a weaker algorithm explicitly overriding the login.defs default
        let config = test_config(&[(
            "passwd",
            "password [success=1 default=ignore] pam_unix.so obscure use_authtok sha512",
        )]);
        assert_eq!(
            get_pam_crypt_flag(&config, "passwd", "password", "required", "pam_unix"),
            Some("sha512".to_string())
        );

        // no algorithm flag, `ENCRYPT_METHOD` from login.defs decides
        let config = test_config(&[(
            "passwd",
            "password required pam_unix.so obscure use_authtok",
        )]);
        assert_eq!(
            get_pam_crypt_flag(&config, "passwd", "password", "required", "pam_unix"),
            None
        );
    }

    #[test]
    fn test_find_rule_flag_files() {
        let content = "auth [success=1 default=ignore] pam_unix.so nullok";
        let path = PathBuf::from("/etc/pam.d/common-auth");

        // the same file is a service on its own and included by the other
        // services, it must be reported once
        let config: PamRules = ["common-auth", "login", "su"]
            .into_iter()
            .map(|service| {
                let mut stack = vec![path.clone()];
                (
                    service.to_string(),
                    parse_pam_file(&path, content, None, &mut stack, 0),
                )
            })
            .collect();

        assert_eq!(
            find_rule_flag_files(&config, "auth", "pam_unix", "nullok"),
            vec!["/etc/pam.d/common-auth".to_string()]
        );
        // another rule type, another module, another flag
        assert!(find_rule_flag_files(&config, "session", "pam_unix", "nullok").is_empty());
        assert!(find_rule_flag_files(&config, "auth", "pam_faillock", "nullok").is_empty());
        assert!(find_rule_flag_files(&config, "auth", "pam_unix", "shadow").is_empty());

        // the files are sorted, `config` is a HashMap
        let config = test_config(&[("su", content), ("login", content)]);
        assert_eq!(
            find_rule_flag_files(&config, "auth", "pam_unix", "nullok"),
            vec!["/etc/pam.d/login".to_string(), "/etc/pam.d/su".to_string()]
        );
    }

    #[test]
    fn test_checks() {
        // the collected configuration is a process wide state, the checks
        // reading it are all tested here
        PAM_RULES.init(|| {
            Ok::<PamRules, String>(test_config(&[
                (
                    "common-auth",
                    "auth [success=1 default=ignore] pam_unix.so nullok",
                ),
                ("passwd", PASSWORD_STACK),
                (
                    "chpasswd",
                    "password required pam_unix.so use_authtok
password required pam_pwhistory.so remember=5 use_authtok
",
                ),
                (
                    "su",
                    "auth sufficient pam_rootok.so
auth required pam_wheel.so use_uid
",
                ),
            ]))
        });

        assert_eq!(
            check_rule("su", "auth", "required", "pam_wheel"),
            (check::CheckState::Pass, None)
        );
        assert_eq!(
            check_rule("su", "auth", "required", "pam_unix"),
            (check::CheckState::Fail, Some("rule not found".to_string()))
        );
        assert_eq!(
            check_rule("sshd", "auth", "required", "pam_unix"),
            (
                check::CheckState::Fail,
                Some("services not configured with pam".to_string())
            )
        );

        assert_eq!(
            get_rule_flag(
                "passwd",
                "password",
                "required",
                "pam_pwhistory",
                "remember"
            )
            .unwrap(),
            Some("5".to_string())
        );
        // a service that is not configured sets no flag
        assert_eq!(
            get_rule_flag("sshd", "auth", "required", "pam_unix", "nullok").unwrap(),
            None
        );

        // `pam_pwhistory` runs before `pam_unix` in the `passwd` stack
        assert_eq!(
            check_rule_before(
                "passwd",
                "password",
                "required",
                "pam_pwhistory",
                "required",
                "pam_unix"
            ),
            (check::CheckState::Pass, None)
        );
        // the reversed `chpasswd` stack places it after
        assert_eq!(
            check_rule_before(
                "chpasswd",
                "password",
                "required",
                "pam_pwhistory",
                "required",
                "pam_unix"
            ),
            (
                check::CheckState::Fail,
                Some("`pam_pwhistory` is placed after `pam_unix`".to_string())
            )
        );

        assert_eq!(
            check_yescrypt("passwd", "password", "required", "pam_unix"),
            (check::CheckState::Pass, None)
        );
        // the `su` service has no password stack
        assert_eq!(
            check_yescrypt("su", "password", "required", "pam_unix"),
            (check::CheckState::Fail, Some("rule not found".to_string()))
        );

        assert_eq!(
            check_no_rule_flag("auth", "pam_unix", "nullok"),
            (
                check::CheckState::Fail,
                Some("`nullok` set in /etc/pam.d/common-auth".to_string())
            )
        );
        assert_eq!(
            check_no_rule_flag("auth", "pam_unix", "shadow"),
            (check::CheckState::Pass, None)
        );
    }

    #[test]
    fn test_control_matches() {
        // exact match
        assert!(control_matches("required", "required"));
        assert!(control_matches("optional", "optional"));
        // enforcing controls satisfy an expected `required`
        assert!(control_matches("requisite", "required"));
        assert!(control_matches("[success=1 default=ignore]", "required"));
        assert!(control_matches("[default=die]", "required"));
        // `optional` must stay exact, a required rule is not an optional one
        assert!(!control_matches("required", "optional"));
        assert!(!control_matches("[default=die]", "optional"));
        // sufficient is not enforcing
        assert!(!control_matches("sufficient", "required"));
    }

    /// A temporary `/etc/pam.d` like directory, removed on drop, used to test
    /// the import resolution which reads the imported files from disk.
    struct TempPamDir(PathBuf);

    impl TempPamDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "raudit-pam-{}-{}-{}",
                std::process::id(),
                tag,
                id
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            TempPamDir(dir)
        }

        fn write(&self, name: &str, content: &str) {
            fs::write(self.0.join(name), content).unwrap();
        }

        /// Resolve one service file like [`get_pam`] does.
        fn resolve(&self, service: &str) -> Vec<PamRule> {
            let path = self.0.join(service);
            let content = fs::read_to_string(&path).unwrap();
            let mut stack = vec![path.clone()];
            parse_pam_file(&path, &content, None, &mut stack, 0)
        }
    }

    impl Drop for TempPamDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The module names of the rules of one type, in stack order.
    fn modules_of_type<'a>(rules: &'a [PamRule], rule_type: &str) -> Vec<&'a str> {
        rules
            .iter()
            .filter(|rule| rule.rule_type == rule_type)
            .map(|rule| rule.module.as_str())
            .collect()
    }

    #[test]
    fn test_include_resolution() {
        let dir = TempPamDir::new("arch-include");

        // Arch style, one `system-auth` holds every rule type and each service
        // imports it once per type with `<type> include`.
        dir.write(
            "system-auth",
            "auth required pam_faillock.so preauth
auth sufficient pam_unix.so nullok
account required pam_unix.so
password required pam_unix.so yescrypt
session required pam_limits.so
",
        );
        dir.write(
            "su",
            "auth sufficient pam_rootok.so
auth include system-auth
account include system-auth
password include system-auth
session include system-auth
",
        );

        let rules = dir.resolve("su");

        // each `<type> include` pulls in only the matching rules of system-auth,
        // the same file is imported four times without being deduplicated
        assert_eq!(
            modules_of_type(&rules, "auth"),
            vec!["pam_rootok", "pam_faillock", "pam_unix"]
        );
        assert_eq!(modules_of_type(&rules, "account"), vec!["pam_unix"]);
        assert_eq!(modules_of_type(&rules, "password"), vec!["pam_unix"]);
        assert_eq!(modules_of_type(&rules, "session"), vec!["pam_limits"]);

        // the imported rules keep the file they were read from
        let faillock = rules
            .iter()
            .find(|rule| rule.module == "pam_faillock")
            .unwrap();
        assert_eq!(faillock.file, dir.0.join("system-auth"));
        let rootok = rules
            .iter()
            .find(|rule| rule.module == "pam_rootok")
            .unwrap();
        assert_eq!(rootok.file, dir.0.join("su"));
    }

    #[test]
    fn test_include_all_and_cycle() {
        let dir = TempPamDir::new("debian-include");

        // Debian/Ubuntu style, `@include` pulls in every type of the file.
        dir.write("common-auth", "auth required pam_unix.so\n");
        dir.write("common-account", "account required pam_unix.so\n");
        dir.write(
            "login",
            "@include common-auth
@include common-account
session required pam_env.so
",
        );

        let rules = dir.resolve("login");
        let kinds: Vec<(&str, &str)> = rules
            .iter()
            .map(|rule| (rule.rule_type.as_str(), rule.module.as_str()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("auth", "pam_unix"),
                ("account", "pam_unix"),
                ("session", "pam_env"),
            ]
        );

        // a file importing itself is read once, the cycle is skipped
        dir.write("loop", "auth required pam_unix.so\nauth include loop\n");
        let rules = dir.resolve("loop");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].module, "pam_unix");
    }

    #[test]
    fn test_substack_and_nested_include() {
        let dir = TempPamDir::new("substack");

        dir.write("common-auth", "auth required pam_unix.so\n");
        dir.write(
            "system-auth",
            "auth substack common-auth
auth required pam_faillock.so
account required pam_unix.so
",
        );
        dir.write(
            "sshd",
            "auth substack system-auth
session required pam_loginuid.so
",
        );

        let rules = dir.resolve("sshd");

        // the nested `auth substack` is followed and its auth rules flattened in
        // order, but the `account` rule of system-auth does not leak into sshd
        // because the import only collects the `auth` type
        assert_eq!(
            modules_of_type(&rules, "auth"),
            vec!["pam_unix", "pam_faillock"]
        );
        assert_eq!(modules_of_type(&rules, "session"), vec!["pam_loginuid"]);
        assert!(rules.iter().all(|rule| rule.rule_type != "account"));
    }
}
