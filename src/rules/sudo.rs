use crate::check;
use crate::check::Severity;
use crate::modules::{audit, base, sudo};

pub fn add_checks() {
    check::Check::new(
        "SUD_001",
        "Ensure that sudo default config \"noexec\" is set",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("noexec"),
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("Prevent commands run via sudo from spawning further processes (blocks shell escapes from editors/pagers that link against the preloaded dummy exec(3) wrappers).")
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults noexec\"")
    .register();

    check::Check::new(
        "SUD_002",
        "Ensure that sudo default config \"requiretty\" is set",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("requiretty"),
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("Refuse to run unless sudo is invoked from a real tty, blocking exploitation paths via cron jobs or web shells. May break remote management tools, can be ignored for a remote management user with: \"Defaults:user !noexec\".")
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults requiretty\"")
    .register();

    check::Check::new(
        "SUD_003",
        "Ensure that sudo default config \"use_pty\" is set",
        Severity::Medium,
        vec!["sudo", "CIS", "server", "workstation"],
        || sudo::check_sudo_defaults("use_pty"),
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("Run the target command in a new pseudo-terminal so a compromised child cannot inject input into the parent tty.")
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults use_pty\"")
    .register();

    check::Check::new(
        "SUD_004",
        "Ensure that sudo default config \"umask=0027\" is set",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("umask=0027"),
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("Force a restrictive umask on files created by sudo'd commands.")
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults umask=0027\"")
    .register();

    check::Check::new(
        "SUD_005",
        "Ensure that sudo default config \"ignore_dot\" is set",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("ignore_dot"),
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("Skip \".\" when searching PATH for the target binary. Without it, an attacker who drops a malicious binary into a sudo'd user's CWD can have it executed as root simply because PATH started with \".\".")
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults ignore_dot\"")
    .register();

    check::Check::new(
        "SUD_006",
        "Ensure that sudo default config \"passwd_timeout=1\" is set",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("passwd_timeout=1"),
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("Abort the password prompt after 1 minute idle.")
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults passwd_timeout=1\"")
    .register();

    check::Check::new(
        "SUD_007",
        "Ensure that sudo default config \"env_reset\" is set",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("env_reset"),
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("Start the command with a minimal, sanitized environment (only variables on env_keep survive), blocks LD_PRELOAD-style attacks.")
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults env_reset\"")
    .register();

    check::Check::new(
        "SUD_008",
        "Ensure that sudo default config \"timestamp_timeout=0\" is set",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("timestamp_timeout=0"),
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("Never cache credentials, every sudo invocation re-prompts for the password.")
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults timestamp_timeout=0\"")
    .register();

    check::Check::new(
        "SUD_010",
        "Ensure that sudo default config \"mail_badpass\" is set",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("mail_badpass"),
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("Send mail to the sudo mailto address whenever a user enters an incorrect password at the sudo prompt.")
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults mail_badpass\"")
    .register();

    check::Check::new(
        "SUD_011",
        "Ensure that sudo default config \"logfile=\"/var/log/sudo.log\"\" is set",
        Severity::Medium,
        vec!["sudo", "CIS", "server", "workstation"],
        || sudo::check_sudo_defaults("logfile=\"/var/log/sudo.log\""),
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("Append a record of every sudo command (success and failure) to this file in addition to syslog.")
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults logfile=\"/var/log/sudo.log\"\"")
    .register();

    check::Check::new(
        "SUD_013",
        "Ensure that sudo default config \"lecture=\"always\"\" is set",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("lecture=\"always\""),
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults lecture=\"always\"\"")
    .register();

    check::Check::new(
        "SUD_014",
        "Ensure that sudo default config \"lecture_file=\"/usr/share/doc/sudo_lecture.txt\"\" is set",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        // TODO: should also check the content of the file
        || sudo::check_sudo_defaults("lecture_file=\"/usr/share/doc/sudo_lecture.txt\""),
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults lecture_file=\"/usr/share/doc/sudo_lecture.txt\"\" and provide that file with the org's warning text.")
    .register();

    check::Check::new(
        "SUD_015",
        "Ensure that sudoers config does not contain \"NOPASSWD\"",
        Severity::Critical,
        vec!["sudo", "CIS", "server", "workstation"],
        sudo::check_has_no_nopaswd,
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("\"NOPASSWD\" lets a sudo-able account escalate to root with no password prompt at all. An attacker who steals only the user's session token (no password) immediately becomes root. Defeats the whole point of sudo's auth gate.")
    .with_fix(
        "In \"/etc/sudoers\", and \"/etc/sudoers.d/*\", remove all instances with \"NOPASSWD\"",
    )
    .register();

    check::Check::new(
        "SUD_016",
        "Ensure that sudoers re authentication is not disabled",
        Severity::Critical,
        vec!["sudo", "server", "workstation"],
        sudo::check_re_authentication_not_disabled,
        vec![sudo::init_sudo],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("\"!authenticate\" disables the password prompt entirely for matching rules, the same effect as \"NOPASSWD\" via the negated tag form, often missed by NOPASSWD-only audits. Removes the auth gate that protects every sudo invocation.")
    .with_fix("In \"/etc/sudoers\", and \"/etc/sudoers.d/*\", remove all instances with \"!authenticate\"")
    .register();

    check::Check::new(
        "SUD_017",
        "Ensure sudoers config file permissions is 440",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        || base::check_file_permission("/etc/sudoers", 0o440),
        vec![],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("Looser permissions on \"/etc/sudoers\" let unauthorized users read or modify the privilege policy: reading reveals exploitable rules, writing grants instant root via a self-added \"NOPASSWD ALL\" line.")
    .with_fix("chmod 440 /etc/sudoers")
    .register();

    check::Check::new(
        "SUD_018",
        "Ensure /etc/sudoers config file is owned by root",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        || base::check_file_owner_id("/etc/sudoers", 0, 0),
        vec![],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("If \"/etc/sudoers\" is owned by a non-root user, that user can edit the privilege policy and grant themselves root.")
    .with_fix("chown root:root /etc/sudoers")
    .register();

    check::Check::new(
        "SUD_017",
        "Ensure /etc/sudoers.d/ files permissions are 440",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        || base::check_dir_files_permission("/etc/sudoers.d/", 0o440),
        vec![],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("Looser permissions on \"/etc/sudoers.d/\" let unauthorized users read or modify the privilege policy: reading reveals exploitable rules, writing grants instant root via a self-added \"NOPASSWD ALL\" line.")
    .with_fix("chmod -R 440 /etc/sudoers.d/*")
    .register();

    check::Check::new(
        "SUD_018",
        "Ensure /etc/sudoers.d/ files are owned by root",
        Severity::High,
        vec!["sudo", "server", "workstation"],
        || base::check_dir_files_owner_id("/etc/sudoers.d/", 0, 0),
        vec![],
    )
    .skip_when(sudo::skip_no_sudo)
    .with_description("If \"/etc/sudoers.d/\" is owned by a non-root user, that user can edit the privilege policy and grant themselves root.")
    .with_fix("chown -R root:root /etc/sudoers.d/*")
    .register();

    check::Check::new(
        "SUD_100",
        "Ensure audit rule for sudo log file is present",
        Severity::Medium,
        vec!["sudo", "audit"],
        || audit::check_audit_rule("-w /var/log/sudo.log -p wa -k log_file"),
        vec![audit::init_audit_rules],
    )
    .with_description("Monitoring the sudo log file for writes and attribute changes detects attempts to tamper with privilege escalation records.")
    .with_fix("Add \"-w /var/log/sudo.log -p wa -k log_file\" to a file under \"/etc/audit/rules.d/\" and \"augenrules --load\".")
    .register();
}
