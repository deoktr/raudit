use crate::*;

pub fn add_checks() {
    // TODO: only run checks if sudo is installed

    check::Check::new(
        "SUD_001",
        "Ensure that sudo default config \"noexec\" is set",
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("noexec"),
        vec![sudo::init_sudo],
    )
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults noexec\"")
    .register();

    check::Check::new(
        "SUD_002",
        "Ensure that sudo default config \"requiretty\" is set",
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("requiretty"),
        vec![sudo::init_sudo],
    )
    .with_description("May break remote management tools, can be ignored for a remote management user with: \"Defaults:user !noexec\".")
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults requiretty\"")
    .register();

    check::Check::new(
        "SUD_003",
        "Ensure that sudo default config \"use_pty\" is set",
        vec!["sudo", "CIS", "server", "workstation"],
        || sudo::check_sudo_defaults("use_pty"),
        vec![sudo::init_sudo],
    )
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults use_pty\"")
    .register();

    check::Check::new(
        "SUD_004",
        "Ensure that sudo default config \"umask=0027\" is set",
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("umask=0027"),
        vec![sudo::init_sudo],
    )
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults umask=0027\"")
    .register();

    check::Check::new(
        "SUD_005",
        "Ensure that sudo default config \"ignore_dot\" is set",
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("ignore_dot"),
        vec![sudo::init_sudo],
    )
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults ignore_dot\"")
    .register();

    check::Check::new(
        "SUD_006",
        "Ensure that sudo default config \"passwd_timeout=1\" is set",
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("passwd_timeout=1"),
        vec![sudo::init_sudo],
    )
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults passwd_timeout=1\"")
    .register();

    check::Check::new(
        "SUD_007",
        "Ensure that sudo default config \"env_reset, timestamp_timeout=15\" is set",
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("env_reset, timestamp_timeout=15"),
        vec![sudo::init_sudo],
    )
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults env_reset, timestamp_timeout=15\"")
    .register();

    check::Check::new(
        "SUD_008",
        "Ensure that sudo default config \"timestamp_timeout=15\" is set",
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("timestamp_timeout=15"),
        vec![sudo::init_sudo],
    )
    .with_fix(
        "In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults timestamp_timeout=15\"",
    )
    .register();

    check::Check::new(
        "SUD_009",
        "Ensure that sudo default config \"env_reset\" is set",
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("env_reset"),
        vec![sudo::init_sudo],
    )
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults env_reset\"")
    .register();

    check::Check::new(
        "SUD_010",
        "Ensure that sudo default config \"mail_badpass\" is set",
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("mail_badpass"),
        vec![sudo::init_sudo],
    )
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults mail_badpass\"")
    .register();

    check::Check::new(
        "SUD_011",
        "Ensure that sudo default config \"logfile=\"/var/log/sudo.log\"\" is set",
        vec!["sudo", "CIS", "server", "workstation"],
        || sudo::check_sudo_defaults("logfile=\"/var/log/sudo.log\""),
        vec![sudo::init_sudo],
    )
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults logfile=\"/var/log/sudo.log\"\"")
    .register();

    check::Check::new(
        "SUD_012",
        "Ensure that sudo default config \":%sudo !noexec\" is set",
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults(":%sudo !noexec"),
        vec![sudo::init_sudo],
    )
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults:%sudo !noexec\"")
    .register();

    check::Check::new(
        "SUD_013",
        "Ensure that sudo default config \"lecture=\"always\"\" is set",
        vec!["sudo", "server", "workstation"],
        || sudo::check_sudo_defaults("lecture=\"always\""),
        vec![sudo::init_sudo],
    )
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"Defaults lecture=\"always\"\"")
    .register();

    check::Check::new(
        "SUD_014",
        "Ensure that sudo default config \"lecture_file=\"/usr/share/doc/sudo_lecture.txt\"\" is set",
        vec!["sudo", "server", "workstation"],
        // TODO: should also check the content of the file
        || sudo::check_sudo_defaults("lecture_file=\"/usr/share/doc/sudo_lecture.txt\""),
        vec![sudo::init_sudo],
    )
    .with_fix("In \"/etc/sudoers\", or \"/etc/sudoers.d/*\", add: \"lecture_file=\"/usr/share/doc/sudo_lecture.txt\"\"")
    .register();

    check::Check::new(
        "SUD_015",
        "Ensure that sudoers config does not contain \"NOPASSWD\"",
        vec!["sudo", "CIS", "server", "workstation"],
        sudo::check_has_no_nopaswd,
        vec![sudo::init_sudo],
    )
    .with_fix(
        "In \"/etc/sudoers\", and \"/etc/sudoers.d/*\", remove all instances with \"NOPASSWD\"",
    )
    .register();

    check::Check::new(
        "SUD_016",
        "Ensure that sudoers re authentication is not disabled",
        vec!["sudo", "server", "workstation"],
        sudo::check_re_authentication_not_disabled,
        vec![sudo::init_sudo],
    )
    .with_fix("In \"/etc/sudoers\", and \"/etc/sudoers.d/*\", remove all instances with \"!authenticate\"")
    .register();

    check::Check::new(
        "SUD_017",
        "Ensure sudoers config file permissions is 440",
        vec!["sudo", "server", "workstation"],
        || base::check_file_permission("/etc/sudoers", 0o440),
        vec![],
    )
    .with_fix("chmod 440 /etc/sudoers")
    .register();

    check::Check::new(
        "SUD_018",
        "Ensure /etc/sudoers config file is owned by root",
        vec!["sudo", "server", "workstation"],
        || base::check_file_owner_id("/etc/sudoers", 0, 0),
        vec![],
    )
    .with_fix("chown root:root /etc/sudoers")
    .register();

    check::Check::new(
        "SUD_017",
        "Ensure /etc/sudoers.d/ files permissions are 440",
        vec!["sudo", "server", "workstation"],
        || base::check_dir_files_permission("/etc/sudoers.d/", 0o440),
        vec![],
    )
    .with_fix("chmod -R 440 /etc/sudoers.d/*")
    .register();

    check::Check::new(
        "SUD_018",
        "Ensure /etc/sudoers.d/ files are owned by root",
        vec!["sudo", "server", "workstation"],
        || base::check_dir_files_owner_id("/etc/sudoers.d/", 0, 0),
        vec![],
    )
    .with_fix("chown -R root:root /etc/sudoers.d/*")
    .register();
}
