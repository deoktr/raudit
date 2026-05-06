use crate::check;
use crate::check::Severity;
use crate::modules::pam;

pub fn add_checks() {
    // TODO: ensure yescrypt is used

    check::Check::new(
        "PAM_001",
        "Ensure PAM service \"passwd\" has rule \"account required pam_unix\"",
        Severity::High,
        vec!["pam", "server", "workstation"],
        || pam::check_rule("passwd", "account", "required", "pam_unix"),
        vec![pam::init_pam],
    )
    .with_description("Without `pam_unix` enforcing account validity on password changes, expired or locked accounts could still rotate credentials and regain interactive access, undermining account-lifecycle controls.")
    .with_fix("Add \"account required pam_unix.so\" to \"/etc/pam.d/passwd\".")
    .register();

    // TODO: add pam_pwquality configuration
    check::Check::new(
        "PAM_002",
        "Ensure PAM service \"passwd\" has rule \"password required pam_pwquality\"",
        Severity::High,
        vec!["pam", "server", "workstation"],
        || pam::check_rule("passwd", "password", "required", "pam_pwquality"),
        vec![pam::init_pam],
    )
    .with_description("Enforce password policy.")
    .with_fix("Add \"password required pam_pwquality.so\" to \"/etc/pam.d/passwd\".")
    .register();

    check::Check::new(
        "PAM_015",
        "Ensure PAM service \"su\" has rule \"auth required pam_wheel\"",
        Severity::High,
        vec!["pam", "server", "workstation"],
        || pam::check_rule("su", "auth", "required", "pam_wheel"),
        vec![pam::init_pam],
    )
    .with_description("Without `pam_wheel` gating `su`, any compromised local account can attempt root password attacks. Restricting `su` to a single privileged group narrows the privilege-escalation path and aids audit attribution.")
    .with_fix("Add \"auth required pam_wheel.so use_uid\" to \"/etc/pam.d/su\" and add the intended admins to the `wheel` group.")
    .register();

    // TODO: configure in /etc/security/faillock.conf
    check::Check::new(
        "PAM_024",
        "Ensure PAM service \"login\" has rule \"auth required pam_faillock\"",
        Severity::High,
        vec!["pam", "server"],
        || pam::check_rule("login", "auth", "required", "pam_faillock"),
        vec![pam::init_pam],
    )
    .with_description("Without `pam_faillock` locking accounts after repeated failed logins, an attacker with console or terminal access can brute-force passwords.")
    .with_fix("Add \"auth required pam_faillock.so preauth\" and \"auth [default=die] pam_faillock.so authfail\" entries to \"/etc/pam.d/login\" (or common-auth).")
    .register();

    check::Check::new(
        "PAM_030",
        "Ensure PAM service \"login\" has rule \"auth optional pam_faildelay\"",
        Severity::Medium,
        vec!["pam", "server", "workstation"],
        || pam::check_rule("login", "auth", "optional", "pam_faildelay"),
        vec![pam::init_pam],
    )
    .with_description("`pam_faildelay` adds a randomized pause after failed authentications, defeating timing side channels that distinguish unknown user from wrong password.")
    .with_fix("Add \"auth optional pam_faildelay.so delay=4000000\" to \"/etc/pam.d/login\".")
    .register();
}
