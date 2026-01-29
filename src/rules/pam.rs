use crate::*;

pub fn add_checks() {
    check::add_check(
        "PAM_001",
        "Ensure PAM service \"passwd\" has rule \"account required pam_unix\"",
        vec!["pam", "server", "workstation"],
        || pam::check_rule("passwd", "account", "required", "pam_unix"),
        vec![pam::init_pam],
    );
    check::add_check(
        "PAM_002",
        "Ensure PAM service \"passwd\" has rule \"password required pam_pwquality\"",
        vec!["pam", "server", "workstation"],
        || pam::check_rule("passwd", "password", "required", "pam_pwquality"),
        vec![pam::init_pam],
    );
    check::add_check(
        "PAM_015",
        "Ensure PAM service \"su\" has rule \"auth required pam_wheel\"",
        vec!["pam", "server", "workstation"],
        || pam::check_rule("su", "auth", "required", "pam_wheel"),
        vec![pam::init_pam],
    );
    check::add_check(
        "PAM_024",
        "Ensure PAM service \"login\" has rule \"auth required pam_faillock\"",
        vec!["pam", "server"],
        || pam::check_rule("login", "auth", "required", "pam_faillock"),
        vec![pam::init_pam],
    );
    check::add_check(
        "PAM_030",
        "Ensure PAM service \"login\" has rule \"auth optional pam_faildelay\"",
        vec!["pam", "server", "workstation"],
        || pam::check_rule("login", "auth", "optional", "pam_faildelay"),
        vec![pam::init_pam],
    );
}
