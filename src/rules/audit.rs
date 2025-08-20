use crate::*;

pub fn add_checks() {
    check::add_check(
        "AUD_001",
        "Ensure \"auditd\" is running",
        vec!["audit"],
        || ps::is_running("auditd"),
        vec![ps::init_proc],
    );
    check::add_check(
        "AUD_010",
        "Ensure that audit is configured with \"disk_full_action\" = \"HALT\"",
        vec!["audit"],
        || audit::check_audit_config("disk_full_action", "HALT"),
        vec![audit::init_audit_config],
    );
    check::add_check(
        "AUD_100",
        "Ensure audit rules are immutable",
        vec!["audit", "STIG"],
        || audit::check_audit_rule("-e 2"),
        vec![audit::init_audit_rules],
    );
    check::add_check(
        "AUD_101",
        "Ensure audit rule for sudo log file is present",
        vec!["audit"],
        || audit::check_audit_rule("-w /var/log/sudo.log -p wa -k log_file"),
        vec![audit::init_audit_rules],
    );
}
