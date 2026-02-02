use crate::*;

pub fn add_checks() {
    check::Check::new(
        "AUD_001",
        "Ensure \"auditd\" is running",
        vec!["audit", "server", "workstation"],
        || ps::is_running("auditd"),
        vec![ps::init_proc],
    )
    .with_description("Kernel-level subsystem that provides detailed logging and monitoring of system activities. Allows detection of attacks.")
    .register();
    check::Check::new(
        "AUD_010",
        "Ensure that audit is configured with \"disk_full_action\" = \"HALT\"",
        vec!["audit", "paranoid"],
        || audit::check_audit_config("disk_full_action", "HALT"),
        vec![audit::init_audit_config],
    )
    .register();
    check::Check::new(
        "AUD_100",
        "Ensure audit rules are immutable",
        vec!["audit", "STIG", "server", "workstation"],
        || audit::check_audit_rule("-e 2"),
        vec![audit::init_audit_rules],
    )
    .register();
    check::Check::new(
        "AUD_101",
        "Ensure audit rule for sudo log file is present",
        vec!["audit"],
        || audit::check_audit_rule("-w /var/log/sudo.log -p wa -k log_file"),
        vec![audit::init_audit_rules],
    )
    .register();
}
