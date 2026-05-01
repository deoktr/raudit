use crate::check;
use crate::check::Severity;
use crate::modules::{audit, ps};

pub fn add_checks() {
    check::Check::new(
        "AUD_001",
        "Ensure \"auditd\" is running",
        Severity::High,
        vec!["audit", "server", "workstation"],
        || ps::is_running("auditd"),
        vec![ps::init_proc],
    )
    .with_description("Kernel-level subsystem that provides detailed logging and monitoring of system activities. Allows detection of attacks.")
    .register();

    check::Check::new(
        "AUD_010",
        "Ensure that audit is configured with \"disk_full_action\" = \"HALT\"",
        Severity::Medium,
        vec!["audit", "paranoid"],
        || audit::check_audit_config("disk_full_action", "HALT"),
        vec![audit::init_audit_config],
    )
    .with_description("Halting the system when audit disk is full prevents an attacker from evading detection by filling up audit storage. Only apply in security critical environments, where it is more important than availability.")
    .register();

    check::Check::new(
        "AUD_100",
        "Ensure audit rules are immutable",
        Severity::Medium,
        vec!["audit", "STIG", "server", "workstation"],
        || audit::check_audit_rule("-e 2"),
        vec![audit::init_audit_rules],
    )
    .with_description("Immutable audit rules prevent attackers from disabling or modifying audit logging to cover their tracks.")
    .register();

    check::Check::new(
        "AUD_101",
        "Ensure audit rule for sudo log file is present",
        Severity::Medium,
        vec!["audit"],
        || audit::check_audit_rule("-w /var/log/sudo.log -p wa -k log_file"),
        vec![audit::init_audit_rules],
    )
    .with_description("Monitoring the sudo log file for writes and attribute changes detects attempts to tamper with privilege escalation records.")
    .register();
}
