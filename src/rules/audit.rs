use crate::check;
use crate::check::Severity;
use crate::modules::{audit, base, ps};

pub fn add_checks() {
    check::Check::new(
        "AUD_001",
        "Ensure \"auditd\" is running",
        Severity::High,
        vec!["audit", "server", "workstation"],
        || ps::check_is_running("auditd"),
        vec![ps::init_proc],
    )
    .with_description("Kernel-level subsystem that provides detailed logging and monitoring of system activities. Allows detection of attacks. Without auditd running, kernel-emitted security events go unrecorded. Audit logging adds disk I/O and CPU overhead; on busy systems, audit logs can grow rapidly and consume significant disk space, make sure to have a dedicated partition.")
    .with_fix("Install and enable: \"systemctl enable --now auditd\". Verify with \"systemctl status auditd\".")
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
    .with_fix("Set \"disk_full_action = HALT\" in \"/etc/audit/auditd.conf\" and \"systemctl restart auditd\".")
    .register();

    check::Check::new(
        "AUD_100",
        "Ensure audit rules are immutable",
        Severity::High,
        vec!["audit", "STIG", "server", "workstation"],
        || audit::check_audit_rule("-e 2"),
        vec![audit::init_audit_rules],
    )
    .with_description("Immutable audit rules prevent attackers from disabling or modifying audit logging to cover their tracks. Once set, audit rules cannot be changed without a system reboot, which may block legitimate rule updates during system maintenance or testing.")
    .register();

    check::Check::new(
        "AUD_101",
        "Ensure /etc/audit/auditd.conf is owned by root",
        Severity::High,
        vec!["audit", "server", "workstation"],
        || base::check_file_owner_id("/etc/audit/auditd.conf", 0, 0),
        vec![],
    )
    .with_description("The auditd configuration file controls audit logging behavior. Non-root ownership could allow an attacker to modify logging settings to evade detection.")
    .with_fix("chown root:root /etc/audit/auditd.conf")
    .register();

    check::Check::new(
        "AUD_102",
        "Ensure /etc/audit/auditd.conf has permissions 640",
        Severity::High,
        vec!["audit", "server", "workstation"],
        || base::check_file_permission("/etc/audit/auditd.conf", 0o640),
        vec![],
    )
    .with_description("The auditd configuration should have restrictive permissions to prevent unauthorized modification of audit logging settings.")
    .with_fix("chmod 640 /etc/audit/auditd.conf")
    .register();

    check::Check::new(
        "AUD_103",
        "Ensure /etc/audit/audit.rules is owned by root",
        Severity::High,
        vec!["audit", "server", "workstation"],
        || base::check_file_owner_id("/etc/audit/audit.rules", 0, 0),
        vec![],
    )
    .with_description("The audit rules file defines what events are logged. Non-root ownership could allow an attacker to disable audit rules to cover their tracks.")
    .with_fix("chown root:root /etc/audit/audit.rules")
    .register();

    check::Check::new(
        "AUD_104",
        "Ensure /etc/audit/audit.rules has permissions 640",
        Severity::High,
        vec!["audit", "server", "workstation"],
        || base::check_file_permission("/etc/audit/audit.rules", 0o640),
        vec![],
    )
    .with_description("The audit rules file should have restrictive permissions to prevent unauthorized modification of audit rules.")
    .with_fix("chmod 640 /etc/audit/audit.rules")
    .register();

    check::Check::new(
        "AUD_105",
        "Ensure audit log directory is owned by root",
        Severity::High,
        vec!["audit", "server", "workstation"],
        || base::check_dir_owner_id("/var/log/audit", 0, 0),
        vec![],
    )
    .with_description("The audit log directory contains security-critical logs. Non-root ownership could allow an attacker to delete or modify audit logs to cover their tracks.")
    .with_fix("chown root:root /var/log/audit")
    .register();

    check::Check::new(
        "AUD_106",
        "Ensure audit log directory has permissions 700",
        Severity::High,
        vec!["audit", "server", "workstation"],
        || base::check_dir_permission("/var/log/audit", 0o700),
        vec![],
    )
    .with_description("The audit log directory should have restrictive permissions to prevent unauthorized access to security logs that may contain sensitive information.")
    .with_fix("chmod 700 /var/log/audit")
    .register();

    check::Check::new(
        "AUD_107",
        "Ensure audit log files are owned by root",
        Severity::High,
        vec!["audit", "server", "workstation"],
        || base::check_dir_files_owner_id("/var/log/audit", 0, 0),
        vec![],
    )
    .with_description("Audit log files should be owned by root to prevent unauthorized modification or deletion of security-critical logs.")
    .with_fix("chown root:root /var/log/audit/*")
    .register();

    check::Check::new(
        "AUD_108",
        "Ensure audit log files have permissions 600",
        Severity::High,
        vec!["audit", "server", "workstation"],
        || base::check_dir_files_permission("/var/log/audit", 0o600),
        vec![],
    )
    .with_description("Audit log files should have restrictive permissions to prevent unauthorized users from reading or modifying security logs.")
    .with_fix("chmod 600 /var/log/audit/*")
    .register();
}
