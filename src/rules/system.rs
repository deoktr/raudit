use crate::check;
use crate::check::Severity;
use crate::modules::{base, kernel};
use crate::utils;

pub fn add_checks() {
    check::Check::new(
        "SYT_001",
        "Ensure no reboot is required",
        Severity::Informational,
        vec!["system", "server", "workstation"],
        kernel::check_reboot_required,
        vec![],
    )
    .with_description("A pending reboot indicates that security updates have been installed but are not yet active, leaving the system potentially vulnerable.")
    .with_fix("Reboot host.")
    .register();

    check::Check::new(
        "SYT_002",
        "Ensure /etc/hostname is owned by root",
        Severity::Medium,
        vec!["system", "server", "workstation"],
        || base::check_file_owner_id("/etc/hostname", 0, 0),
        vec![],
    )
    .with_description("The hostname file should be owned by root to prevent unauthorized modification of the system hostname, which could affect network identification and log attribution.")
    .with_fix("chown root:root /etc/hostname")
    .register();

    check::Check::new(
        "SYT_003",
        "Ensure /etc/hostname has permissions 644",
        Severity::Low,
        vec!["system", "server", "workstation"],
        || base::check_file_permission("/etc/hostname", 0o644),
        vec![],
    )
    .with_description("The hostname file should have appropriate permissions to prevent unauthorized modification.")
    .with_fix("chmod 644 /etc/hostname")
    .register();

    check::Check::new(
        "SYT_004",
        "Ensure /etc/machine-id is owned by root",
        Severity::Medium,
        vec!["system", "server", "workstation"],
        || base::check_file_owner_id("/etc/machine-id", 0, 0),
        vec![],
    )
    .with_description("The machine-id file should be owned by root. Tampering with machine-id can break logging, licensing, and other system identification mechanisms.")
    .with_fix("chown root:root /etc/machine-id")
    .register();

    check::Check::new(
        "SYT_005",
        "Ensure /etc/machine-id has permissions 444",
        Severity::Low,
        vec!["system", "server", "workstation"],
        || base::check_file_permission_ignore_missing("/etc/machine-id", 0o444),
        vec![],
    )
    .with_description("The machine-id should be read-only to prevent unauthorized changes. Some systems may not have this file.")
    .with_fix("chmod 444 /etc/machine-id")
    .register();

    check::Check::new(
        "SYT_006",
        "Ensure /etc/hosts file is owned by root",
        Severity::High,
        vec!["system", "server", "workstation"],
        || base::check_file_owner_id("/etc/hosts", 0, 0),
        vec![],
    )
    .with_description("The /etc/hosts file controls hostname resolution. Non-root ownership could allow an attacker to redirect traffic by modifying DNS entries, enabling man-in-the-middle attacks.")
    .with_fix("chown root:root /etc/hosts")
    .register();

    check::Check::new(
        "SYT_007",
        "Ensure /etc/hosts file has permissions 644",
        Severity::High,
        vec!["system", "server", "workstation"],
        || base::check_file_permission("/etc/hosts", 0o644),
        vec![],
    )
    .with_description("The /etc/hosts file should have restrictive permissions to prevent unauthorized modification of hostname resolution, which could redirect traffic to malicious servers.")
    .with_fix("chmod 644 /etc/hosts")
    .register();

    check::Check::new(
        "SYT_008",
        "Ensure /etc/resolv.conf is owned by root or systemd-resolve",
        Severity::High,
        vec!["system", "server", "workstation"],
        || {
            let result = base::check_file_owner_id("/etc/resolv.conf", 0, 0);
            if result.0 == check::CheckState::Pass {
                return result;
            }
            if let (Some(uid), Some(gid)) = (
                utils::uid_from_name("systemd-resolve"),
                utils::gid_from_name("systemd-resolve"),
            ) {
                let result = base::check_file_owner_id("/etc/resolv.conf", uid, gid);
                if result.0 == check::CheckState::Pass {
                    return result;
                }
            }
            result
        },
        vec![],
    )
    .with_description("The resolv.conf file controls DNS resolution. Non-root ownership could allow an attacker to redirect DNS queries to malicious servers. When systemd-resolved manages DNS, ownership by systemd-resolve:systemd-resolve is also acceptable.")
    .with_fix("chown root:root /etc/resolv.conf (or leave as systemd-resolve:systemd-resolve if using systemd-resolved)")
    .register();

    check::Check::new(
        "SYT_009",
        "Ensure /etc/resolv.conf has permissions 644",
        Severity::Medium,
        vec!["system", "server", "workstation"],
        || base::check_file_permission("/etc/resolv.conf", 0o644),
        vec![],
    )
    .with_description("The resolv.conf file should have restrictive permissions to prevent unauthorized modification of DNS configuration.")
    .with_fix("chmod 644 /etc/resolv.conf")
    .register();
}
