use crate::check;
use crate::check::Severity;
use crate::modules::{base, systemd};

pub fn add_checks() {
    check::Check::new(
        "SYD_001",
        "Ensure that systemd config \"CtrlAltDelBurstAction=none\"",
        Severity::Low,
        vec!["systemd", "server", "workstation"],
        || systemd::get_systemd_config_value("CtrlAltDelBurstAction", "none"),
        vec![systemd::init_systemd_config],
    )
    .skip_when(systemd::skip_no_systemd)
    .with_description("Disables the ability to rapidly trigger system reboots, protecting against accidental or malicious reboot attempts.")
    .with_fix("In \"/etc/systemd/system.conf\" under \"[Manager]\" add: \"CtrlAltDelBurstAction=none\"")
    .register();

    // NOTE: Nix installs a system service for a user
    check::Check::new(
        "SYD_002",
        "Ensure /etc/systemd/system/ files permissions are owned by root",
        Severity::High,
        vec!["systemd", "server", "workstation"],
        || base::check_dir_files_owner_id("/etc/systemd/system", 0, 0),
        vec![],
    )
    .skip_when(systemd::skip_no_systemd)
    .with_description(
        "A unprotected systemd system service file could lead to privilege escalation.",
    )
    .with_fix("chown -R root:root /etc/systemd/system/*")
    .register();
}
