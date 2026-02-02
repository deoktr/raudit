use crate::*;

pub fn add_checks() {
    check::Check::new(
        "SYD_001",
        "Ensure that systemd config \"CtrlAltDelBurstAction=none\"",
        vec!["systemd", "server", "workstation"],
        || systemd::get_systemd_config_value("CtrlAltDelBurstAction", "none"),
        vec![systemd::init_systemd_config],
    )
    .with_description("Disables the ability to rapidly trigger system reboots, protecting against accidental or malicious reboot attempts.")
    .with_fix("In \"/etc/systemd/system.conf\" under \"[Manager]\" add: \"CtrlAltDelBurstAction=none\"")
    .register();

    check::Check::new(
        "SYD_002",
        "Ensure /etc/systemd/system/ files permissions are owned by root",
        vec!["systemd", "server", "workstation"],
        || base::check_dir_files_owner_id("/etc/systemd/system", 0, 0),
        vec![],
    )
    .with_description(
        "A unprotected systemd system service file could lead to privilege escalation.",
    )
    .with_fix("chown -R root:root /etc/systemd/system/*")
    .register();
}
