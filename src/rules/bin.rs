use crate::*;

pub fn add_checks() {
    check::Check::new(
        "BIN_001",
        "Ensure all SUID/SGID executables are allowed",
        vec!["bin", "slow", "server", "workstation"],
        // TODO: ideally should check the entire fs, but could be extremly slow
        || bin::check_sid_bin("/usr/bin/"),
        vec![],
    )
    .with_description("Set UID binaries could be exploited for privilege escalation.")
    .register();
}
