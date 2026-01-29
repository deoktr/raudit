use crate::*;

pub fn add_checks() {
    check::add_check(
        "BIN_001",
        "Ensure all SUID/SGID executables are allowed",
        vec!["bin", "slow", "server", "workstation"],
        // TODO: ideally should check the entire fs, but could be extremly slow
        || bin::check_sid_bin("/usr/bin/"),
        vec![],
    );
}
