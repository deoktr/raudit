use crate::*;

pub fn add_checks() {
    check::add_check(
        "AAR_001",
        "Ensure AppArmor is enabled",
        vec!["apparmor", "server", "workstation"],
        apparmor::apparmor_enabled,
        vec![],
    );
}
