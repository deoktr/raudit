use crate::*;

pub fn add_checks() {
    check::Check::new(
        "AAR_001",
        "Ensure AppArmor is enabled",
        vec!["apparmor", "server", "workstation"],
        apparmor::apparmor_enabled,
        vec![],
    )
    .with_description("Linux security module (LSM) that provides mandatory access control (MAC) for applications. Strongly increases security by restricting applications to the bare minimum, follows the least privilege principle.")
    .register();
}
