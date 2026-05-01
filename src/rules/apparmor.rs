use crate::check;
use crate::check::Severity;
use crate::modules::apparmor;

// TODO: have "generic" LSM rule to either have AppArmor or SELinux installed.

pub fn add_checks() {
    check::Check::new(
        "AAR_001",
        "Ensure AppArmor is enabled",
        Severity::High,
        vec!["apparmor", "server", "workstation"],
        apparmor::apparmor_enabled,
        vec![],
    )
    .skip_when(apparmor::skip_no_apparmor)
    .with_description("Linux security module (LSM) that provides mandatory access control (MAC) for applications. Strongly increases security by restricting applications to the bare minimum, follows the least privilege principle.")
    .register();
}
