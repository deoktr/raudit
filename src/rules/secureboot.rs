use crate::check;
use crate::check::Severity;
use crate::modules::secureboot;

pub fn add_checks() {
    check::Check::new(
        "SCB_001",
        "Ensure Secure Boot is enabled",
        Severity::High,
        vec!["secureboot", "server", "workstation"],
        secureboot::is_secureboot_enabled,
        vec![],
    )
    .with_description("Secure Boot verifies that only trusted code runs during startup, preventing malware from loading before your OS starts and gaining deep system control.")
    .with_fix("Follow your distribution documentation to setup Secure Boot.")
    .register();
}
