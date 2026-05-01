use crate::check;
use crate::check::Severity;
use crate::modules::kernel;

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
}
