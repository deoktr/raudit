use crate::*;

pub fn add_checks() {
    check::Check::new(
        "SYT_001",
        "Ensure no reboot is required",
        vec!["system", "server", "workstation"],
        kernel::check_reboot_required,
        vec![],
    )
    .with_description("A pending reboot indicates that security updates have been installed but are not yet active, leaving the system potentially vulnerable.")
    .with_fix("Reboot host.")
    .register();
}
