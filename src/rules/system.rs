use crate::*;

pub fn add_checks() {
    check::Check::new(
        "SYT_001",
        "Ensure no reboot is required",
        vec!["system", "server", "workstation"],
        kernel::check_reboot_required,
        vec![],
    )
    .register();
}
