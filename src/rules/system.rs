use crate::*;

pub fn add_checks() {
    check::add_check(
        "HST_001",
        "Ensure no reboot is required",
        vec!["system"],
        kernel::check_reboot_required,
        vec![],
    );
}
