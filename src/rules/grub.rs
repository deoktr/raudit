use crate::check::Severity;
use crate::*;

pub fn add_checks() {
    check::Check::new(
        "GRB_001",
        "Ensure that bootloader password is set",
        Severity::High,
        vec!["grub", "server", "workstation"],
        grub::password_is_set,
        vec![grub::init_grub_cfg],
    )
    .register();
}
