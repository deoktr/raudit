use crate::*;

pub fn add_checks() {
    check::add_check(
        "GRB_001",
        "Ensure that bootloader password is set",
        vec!["grub", "server", "workstation"],
        grub::password_is_set,
        vec![grub::init_grub_cfg],
    );
}
