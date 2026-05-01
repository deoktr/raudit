use crate::check::Severity;
use crate::*;

pub fn add_checks() {
    check::Check::new(
        "GRB_001",
        "Ensure that GRUB bootloader password is set",
        Severity::High,
        vec!["grub", "server", "workstation"],
        grub::password_is_set,
        vec![grub::init_grub_cfg],
    )
    .skip_when(grub::skip_no_grub)
    .with_description("Setting a GRUB bootloader password prevents an attacker with physical access from editing kernel boot parameters (e.g., adding init=/bin/bash) to bypass authentication and gain root access.")
    .with_fix("Run \"grub-mkpasswd-pbkdf2\" and add the resulting hash to \"/etc/grub.d/40_custom\" with \"set superusers\" and \"password_pbkdf2\" directives, then run \"update-grub\".")
    .register();
}
