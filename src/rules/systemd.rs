use crate::*;

pub fn add_checks() {
    check::add_check(
        "SYD_001",
        "Ensure that systemd config \"CtrlAltDelBurstAction\" = \"none\"",
        vec!["systemd"],
        || systemd::get_systemd_config("CtrlAltDelBurstAction", "none"),
        vec![systemd::init_systemd_config],
    );
}
