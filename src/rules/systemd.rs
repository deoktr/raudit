use crate::*;

pub fn add_checks() {
    check::Check::new(
        "SYD_001",
        "Ensure that systemd config \"CtrlAltDelBurstAction\" = \"none\"",
        vec!["systemd", "server", "workstation"],
        || systemd::get_systemd_config_value("CtrlAltDelBurstAction", "none"),
        vec![systemd::init_systemd_config],
    )
    .register();
}
