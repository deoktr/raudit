use crate::*;

pub fn add_checks() {
    check::Check::new(
        "UPT_001",
        "Ensure host has not been running for more than 3 months without reboot",
        vec!["uptime", "server", "workstation"],
        || uptime::uptime_bellow(7776000),
        vec![uptime::init_uptime],
    )
    .register();
}
