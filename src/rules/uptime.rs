use crate::*;

pub fn add_checks() {
    check::add_check(
        "UPT_001",
        "Ensure host has not been running for more than 3 months without reboot",
        vec!["uptime", "server", "workstation"],
        || uptime::uptime_bellow(3 * 24 * 60 * 60),
        vec![uptime::init_uptime],
    );
}
