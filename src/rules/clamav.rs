use crate::*;

pub fn add_checks() {
    check::add_check(
        "CAV_001",
        "Ensure ClamAV is installed",
        vec!["clamav", "CIS", "useless"],
        clamav::clamav_installed,
        vec![],
    );
}
