use crate::*;

pub fn add_checks() {
    check::Check::new(
        "GDM_001",
        "Ensure no automatic logon to the system via a GUI is possible",
        vec!["gdm", "workstation"],
        gdm::no_gdm_auto_logon,
        vec![],
    )
    .register();
}
