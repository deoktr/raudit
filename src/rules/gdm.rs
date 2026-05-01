use crate::check;
use crate::check::Severity;
use crate::modules::gdm;

pub fn add_checks() {
    check::Check::new(
        "GDM_001",
        "Ensure no automatic logon to the system via a GUI is possible",
        Severity::Medium,
        vec!["gdm", "workstation"],
        gdm::no_gdm_auto_logon,
        vec![],
    )
    .skip_when(gdm::skip_no_gdm)
    .with_description("Automatic GUI login bypasses authentication, allowing anyone with physical access to gain immediate access to the system.")
    .register();
}
