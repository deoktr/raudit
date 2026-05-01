use crate::check;
use crate::check::Severity;
use crate::modules::clamav;

pub fn add_checks() {
    check::Check::new(
        "CAV_001",
        "Ensure ClamAV is installed",
        Severity::Medium,
        vec!["clamav", "CIS", "useless"],
        clamav::clamav_installed,
        vec![],
    )
    .with_description("ClamAV provides open-source antivirus scanning to detect malware, trojans, and other threats on the system. Only needed in as a regulatory requirement.")
    .register();
}
