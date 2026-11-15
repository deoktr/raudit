use raudit_core::check;
use raudit_core::check::Severity;
use raudit_modules::clamav;

pub fn add_checks() {
    check::Check::new(
        "CAV_001",
        "Ensure ClamAV is installed",
        Severity::Low,
        vec!["clamav", "CIS", "useless"],
        clamav::clamav_installed,
        vec![],
    )
    .with_description("ClamAV provides open-source antivirus scanning to detect malware, trojans, and other threats on the system. Only needed in as a regulatory requirement.")
    .with_fix("Install via the distro package manager (e.g. `apt install clamav clamav-daemon`) and enable signature updates with `freshclam`.")
    .register();
}
