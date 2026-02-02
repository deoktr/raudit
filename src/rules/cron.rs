use crate::*;

pub fn add_checks() {
    check::Check::new(
        "CRO_001",
        "Ensure cron service file is owned by root",
        vec!["cron", "systemd", "workstation", "server"],
        || match systemd::get_service_file("cron") {
            Some(path) => base::check_file_owner_id(&path, 0, 0),
            None => (
                check::CheckState::Error,
                Some("systemd cron service file not found".to_string()),
            ),
        },
        vec![],
    )
    .register();
    check::Check::new(
        "CRO_002",
        "Ensure cron service file permissions 644 are set",
        vec!["cron", "systemd", "workstation", "server"],
        || match systemd::get_service_file("cron") {
            Some(path) => base::check_file_permission(&path, 0o644),
            None => (
                check::CheckState::Error,
                Some("systemd cron service file not found".to_string()),
            ),
        },
        vec![],
    )
    .register();
    check::Check::new(
        "CRO_003",
        "Ensure /etc/cron.d directory is owned by root",
        vec!["cron", "workstation", "server"],
        || base::check_dir_owner_id("/etc/cron.d", 0, 0),
        vec![],
    )
    .register();
    check::Check::new(
        "CRO_004",
        "Ensure /etc/cron.d directory permissions is 755",
        vec!["cron", "workstation", "server"],
        || base::check_dir_permission("/etc/cron.d", 0o755),
        vec![],
    )
    .register();
    check::Check::new(
        "CRO_005",
        "Ensure /etc/cron.hourly directory is owned by root",
        vec!["cron", "workstation", "server"],
        || base::check_dir_owner_id("/etc/cron.hourly", 0, 0),
        vec![],
    )
    .register();
    check::Check::new(
        "CRO_006",
        "Ensure /etc/cron.hourly directory permissions is 755",
        vec!["cron", "workstation", "server"],
        || base::check_dir_permission("/etc/cron.hourly", 0o755),
        vec![],
    )
    .register();
    check::Check::new(
        "CRO_007",
        "Ensure /etc/cron.daily directory is owned by root",
        vec!["cron", "workstation", "server"],
        || base::check_dir_owner_id("/etc/cron.daily", 0, 0),
        vec![],
    )
    .register();
    check::Check::new(
        "CRO_008",
        "Ensure /etc/cron.daily directory permissions is 755",
        vec!["cron", "workstation", "server"],
        || base::check_dir_permission("/etc/cron.daily", 0o755),
        vec![],
    )
    .register();
    check::Check::new(
        "CRO_009",
        "Ensure /etc/cron.weekly directory is owned by root",
        vec!["cron", "workstation", "server"],
        || base::check_dir_owner_id("/etc/cron.weekly", 0, 0),
        vec![],
    )
    .register();
    check::Check::new(
        "CRO_010",
        "Ensure /etc/cron.weekly directory permissions is 755",
        vec!["cron", "workstation", "server"],
        || base::check_dir_permission("/etc/cron.weekly", 0o755),
        vec![],
    )
    .register();
    check::Check::new(
        "CRO_011",
        "Ensure /etc/cron.monthly directory is owned by root",
        vec!["cron", "workstation", "server"],
        || base::check_dir_owner_id("/etc/cron.monthly", 0, 0),
        vec![],
    )
    .register();
    check::Check::new(
        "CRO_012",
        "Ensure /etc/cron.monthly directory permissions is 755",
        vec!["cron", "workstation", "server"],
        || base::check_dir_permission("/etc/cron.monthly", 0o755),
        vec![],
    )
    .register();
    check::Check::new(
        "CRO_013",
        "Ensure /etc/cron.yearly directory is owned by root",
        vec!["cron", "workstation", "server"],
        || base::check_dir_owner_id("/etc/cron.yearly", 0, 0),
        vec![],
    )
    .register();
    check::Check::new(
        "CRO_014",
        "Ensure /etc/cron.yearly directory permissions is 755",
        vec!["cron", "workstation", "server"],
        || base::check_dir_permission("/etc/cron.yearly", 0o755),
        vec![],
    )
    .register();
}
