use crate::check;
use crate::check::Severity;
use crate::modules::{base, cron, systemd};

const CRON_DESCRIPTION: &str = "The cron service file must be configured to prevent unauthorized users from modifying scheduled task execution, which could lead to privilege escalation.";

const ANACRON_DESCRIPTION: &str = "The anacron service file must be configured to prevent unauthorized users from modifying scheduled task execution, which could lead to privilege escalation.";

pub fn add_checks() {
    check::Check::new(
        "CRN_001",
        "Ensure cron service file is owned by root",
        Severity::Medium,
        vec!["cron", "systemd", "server", "workstation"],
        || match systemd::get_service_file("cron") {
            Some(path) => base::check_file_owner_id(&path, 0, 0),
            None => (
                check::CheckState::Warning,
                Some("systemd cron service file not found".to_string()),
            ),
        },
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown root:root /etc/systemd/system/cron.service`")
    .register();

    check::Check::new(
        "CRN_002",
        "Ensure cron service file permissions 644 are set",
        Severity::Medium,
        vec!["cron", "systemd", "server", "workstation"],
        || match systemd::get_service_file("cron") {
            Some(path) => base::check_file_permission(&path, 0o644),
            None => (
                check::CheckState::Warning,
                Some("systemd cron service file not found".to_string()),
            ),
        },
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 644 /etc/systemd/system/cron.service`")
    .register();

    check::Check::new(
        "CRN_003",
        "Ensure `/etc/cron.d` directory is owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_dir_owner_id("/etc/cron.d", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown root:root /etc/cron.d/`")
    .register();

    check::Check::new(
        "CRN_004",
        "Ensure `/etc/cron.d` directory permissions is 755",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_permission("/etc/cron.d", 0o755),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 755 /etc/cron.d`")
    .register();

    check::Check::new(
        "CRN_005",
        "Ensure all `/etc/cron.d/` files have 644 permissions",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_permission("/etc/cron.d", 0o644),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 644 /etc/cron.d/*`")
    .register();

    check::Check::new(
        "CRN_006",
        "Ensure all `/etc/cron.d/` files are owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_owner_id("/etc/cron.d/", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown -R root:root /etc/cron.d/*`")
    .register();

    check::Check::new(
        "CRN_007",
        "Ensure `/etc/cron.hourly` directory is owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_dir_owner_id("/etc/cron.hourly", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown root:root /etc/cron.d/`")
    .register();

    check::Check::new(
        "CRN_008",
        "Ensure `/etc/cron.hourly` directory permissions is 755",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_permission("/etc/cron.hourly", 0o755),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 755 /etc/cron.hourly`")
    .register();

    check::Check::new(
        "CRN_009",
        "Ensure all `/etc/cron.hourly/` files have 644 permissions",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_permission("/etc/cron.hourly/", 0o644),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 644 /etc/cron.hourly/*`")
    .register();

    check::Check::new(
        "CRN_010",
        "Ensure all `/etc/cron.hourly/` files are owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_owner_id("/etc/cron.hourly/", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown -R root:root /etc/cron.hourly/*`")
    .register();

    check::Check::new(
        "CRN_011",
        "Ensure `/etc/cron.daily` directory is owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_dir_owner_id("/etc/cron.daily", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown root:root /etc/cron.daily/`")
    .register();

    check::Check::new(
        "CRN_012",
        "Ensure `/etc/cron.daily` directory permissions is 755",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_permission("/etc/cron.daily", 0o755),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 755 /etc/cron.daily`")
    .register();

    check::Check::new(
        "CRN_013",
        "Ensure all `/etc/cron.daily/` files have 644 permissions",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_permission("/etc/cron.daily/", 0o644),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 644 /etc/cron.daily/*`")
    .register();

    check::Check::new(
        "CRN_014",
        "Ensure all `/etc/cron.daily/` files are owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_owner_id("/etc/cron.daily/", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown -R root:root /etc/cron.daily/*`")
    .register();

    check::Check::new(
        "CRN_015",
        "Ensure `/etc/cron.weekly` directory is owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_dir_owner_id("/etc/cron.weekly", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown root:root /etc/cron.weekly/`")
    .register();

    check::Check::new(
        "CRN_016",
        "Ensure `/etc/cron.weekly` directory permissions is 755",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_permission("/etc/cron.weekly", 0o755),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 755 /etc/cron.weekly`")
    .register();

    check::Check::new(
        "CRN_017",
        "Ensure all `/etc/cron.weekly/` files have 644 permissions",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_permission("/etc/cron.weekly/", 0o644),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 644 /etc/cron.weekly/*`")
    .register();

    check::Check::new(
        "CRN_018",
        "Ensure all `/etc/cron.weekly/` files are owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_owner_id("/etc/cron.weekly/", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown -R root:root /etc/cron.monthly/*`")
    .register();

    check::Check::new(
        "CRN_019",
        "Ensure `/etc/cron.monthly` directory is owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_dir_owner_id("/etc/cron.monthly", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown root:root /etc/cron.monthly`")
    .register();

    check::Check::new(
        "CRN_020",
        "Ensure `/etc/cron.monthly` directory permissions is 755",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_permission("/etc/cron.monthly", 0o755),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 755 /etc/cron.monthly`")
    .register();

    check::Check::new(
        "CRN_021",
        "Ensure all `/etc/cron.monthly/` files have 644 permissions",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_permission("/etc/cron.monthly/", 0o644),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 644 /etc/cron.monthly/*`")
    .register();

    check::Check::new(
        "CRN_022",
        "Ensure all `/etc/cron.monthly/` files are owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_owner_id("/etc/cron.monthly/", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown -R root:root /etc/cron.monthly/*`")
    .register();

    check::Check::new(
        "CRN_023",
        "Ensure `/etc/cron.yearly` directory is owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_dir_owner_id("/etc/cron.yearly", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown root:root /etc/cron.yearly`")
    .register();

    check::Check::new(
        "CRN_024",
        "Ensure `/etc/cron.yearly` directory permissions is 755",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_permission("/etc/cron.yearly", 0o755),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 755 /etc/cron.yearly`")
    .register();

    check::Check::new(
        "CRN_025",
        "Ensure all `/etc/cron.yearly/` files have 644 permissions",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_permission("/etc/cron.yearly/", 0o644),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 644 /etc/cron.yearly/*`")
    .register();

    check::Check::new(
        "CRN_026",
        "Ensure all `/etc/cron.yearly/` files are owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_owner_id("/etc/cron.yearly/", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown -R root:root /etc/cron.yearly/*`")
    .register();

    check::Check::new(
        "CRN_027",
        "Ensure `/etc/crontab` is owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_file_owner_id_ignore_missing("/etc/crontab", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chown root:root /etc/crontab`")
    .register();

    check::Check::new(
        "CRN_028",
        "Ensure `/etc/crontab` has permissions 644 or stricter",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_file_permission_or_stricter_ignore_missing("/etc/crontab", 0o644),
        vec![],
    )
    .skip_when(cron::skip_no_cron)
    .with_description(CRON_DESCRIPTION)
    .with_fix("`chmod 644 /etc/crontab`")
    .register();

    check::Check::new(
        "CRN_200",
        "Ensure /etc/anacrontab is owned by root",
        Severity::Medium,
        vec!["cron", "server", "workstation"],
        || base::check_file_owner_id_ignore_missing("/etc/anacrontab", 0, 0),
        vec![],
    )
    .skip_when(cron::skip_no_anacron)
    .with_description(ANACRON_DESCRIPTION)
    .with_fix("`chown root:root /etc/anacrontab`")
    .register();

    check::Check::new(
        "CRN_201",
        "Ensure /etc/anacrontab has permissions 644 or stricter",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_file_permission_or_stricter_ignore_missing("/etc/anacrontab", 0o644),
        vec![],
    )
    .skip_when(cron::skip_no_anacron)
    .with_description(ANACRON_DESCRIPTION)
    .with_fix("`chmod 644 /etc/anacrontab`")
    .register();
}
