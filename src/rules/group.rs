use crate::check;
use crate::check::Severity;
use crate::modules::{base, group, os};
use crate::utils;

pub fn add_checks() {
    check::Check::new(
        "GRP_001",
        "Ensure group shadow file is empty or missing",
        Severity::Medium,
        vec!["group", "server", "workstation"],
        group::empty_gshadow,
        vec![],
    )
    .with_fix("rm /etc/gshadow")
    .register();

    check::Check::new(
        "GRP_002",
        "Ensure no group has a password set",
        Severity::Medium,
        vec!["group", "server", "workstation"],
        group::no_password_in_group,
        vec![group::init_group],
    )
    .register();

    check::Check::new(
        "GRP_003",
        "Ensure that only root has GID 0",
        Severity::High,
        vec!["group", "server", "workstation"],
        group::one_gid_zero,
        vec![group::init_group],
    )
    .register();

    check::Check::new(
        "GRP_004",
        "Ensure no duplicate GIDs exist",
        Severity::Medium,
        vec!["group", "server", "workstation"],
        group::no_dup_gid,
        vec![group::init_group],
    )
    .register();

    check::Check::new(
        "GRP_005",
        "Ensure no duplicate group names exist",
        Severity::Medium,
        vec!["group", "server", "workstation"],
        group::no_dup_name,
        vec![group::init_group],
    )
    .register();

    // TODO: only enable for Debian
    check::Check::new(
        "GRP_006",
        "Ensure \"shadow\" group is empty",
        Severity::Medium,
        vec!["group", "CIS", "STIG", "server", "workstation"],
        || group::no_members("shadow"),
        vec![group::init_group],
    )
    .register();

    check::Check::new(
        "GRP_100",
        "Ensure \"/etc/group\" file owner is \"root:root\"",
        Severity::Medium,
        vec!["group", "CIS", "server", "workstation"],
        || base::check_file_owner_id("/etc/group", 0, 0),
        vec![],
    )
    .register();

    check::Check::new(
        "GRP_101",
        "Ensure \"/etc/group\" file permissions are \"644\"",
        Severity::High,
        vec!["group", "CIS", "server", "workstation"],
        || base::check_file_permission("/etc/group", 0o644),
        vec![],
    )
    .register();

    check::Check::new(
        "GRP_102",
        "Ensure \"/etc/gshadow\" file owner is \"root:root\" or file is missing",
        Severity::Medium,
        vec!["group", "CIS", "server", "workstation"],
        || {
            base::check_file_owner_id_ignore_missing(
                "/etc/gshadow",
                0,
                if os::is_debian() {
                    utils::gid_from_name("shadow").unwrap_or(42)
                } else {
                    0
                },
            )
        },
        vec![os::init_os_release],
    )
    .register();

    check::Check::new(
        "GRP_103",
        "Ensure \"/etc/gshadow\" file permissions are set or file is missing",
        Severity::High,
        vec!["group", "CIS", "server", "workstation"],
        || {
            base::check_file_permission_ignore_missing(
                "/etc/gshadow",
                if os::is_debian() {
                    // on Debian there is the shadow group owner of the file
                    0o640
                } else {
                    0o600
                },
            )
        },
        vec![os::init_os_release],
    )
    .register();

    check::Check::new(
        "GRP_104",
        "Ensure \"/etc/gshadow-\" file owner is \"root:root\" or file is missing",
        Severity::Medium,
        vec!["group", "CIS", "server", "workstation"],
        || {
            base::check_file_owner_id_ignore_missing(
                "/etc/gshadow-",
                0,
                if os::is_debian() {
                    utils::gid_from_name("shadow").unwrap_or(42)
                } else {
                    0
                },
            )
        },
        vec![os::init_os_release],
    )
    .register();

    check::Check::new(
        "GRP_105",
        "Ensure \"/etc/gshadow-\" file permissions are set or file is missing",
        Severity::High,
        vec!["group", "CIS", "server", "workstation"],
        || {
            base::check_file_permission_ignore_missing(
                "/etc/gshadow-",
                if os::is_debian() {
                    // on Debian there is the shadow group owner of the file
                    0o640
                } else {
                    0o600
                },
            )
        },
        vec![os::init_os_release],
    )
    .register();
}
