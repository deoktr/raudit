use crate::*;

pub fn add_checks() {
    check::add_check(
        "GRP_001",
        "Ensure group shadow empty or missing",
        vec!["group", "server", "workstation"],
        group::empty_gshadow,
        vec![],
    );
    check::add_check(
        "GRP_002",
        "Ensure no group has a password set",
        vec!["group", "server", "workstation"],
        group::no_password_in_group,
        vec![group::init_group],
    );
    check::add_check(
        "GRP_003",
        "Ensure that only root has GID 0",
        vec!["group", "server", "workstation"],
        group::one_gid_zero,
        vec![group::init_group],
    );
    check::add_check(
        "GRP_004",
        "Ensure no duplicate GIDs exist",
        vec!["group", "server", "workstation"],
        group::no_dup_gid,
        vec![group::init_group],
    );
    check::add_check(
        "GRP_005",
        "Ensure no duplicate group names exist",
        vec!["group", "server", "workstation"],
        group::no_dup_name,
        vec![group::init_group],
    );
    check::add_check(
        "GRP_006",
        "Ensure \"shadow\" group is empty",
        vec!["group", "CIS", "STIG", "server", "workstation"],
        || group::no_members("shadow"),
        vec![group::init_group],
    );
    check::add_check(
        "GRP_100",
        "Ensure \"/etc/group\" file owner is \"root:root\"",
        vec!["group", "CIS", "server", "workstation"],
        || base::check_file_owner_id("/etc/group", 0, 0),
        vec![],
    );
    check::add_check(
        "GRP_101",
        "Ensure \"/etc/group\" file permissions are \"644\"",
        vec!["group", "CIS", "server", "workstation"],
        || base::check_file_permission("/etc/group", 0o644),
        vec![],
    );
    check::add_check(
        "GRP_102",
        "Ensure \"/etc/gshadow\" file owner is \"root:root\" or file is missing",
        vec!["group", "CIS", "server", "workstation"],
        // FIXME: use gid of group shadow instead of 42
        || base::check_file_owner_id_ignore_missing("/etc/gshadow", 0, 42),
        vec![],
    );
    check::add_check(
        "GRP_103",
        "Ensure \"/etc/gshadow\" file permissions are \"640\" or file is missing",
        vec!["group", "CIS", "server", "workstation"],
        || base::check_file_permission_ignore_missing("/etc/gshadow", 0o640),
        vec![],
    );
    check::add_check(
        "GRP_104",
        "Ensure \"/etc/gshadow-\" file owner is \"root:root\" or file is missing",
        vec!["group", "CIS", "server", "workstation"],
        // FIXME: use gid of group shadow instead of 42
        || base::check_file_owner_id_ignore_missing("/etc/gshadow-", 0, 42),
        vec![],
    );
    check::add_check(
        "GRP_105",
        "Ensure \"/etc/gshadow-\" file permissions are \"640\" or file is missing",
        vec!["group", "CIS", "server", "workstation"],
        || base::check_file_permission_ignore_missing("/etc/gshadow-", 0o640),
        vec![],
    );
}
