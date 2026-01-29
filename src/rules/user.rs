use crate::*;

pub fn add_checks() {
    check::add_check(
        "USR_001",
        "Ensure that root is the only user with UID 0",
        vec!["user", "passwd", "server", "workstation"],
        users::no_uid_zero,
        vec![users::init_passwd],
    );
    check::add_check(
        "USR_002",
        "Ensure no duplicate user names exist",
        vec!["user", "passwd", "server", "workstation"],
        users::no_dup_username,
        vec![users::init_passwd],
    );
    check::add_check(
        "USR_003",
        "Ensure no duplicate UIDs exist",
        vec!["user", "passwd", "server", "workstation"],
        users::no_dup_uid,
        vec![users::init_passwd],
    );
    check::add_check(
        "USR_004",
        "Ensure that \"/etc/securetty\" is empty",
        vec!["user", "server", "workstation"],
        users::empty_securetty,
        vec![],
    );
    check::add_check(
        "USR_005",
        "Ensure no login is available on system accounts",
        vec!["user", "passwd", "server", "workstation"],
        users::no_login_sys_users,
        vec![users::init_passwd],
    );
    check::add_check(
        "USR_006",
        "Ensure all passwords are hashed with yescrypt",
        vec!["user", "shadow", "server", "workstation"],
        users::yescrypt_hashes,
        vec![users::init_shadow],
    );
    check::add_check(
        "USR_007",
        "Ensure no accounts are locked, delete them",
        vec!["user", "shadow", "server", "workstation"],
        users::no_locked_account,
        vec![users::init_shadow],
    );
    check::add_check(
        "USR_008",
        "Ensure that all home directories exist",
        vec!["user", "passwd", "server", "workstation"],
        users::no_missing_home,
        vec![users::init_passwd],
    );
    check::add_check(
        "USR_009",
        "Ensure \"/etc/shadow\" password fields are not empty",
        vec!["user", "shadow", "server", "workstation"],
        users::no_empty_shadow_password,
        vec![users::init_shadow],
    );
    check::add_check(
        "USR_010",
        "Ensure \"/etc/passwd\" password fields are not empty",
        vec!["user", "passwd", "server", "workstation"],
        users::no_empty_passwd_password,
        vec![users::init_shadow],
    );
    check::add_check(
        "USR_011",
        "Ensure accounts in \"/etc/passwd\" use shadowed passwords",
        vec!["user", "passwd", "server", "workstation"],
        users::no_password_in_passwd,
        vec![users::init_passwd],
    );
    check::add_check(
        "USR_100",
        // TODO: allow root:root
        "Ensure \"/etc/shadow\" file owner is \"root:shadow\"",
        vec!["group", "CIS", "server", "workstation"],
        // FIXME: use shadow gid instead of 42
        || base::check_file_owner_id("/etc/shadow", 0, 42),
        vec![],
    );
    check::add_check(
        "USR_101",
        "Ensure \"/etc/shadow\" file permissions are \"640\"",
        vec!["group", "CIS", "server", "workstation"],
        // TODO: accept less permissions, like 600
        || base::check_file_permission("/etc/shadow", 0o640),
        vec![],
    );
    check::add_check(
        "USR_102",
        "Ensure \"/etc/shadow-\" file owner is \"root:shadow\" or file is missing",
        vec!["group", "CIS", "server", "workstation"],
        // TODO: allow root:root
        // FIXME: use shadow gid instead of 42
        // TODO: create util function to get UID fron username
        || base::check_file_owner_id_ignore_missing("/etc/shadow-", 0, 42),
        vec![],
    );
    check::add_check(
        "USR_103",
        "Ensure \"/etc/shadow-\" file permissions are \"640\" or file is missing",
        vec!["group", "CIS", "server", "workstation"],
        || base::check_file_permission_ignore_missing("/etc/shadow-", 0o640),
        vec![],
    );
    check::add_check(
        "USR_104",
        "Ensure \"/etc/security/opasswd\" file owner is \"root:root\" or file is missing",
        vec!["group", "server", "workstation"],
        || base::check_file_owner_id_ignore_missing("/etc/security/opasswd", 0, 0),
        vec![],
    );
    check::add_check(
        "USR_105",
        "Ensure \"/etc/security/opasswd\" file permissions are \"600\" or file is missing",
        vec!["group", "server", "workstation"],
        || base::check_file_permission_ignore_missing("/etc/security/opasswd", 0o600),
        vec![],
    );
}
