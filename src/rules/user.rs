use crate::check;
use crate::check::Severity;
use crate::modules::{base, os, users};
use crate::utils;

pub fn add_checks() {
    check::Check::new(
        "USR_001",
        "Ensure that root is the only user with UID 0",
        Severity::Critical,
        vec!["user", "passwd", "server", "workstation"],
        users::no_uid_zero,
        vec![users::init_passwd],
    )
    .with_description("Multiple accounts with UID 0 are root-equivalent for filesystem and process semantics. An attacker who creates one bypasses every name-based audit and detection that watches the literal \"root\" user.")
    .with_fix("Identify the offending account in \"/etc/passwd\" and either delete it or assign it a fresh non-zero UID. Investigate how it was created.")
    .register();

    check::Check::new(
        "USR_002",
        "Ensure no duplicate user names exist",
        Severity::Medium,
        vec!["user", "passwd", "server", "workstation"],
        users::no_dup_username,
        vec![users::init_passwd],
    )
    .with_description("Duplicate user names indicate hand-edited passwd or merged user databases. Tools may resolve only the first match, masking permissions and audit attribution on the shadowed entry.")
    .with_fix("Edit \"/etc/passwd\" to remove or rename the duplicate. Investigate the source.")
    .register();

    check::Check::new(
        "USR_003",
        "Ensure no duplicate UIDs exist",
        Severity::Medium,
        vec!["user", "passwd", "server", "workstation"],
        users::no_dup_uid,
        vec![users::init_passwd],
    )
    .with_description("Two user names sharing one UID makes ownership and audit logs ambiguous: a file owned by UID X cannot be reliably attributed to one principal, undermining accountability and forensics.")
    .with_fix("Renumber duplicates via \"usermod -u <new-uid> <name>\" and \"chown -R\" their files. Investigate the duplicate's origin.")
    .register();

    check::Check::new(
        "USR_004",
        "Ensure that \"/etc/securetty\" is empty",
        Severity::High,
        vec!["user", "server", "workstation"],
        users::empty_securetty,
        vec![],
    )
    .with_description("An empty (or missing) \"/etc/securetty\" disables direct root login on every console, physical and virtual, forcing administrators to log in as themselves and sudo to root, which preserves audit attribution.")
    .with_fix("Truncate the file or remove it.")
    .register();

    check::Check::new(
        "USR_005",
        "Ensure no login is available on system accounts",
        Severity::High,
        vec!["user", "passwd", "server", "workstation"],
        users::no_login_sys_users,
        vec![users::init_passwd],
    )
    .with_description("System accounts (UID < 1000) own daemons, not humans, granting them an interactive shell turns each one into a possible login target.")
    .with_fix("For each offending system account: \"usermod -s /usr/sbin/nologin <name>\".")
    .register();

    check::Check::new(
        "USR_006",
        "Ensure all passwords are hashed with yescrypt",
        Severity::High,
        vec!["user", "shadow", "server", "workstation"],
        users::yescrypt_hashes,
        vec![users::init_shadow],
    )
    .with_description("Hashes from older algorithms (DES, MD5, SHA-256/512 crypt) are far cheaper to crack on modern GPUs than yescrypt (which also requires RAM to crack/calculate).")
    .with_fix("Edit PAM passwd to use yescrypt when changing password, and force users to change passwords \"passwd --expire <user>\".")
    .register();

    check::Check::new(
        "USR_007",
        "Ensure no accounts are locked, delete them",
        Severity::Low,
        vec!["user", "shadow", "server", "workstation"],
        users::no_locked_account,
        vec![users::init_shadow],
    )
    .with_description("Locked accounts that are kept around clutter the user database and risk being unlocked accidentally. If an account is no longer needed, deletion is cleaner than indefinite locking.")
    .with_fix("After confirming the account is not needed: \"userdel -r <name>\". Investigate any locked account whose home dir still contains active data before deleting.")
    .register();

    check::Check::new(
        "USR_008",
        "Ensure that all home directories exist",
        Severity::Low,
        vec!["user", "passwd", "server", "workstation"],
        users::no_missing_home,
        vec![users::init_passwd],
    )
    .with_description("A missing home directory referenced from \"/etc/passwd\" could be created by an attacker, and could include configurations that could lead to privilege escalation or persistence.")
    .with_fix("Either re-create the missing directory with the right ownership and 0700 permissions, or remove the user with \"userdel\".")
    .register();

    check::Check::new(
        "USR_009",
        "Ensure \"/etc/shadow\" password fields are not empty",
        Severity::Critical,
        vec!["user", "shadow", "server", "workstation"],
        users::no_empty_shadow_password,
        vec![users::init_shadow],
    )
    .with_description("An empty password field in \"/etc/shadow\" lets that account log in with no password at all, on any service that consults shadow (login, ssh PasswordAuthentication, etc.).")
    .with_fix("Lock the account immediately: \"passwd -l <name>\"; then either set a real password \"passwd <name>\" or delete the account.")
    .register();

    check::Check::new(
        "USR_010",
        "Ensure \"/etc/passwd\" password fields are not empty",
        Severity::Critical,
        vec!["user", "passwd", "server", "workstation"],
        users::no_empty_passwd_password,
        vec![users::init_shadow],
    )
    .with_description("An empty password field, instead of \"x\" in \"/etc/passwd\", means the system reads the password directly from passwd and treats absence as no password required.")
    .with_fix("Run \"pwconv\" to migrate password fields to \"/etc/shadow\", investigate any user with an empty field.")
    .register();

    check::Check::new(
        "USR_011",
        "Ensure accounts in \"/etc/passwd\" use shadowed passwords",
        Severity::High,
        vec!["user", "passwd", "server", "workstation"],
        users::no_password_in_passwd,
        vec![users::init_passwd],
    )
    .with_description("Password hashes in \"/etc/passwd\" are world-readable, exposing every account's hash to any local user for cracking.")
    .with_fix("Run \"pwconv\" to migrate hashes to \"/etc/shadow\", verify all password fields in \"/etc/passwd\" are \"x\".")
    .register();

    check::Check::new(
        "USR_106",
        "Ensure \"/etc/passwd\" file permissions are \"644\"",
        Severity::High,
        vec!["group", "CIS", "server", "workstation"],
        || base::check_file_permission("/etc/passwd", 0o644),
        vec![],
    )
    .with_description("Looser permissions on \"/etc/passwd\" let unprivileged users edit account metadata (UID, shell, home dir) and grant themselves access, tighter than 0644 breaks userland tools that need to resolve user names.")
    .with_fix("chmod 644 /etc/passwd")
    .register();

    check::Check::new(
        "USR_107",
        "Ensure \"/etc/passwd\" file owner is \"root:root\" or file is missing",
        Severity::High,
        vec!["group", "CIS", "server", "workstation"],
        || base::check_file_owner_id_ignore_missing("/etc/passwd", 0, 0),
        vec![],
    )
    .with_description("If \"/etc/passwd\" is owned by a non-root user, that user can edit account UIDs and shells, granting themselves UID 0 or pointing root's shell at malicious code.")
    .with_fix("chown root:root /etc/passwd")
    .register();

    check::Check::new(
        "USR_100",
        // TODO: allow root:root
        "Ensure \"/etc/shadow\" file owner is correct",
        Severity::High,
        vec!["group", "CIS", "server", "workstation"],
        || {
            base::check_file_owner_id(
                "/etc/shadow",
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
    .with_description("Wrong ownership on \"/etc/shadow\" lets a non-root principal read every account's password hash for offline cracking, or rewrite hashes to take over arbitrary accounts.")
    .with_fix("On Debian: \"chown root:shadow /etc/shadow\"\nOn other distros: \"chown root:root /etc/shadow\"")
    .register();

    check::Check::new(
        "USR_101",
        "Ensure \"/etc/shadow\" file permissions are correct",
        Severity::High,
        vec!["group", "CIS", "server", "workstation"],
        || base::check_file_permission("/etc/shadow", if os::is_debian() { 0o640 } else { 0o600 }),
        vec![os::init_os_release],
    )
    .with_description("Loose permissions on \"/etc/shadow\" expose every account's password hash to non-root users, who can then crack them.")
    .with_fix("On Debian: \"chmod 640 /etc/shadow\"\nOn other distros: \"chmod 600 /etc/shadow\"")
    .register();

    check::Check::new(
        "USR_102",
        "Ensure \"/etc/shadow-\" file owner is correct or file is missing",
        Severity::Medium,
        vec!["group", "CIS", "server", "workstation"],
        || {
            base::check_file_owner_id_ignore_missing(
                "/etc/shadow-",
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
    .with_description("\"/etc/shadow-\" is the previous-generation backup of shadow, if its ownership is wrong, an attacker can recover password hashes from the backup that the live file's tighter ownership would have blocked.")
    .with_fix("On Debian: \"chown root:shadow /etc/shadow-\"\nOn other distros: \"chown root:root /etc/shadow-\"")
    .register();

    check::Check::new(
        "USR_103",
        "Ensure \"/etc/shadow-\" file permissions are correct or file is missing",
        Severity::Medium,
        vec!["group", "CIS", "server", "workstation"],
        || {
            base::check_file_permission_ignore_missing(
                "/etc/shadow-",
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
    .with_description("Loose permissions on the shadow backup file leak the same password hashes as the live file.")
    .with_fix("On Debian: \"chmod 640 /etc/shadow-\"\nOn other distros: \"chmod 600 /etc/shadow-\"")
    .register();

    check::Check::new(
        "USR_104",
        "Ensure \"/etc/security/opasswd\" file owner is \"root:root\" or file is missing",
        Severity::Medium,
        vec!["group", "server", "workstation"],
        || base::check_file_owner_id_ignore_missing("/etc/security/opasswd", 0, 0),
        vec![],
    )
    .with_description("\"/etc/security/opasswd\" stores previously-used password hashes for \"pam_pwhistory\" reuse prevention. Wrong ownership exposes those historical hashes to non-root users for cracking, leaking old password that could indicate patterns or be reused elsewhere.")
    .with_fix("chown root:root /etc/security/opasswd")
    .register();

    check::Check::new(
        "USR_105",
        "Ensure \"/etc/security/opasswd\" file permissions are \"600\" or file is missing",
        Severity::Medium,
        vec!["group", "server", "workstation"],
        || base::check_file_permission_ignore_missing("/etc/security/opasswd", 0o600),
        vec![],
    )
    .with_description("\"/etc/security/opasswd\" stores previously-used password hashes for \"pam_pwhistory\" reuse prevention. Wrong permissions exposes those historical hashes to non-root users for cracking, leaking old password that could indicate patterns or be reused elsewhere.")
    .with_fix("chmod 600 /etc/security/opasswd")
    .register();
}
