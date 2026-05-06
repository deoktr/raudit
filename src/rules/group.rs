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
    .with_description("Group passwords stored in /etc/gshadow let any holder switch into the group via `newgrp`, expanding lateral movement. Modern systems do not need group passwords and the file should be empty or absent so this attack vector does not exist.")
    .with_fix("Remove or empty \"/etc/gshadow\", ensure no group has a password by clearing the second field of each line via `gpasswd -r <group>`.")
    .register();

    check::Check::new(
        "GRP_002",
        "Ensure no group has a password set",
        Severity::Medium,
        vec!["group", "server", "workstation"],
        group::no_password_in_group,
        vec![group::init_group],
    )
    .with_description("A password in /etc/group lets any user with that password assume the group's privileges via `newgrp`, bypassing the membership list, turning the group hash into a shared lateral-movement credential as soon as it leaks.")
    .with_fix("Remove passwords from groups via `gpasswd -r <group>`.")
    .register();

    check::Check::new(
        "GRP_003",
        "Ensure that only root has GID 0",
        Severity::High,
        vec!["group", "server", "workstation"],
        group::one_gid_zero,
        vec![group::init_group],
    )
    .with_description("A second group with GID 0 is privilege-equivalent to `root` for filesystem and IPC ACLs. An attacker who creates one or who pivots into membership gains root-level group access without ever being root.")
    .with_fix("Remove or renumber any non-`root` group with GID 0 via `groupmod -g <new-gid> <name>`, investigate how it was created.")
    .register();

    check::Check::new(
        "GRP_004",
        "Ensure no duplicate GIDs exist",
        Severity::Medium,
        vec!["group", "server", "workstation"],
        group::no_dup_gid,
        vec![group::init_group],
    )
    .with_description("Two group names sharing one GID makes audit logs and ACL decisions ambiguous: a file owned by GID X cannot be reliably attributed to one group, hiding privilege relationships and complicating forensics.")
    .with_fix("Renumber duplicates via `groupmod -g <new-gid> <name>`.")
    .register();

    check::Check::new(
        "GRP_005",
        "Ensure no duplicate group names exist",
        Severity::Medium,
        vec!["group", "server", "workstation"],
        group::no_dup_name,
        vec![group::init_group],
    )
    .with_description("Duplicate group names indicate manual editing of \"/etc/group\" or a corrupt name service.")
    .with_fix("Edit \"/etc/group\" (with `vigr`) to remove or rename the duplicate.")
    .register();

    check::Check::new(
        "GRP_006",
        "Ensure \"shadow\" group is empty",
        Severity::Medium,
        vec!["group", "CIS", "STIG", "server", "workstation"],
        || group::no_members("shadow"),
        vec![group::init_group],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Members of the `shadow` group can read \"/etc/shadow\" and crack account's password hash. Membership should be empty so no non-root account holds that capability.")
    .with_fix("Remove all members from the `shadow` group via `gpasswd -d <user> shadow`.")
    .register();

    check::Check::new(
        "GRP_100",
        "Ensure \"/etc/group\" file owner is \"root:root\"",
        Severity::Medium,
        vec!["group", "CIS", "server", "workstation"],
        || base::check_file_owner_id("/etc/group", 0, 0),
        vec![],
    )
    .with_description("If \"/etc/group\" is owned by a non-root user, that user can edit group membership and silently grant themselves any group's privileges, including `wheel`, `sudo`, or `docker`, each of which leads to root.")
    .with_fix("`chown root:root /etc/group`")
    .register();

    check::Check::new(
        "GRP_101",
        "Ensure \"/etc/group\" file permissions are \"644\"",
        Severity::High,
        vec!["group", "CIS", "server", "workstation"],
        || base::check_file_permission("/etc/group", 0o644),
        vec![],
    )
    .with_description("Permissions wider than 0644 let unprivileged users modify group membership. Tighter than 0644 breaks userland tools that expect to read group names. 0644 is the only safe value.")
    .with_fix("`chmod 644 /etc/group`")
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
    .with_description("Wrong ownershoip of \"/etc/gshadow\" leaks group password hashes (when present) for offline cracking and exposes sensitive group elevation policy.")
    .with_fix("On Debian: `chown root:shadow /etc/gshadow`. Elsewhere: `chown root:root /etc/gshadow`.")
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
    .with_description("World- or group-readable \"/etc/gshadow\" leaks group password hashes (when present) for offline cracking and exposes sensitive group elevation policy.")
    .with_fix("On Debian: `chmod 640 /etc/gshadow`. Elsewhere: `chmod 600 /etc/gshadow`.")
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
    .with_description("\"/etc/gshadow-\" is the previous-generation backup of gshadow, if its ownership is wrong, an attacker can recover group hashes and policy from the backup that the live file no longer reveals.")
    .with_fix("On Debian: `chown root:shadow /etc/gshadow-`. Elsewhere: `chown root:root /etc/gshadow-`.")
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
    .with_description("\"/etc/gshadow-\" is the previous-generation backup of gshadow, if its permissions are wrong, an attacker can recover group hashes and policy from the backup that the live file no longer reveals.")
    .with_fix("On Debian: `chmod 640 /etc/gshadow-`. Elsewhere: `chmod 600 /etc/gshadow-`.")
    .register();
}
