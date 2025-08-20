use crate::*;

pub fn add_checks() {
    // mounts
    check::add_check(
        "MNT_001",
        "Ensure mount point \"/boot\" exist",
        vec!["mount"],
        || mount::check_mount_present("/boot"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_002",
        "Ensure mount point \"/tmp\" exist",
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/tmp"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_003",
        "Ensure mount point \"/home\" exist",
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/home"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_004",
        "Ensure mount point \"/var\" exist",
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/var"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_005",
        "Ensure mount point \"/var/log\" exist",
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/var/log"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_006",
        "Ensure mount point \"/var/log/audit\" exist",
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/var/log/audit"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_007",
        "Ensure mount point \"/var/tmp\" exist",
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/var/tmp"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_008",
        "Ensure mount point \"/dev/shm\" exist",
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/dev/shm"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_020",
        "Ensure mount option \"nodev\" is set for \"/dev/shm\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/dev/shm", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_001",
        "Ensure mount option \"errors=remount-ro\" is set for \"/\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/", "errors=remount-ro"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_002",
        "Ensure mount option \"nodev\" is set for \"/boot\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/boot", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_003",
        "Ensure mount option \"nosuid\" is set for \"/boot\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/boot", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_004",
        "Ensure mount option \"noexec\" is set for \"/boot\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/boot", "noexec"),
        vec![mount::init_mounts],
    );
    // TODO: optional
    check::add_check(
        "MNT_005",
        "Ensure mount option \"noauto\" is set for \"/boot\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/boot", "noauto"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_006",
        "Ensure mount option \"nodev\" is set for \"/home\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/home", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_007",
        "Ensure mount option \"nosuid\" is set for \"/home\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/home", "nosuid"),
        vec![mount::init_mounts],
    );
    // TODO: optional
    check::add_check(
        "MNT_008",
        "Ensure mount option \"noexec\" is set for \"/home\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/home", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_009",
        "Ensure mount option \"nodev\" is set for \"/tmp\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/tmp", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_010",
        "Ensure mount option \"nosuid\" is set for \"/tmp\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/tmp", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_011",
        "Ensure mount option \"noexec\" is set for \"/tmp\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/tmp", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_012",
        "Ensure mount option \"nodev\" is set for \"/var\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_013",
        "Ensure mount option \"nosuid\" is set for \"/var\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var", "nosuid"),
        vec![mount::init_mounts],
    );
    // TODO: optional
    check::add_check(
        "MNT_014",
        "Ensure mount option \"noexec\" is set for \"/var\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/var", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_015",
        "Ensure mount option \"nodev\" is set for \"/var/log\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_016",
        "Ensure mount option \"nosuid\" is set for \"/var/log\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_017",
        "Ensure mount option \"noexec\" is set for \"/var/log\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_018",
        "Ensure mount option \"nodev\" is set for \"/var/log/audit\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log/audit", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_019",
        "Ensure mount option \"nosuid\" is set for \"/var/log/audit\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log/audit", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_010",
        "Ensure mount option \"noexec\" is set for \"/var/log/audit\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log/audit", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_011",
        "Ensure mount option \"nodev\" is set for \"/var/tmp\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/tmp", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_012",
        "Ensure mount option \"nosuid\" is set for \"/var/tmp\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/tmp", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_013",
        "Ensure mount option \"noexec\" is set for \"/var/tmp\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/tmp", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_014",
        "Ensure mount option \"nodev\" is set for \"/proc\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/proc", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_015",
        "Ensure mount option \"nosuid\" is set for \"/proc\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/proc", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_016",
        "Ensure mount option \"noexec\" is set for \"/proc\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/proc", "noexec"),
        vec![mount::init_mounts],
    );
    // `hidepid=2` is not supported by systemd, breaks polkit, GDM, etc.
    // https://wiki.archlinux.org/title/Security#hidepid
    // https://github.com/systemd/systemd/issues/12955#issuecomment-508490893
    // https://github.com/systemd/systemd/issues/20848#issuecomment-930185888
    check::add_check(
        "MNT_017",
        "Ensure mount option \"hidepid=invisible\" is set for \"/proc\"",
        vec!["mount", "fs", "mount_option", "paranoid"],
        || mount::check_mount_option("/proc", "hidepid=invisible"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_018",
        "Ensure mount option \"nosuid\" is set for \"/dev\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/dev", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_019",
        "Ensure mount option \"noexec\" is set for \"/dev\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/dev", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_020",
        "Ensure mount option \"nodev\" is set for \"/dev/shm\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/dev/shm", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_021",
        "Ensure mount option \"nosuid\" is set for \"/dev/shm\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/dev/shm", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_022",
        "Ensure mount option \"noexec\" is set for \"/dev/shm\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/dev/shm", "noexec"),
        vec![mount::init_mounts],
    );
}
