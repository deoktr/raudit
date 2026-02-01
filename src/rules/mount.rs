use crate::*;

pub fn add_checks() {
    // mounts
    check::Check::new(
        "MNT_001",
        "Ensure mount point \"/boot\" exist",
        vec!["mount", "server", "workstation"],
        || mount::check_mount_present("/boot"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_002",
        "Ensure mount point \"/tmp\" exist",
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/tmp"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_003",
        "Ensure mount point \"/home\" exist",
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/home"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_004",
        "Ensure mount point \"/var\" exist",
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/var"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_005",
        "Ensure mount point \"/var/log\" exist",
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/var/log"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_006",
        "Ensure mount point \"/var/log/audit\" exist",
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/var/log/audit"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_007",
        "Ensure mount point \"/var/tmp\" exist",
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/var/tmp"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_008",
        "Ensure mount point \"/dev/shm\" exist",
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/dev/shm"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_020",
        "Ensure mount option \"nodev\" is set for \"/dev/shm\"",
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/dev/shm", "nodev"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_024",
        "Ensure mount option \"nodev\" is set for \"/boot\"",
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/boot", "nodev"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_025",
        "Ensure mount option \"nosuid\" is set for \"/boot\"",
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/boot", "nosuid"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_026",
        "Ensure mount option \"noexec\" is set for \"/boot\"",
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/boot", "noexec"),
        vec![mount::init_mounts],
    )
    .register();
    // TODO: optional
    check::Check::new(
        "MNT_027",
        "Ensure mount option \"noauto\" is set for \"/boot\"",
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/boot", "noauto"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_028",
        "Ensure mount option \"nodev\" is set for \"/home\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/home", "nodev"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_029",
        "Ensure mount option \"nosuid\" is set for \"/home\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/home", "nosuid"),
        vec![mount::init_mounts],
    )
    .register();
    // TODO: optional
    check::Check::new(
        "MNT_030",
        "Ensure mount option \"noexec\" is set for \"/home\"",
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/home", "noexec"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_031",
        "Ensure mount option \"nodev\" is set for \"/tmp\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/tmp", "nodev"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_032",
        "Ensure mount option \"nosuid\" is set for \"/tmp\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/tmp", "nosuid"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_033",
        "Ensure mount option \"noexec\" is set for \"/tmp\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/tmp", "noexec"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_034",
        "Ensure mount option \"nodev\" is set for \"/var\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/var", "nodev"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_035",
        "Ensure mount option \"nosuid\" is set for \"/var\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/var", "nosuid"),
        vec![mount::init_mounts],
    )
    .register();
    // TODO: optional
    check::Check::new(
        "MNT_036",
        "Ensure mount option \"noexec\" is set for \"/var\"",
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/var", "noexec"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_037",
        "Ensure mount option \"nodev\" is set for \"/var/log\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/var/log", "nodev"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_038",
        "Ensure mount option \"nosuid\" is set for \"/var/log\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/var/log", "nosuid"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_039",
        "Ensure mount option \"noexec\" is set for \"/var/log\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/var/log", "noexec"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_040",
        "Ensure mount option \"nodev\" is set for \"/var/log/audit\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/var/log/audit", "nodev"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_041",
        "Ensure mount option \"nosuid\" is set for \"/var/log/audit\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/var/log/audit", "nosuid"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_042",
        "Ensure mount option \"noexec\" is set for \"/var/log/audit\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/var/log/audit", "noexec"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_043",
        "Ensure mount option \"nodev\" is set for \"/var/tmp\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/var/tmp", "nodev"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_044",
        "Ensure mount option \"nosuid\" is set for \"/var/tmp\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/var/tmp", "nosuid"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_045",
        "Ensure mount option \"noexec\" is set for \"/var/tmp\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/var/tmp", "noexec"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_046",
        "Ensure mount option \"nodev\" is set for \"/proc\"",
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/proc", "nodev"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_047",
        "Ensure mount option \"nosuid\" is set for \"/proc\"",
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/proc", "nosuid"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_048",
        "Ensure mount option \"noexec\" is set for \"/proc\"",
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/proc", "noexec"),
        vec![mount::init_mounts],
    )
    .register();

    // `hidepid=2` is not supported by systemd, breaks polkit, GDM, etc.
    // https://wiki.archlinux.org/title/Security#hidepid
    // https://github.com/systemd/systemd/issues/12955#issuecomment-508490893
    // https://github.com/systemd/systemd/issues/20848#issuecomment-930185888
    // check::Check::new(
    //     "MNT_049",
    //     "Ensure mount option \"hidepid=invisible\" is set for \"/proc\"",
    //     vec![
    //         "mount",
    //         "fs",
    //         "mount_option",
    //         "paranoid",
    //         "server",
    //         "workstation",
    //     ],
    //     || mount::check_mount_option("/proc", "hidepid=invisible"),
    //     vec![mount::init_mounts],
    // )
    // .register();

    check::Check::new(
        "MNT_050",
        "Ensure mount option \"nosuid\" is set for \"/dev\"",
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/dev", "nosuid"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_051",
        "Ensure mount option \"noexec\" is set for \"/dev\"",
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/dev", "noexec"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_052",
        "Ensure mount option \"nodev\" is set for \"/dev/shm\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/dev/shm", "nodev"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_053",
        "Ensure mount option \"nosuid\" is set for \"/dev/shm\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/dev/shm", "nosuid"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "MNT_054",
        "Ensure mount option \"noexec\" is set for \"/dev/shm\"",
        vec![
            "mount",
            "fs",
            "mount_option",
            "CIS",
            "server",
            "workstation",
        ],
        || mount::check_mount_option("/dev/shm", "noexec"),
        vec![mount::init_mounts],
    )
    .register();
}
