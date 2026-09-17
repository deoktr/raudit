use crate::check;
use crate::check::Severity;
use crate::modules::mount;

pub fn add_checks() {
    check::Check::new(
        "MNT_001",
        "Ensure mount point \"/boot\" exist",
        Severity::Medium,
        vec!["mount", "server", "workstation"],
        || mount::check_mount_present("/boot"),
        vec![mount::init_mounts],
    )
    .with_description("A separate /boot partition allows it to be mounted read-only after boot, preventing attackers from modifying kernel or bootloader files.")
    .register();

    check::Check::new(
        "MNT_002",
        "Ensure mount point \"/tmp\" exist",
        Severity::Medium,
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/tmp"),
        vec![mount::init_mounts],
    )
    .with_description("A separate /tmp filesystem prevents temporary file abuse from filling the root partition, protecting from potential DOS, and allows restrictive mount options like noexec.")
    .register();

    check::Check::new(
        "MNT_003",
        "Ensure mount point \"/home\" exist",
        Severity::Medium,
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/home"),
        vec![mount::init_mounts],
    )
    .with_description(
        "A separate /home partition allows filesystem-specific security options like noexec.",
    )
    .register();

    check::Check::new(
        "MNT_004",
        "Ensure mount point \"/var\" exist",
        Severity::Medium,
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/var"),
        vec![mount::init_mounts],
    )
    .with_description("A separate /var partition prevents variable data from filling the root filesystem and allows restrictive mount options like noexec.")
    .register();

    check::Check::new(
        "MNT_005",
        "Ensure mount point \"/var/log\" exist",
        Severity::Medium,
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/var/log"),
        vec![mount::init_mounts],
    )
    .with_description("A separate /var/log partition ensures audit logs survive a full root filesystem and allows restrictive mount options.")
    .register();

    check::Check::new(
        "MNT_006",
        "Ensure mount point \"/var/log/audit\" exist",
        Severity::Medium,
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/var/log/audit"),
        vec![mount::init_mounts],
    )
    .with_description("A separate /var/log/audit partition ensures audit logs survive disk exhaustion attacks and allows restrictive mount options.")
    .register();

    check::Check::new(
        "MNT_007",
        "Ensure mount point \"/var/tmp\" exist",
        Severity::Medium,
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/var/tmp"),
        vec![mount::init_mounts],
    )
    .with_description("A separate /var/tmp partition isolates large temporary files from /tmp and allows restrictive mount options.")
    .register();

    check::Check::new(
        "MNT_008",
        "Ensure mount point \"/dev/shm\" exist",
        Severity::Medium,
        vec!["mount", "fs", "CIS", "server", "workstation"],
        || mount::check_mount_present("/dev/shm"),
        vec![mount::init_mounts],
    )
    .with_description(
        "A separate /dev/shm mount allows restrictive options to prevent shared-memory abuse.",
    )
    .register();

    check::Check::new(
        "MNT_020",
        "Ensure mount option \"nodev\" is set for \"/dev/shm\"",
        Severity::High,
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/dev/shm", "nodev"),
        vec![mount::init_mounts],
    )
    .with_description("Prevent device node creation on /dev/shm, blocking attackers from creating block devices to bypass filesystem access controls.")
    .register();

    check::Check::new(
        "MNT_024",
        "Ensure mount option \"nodev\" is set for \"/boot\"",
        Severity::Medium,
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/boot", "nodev"),
        vec![mount::init_mounts],
    )
    .with_description("Prevent device node creation on /boot, blocking attackers from creating block devices to bypass filesystem access controls.")
    .register();

    check::Check::new(
        "MNT_025",
        "Ensure mount option \"nosuid\" is set for \"/boot\"",
        Severity::Medium,
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/boot", "nosuid"),
        vec![mount::init_mounts],
    )
    .with_description(
        "Ignore SUID bits on /boot, preventing attackers from exploiting setuid binaries.",
    )
    .register();

    check::Check::new(
        "MNT_026",
        "Ensure mount option \"noexec\" is set for \"/boot\"",
        Severity::Medium,
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/boot", "noexec"),
        vec![mount::init_mounts],
    )
    .with_description("Prevent direct execution of binaries on /boot, blocking attackers from running malicious code placed in the boot partition.")
    .register();

    // TODO: optional
    check::Check::new(
        "MNT_027",
        "Ensure mount option \"noauto\" is set for \"/boot\"",
        Severity::Medium,
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/boot", "noauto"),
        vec![mount::init_mounts],
    )
    .with_description("Require explicit mounting of /boot, reducing the window during which attackers can modify boot files. /boot is only needed during kernel updates.")
    .register();

    check::Check::new(
        "MNT_028",
        "Ensure mount option \"nodev\" is set for \"/home\"",
        Severity::Medium,
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
    .with_description("Prevent device node creation on /home, blocking attackers from creating block devices to bypass filesystem access controls.")
    .register();

    check::Check::new(
        "MNT_029",
        "Ensure mount option \"nosuid\" is set for \"/home\"",
        Severity::Medium,
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
    .with_description(
        "Ignore SUID bits on /home, preventing attackers from exploiting setuid binaries.",
    )
    .register();

    // TODO: optional
    check::Check::new(
        "MNT_030",
        "Ensure mount option \"noexec\" is set for \"/home\"",
        Severity::Medium,
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/home", "noexec"),
        vec![mount::init_mounts],
    )
    .with_description("Prevent direct execution of binaries on /home, blocking attackers from running malicious code in user home directories.")
    .register();

    check::Check::new(
        "MNT_031",
        "Ensure mount option \"nodev\" is set for \"/tmp\"",
        Severity::High,
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
    .with_description("Prevent device node creation on /tmp, blocking attackers from creating block devices to bypass filesystem access controls.")
    .register();

    check::Check::new(
        "MNT_032",
        "Ensure mount option \"nosuid\" is set for \"/tmp\"",
        Severity::High,
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
    .with_description(
        "Ignore SUID bits on /tmp, preventing attackers from exploiting setuid binaries.",
    )
    .register();

    check::Check::new(
        "MNT_033",
        "Ensure mount option \"noexec\" is set for \"/tmp\"",
        Severity::High,
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
    .with_description("Prevent direct execution of binaries on /tmp, blocking attackers from downloading and running exploits in world-writable /tmp.")
    .register();

    check::Check::new(
        "MNT_034",
        "Ensure mount option \"nodev\" is set for \"/var\"",
        Severity::Medium,
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
    .with_description("Prevent device node creation on /var, blocking attackers from creating block devices to bypass filesystem access controls.")
    .register();

    check::Check::new(
        "MNT_035",
        "Ensure mount option \"nosuid\" is set for \"/var\"",
        Severity::Medium,
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
    .with_description(
        "Ignore SUID bits on /var, preventing attackers from exploiting setuid binaries.",
    )
    .register();

    // TODO: optional
    check::Check::new(
        "MNT_036",
        "Ensure mount option \"noexec\" is set for \"/var\"",
        Severity::Medium,
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/var", "noexec"),
        vec![mount::init_mounts],
    )
    .with_description("Prevent direct execution of binaries on /var, blocking attackers from running malicious code in writable system directories.")
    .register();

    check::Check::new(
        "MNT_037",
        "Ensure mount option \"nodev\" is set for \"/var/log\"",
        Severity::Medium,
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
    .with_description("Prevent device node creation on /var/log, blocking attackers from creating block devices to bypass filesystem access controls.")
    .register();

    check::Check::new(
        "MNT_038",
        "Ensure mount option \"nosuid\" is set for \"/var/log\"",
        Severity::Medium,
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
    .with_description(
        "Ignore SUID bits on /var/log, preventing attackers from exploiting setuid binaries.",
    )
    .register();

    check::Check::new(
        "MNT_039",
        "Ensure mount option \"noexec\" is set for \"/var/log\"",
        Severity::Medium,
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
    .with_description("Prevent direct execution of binaries on /var/log, blocking attackers from running malicious code disguised as log files.")
    .register();

    check::Check::new(
        "MNT_040",
        "Ensure mount option \"nodev\" is set for \"/var/log/audit\"",
        Severity::Medium,
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
    .with_description("Prevent device node creation on /var/log/audit, blocking attackers from creating block devices to bypass filesystem access controls.")
    .register();

    check::Check::new(
        "MNT_041",
        "Ensure mount option \"nosuid\" is set for \"/var/log/audit\"",
        Severity::Medium,
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
    .with_description(
        "Ignore SUID bits on /var/log/audit, preventing attackers from exploiting setuid binaries.",
    )
    .register();

    check::Check::new(
        "MNT_042",
        "Ensure mount option \"noexec\" is set for \"/var/log/audit\"",
        Severity::Medium,
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
    .with_description("Prevent direct execution of binaries on the audit log partition, blocking attackers from running code in audit storage.")
    .register();

    check::Check::new(
        "MNT_043",
        "Ensure mount option \"nodev\" is set for \"/var/tmp\"",
        Severity::High,
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
    .with_description("Prevent device node creation on /var/tmp, blocking attackers from creating block devices to bypass filesystem access controls.")
    .register();

    check::Check::new(
        "MNT_044",
        "Ensure mount option \"nosuid\" is set for \"/var/tmp\"",
        Severity::High,
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
    .with_description(
        "Ignore SUID bits on /var/tmp, preventing attackers from exploiting setuid binaries.",
    )
    .register();

    check::Check::new(
        "MNT_045",
        "Ensure mount option \"noexec\" is set for \"/var/tmp\"",
        Severity::High,
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
    .with_description("Prevent direct execution of binaries on /var/tmp, blocking attackers from running exploits in world-writable /var/tmp.")
    .register();

    check::Check::new(
        "MNT_046",
        "Ensure mount option \"nodev\" is set for \"/proc\"",
        Severity::Medium,
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/proc", "nodev"),
        vec![mount::init_mounts],
    )
    .with_description("Prevent device node creation on /proc, blocking attackers from creating block devices to bypass filesystem access controls.")
    .register();

    check::Check::new(
        "MNT_047",
        "Ensure mount option \"nosuid\" is set for \"/proc\"",
        Severity::Medium,
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/proc", "nosuid"),
        vec![mount::init_mounts],
    )
    .with_description(
        "Ignore SUID bits on /proc, preventing attackers from exploiting setuid binaries.",
    )
    .register();

    check::Check::new(
        "MNT_048",
        "Ensure mount option \"noexec\" is set for \"/proc\"",
        Severity::Medium,
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/proc", "noexec"),
        vec![mount::init_mounts],
    )
    .with_description("Prevent execution on /proc, reinforcing the virtual filesystem against code execution attacks.")
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
        Severity::Medium,
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/dev", "nosuid"),
        vec![mount::init_mounts],
    )
    .with_description(
        "Ignore SUID bits on /dev, preventing attackers from exploiting setuid binaries.",
    )
    .register();

    check::Check::new(
        "MNT_051",
        "Ensure mount option \"noexec\" is set for \"/dev\"",
        Severity::Medium,
        vec!["mount", "fs", "mount_option", "server", "workstation"],
        || mount::check_mount_option("/dev", "noexec"),
        vec![mount::init_mounts],
    )
    .with_description("Prevent execution of binaries on /dev, blocking attackers from running malicious code via device nodes.")
    .register();

    check::Check::new(
        "MNT_053",
        "Ensure mount option \"nosuid\" is set for \"/dev/shm\"",
        Severity::High,
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
    .with_description(
        "Ignore SUID bits on /dev/shm, preventing attackers from exploiting setuid binaries.",
    )
    .register();

    check::Check::new(
        "MNT_054",
        "Ensure mount option \"noexec\" is set for \"/dev/shm\"",
        Severity::High,
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
    .with_description("Prevent execution of binaries on /dev/shm, blocking attackers from running exploits from shared memory. This could be used to bypass AV and EDR that scan files created on disk but may ignore files created in shared memory.")
    .register();
}
