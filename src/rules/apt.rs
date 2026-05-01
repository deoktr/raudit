use crate::check;
use crate::check::Severity;
use crate::modules::{apt, base, os};

pub fn add_checks() {
    check::Check::new(
        "APT_001",
        "Ensure apt is configured with \"Acquire::http::AllowRedirect\" = \"0\"",
        Severity::Medium,
        vec!["apt", "server", "workstation"],
        || apt::check_apt("Acquire::http::AllowRedirect", "0"),
        vec![apt::init_apt_config],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Disabling HTTP redirects prevents man-in-the-middle attacks that could redirect package downloads to malicious servers.")
    .with_fix("In \"/etc/apt/apt.conf\" add: 'Acquire::http::AllowRedirect = \"0\";'")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_002",
        "Ensure apt is configured with \"APT::Get::AllowUnauthenticated\" = \"0\"",
        Severity::High,
        vec!["apt", "server", "workstation"],
        || apt::check_apt("APT::Get::AllowUnauthenticated", "0"),
        vec![apt::init_apt_config],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Blocks installation of packages without proper authentication.")
    .with_fix("In \"/etc/apt/apt.conf\" add: 'APT::Get::AllowUnauthenticated = \"0\";'")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_003",
        "Ensure apt is configured with \"APT::Periodic::AutocleanInterval\" = \"7\"",
        Severity::Low,
        vec!["apt", "server", "workstation"],
        || apt::check_apt("APT::Periodic::AutocleanInterval", "7"),
        vec![apt::init_apt_config],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Automatically cleans package cache every 7 days, reducing disk space usage and potential stale package vulnerabilities.")
    .with_fix("In \"/etc/apt/apt.conf\" add: 'APT::Periodic::AutocleanInterval = \"7\";'")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_004",
        "Ensure apt is configured with \"APT::Get::AutomaticRemove\" = \"1\"",
        Severity::Low,
        vec!["apt", "workstation"],
        || apt::check_apt("APT::Get::AutomaticRemove", "1"),
        vec![apt::init_apt_config],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Automatically removes orphaned packages that are no longer needed, reducing the number of installed packages and the attack surface.")
    .with_fix("In \"/etc/apt/apt.conf\" add: 'APT::Get::AutomaticRemove = \"1\";'")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_005",
        "Ensure apt is configured with \"APT::Install-Recommends\" = \"0\"",
        Severity::Medium,
        vec!["apt", "server", "workstation"],
        || apt::check_apt("APT::Install-Recommends", "0"),
        vec![apt::init_apt_config],
    )
    .skip_when(os::skip_not_debian)
    .with_description(
        "Prevents automatic installation of recommended packages, minimizing attack surface.",
    )
    .with_fix("In \"/etc/apt/apt.conf\" add: 'APT::Install-Recommends = \"0\";'")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_006",
        "Ensure apt is configured with \"APT::Install-Suggests\" = \"0\"",
        Severity::Medium,
        vec!["apt", "server", "workstation"],
        || apt::check_apt("APT::Install-Suggests", "0"),
        vec![apt::init_apt_config],
    )
    .skip_when(os::skip_not_debian)
    .with_description(
        "Prevents automatic installation of suggested packages, minimizing attack surface.",
    )
    .with_fix("In \"/etc/apt/apt.conf\" add: 'APT::Install-Suggests = \"0\";'")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_007",
        "Ensure apt is configured with \"Acquire::AllowInsecureRepositories\" = \"0\"",
        Severity::High,
        vec!["apt", "server", "workstation"],
        || apt::check_apt("Acquire::AllowInsecureRepositories", "0"),
        vec![apt::init_apt_config],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Blocks use of repositories without valid cryptographic signatures, preventing installation of tampered packages.")
    .with_fix("In \"/etc/apt/apt.conf\" add: 'Acquire::AllowInsecureRepositories = \"0\";'")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_008",
        "Ensure apt is configured with \"Acquire::AllowDowngradeToInsecureRepositories\" = \"0\"",
        Severity::High,
        vec!["apt", "server", "workstation"],
        || apt::check_apt("Acquire::AllowDowngradeToInsecureRepositories", "0"),
        vec![apt::init_apt_config],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Prevents downgrading a previously authenticated repository to an insecure one, blocking a potential supply chain attack vector.")
    .with_fix(
        "In \"/etc/apt/apt.conf\" add: 'Acquire::AllowDowngradeToInsecureRepositories = \"0\";'",
    )
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_009",
        "Ensure apt is configured with \"APT::Sandbox::Seccomp\" = \"1\"",
        Severity::Medium,
        vec!["apt", "server", "workstation"],
        || apt::check_apt("APT::Sandbox::Seccomp", "1"),
        vec![apt::init_apt_config],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Enables Seccomp sandboxing for package management, providing additional process isolation.")
    .with_fix("In \"/etc/apt/apt.conf\" add: 'APT::Sandbox::Seccomp = \"1\";'")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    // unattended-upgrade
    check::Check::new(
        "APT_010",
        "Ensure apt is configured with \"Unattended-Upgrade::Remove-Unused-Dependencies\" = \"1\"",
        Severity::Medium,
        vec!["apt", "workstation", "unattended-upgrade"],
        || apt::check_apt("Unattended-Upgrade::Remove-Unused-Dependencies", "1"),
        vec![apt::init_apt_config],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Automatically removes unused dependencies, minimizing attack surface.")
    .with_fix("Install apt unattended-upgrade. In \"/etc/apt/apt.conf\" add: 'Unattended-Upgrade::Remove-Unused-Dependencies = \"1\";'")
    .with_link("https://wiki.debian.org/PeriodicUpdates")
    .register();

    check::Check::new(
        "APT_011",
        "Ensure apt is configured with \"Unattended-Upgrade::Remove-Unused-Kernel-Packages\" = \"1\"",
        Severity::Medium,
        vec!["apt", "workstation", "unattended-upgrade"],
        || apt::check_apt("Unattended-Upgrade::Remove-Unused-Kernel-Packages", "1"),
        vec![apt::init_apt_config],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Automatically removes unused kernel packages, minimizing attack surface.")
    .with_fix("Install apt unattended-upgrade. In \"/etc/apt/apt.conf\" add: 'Unattended-Upgrade::Remove-Unused-Kernel-Packages = \"1\";'")
    .with_link("https://wiki.debian.org/PeriodicUpdates")
    .register();

    // fs
    check::Check::new(
        "APT_100",
        "Ensure /etc/apt/source.list file have 644 permission",
        Severity::High,
        vec!["apt", "server", "workstation"],
        || base::check_file_permission("/etc/apt/source.list", 0o644),
        vec![],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Prevents unauthorized modification of package repositories. Could be exploited to download packages from attacker controlled servers.")
    .with_fix("chmod 644 /etc/apt/source.list")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_101",
        "Ensure /etc/apt/source.list is owned by root",
        Severity::High,
        vec!["apt", "server", "workstation"],
        || base::check_file_owner_id("/etc/apt/source.list", 0, 0),
        vec![],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Prevents unauthorized modification of package repositories. Could be exploited to download packages from attacker controlled servers.")
    .with_fix("chown root:root /etc/apt/source.list")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_102",
        "Ensure all /etc/apt/source.list.d/ files have 644 permissions",
        Severity::High,
        vec!["apt", "server", "workstation"],
        || base::check_dir_files_permission("/etc/apt/source.list.d/", 0o644),
        vec![],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Prevents unauthorized modification of package repositories. Could be exploited to download packages from attacker controlled servers.")
    .with_fix("chmod -R 644 /etc/apt/source.list.d/*")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_103",
        "Ensure all /etc/apt/source.list.d/ files are owned by root",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_owner_id("/etc/apt/source.list.d/", 0, 0),
        vec![],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Prevents unauthorized modification of package repositories. Could be exploited to download packages from attacker controlled servers.")
    .with_fix("chown -R root:root /etc/apt/source.list.d/*")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_104",
        "Ensure /etc/apt/apt.conf file have 644 permission",
        Severity::High,
        vec!["apt", "server", "workstation"],
        || base::check_file_permission_ignore_missing("/etc/apt/apt.conf", 0o644),
        vec![],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Could be exploited to modify package installation behavior, and could lead to a wide range of impacts.")
    .with_fix("chmod 644 /etc/apt/apt.conf")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_105",
        "Ensure /etc/apt/apt.conf is owned by root",
        Severity::High,
        vec!["apt", "server", "workstation"],
        || base::check_file_owner_id_ignore_missing("/etc/apt/apt.conf", 0, 0),
        vec![],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Could be exploited to modify package installation behavior, and could lead to a wide range of impacts.")
    .with_fix("chown root:root /etc/apt/apt.conf")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_106",
        "Ensure all /etc/apt/apt.conf.d/ files have 644 permissions",
        Severity::High,
        vec!["apt", "server", "workstation"],
        || base::check_dir_files_permission("/etc/apt/apt.conf.d/", 0o644),
        vec![],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Could be exploited to modify package installation behavior, and could lead to a wide range of impacts.")
    .with_fix("chmod -R 644 /etc/apt/apt.conf.d/*")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();

    check::Check::new(
        "APT_107",
        "Ensure all /etc/apt/apt.conf.d/ files are owned by root",
        Severity::High,
        vec!["cron", "server", "workstation"],
        || base::check_dir_files_owner_id("/etc/apt/apt.conf.d/", 0, 0),
        vec![],
    )
    .skip_when(os::skip_not_debian)
    .with_description("Could be exploited to modify package installation behavior, and could lead to a wide range of impacts.")
    .with_fix("chown -R root:root /etc/apt/apt.conf.d/*")
    .with_link("https://wiki.debian.org/SecureApt")
    .register();
}
