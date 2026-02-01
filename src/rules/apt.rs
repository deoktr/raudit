use crate::*;

pub fn add_checks() {
    check::Check::new(
        "APT_001",
        "Ensure apt is configured with \"Acquire::http::AllowRedirect\" = \"0\"",
        vec!["apt", "server", "workstation"],
        || apt::check_apt("Acquire::http::AllowRedirect", "0"),
        vec![apt::init_apt_config],
    )
    .register();
    check::Check::new(
        "APT_002",
        "Ensure apt is configured with \"APT::Get::AllowUnauthenticated\" = \"0\"",
        vec!["apt", "server", "workstation"],
        || apt::check_apt("APT::Get::AllowUnauthenticated", "0"),
        vec![apt::init_apt_config],
    )
    .register();
    check::Check::new(
        "APT_003",
        "Ensure apt is configured with \"APT::Periodic::AutocleanInterval\" = \"7\"",
        vec!["apt", "workstation"],
        || apt::check_apt("APT::Periodic::AutocleanInterval", "7"),
        vec![apt::init_apt_config],
    )
    .register();
    check::Check::new(
        "APT_004",
        "Ensure apt is configured with \"APT::Get::AutomaticRemove\" = \"1\"",
        vec!["apt", "workstation"],
        || apt::check_apt("APT::Get::AutomaticRemove", "1"),
        vec![apt::init_apt_config],
    )
    .register();
    check::Check::new(
        "APT_005",
        "Ensure apt is configured with \"APT::Install-Recommends\" = \"0\"",
        vec!["apt", "server", "workstation"],
        || apt::check_apt("APT::Install-Recommends", "0"),
        vec![apt::init_apt_config],
    )
    .register();
    check::Check::new(
        "APT_006",
        "Ensure apt is configured with \"APT::Install-Suggests\" = \"0\"",
        vec!["apt", "server", "workstation"],
        || apt::check_apt("APT::Install-Suggests", "0"),
        vec![apt::init_apt_config],
    )
    .register();
    check::Check::new(
        "APT_007",
        "Ensure apt is configured with \"Acquire::AllowInsecureRepositories\" = \"0\"",
        vec!["apt", "server", "workstation"],
        || apt::check_apt("Acquire::AllowInsecureRepositories", "0"),
        vec![apt::init_apt_config],
    )
    .register();
    check::Check::new(
        "APT_008",
        "Ensure apt is configured with \"Acquire::AllowDowngradeToInsecureRepositories\" = \"0\"",
        vec!["apt", "server", "workstation"],
        || apt::check_apt("Acquire::AllowDowngradeToInsecureRepositories", "0"),
        vec![apt::init_apt_config],
    )
    .register();
    check::Check::new(
        "APT_009",
        "Ensure apt is configured with \"APT::Sandbox::Seccomp\" = \"1\"",
        vec!["apt", "server", "workstation"],
        || apt::check_apt("APT::Sandbox::Seccomp", "1"),
        vec![apt::init_apt_config],
    )
    .register();

    // unattended-upgrade
    check::Check::new(
        "APT_010",
        "Ensure apt is configured with \"Unattended-Upgrade::Remove-Unused-Dependencies\" = \"1\"",
        vec!["apt", "workstation", "unattended-upgrade"],
        || apt::check_apt("Unattended-Upgrade::Remove-Unused-Dependencies", "1"),
        vec![apt::init_apt_config],
    )
    .with_link("https://wiki.debian.org/PeriodicUpdates")
    .register();
    check::Check::new(
        "APT_011",
        "Ensure apt is configured with \"Unattended-Upgrade::Remove-Unused-Kernel-Packages\" = \"1\"",
        vec!["apt", "workstation", "unattended-upgrade"],
        || apt::check_apt("Unattended-Upgrade::Remove-Unused-Kernel-Packages", "1"),
        vec![apt::init_apt_config],
    )
    .with_link("https://wiki.debian.org/PeriodicUpdates")
    .register();
}
