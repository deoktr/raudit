use crate::*;

pub fn add_checks() {
    check::add_check(
        "APT_001",
        "Ensure apt is configured with \"Acquire::http::AllowRedirect\" = \"false\"",
        vec!["apt"],
        || apt::check_apt("Acquire::http::AllowRedirect", "false"),
        vec![apt::init_apt_config],
    );
    check::add_check(
        "APT_002",
        "Ensure apt is configured with \"APT::Get::AllowUnauthenticated\" = \"false\"",
        vec!["apt"],
        || apt::check_apt("APT::Get::AllowUnauthenticated", "false"),
        vec![apt::init_apt_config],
    );
    check::add_check(
        "APT_003",
        "Ensure apt is configured with \"APT::Periodic::AutocleanInterval\" = \"7\"",
        vec!["apt"],
        || apt::check_apt("APT::Periodic::AutocleanInterval", "7"),
        vec![apt::init_apt_config],
    );
    check::add_check(
        "APT_004",
        "Ensure apt is configured with \"APT::Get::AutomaticRemove\" = \"true\"",
        vec!["apt"],
        || apt::check_apt("APT::Get::AutomaticRemove", "true"),
        vec![apt::init_apt_config],
    );
    check::add_check(
        "APT_005",
        "Ensure apt is configured with \"APT::Install-Recommends\" = \"false\"",
        vec!["apt"],
        || apt::check_apt("APT::Install-Recommends", "false"),
        vec![apt::init_apt_config],
    );
    check::add_check(
        "APT_006",
        "Ensure apt is configured with \"APT::Install-Suggests\" = \"false\"",
        vec!["apt"],
        || apt::check_apt("APT::Install-Suggests", "false"),
        vec![apt::init_apt_config],
    );
    check::add_check(
        "APT_007",
        "Ensure apt is configured with \"Acquire::AllowInsecureRepositories\" = \"false\"",
        vec!["apt"],
        || apt::check_apt("Acquire::AllowInsecureRepositories", "false"),
        vec![apt::init_apt_config],
    );
    check::add_check(
        "APT_008",
        "Ensure apt is configured with \"Acquire::AllowDowngradeToInsecureRepositories\" = \"false\"",
        vec!["apt"],
        || apt::check_apt("Acquire::AllowDowngradeToInsecureRepositories", "false"),
        vec![apt::init_apt_config],
    );
    check::add_check(
        "APT_009",
        "Ensure apt is configured with \"APT::Sandbox::Seccomp\" = \"1\"",
        vec!["apt"],
        || apt::check_apt("APT::Sandbox::Seccomp", "1"),
        vec![apt::init_apt_config],
    );

    // unattended-upgrade
    check::add_check(
        "APT_010",
        "Ensure apt is configured with \"Unattended-Upgrade::Remove-Unused-Dependencies\" = \"true\"",
        vec!["apt"],
        || apt::check_apt("Unattended-Upgrade::Remove-Unused-Dependencies", "true"),
        vec![apt::init_apt_config],
    );
    check::add_check(
        "APT_011",
        "Ensure apt is configured with \"Unattended-Upgrade::Remove-Unused-Kernel-Packages\" = \"true\"",
        vec!["apt"],
        || apt::check_apt("Unattended-Upgrade::Remove-Unused-Kernel-Packages", "true"),
        vec![apt::init_apt_config],
    );
}
