use crate::*;

pub fn add_checks() {
    check::add_check(
        "CNT_001",
        "Ensure containers are not started with \"--privileged\" flag",
        vec!["container", "docker"],
        docker::docker_not_privileged,
        vec![],
    );
    check::add_check(
        "CNT_002",
        "Ensure containers capabilities are dopped",
        vec!["container", "docker"],
        docker::docker_cap_drop,
        vec![],
    );
    // https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/abusing-docker-socket-for-privilege-escalation.html
    check::add_check(
        "CNT_003",
        "Ensure group \"docker\" is empty",
        vec!["container", "docker", "group"],
        || group::no_members("docker"),
        vec![group::init_group],
    );
}
