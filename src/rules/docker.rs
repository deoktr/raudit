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
}
