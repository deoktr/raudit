use crate::*;

pub fn add_checks() {
    check::add_check(
        "CNT_501",
        "Ensure podman containers are not started with \"--privileged\" flag",
        vec!["container", "podman"],
        podman::podman_not_privileged,
        vec![],
    );
    check::add_check(
        "CNT_502",
        "Ensure podman containers capabilities are dopped",
        vec!["container", "podman"],
        podman::podman_cap_drop,
        vec![],
    );
    check::add_check(
        "CNT_503",
        "Ensure podman containers are started with a user",
        vec!["container", "podman"],
        podman::podman_user,
        vec![],
    );
    check::add_check(
        "CNT_504",
        "Ensure podman mount point \"/var/lib/containers\" exist",
        vec!["container", "podman", "mount"],
        // TODO: get path by running: podman info -f '{{ .Store.RunRoot }}'
        || mount::check_mount_present("/var/lib/containers"),
        vec![mount::init_mounts],
    );
}
