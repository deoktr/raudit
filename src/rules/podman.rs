use crate::*;

pub fn add_checks() {
    check::Check::new(
        "CNT_501",
        "Ensure podman containers are not started with \"--privileged\" flag",
        vec!["container", "podman", "server", "workstation"],
        podman::podman_not_privileged,
        vec![podman::init_containers_inspect],
    )
    .register();
    check::Check::new(
        "CNT_502",
        "Ensure podman containers capabilities are dopped",
        vec!["container", "podman", "server", "workstation"],
        podman::podman_cap_drop,
        vec![podman::init_containers_inspect],
    )
    .register();
    check::Check::new(
        "CNT_503",
        "Ensure podman containers are started with a user",
        vec!["container", "podman", "server", "workstation"],
        podman::podman_user,
        vec![podman::init_containers_inspect],
    )
    .register();
    check::Check::new(
        "CNT_504",
        "Ensure podman mount point \"/var/lib/containers\" exist",
        vec!["container", "podman", "mount", "server", "workstation"],
        // TODO: get path by running: podman info -f '{{ .Store.RunRoot }}'
        || mount::check_mount_present("/var/lib/containers"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "CNT_505",
        "Ensure apparmor is enabled for podman",
        vec!["container", "podman", "apparmor", "server", "workstation"],
        || {
            podman::check_podman_info(
                "/host/security/apparmorEnabled",
                serde_json::Value::Bool(true),
            )
        },
        vec![podman::init_podman_info],
    )
    .register();
    check::Check::new(
        "CNT_506",
        "Ensure podman containers are started with an apparmor profile",
        vec!["container", "podman", "apparmor", "server", "workstation"],
        podman::podman_apparmor,
        vec![podman::init_containers_inspect],
    )
    .register();
}
