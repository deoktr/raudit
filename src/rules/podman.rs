use crate::check::Severity;
use crate::*;

pub fn add_checks() {
    check::Check::new(
        "CNT_501",
        "Ensure podman containers are not started with \"--privileged\" flag",
        Severity::High,
        vec!["container", "podman", "server", "workstation"],
        podman::podman_not_privileged,
        vec![podman::init_containers_inspect],
    )
    .with_description("Privileged containers have full access to the host system, effectively disabling all security isolation and allowing container escape to root on the host.")
    .register();

    check::Check::new(
        "CNT_502",
        "Ensure podman containers capabilities are dropped",
        Severity::High,
        vec!["container", "podman", "server", "workstation"],
        podman::podman_cap_drop,
        vec![podman::init_containers_inspect],
    )
    .with_description("Dropping Linux capabilities reduces the kernel attack surface available to a compromised container, limiting the damage an attacker can do if they gain code execution.")
    .register();

    check::Check::new(
        "CNT_503",
        "Ensure podman containers are started with a user",
        Severity::High,
        vec!["container", "podman", "server", "workstation"],
        podman::podman_user,
        vec![podman::init_containers_inspect],
    )
    .register();
    check::Check::new(
        "CNT_504",
        "Ensure podman mount point \"/var/lib/containers\" exist",
        Severity::Medium,
        vec!["container", "podman", "mount", "server", "workstation"],
        // TODO: get path by running: podman info -f '{{ .Store.RunRoot }}'
        || mount::check_mount_present("/var/lib/containers"),
        vec![mount::init_mounts],
    )
    .register();
    check::Check::new(
        "CNT_505",
        "Ensure apparmor is enabled for podman",
        Severity::Medium,
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
        Severity::Medium,
        vec!["container", "podman", "apparmor", "server", "workstation"],
        podman::podman_apparmor,
        vec![podman::init_containers_inspect],
    )
    .register();
}
