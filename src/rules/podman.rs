use crate::check;
use crate::check::Severity;
use crate::modules::{mount, podman};

pub fn add_checks() {
    check::Check::new(
        "CNT_501",
        "Ensure podman containers are not started with \"--privileged\" flag",
        Severity::High,
        vec!["container", "podman", "server", "workstation"],
        podman::podman_not_privileged,
        vec![podman::init_containers_inspect],
    )
    .skip_when(podman::skip_no_podman)
    .with_description("Privileged containers have full access to the host system, effectively disabling all security isolation (seccomp/AppArmor/SELinux) and allowing container escape to root on the host.")
    .with_fix("Run containers without `--privileged`. If specific capabilities or devices are needed, grant them individually via `--cap-add`/`--device`.")
    .register();

    check::Check::new(
        "CNT_502",
        "Ensure podman containers capabilities are dropped",
        Severity::High,
        vec!["container", "podman", "server", "workstation"],
        podman::podman_cap_drop,
        vec![podman::init_containers_inspect],
    )
    .skip_when(podman::skip_no_podman)
    .with_description("Dropping Linux capabilities reduces the kernel attack surface available to a compromised container, limiting the damage an attacker can do if they gain code execution.")
    .with_fix("Start containers with flag \"--cap-drop all\"")
    .register();

    check::Check::new(
        "CNT_503",
        "Ensure podman containers are started with a user",
        Severity::High,
        vec!["container", "podman", "server", "workstation"],
        podman::podman_user,
        vec![podman::init_containers_inspect],
    )
    .skip_when(podman::skip_no_podman)
    .with_description("Containers running as root inside the namespace can exploit any kernel bug, capability loophole, or shared mount to escape the container. Running as a non-root UID forces an attacker to find an additional escalation primitive first. Limit impact of a container process compromise and follow principle of least privilege.")
    .with_fix("Set `USER` in the Dockerfile to a non-root UID, or pass `--user <uid>` at run time.")
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
    .skip_when(podman::skip_no_podman)
    .with_description("A separate filesystem for /var/lib/containers lets the operator apply hardened mount options (e.g. nodev, quotas) to container storage and prevents a runaway container from filling the root filesystem and breaking host services.")
    .with_fix("Mount /var/lib/containers as a dedicated filesystem in /etc/fstab, consider `nodev` and disk quotas.")
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
    .skip_when(podman::skip_no_podman)
    .with_description("AppArmor confines container processes via mandatory access control. With it disabled, a compromised container relies only on namespaces and capabilities for isolation, removing a defence-in-depth layer that has historically blocked container escapes.")
    .with_fix("Install and enable AppArmor host-side, ensure podman picks up the default container profile.")
    .register();

    check::Check::new(
        "CNT_506",
        "Ensure podman containers are started with an apparmor profile",
        Severity::High,
        vec!["container", "podman", "apparmor", "server", "workstation"],
        podman::podman_apparmor,
        vec![podman::init_containers_inspect],
    )
    .skip_when(podman::skip_no_podman)
    .with_description("Even with AppArmor enabled host-side, a container started with `--security-opt apparmor=unconfined` runs without the profile, per-container confirmation ensures every container actually inherits the profile.")
    .with_fix("Start containers without `--security-opt apparmor=unconfined`, the default profile applies automatically when AppArmor is enabled.")
    .register();
}
