use crate::check;
use crate::check::Severity;
use crate::modules::{audit, base, docker, group, mount, ps, systemd};
use serde_json::Value;

// TODO: add checks to ensure limits are set, globally and per containers
// TODO: add checks for cgroups, apparmor

pub fn add_checks() {
    check::Check::new(
        "CNT_001",
        "Ensure docker containers are not started with \"--privileged\" flag",
        Severity::Critical,
        vec!["container", "docker", "server", "workstation"],
        docker::docker_not_privileged,
        vec![docker::init_containers_inspect],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Privileged containers have full access to the host system, effectively disabling all security isolation and allowing container escape to root on the host.")
    .register();

    check::Check::new(
        "CNT_002",
        "Ensure docker containers capabilities are dropped",
        Severity::High,
        vec!["container", "docker", "server", "workstation"],
        docker::docker_cap_drop,
        vec![docker::init_containers_inspect],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Dropping Linux capabilities reduces the kernel attack surface available to a compromised container, limiting the damage an attacker can do if they gain code execution.")
    .register();

    check::Check::new(
        "CNT_003",
        "Ensure docker containers are running with a user",
        Severity::High,
        vec!["container", "docker", "server", "workstation"],
        docker::docker_container_user,
        vec![docker::init_containers_inspect],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Containers running as root inside the namespace can exploit any kernel bug, capability loophole, or shared mount to escape the container. Running as a non-root UID forces an attacker to find an additional escalation primitive first. Limit impact of a container process compromise and follow principle of least privilege.")
    .with_fix("Set `USER` in the Dockerfile to a non-root UID, or pass `--user <uid>` at run time.")
    .register();

    check::Check::new(
        "CNT_004",
        "Ensure docker mount point \"/var/lib/docker\" exist",
        Severity::Medium,
        vec!["container", "docker", "mount", "CIS", "server"], // CIS Docker 1.1.1
        // TODO: get path by running: docker info -f '{{ .DockerRootDir }}'
        || mount::check_mount_present("/var/lib/docker"),
        vec![mount::init_mounts],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("A separate filesystem for /var/lib/containers lets the operator apply hardened mount options (e.g. nodev, quotas) to container storage and prevents a runaway container from filling the root filesystem and breaking host services.")
    .with_fix("Mount /var/lib/containers as a dedicated filesystem in /etc/fstab, consider `nodev` and disk quotas.")
    .with_link("https://docs.docker.com/reference/cli/dockerd/")
    .register();

    check::Check::new(
        "CNT_005",
        "Ensure docker network traffic is restricted between containers on the default bridge",
        Severity::Medium,
        vec!["container", "docker", "ps", "CIS", "server", "workstation"], // CIS Docker 2.2
        // TODO: and check dockerd config file
        || ps::is_running_without_flag_value("dockerd", "--icc", "false"),
        vec![ps::init_proc],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("By default all containers on the default bridge can communicate freely, which allows lateral movement if one container is compromised. Restricting inter-container communication limits blast radius.")
    .with_link("https://docs.docker.com/reference/cli/dockerd/")
    .register();

    check::Check::new(
        "CNT_006",
        "Ensure docker logging level is set to info",
        Severity::Medium,
        vec!["container", "docker", "ps", "CIS", "server", "workstation"], // CIS Docker 2.3
        // TODO: or check dockerd config file
        // TODO: can also be short '-l'
        || ps::is_running_with_flag_value("dockerd", "--log-level", "info"),
        vec![ps::init_proc],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Setting the log level to info ensures that security-relevant events are captured without excessive noise, enabling effective incident detection and forensic analysis.")
    .with_fix("In \"/etc/docker/daemon.json\" add `{\"log-level\": \"info\"}`, or start the daemon with `--no-new-privileges` flag.")
    .register();

    check::Check::new(
        "CNT_007",
        "Ensure docker is allowed to make changes to iptables",
        Severity::High,
        vec!["container", "docker", "ps", "CIS", "server", "workstation"], // CIS Docker 2.4
        // TODO: and check dockerd config file
        || ps::is_running_without_flag_value("dockerd", "--iptables", "false"),
        vec![ps::init_proc],
    )
    .skip_when(docker::skip_no_docker)
    .register();

    check::Check::new(
        "CNT_008",
        "Ensure docker does not allow insecure registry",
        Severity::High,
        vec!["container", "docker", "ps", "CIS", "server", "workstation"], // CIS Docker 2.5
        // TODO: and check dockerd config file
        || ps::is_running_without_flag("dockerd", "--insecure-registry"),
        vec![ps::init_proc],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Insecure registries allow unencrypted and unauthenticated communication, exposing image pulls and pushes to man-in-the-middle attacks and credential theft.")
    .with_link("https://docs.docker.com/reference/cli/dockerd/")
    .register();

    // TODO: could remove since this driver is no longer supported
    check::Check::new(
        "CNT_009",
        "Ensure docker storage driver is not aufs",
        Severity::Medium,
        vec!["container", "docker", "ps", "CIS", "server", "workstation"], // CIS Docker 2.6
        // TODO: can also be short '-s'
        || ps::is_running_without_flag_value("dockerd", "--storage-driver", "aufs"),
        vec![ps::init_proc],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("The aufs storage driver is deprecated and has known security issues including incomplete layer isolation. Using a supported driver reduces the risk of container filesystem leaks.")
    .with_link("https://docs.docker.com/reference/cli/dockerd/")
    .register();

    check::Check::new(
        "CNT_010",
        "Ensure docker storage options \"dm.basesize\" are not set",
        Severity::Medium,
        vec!["container", "docker", "ps", "CIS", "server", "workstation"], // CIS Docker 2.10
        // TODO: and check dockerd config file
        || ps::is_running_without_flag_value("dockerd", "--storage-opt", "dm-basesize"),
        vec![ps::init_proc],
    )
    .skip_when(docker::skip_no_docker)
    .with_link("https://docs.docker.com/reference/cli/dockerd/")
    .register();

    // TODO: ensure TLS authentication for Docker daemon is used
    // https://docs.docker.com/engine/security/protect-access/
    // TODO: add rule to ensure Docker is up to date (CIS 1.2.2)

    check::Check::new(
        "CNT_011",
        "Ensure docker uses an authorization plugin",
        Severity::High,
        vec!["container", "docker", "ps", "CIS", "server"], // CIS Docker 2.12
        || docker::check_docker_info_ne("/Plugins/Authorization", Value::Null),
        vec![ps::init_proc],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Without an authorization plugin, any user with access to the Docker daemon can execute any Docker command, including privileged operations that could compromise the host. Some attackers use containers to evade security tools like EDR.")
    .with_fix("Start Docker deamon with `--authorization-plugin ...` flag.")
    .with_link("https://docs.docker.com/engine/extend/plugins_authorization/")
    .with_link("https://docs.docker.com/reference/cli/dockerd/")
    .register();

    check::Check::new(
        "CNT_012",
        "Ensure docker containers cannot acquire new privileges",
        Severity::High,
        vec!["container", "docker", "CIS", "server", "workstation"], // CIS Docker 2.14
        || {
            let pointer = "/SecurityOptions";
            if let Some(Value::Array(arr)) = docker::get_docker_info_value(pointer) {
                if arr.iter().any(|v| *v == Value::String("name=no-new-privileges".to_string())) {
                    (check::CheckState::Pass, None)
                } else {
                    (check::CheckState::Fail, None)
                }
            } else {
            (
                check::CheckState::Warning,
                Some(format!("pointer {:?} not found", pointer)),
            )
            }
        },
        vec![ps::init_proc],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Set no-new-privileges by default for new containers.")
    .with_fix("In \"/etc/docker/daemon.json\" add `{\"no-new-privileges\": true}`, or start the daemon with `--no-new-privileges` flag.")
    .with_link("https://docs.docker.com/reference/cli/dockerd/")
    .register();

    check::Check::new(
        "CNT_113",
        "Ensure docker builtin seccomp profile is used",
        Severity::High,
        vec!["container", "docker", "seccomp", "server", "workstation"],
        || {
            let pointer = "/SecurityOptions";
            if let Some(Value::Array(arr)) = docker::get_docker_info_value(pointer) {
                if arr.iter().any(|v| *v == Value::String("name=seccomp,profile=builtin".to_string())) {
                    (check::CheckState::Pass, None)
                } else {
                    (check::CheckState::Fail, None)
                }
            } else {
            (
                check::CheckState::Warning,
                Some(format!("pointer {:?} not found", pointer)),
            )
            }
        },
        vec![ps::init_proc],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Use the builtin seccomp Docker profile to ensure some system calls are restricted within containers.")
    .with_fix("In \"/etc/docker/daemon.json\" remove `{\"seccomp-profile\": \"unconfined\"}`, or start the daemon without `--seccomp-profile unconfined` flag.")
    .with_link("https://docs.docker.com/reference/cli/dockerd/")
    .register();

    check::Check::new(
        "CNT_013",
        "Ensure docker live restore is enabled",
        Severity::Low,
        vec!["container", "docker", "ps", "CIS", "server", "workstation"], // CIS Docker 2.15
        // TODO: or check dockerd config file
        || ps::is_running_with_flag("dockerd", "--live-restore"),
        vec![ps::init_proc],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Live restore keeps containers running during daemon downtime, preventing denial of service during Docker daemon updates or restarts.")
    .with_link("https://docs.docker.com/engine/daemon/live-restore/")
    .with_link("https://docs.docker.com/reference/cli/dockerd/")
    .register();

    check::Check::new(
        "CNT_014",
        "Ensure docker userland proxy is disabled",
        Severity::Medium,
        vec!["container", "docker", "ps", "CIS", "server", "workstation"], // CIS Docker 2.16
        // TODO: or check dockerd config file
        || ps::is_running_with_flag_value("dockerd", "--userlad-proxy", "false"),
        vec![ps::init_proc],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("The userland proxy bypasses iptables filtering rules, which means network-based security policies are not enforced on proxied traffic, weakening network segmentation.")
    .with_fix("In \"/etc/docker/daemon.json\" remove `{\"userlad-proxy\": false}`, or start the daemon without `--userlad-proxy false` flag.")
    .with_link("https://docs.docker.com/reference/cli/dockerd/")
    .register();

    check::Check::new(
        "CNT_015",
        "Ensure docker runs without experimental features",
        Severity::Medium,
        vec!["container", "docker", "ps", "CIS", "server", "workstation"], // CIS Docker 2.18
        // TODO: and check dockerd config file
        || ps::is_running_without_flag("dockerd", "--experimental"),
        vec![ps::init_proc],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Experimental features are not fully tested and may contain security vulnerabilities or unexpected behaviors that could be exploited to compromise the Docker host.")
    .with_link("https://docs.docker.com/reference/cli/dockerd/")
    .register();

    check::Check::new(
        "CNT_016",
        "Ensure docker service file is owned by root",
        Severity::High,
        vec![
            "container",
            "docker",
            "systemd",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 3.1
        || match systemd::get_service_file("docker") {
            Some(path) => base::check_file_owner_id(&path, 0, 0),
            None => (
                check::CheckState::Warning,
                Some("systemd docker service file not found".to_string()),
            ),
        },
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("If the Docker service file is not owned by root, a non-privileged user could modify it to escalate privileges or alter daemon startup behavior.")
    .register();

    check::Check::new(
        "CNT_017",
        "Ensure docker service file permissions 644 are set",
        Severity::High,
        vec![
            "container",
            "docker",
            "systemd",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 3.2
        || match systemd::get_service_file("docker") {
            Some(path) => base::check_file_permission(&path, 0o644),
            None => (
                check::CheckState::Warning,
                Some("systemd docker service file not found".to_string()),
            ),
        },
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Overly permissive service file permissions allow unprivileged users to modify Docker daemon startup parameters, potentially disabling security features or mounting host filesystems.")
    .register();

    check::Check::new(
        "CNT_018",
        "Ensure systemd docker socket file is owned by root",
        Severity::Critical,
        vec![
            "container",
            "docker",
            "systemd",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 3.3
        || match systemd::get_socket_file("docker") {
            Some(path) => base::check_file_owner_id(&path, 0, 0),
            None => (
                check::CheckState::Warning,
                Some("systemd docker socket file not found".to_string()),
            ),
        },
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("The Docker socket grants full control over the Docker daemon. If not owned by root, an attacker could modify it to intercept or redirect Docker API requests.")
    .register();

    check::Check::new(
        "CNT_019",
        "Ensure systemd docker socket file permissions 644 are set",
        Severity::Critical,
        vec![
            "container",
            "docker",
            "systemd",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 3.4
        || match systemd::get_socket_file("docker") {
            Some(path) => base::check_file_permission(&path, 0o644),
            None => (
                check::CheckState::Warning,
                Some("systemd docker socket file not found".to_string()),
            ),
        },
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Overly permissive socket file permissions could allow unauthorized users to communicate with the Docker daemon, which is equivalent to root access on the host.")
    .register();

    // TODO: allow missing
    check::Check::new(
        "CNT_020",
        "Ensure docker etc directory is owned by root",
        Severity::High,
        vec!["container", "docker", "CIS", "server", "workstation"], // CIS Docker 3.5
        || base::check_dir_owner_id("/etc/docker", 0, 0),
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("The /etc/docker directory contains sensitive configuration including TLS certificates. Non-root ownership could allow an attacker to tamper with daemon configuration or steal credentials.")
    .register();

    // TODO: allow missing
    check::Check::new(
        "CNT_021",
        "Ensure docker etc directory permissions is 755",
        Severity::High,
        vec!["container", "docker", "CIS", "server", "workstation"], // CIS Docker 3.6
        || base::check_dir_permission("/etc/docker", 0o755),
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Restrictive directory permissions prevent unauthorized users from reading or modifying Docker configuration files, TLS keys, and other sensitive data stored in /etc/docker.")
    .register();

    // TODO: allow missing
    check::Check::new(
        "CNT_022",
        "Ensure docker daemon.json config file is owned by root",
        Severity::High,
        vec!["container", "docker", "CIS", "server", "workstation"], // CIS Docker 3.17
        || base::check_file_owner_id("/etc/docker/daemon.json", 0, 0),
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("The daemon.json file controls Docker daemon behavior including security settings. Non-root ownership allows unauthorized modification of daemon configuration to weaken security controls.")
    .register();

    // TODO: allow missing
    check::Check::new(
        "CNT_023",
        "Ensure docker daemon.json config file permissions is 644",
        Severity::High,
        vec!["container", "docker", "CIS", "server", "workstation"], // CIS Docker 3.18
        || base::check_file_permission("/etc/docker/daemon.json", 0o644),
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Overly permissive daemon.json permissions allow unprivileged users to alter Docker daemon configuration, potentially enabling insecure registries or disabling security features.")
    .register();

    // TODO: allow missing
    check::Check::new(
        "CNT_024",
        "Ensure default docker config file is owned by root",
        Severity::High,
        vec!["container", "docker", "CIS", "server", "workstation"], // CIS Docker 3.19
        || base::check_file_owner_id("/etc/default/docker", 0, 0),
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("The /etc/default/docker file sets environment variables and options for the Docker daemon. Non-root ownership allows unprivileged users to inject malicious daemon startup options.")
    .register();

    // TODO: allow missing
    check::Check::new(
        "CNT_025",
        "Ensure default docker config file permissions is 644",
        Severity::High,
        vec!["container", "docker", "CIS", "server", "workstation"], // CIS Docker 3.20
        || base::check_file_permission("/etc/default/docker", 0o644),
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Overly permissive file permissions on the default Docker config allow local users to modify daemon startup parameters, potentially disabling security protections.")
    .register();

    // TODO: only if on RHEL/Centos
    check::Check::new(
        "CNT_026",
        "Ensure sysconfig docker config file is owned by root",
        Severity::High,
        vec!["container", "docker", "CIS", "server", "workstation"], // CIS Docker 3.21
        || base::check_file_owner_id("/etc/sysconfig/docker", 0, 0),
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("The sysconfig docker file configures daemon options on RHEL/CentOS systems. Non-root ownership could allow an attacker to alter daemon behavior at next restart.")
    .register();

    // TODO: only if on RHEL/Centos
    check::Check::new(
        "CNT_027",
        "Ensure sysconfig docker config file permissions is 644",
        Severity::High,
        vec!["container", "docker", "CIS", "server", "workstation"], // CIS Docker 3.22
        || base::check_file_permission("/etc/sysconfig/docker", 0o644),
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Overly permissive sysconfig file permissions allow local users to modify Docker daemon options on RHEL/CentOS, potentially introducing insecure configurations.")
    .register();

    check::Check::new(
        "CNT_028",
        "Ensure docker containerd socket file is owned by root",
        Severity::Critical,
        vec!["container", "docker", "CIS", "server", "workstation"], // CIS Docker 3.23
        || base::check_socket_owner_id("/run/containerd/containerd.sock", 0, 0),
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("The containerd socket provides direct access to the container runtime. Non-root ownership could allow unauthorized users to manipulate containers or escape to the host.")
    .register();

    check::Check::new(
        "CNT_029",
        "Ensure docker containerd socket file permissions is 660",
        Severity::Critical,
        vec!["container", "docker", "CIS", "server", "workstation"], // CIS Docker 3.24
        || base::check_socket_permission("/run/containerd/containerd.sock", 0o660),
        vec![],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Overly permissive containerd socket permissions grant unauthorized users access to the container runtime, which can be leveraged for privilege escalation to root.")
    .register();

    check::Check::new(
        "CNT_030",
        "Ensure docker swarm is disabled if not needed",
        Severity::Medium,
        vec!["container", "docker", "CIS", "server", "workstation"], // CIS Docker 5.1
        || docker::check_docker_info("/Swarm/ControlAvailable", Value::Bool(false)),
        vec![docker::init_docker_info],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Docker Swarm mode exposes additional attack surface including a distributed key-value store and overlay networking. Disabling it when not needed reduces the risk of cluster-level compromise.")
    .register();

    check::Check::new(
        "CNT_031",
        "Ensure docker group is empty",
        Severity::Critical,
        vec![
            "container",
            "docker",
            "group",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 1.1.2
        || group::no_members("docker"),
        vec![group::init_group],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Membership in the docker group grants the ability to interact with the Docker socket, which effectively provides root-equivalent access to the host system.")
    .register();

    check::Check::new(
        "CNT_100",
        "Ensure audit rule for docker daemon is present",
        Severity::Medium,
        vec![
            "container",
            "docker",
            "audit",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 1.1.3
        || audit::check_audit_rule("-w /usr/bin/dockerd -k docker"),
        vec![audit::init_audit_rules],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Auditing the Docker daemon binary ensures all invocations are logged, enabling detection of unauthorized Docker usage or tampering with the daemon executable.")
    .register();

    check::Check::new(
        "CNT_101",
        "Ensure audit rule for docker run files and directories is present",
        Severity::Medium,
        vec![
            "container",
            "docker",
            "audit",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 1.1.4
        || audit::check_audit_rule("-a exit,always -F path=/run/containerd -F perm=war -k docker"),
        vec![audit::init_audit_rules],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Auditing the containerd runtime directory detects unauthorized modifications to runtime state, which could indicate container escape attempts or runtime tampering.")
    .register();

    check::Check::new(
        "CNT_102",
        "Ensure audit rule for docker var lib files and directories is present",
        Severity::Medium,
        vec![
            "container",
            "docker",
            "audit",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 1.1.5
        || audit::check_audit_rule("-w /var/lib/docker -k docker"),
        vec![audit::init_audit_rules],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("The /var/lib/docker directory contains container images, volumes, and layer data. Auditing it detects unauthorized access or modification of container storage.")
    .register();

    check::Check::new(
        "CNT_103",
        "Ensure audit rule for docker etc files and directories is present",
        Severity::Medium,
        vec![
            "container",
            "docker",
            "audit",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 1.1.6
        || audit::check_audit_rule("-w /etc/docker -k docker"),
        vec![audit::init_audit_rules],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Auditing the /etc/docker directory detects unauthorized changes to Docker configuration files and TLS certificates, which could be used to weaken daemon security.")
    .register();

    // TODO: add CIS Docker 1.1.7 to 1.1.9
    check::Check::new(
        "CNT_107",
        "Ensure audit rule for docker etc default file is present",
        Severity::Medium,
        vec![
            "container",
            "docker",
            "audit",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 1.1.10
        || audit::check_audit_rule("-w /etc/default/docker -k docker"),
        vec![audit::init_audit_rules],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Auditing the /etc/default/docker file detects unauthorized changes to Docker daemon environment variables and startup options that could weaken security.")
    .register();

    check::Check::new(
        "CNT_108",
        "Ensure audit rule for docker etc daemon file is present",
        Severity::Medium,
        vec![
            "container",
            "docker",
            "audit",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 1.1.11
        || audit::check_audit_rule("-w /etc/docker/daemon.json -k docker"),
        vec![audit::init_audit_rules],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Auditing the daemon.json configuration file provides a trail of any changes to Docker daemon settings, enabling detection of unauthorized security configuration modifications.")
    .register();

    check::Check::new(
        "CNT_109",
        "Ensure audit rule for docker etc containerd config file is present",
        Severity::Medium,
        vec![
            "container",
            "docker",
            "audit",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 1.1.12
        || audit::check_audit_rule("-w /etc/containerd/config.toml -k docker"),
        vec![audit::init_audit_rules],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Auditing the containerd configuration file detects unauthorized changes to the container runtime, which could disable security features like seccomp or AppArmor profiles.")
    .register();

    check::Check::new(
        "CNT_110",
        "Ensure audit rule for docker sysconfig file is present",
        Severity::Medium,
        vec![
            "container",
            "docker",
            "audit",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 1.1.13
        || audit::check_audit_rule("-w /etc/sysconfig/docker -k docker"),
        vec![audit::init_audit_rules],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Auditing the sysconfig docker file detects unauthorized changes to Docker daemon options on RHEL/CentOS systems, which could introduce insecure configurations.")
    .register();

    check::Check::new(
        "CNT_111",
        "Ensure audit rule for docker containerd bin is present",
        Severity::Medium,
        vec![
            "container",
            "docker",
            "audit",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 1.1.14
        || audit::check_audit_rule("-w /usr/bin/containerd -k docker"),
        vec![audit::init_audit_rules],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Auditing the containerd binary detects unauthorized replacement or modification of the container runtime, which could be used to bypass container isolation.")
    .register();

    check::Check::new(
        "CNT_112",
        "Ensure audit rule for docker runc bin is present",
        Severity::Medium,
        vec![
            "container",
            "docker",
            "audit",
            "CIS",
            "server",
            "workstation",
        ], // CIS Docker 1.1.18
        || audit::check_audit_rule("-w /usr/bin/runc -k docker"),
        vec![audit::init_audit_rules],
    )
    .skip_when(docker::skip_no_docker)
    .with_description("Auditing the runc binary detects unauthorized replacement or modification of the low-level container runtime, which has been the target of critical container escape vulnerabilities like CVE-2019-5736.")
    .register();

    // TODO: what is this rule?
    // check::Check::new(
    //     "CNT_113",
    //     "Ensure audit rule for docker containerd shim bin is present",
    //     vec!["container", "docker", "audit", "CIS", "server", "workstation"], // CIS Docker 1.1.15
    //     || audit::check_audit_rule("-w /usr/bin/containerd-shim -k docker"),
    //     vec![audit::init_audit_rules],
    // ).register();
    // check::Check::new(
    //     "CNT_114",
    //     "Ensure audit rule for docker containerd shim v1 bin is present",
    //     vec!["container", "docker", "audit", "CIS", "server", "workstation"], // CIS Docker 1.1.16
    //     || audit::check_audit_rule("-w /usr/bin/containerd-shim-runc-v1 -k docker"),
    //     vec![audit::init_audit_rules],
    // ).register();
    // check::Check::new(
    //     "CNT_115",
    //     "Ensure audit rule for docker containerd shim v2 bin is present",
    //     vec!["container", "docker", "audit", "CIS", "server", "workstation"], // CIS Docker 1.1.17
    //     || audit::check_audit_rule("-w /usr/bin/containerd-shim-runc-v2 -k docker"),
    //     vec![audit::init_audit_rules],
    // ).register();
}
