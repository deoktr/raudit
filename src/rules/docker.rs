use crate::*;

pub fn add_checks() {
    check::add_check(
        "CNT_001",
        "Ensure docker containers are not started with \"--privileged\" flag",
        vec!["container", "docker"],
        docker::docker_not_privileged,
        vec![docker::init_containers_inspect],
    );
    check::add_check(
        "CNT_002",
        "Ensure docker containers capabilities are dopped",
        vec!["container", "docker"],
        docker::docker_cap_drop,
        vec![docker::init_containers_inspect],
    );
    check::add_check(
        "CNT_003",
        "Ensure docker containers are running with a user",
        vec!["container", "docker"],
        docker::docker_container_user,
        vec![docker::init_containers_inspect],
    );
    // TODO: get mount point from Docker configuration "DockerRootDir"
    check::add_check(
        "CNT_004",
        "Ensure docker mount point \"/var/lib/docker\" exist",
        vec!["container", "docker", "mount", "CIS"], // CIS Docker 1.1.1
        // TODO: get path by running: docker info -f '{{ .DockerRootDir }}'
        || mount::check_mount_present("/var/lib/docker"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "CNT_005",
        "Ensure docker network traffic is restricted between containers on the default bridge",
        vec!["container", "docker", "ps", "CIS"], // CIS Docker 2.2
        || ps::is_running_with_flag("dockerd", "--icc"),
        vec![ps::init_proc],
    );
    check::add_check(
        "CNT_006",
        "Ensure docker logging level is set info",
        vec!["container", "docker", "ps", "CIS"], // CIS Docker 2.3
        // TODO: can also be short '-l'
        || ps::is_running_with_flag_value("dockerd", "--log-level", "info"),
        vec![ps::init_proc],
    );
    // TODO: add helper function
    // check::add_check(
    //     "CNT_007",
    //     "Ensure docker is allowed to make changes to iptables",
    //     vec!["container", "docker", "ps", "CIS"], // CIS Docker 2.4
    //     || ps::is_running_without_flag_value("dockerd", "--iptables", "false"),
    //     vec![ps::init_proc],
    // );
    check::add_check(
        "CNT_008",
        "Ensure docker does not allow insecure registry",
        vec!["container", "docker", "ps", "CIS"], // CIS Docker 2.5
        || ps::is_running_without_flag("dockerd", "--insecure-registry"),
        vec![ps::init_proc],
    );
    check::add_check(
        "CNT_009",
        "Ensure docker storage driver is aufs",
        vec!["container", "docker", "ps", "CIS"], // CIS Docker 2.6
        // TODO: can also be short '-s'
        || ps::is_running_with_flag_value("dockerd", "--storage-driver", "aufs"),
        vec![ps::init_proc],
    );
    // check::add_check(
    //     "CNT_010",
    //     "Ensure docker storage options dm.basesize are not set",
    //     vec!["container", "docker", "ps", "CIS"], // CIS Docker 2.10
    //     // TODO: only check fo dm-basesize
    //     || ps::is_running_without_flag("dockerd", "--storage-opt"),
    //     vec![ps::init_proc],
    // );
    // TODO: ensure TLS authentication for Docker daemon is used
    // TODO: add rule to ensure Docker is up to date (CIS 1.2.2)
    check::add_check(
        "CNT_011",
        "Ensure docker uses an authorization plugin",
        vec!["container", "docker", "ps", "CIS"], // CIS Docker 2.12
        || ps::is_running_with_flag("dockerd", "--authorization-plugin"),
        vec![ps::init_proc],
    );
    check::add_check(
        "CNT_012",
        "Ensure docker cannot acquire new privileges",
        vec!["container", "docker", "ps", "CIS"], // CIS Docker 2.14
        || ps::is_running_with_flag("dockerd", "--no-new-privileges"),
        vec![ps::init_proc],
    );
    check::add_check(
        "CNT_013",
        "Ensure docker live restore is enabled",
        vec!["container", "docker", "ps", "CIS"], // CIS Docker 2.15
        || ps::is_running_with_flag("dockerd", "--live-restore"),
        vec![ps::init_proc],
    );
    check::add_check(
        "CNT_014",
        "Ensure docker userland proxy is disabled",
        vec!["container", "docker", "ps", "CIS"], // CIS Docker 2.16
        || ps::is_running_with_flag_value("dockerd", "--userlad-proxy", "false"),
        vec![ps::init_proc],
    );
    check::add_check(
        "CNT_015",
        "Ensure docker runs without experimental features",
        vec!["container", "docker", "ps", "CIS"], // CIS Docker 2.18
        || ps::is_running_without_flag("dockerd", "--experimental"),
        vec![ps::init_proc],
    );
    check::add_check(
        "CNT_016",
        "Ensure docker service file is owned by root",
        vec!["container", "docker", "systemd", "CIS"], // CIS Docker 3.1
        || match systemd::get_service_file("docker") {
            Some(path) => base::check_file_owner_id(&path, 0, 0),
            None => (
                check::CheckState::Error,
                Some("systemd docker file not found".to_string()),
            ),
        },
        vec![],
    );
    check::add_check(
        "CNT_017",
        "Ensure docker service file permissions 644 are set",
        vec!["container", "docker", "systemd", "CIS"], // CIS Docker 3.2
        || match systemd::get_service_file("docker") {
            Some(path) => base::check_file_permission(&path, 0o644),
            None => (
                check::CheckState::Error,
                Some("systemd docker file not found".to_string()),
            ),
        },
        vec![],
    );
    check::add_check(
        "CNT_018",
        "Ensure docker socket file is owned by root",
        vec!["container", "docker", "systemd", "CIS"], // CIS Docker 3.3
        || match systemd::get_socket_file("docker") {
            Some(path) => base::check_file_owner_id(&path, 0, 0),
            None => (
                check::CheckState::Error,
                Some("systemd docker file not found".to_string()),
            ),
        },
        vec![],
    );
    check::add_check(
        "CNT_019",
        "Ensure docker socket file permissions 644 are set",
        vec!["container", "docker", "systemd", "CIS"], // CIS Docker 3.4
        || match systemd::get_socket_file("docker") {
            Some(path) => base::check_file_permission(&path, 0o644),
            None => (
                check::CheckState::Error,
                Some("systemd docker file not found".to_string()),
            ),
        },
        vec![],
    );
    // TODO: allow missing
    check::add_check(
        "CNT_020",
        "Ensure docker etc directory is owned by root",
        vec!["container", "docker", "CIS"], // CIS Docker 3.5
        || base::check_dir_owner_id("/etc/docker", 0, 0),
        vec![],
    );
    // TODO: allow missing
    check::add_check(
        "CNT_021",
        "Ensure docker etc directory permissions is 755",
        vec!["container", "docker", "CIS"], // CIS Docker 3.6
        || base::check_dir_permission("/etc/docker", 0o755),
        vec![],
    );
    // TODO: allow missing
    check::add_check(
        "CNT_022",
        "Ensure docker daemon.json config file is owned by root",
        vec!["container", "docker", "CIS"], // CIS Docker 3.17
        || base::check_file_owner_id("/etc/docker/daemon.json", 0, 0),
        vec![],
    );
    // TODO: allow missing
    check::add_check(
        "CNT_023",
        "Ensure docker daemon.json config file permissions is 644",
        vec!["container", "docker", "CIS"], // CIS Docker 3.18
        || base::check_file_permission("/etc/docker/daemon.json", 0o644),
        vec![],
    );
    // TODO: allow missing
    check::add_check(
        "CNT_024",
        "Ensure default docker config file is owned by root",
        vec!["container", "docker", "CIS"], // CIS Docker 3.19
        || base::check_file_owner_id("/etc/default/docker", 0, 0),
        vec![],
    );
    // TODO: allow missing
    check::add_check(
        "CNT_025",
        "Ensure default docker config file permissions is 644",
        vec!["container", "docker", "CIS"], // CIS Docker 3.20
        || base::check_file_permission("/etc/default/docker", 0o644),
        vec![],
    );
    // TODO: only if on RHEL/Centos
    check::add_check(
        "CNT_026",
        "Ensure sysconfig docker config file is owned by root",
        vec!["container", "docker", "CIS"], // CIS Docker 3.21
        || base::check_file_owner_id("/etc/sysconfig/docker", 0, 0),
        vec![],
    );
    // TODO: only if on RHEL/Centos
    check::add_check(
        "CNT_027",
        "Ensure sysconfig docker config file permissions is 644",
        vec!["container", "docker", "CIS"], // CIS Docker 3.22
        || base::check_file_permission("/etc/sysconfig/docker", 0o644),
        vec![],
    );
    check::add_check(
        "CNT_028",
        "Ensure docker containerd socket file is owned by root",
        vec!["container", "docker", "CIS"], // CIS Docker 3.23
        || base::check_file_owner_id("/run/containerd/containerd.sock", 0, 0),
        vec![],
    );
    check::add_check(
        "CNT_029",
        "Ensure docker containerd socket file permissions is 660",
        vec!["container", "docker", "CIS"], // CIS Docker 3.24
        || base::check_file_permission("/run/containerd/containerd.sock", 0o660),
        vec![],
    );
    check::add_check(
        "CNT_030",
        "Ensure docker swarm is disabled if not needed",
        vec!["container", "docker", "CIS"], // CIS Docker 5.1
        || docker::check_docker_info("/Swarm/ControlAvailable", serde_json::Value::Bool(false)),
        vec![docker::init_docker_info],
    );
    // https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/abusing-docker-socket-for-privilege-escalation.html
    check::add_check(
        "CNT_031",
        "Ensure docker group is empty",
        vec!["container", "docker", "group", "CIS"], // CIS Docker 1.1.2
        || group::no_members("docker"),
        vec![group::init_group],
    );
    check::add_check(
        "CNT_100",
        "Ensure audit rule for docker daemon is present",
        vec!["container", "docker", "audit", "CIS"], // CIS Docker 1.1.3
        || audit::check_audit_rule("-w /usr/bin/dockerd -k docker"),
        vec![audit::init_audit_rules],
    );
    check::add_check(
        "CNT_101",
        "Ensure audit rule for docker run files and directories is present",
        vec!["container", "docker", "audit", "CIS"], // CIS Docker 1.1.4
        || audit::check_audit_rule("-a exit,always -F path=/run/containerd -F perm=war -k docker"),
        vec![audit::init_audit_rules],
    );
    check::add_check(
        "CNT_102",
        "Ensure audit rule for docker var lib files and directories is present",
        vec!["container", "docker", "audit", "CIS"], // CIS Docker 1.1.5
        || audit::check_audit_rule("-w /var/lib/docker -k docker"),
        vec![audit::init_audit_rules],
    );
    check::add_check(
        "CNT_103",
        "Ensure audit rule for docker etc files and directories is present",
        vec!["container", "docker", "audit", "CIS"], // CIS Docker 1.1.6
        || audit::check_audit_rule("-w /etc/docker -k docker"),
        vec![audit::init_audit_rules],
    );
    // TODO: add CIS Docker 1.1.7 to 1.1.9
    check::add_check(
        "CNT_107",
        "Ensure audit rule for docker etc default file is present",
        vec!["container", "docker", "audit", "CIS"], // CIS Docker 1.1.10
        || audit::check_audit_rule("-w /etc/default/docker -k docker"),
        vec![audit::init_audit_rules],
    );
    check::add_check(
        "CNT_108",
        "Ensure audit rule for docker etc daemon file is present",
        vec!["container", "docker", "audit", "CIS"], // CIS Docker 1.1.11
        || audit::check_audit_rule("-w /etc/docker/daemon.json -k docker"),
        vec![audit::init_audit_rules],
    );
    check::add_check(
        "CNT_109",
        "Ensure audit rule for docker etc containerd config file is present",
        vec!["container", "docker", "audit", "CIS"], // CIS Docker 1.1.12
        || audit::check_audit_rule("-w /etc/containerd/config.toml -k docker"),
        vec![audit::init_audit_rules],
    );
    check::add_check(
        "CNT_110",
        "Ensure audit rule for docker sysconfig file is present",
        vec!["container", "docker", "audit", "CIS"], // CIS Docker 1.1.13
        || audit::check_audit_rule("-w /etc/sysconfig/docker -k docker"),
        vec![audit::init_audit_rules],
    );
    check::add_check(
        "CNT_111",
        "Ensure audit rule for docker containerd bin is present",
        vec!["container", "docker", "audit", "CIS"], // CIS Docker 1.1.14
        || audit::check_audit_rule("-w /usr/bin/containerd -k docker"),
        vec![audit::init_audit_rules],
    );
    check::add_check(
        "CNT_112",
        "Ensure audit rule for docker runc bin is present",
        vec!["container", "docker", "audit", "CIS"], // CIS Docker 1.1.18
        || audit::check_audit_rule("-w /usr/bin/runc -k docker"),
        vec![audit::init_audit_rules],
    );
    // TODO: what is this rule?
    // check::add_check(
    //     "CNT_113",
    //     "Ensure audit rule for docker containerd shim bin is present",
    //     vec!["container", "docker", "audit", "CIS"], // CIS Docker 1.1.15
    //     || audit::check_audit_rule("-w /usr/bin/containerd-shim -k docker"),
    //     vec![audit::init_audit_rules],
    // );
    // check::add_check(
    //     "CNT_114",
    //     "Ensure audit rule for docker containerd shim v1 bin is present",
    //     vec!["container", "docker", "audit", "CIS"], // CIS Docker 1.1.16
    //     || audit::check_audit_rule("-w /usr/bin/containerd-shim-runc-v1 -k docker"),
    //     vec![audit::init_audit_rules],
    // );
    // check::add_check(
    //     "CNT_115",
    //     "Ensure audit rule for docker containerd shim v2 bin is present",
    //     vec!["container", "docker", "audit", "CIS"], // CIS Docker 1.1.17
    //     || audit::check_audit_rule("-w /usr/bin/containerd-shim-runc-v2 -k docker"),
    //     vec![audit::init_audit_rules],
    // );
}
