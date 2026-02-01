// sources:
// - tails: https://tails.net/contribute/design/kernel_hardening/

use crate::*;

pub fn add_checks() {
    // Note disabling IPv6 via 'net.ipv6.conf.all.disable_ipv6' is not included
    // as a rule even if it's a CIS rule, this is because it does not increase
    // the security
    sysctl::add_sysctl_check!(
        "SYS_001",
        vec!["sysctl", "server", "workstation", "tails"],
        "kernel.kptr_restrict",
        // TODO: allow for 1 as well
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_002",
        vec!["sysctl", "server", "workstation"],
        "kernel.ftrace_enabled",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_003",
        vec!["sysctl", "CIS", "server", "workstation"],
        "kernel.randomize_va_space",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_004",
        vec!["sysctl", "server", "workstation"],
        "kernel.dmesg_restrict",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_005",
        vec!["sysctl", "server", "workstation"],
        "kernel.printk",
        "3\t3\t3\t3"
    );
    sysctl::add_sysctl_check!(
        "SYS_006",
        vec!["sysctl", "server", "workstation"],
        "kernel.perf_cpu_time_max_percent",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_007",
        vec!["sysctl", "server", "workstation"],
        "kernel.perf_event_max_sample_rate",
        1
    );
    // 2 or 3
    check::add_check(
        "SYS_008",
        "Ensure sysctl \"kernel.perf_event_paranoid\" >= 2",
        vec!["sysctl", "server", "workstation"],
        || {
            const VAL: i32 = 2;
            match sysctl::get_sysctl_i32_value("kernel.perf_event_paranoid") {
                Ok(value) => {
                    if value >= VAL {
                        (check::CheckState::Passed, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failed,
                            Some(format!("{} > {}", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    );
    sysctl::add_sysctl_check!(
        "SYS_009",
        vec!["sysctl", "server", "workstation"],
        "kernel.sysrq",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_010",
        vec!["sysctl", "server", "workstation", "tails"],
        "kernel.kexec_load_disabled",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_011",
        vec!["sysctl", "bpf", "server", "workstation"],
        "kernel.unprivileged_bpf_disabled",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_012",
        vec!["sysctl", "bpf", "server", "workstation", "tails"],
        "net.core.bpf_jit_harden",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_013",
        vec!["sysctl", "server", "workstation"],
        "kernel.panic_on_oops",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_014",
        vec!["sysctl", "server", "workstation"],
        "kernel.panic",
        "-1"
    );
    sysctl::add_sysctl_check!(
        "SYS_015",
        vec!["sysctl", "server", "workstation"],
        "kernel.modules_disabled",
        1
    );
    // FIXME: only available on Debian, create custom rule to check if OS is debian, else ignore
    sysctl::add_sysctl_check!(
        "SYS_016",
        vec!["sysctl", "server", "workstation"],
        "kernel.unprivileged_userns_clone",
        0
    );
    // check::add_check(
    //     "SYS_016",
    //     "Ensure sysctl 'kernel.unprivileged_userns_clone' == 0",
    //     vec!["sysctl", "server", "workstation"],
    //     || sysctl::get_ssyctl_wrapper("kernel.unprivileged_userns_clone", 0),
    //     vec![sysctl::init_sysctl_config, os::init_os],
    // );

    // 2 or 3, CIS recommends 1
    check::add_check(
        "SYS_017",
        "Ensure sysctl \"kernel.yama.ptrace_scope\" >= 1",
        vec!["sysctl", "server", "workstation"],
        || {
            const VAL: i32 = 1;
            match sysctl::get_sysctl_i32_value("kernel.yama.ptrace_scope") {
                Ok(value) => {
                    if value >= VAL {
                        (check::CheckState::Passed, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failed,
                            Some(format!("{} > {}", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    );
    sysctl::add_sysctl_check!(
        "SYS_018",
        vec!["sysctl", "server", "workstation"],
        "kernel.io_uring_disabled",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_019",
        vec!["sysctl", "server", "workstation"],
        "kernel.core_pattern",
        "|/bin/false"
    );
    sysctl::add_sysctl_check!(
        "SYS_020",
        vec!["sysctl", "server", "workstation"],
        "kernel.core_uses_pid",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_021",
        vec!["sysctl", "server", "workstation"],
        "vm.unprivileged_userfaultfd",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_022",
        vec!["sysctl", "server", "workstation", "tails"],
        "vm.mmap_rnd_bits",
        32
    );
    sysctl::add_sysctl_check!(
        "SYS_023",
        vec!["sysctl", "server", "workstation", "tails"],
        "vm.mmap_rnd_compat_bits",
        16
    );
    sysctl::add_sysctl_check!(
        "SYS_024",
        vec!["sysctl", "server", "workstation"],
        "vm.mmap_min_addr",
        65536
    );
    sysctl::add_sysctl_check!(
        "SYS_025",
        vec!["sysctl", "server", "workstation"],
        "dev.tty.ldisc_autoload",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_026",
        vec!["sysctl", "server", "workstation"],
        "dev.tty.legacy_tiocsti",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_027",
        vec!["sysctl", "server", "workstation"],
        "vm.max_map_count",
        1048576
    );
    sysctl::add_sysctl_check!(
        "SYS_028",
        vec!["sysctl", "server", "workstation"],
        "vm.swappiness",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_029",
        vec!["sysctl", "fs", "CIS", "server", "workstation"],
        "fs.suid_dumpable",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_030",
        vec!["sysctl", "fs", "server", "workstation"],
        "fs.protected_fifos",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_031",
        vec!["sysctl", "fs", "server", "workstation"],
        "fs.protected_regular",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_032",
        vec!["sysctl", "fs", "server", "workstation"],
        "fs.protected_symlinks",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_033",
        vec!["sysctl", "fs", "server", "workstation"],
        "fs.protected_hardlinks",
        1
    );
    check::add_check(
        "SYS_034",
        "Ensure sysctl \"fs.binfmt_misc.status\" = 0",
        vec!["sysctl", "fs", "server", "workstation"],
        || {
            let (status, message) = sysctl::check_sysctl("fs.binfmt_misc.status", 0);
            // ignore if not present
            if status == check::CheckState::Error {
                (check::CheckState::Passed, None)
            } else {
                (status, message)
            }
        },
        vec![sysctl::init_sysctl_config],
    );
    sysctl::add_sysctl_check!(
        "SYS_035",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.ip_forward",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_036",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.accept_source_route",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_037",
        vec!["sysctl", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.default.accept_source_route",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_038",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.accept_source_route",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_039",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.default.accept_source_route",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_040",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.accept_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_041",
        vec!["sysctl", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.default.accept_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_042",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.secure_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_043",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.default.secure_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_044",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.send_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_045",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.default.send_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_046",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.accept_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_047",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.default.accept_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_050",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.icmp_echo_ignore_all",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_051",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.icmp.echo_ignore_all",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_052",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.icmp_echo_ignore_broadcasts",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_053",
        vec!["sysctl", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.all.rp_filter",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_054",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.default.rp_filter",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_055",
        vec!["sysctl", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.icmp_ignore_bogus_error_responses",
        1
    );
    check::add_check(
        "SYS_056",
        "Ensure sysctl \"net.ipv4.icmp_ratelimit\" <= 100",
        vec!["sysctl", "server", "workstation"],
        || {
            const VAL: i32 = 100;
            match sysctl::get_sysctl_i32_value("net.ipv4.icmp_ratelimit") {
                Ok(value) => {
                    if value <= VAL {
                        (check::CheckState::Passed, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failed,
                            Some(format!("{} > {}", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    );
    sysctl::add_sysctl_check!(
        "SYS_057",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.icmp_ratemask",
        88089
    );
    sysctl::add_sysctl_check!(
        "SYS_058",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.tcp_syncookies",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_059",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.accept_local",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_060",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.shared_media",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_061",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.default.shared_media",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_062",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.arp_filter",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_063",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.arp_ignore",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_064",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.default.arp_ignore",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_065",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.default.arp_announce",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_066",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.arp_announce",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_067",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.route_localnet",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_068",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.drop_gratuitous_arp",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_069",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.ip_local_port_range",
        "32768\t65535"
    );
    sysctl::add_sysctl_check!(
        "SYS_070",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.tcp_rfc1337",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_071",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.forwarding",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_072",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.forwarding",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_073",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.accept_ra",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_074",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.default.accept_ra",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_075",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.tcp_timestamps",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_076",
        vec!["sysctl", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.all.log_martians",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_077",
        vec!["sysctl", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.default.log_martians",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_078",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.all.router_solicitations",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_079",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.router_solicitations",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_080",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.all.accept_ra_rtr_pref",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_081",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.accept_ra_rtr_pref",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_082",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.all.accept_ra_defrtr",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_083",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.accept_ra_defrtr",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_084",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.all.autoconf",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_085",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.autoconf",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_086",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.all.max_addresses",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_087",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.max_addresses",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_088",
        vec!["sysctl", "bpf", "paranoid", "server", "workstation"],
        "net.core.bpf_jit_enable",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_089",
        vec!["sysctl", "paranoid", "server", "workstation"],
        "net.ipv4.tcp_sack",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_090",
        vec!["sysctl", "paranoid", "server", "workstation"],
        "net.ipv4.tcp_dsack",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_091",
        vec!["sysctl", "paranoid", "server", "workstation"],
        "net.ipv4.tcp_fack",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_092",
        vec!["sysctl", "paranoid", "server", "workstation"],
        "net.ipv6.conf.all.use_tempaddr",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_093",
        vec!["sysctl", "paranoid", "server", "workstation"],
        "net.ipv6.conf.default.use_tempaddr",
        2
    );
    // may break the upower daemon in Ubuntu
    check::add_check(
        "SYS_094",
        "Ensure sysctl \"user.max_user_namespaces\" <= 31231",
        vec!["sysctl", "server", "workstation"],
        || {
            const VAL: i32 = 31231;
            match sysctl::get_sysctl_i32_value("user.max_user_namespaces") {
                Ok(value) => {
                    if value <= VAL {
                        (check::CheckState::Passed, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failed,
                            Some(format!("{} > {}", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    );
    check::add_check(
        "SYS_095",
        "Ensure sysctl \"kernel.warn_limit\" <= 100",
        vec!["sysctl", "server", "workstation"],
        || {
            const VAL: i32 = 100;
            match sysctl::get_sysctl_i32_value("kernel.warn_limit") {
                Ok(value) => {
                    if value <= VAL {
                        (check::CheckState::Passed, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failed,
                            Some(format!("{} > {}", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    );
    check::add_check(
        "SYS_096",
        "Ensure sysctl \"kernel.oops_limit\" <= 100",
        vec!["sysctl", "server", "workstation"],
        || {
            const VAL: i32 = 100;
            match sysctl::get_sysctl_i32_value("kernel.oops_limit") {
                Ok(value) => {
                    if value <= VAL {
                        (check::CheckState::Passed, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failed,
                            Some(format!("{} > {}", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    );
    sysctl::add_sysctl_check!(
        "SYS_097",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.tcp_synack_retries",
        5
    );
    sysctl::add_sysctl_check!(
        "SYS_098",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.icmp.echo_ignore_anycast",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_099",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.icmp.echo_ignore_multicast",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_100",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.forwarding",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_101",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.default.forwarding",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_102",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.mc_forwarding",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_103",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.default.mc_forwarding",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_104",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.all.mc_forwarding",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_105",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.mc_forwarding",
        0
    );
}
