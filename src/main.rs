/*
 * rAudit, a Linux security auditing toolkit
 * Copyright (C) 2024 - 2025  deoktr
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

mod apparmor;
mod audit;
mod base;
mod check;
mod clamav;
mod config;
mod consts;
mod docker;
mod gdm;
mod group;
mod grub;
mod kernel;
mod login_defs;
mod modprobe;
mod mount;
mod pam;
mod ps;
mod sshd;
mod sudo;
mod sysctl;
mod systemd;
mod users;
mod utils;

use clap::Parser;
use std::time::Instant;

/// Audit Linux systems security configurations
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Comma-separated list of tags to filter
    #[arg(long, value_delimiter = ',')]
    tags: Vec<String>,

    // TODO: add exclusion for both tags and IDs
    // TODO: make sure the priority between the tags to include and to exclude
    // is correct, make sense, and is easy to use
    /// Comma-separated list of tags to exclude
    // #[arg(long, value_delimiter = ',', default_values = ["paranoid"])]
    // exclude_tags: Vec<String>,

    /// Comma-separated list of ID prefixes to filter
    #[arg(long, value_delimiter = ',')]
    filters: Vec<String>,

    /// Disable multi-threading parallelization
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_parallelization: bool,

    /// Disable print of individual checks
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_print_checks: bool,

    /// Disable print of successful checks
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_print_success: bool,

    /// Disable print of stats
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_stats: bool,

    /// Disable colored output
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_colors: bool,

    /// Disable timer
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_time: bool,
}

fn main() {
    let now = Instant::now();

    let args = Cli::parse();

    config::set_colored_output(!args.no_colors);

    add_all_checks();

    check::filter_tags(args.tags);
    check::filter_id(args.filters);

    if args.no_parallelization {
        check::run_dependencies();
    } else {
        check::par_run_dependencies();
    }

    if args.no_parallelization {
        check::run_checks();
    } else {
        check::par_run_checks();
    }

    if !args.no_print_checks {
        check::print_checks(args.no_print_success);
    }

    if !args.no_stats {
        check::print_stats();
    }

    if !args.no_time {
        println!("\ntook: {}", utils::format_duration(now.elapsed()));
    }
}

fn add_all_checks() {
    sysctl::add_sysctl_check!("SYS_001", vec!["sysctl"], "kernel.kptr_restrict", 2);
    sysctl::add_sysctl_check!("SYS_002", vec!["sysctl"], "kernel.ftrace_enabled", 0);
    sysctl::add_sysctl_check!(
        "SYS_003",
        vec!["sysctl", "CIS"],
        "kernel.randomize_va_space",
        2
    );
    sysctl::add_sysctl_check!("SYS_004", vec!["sysctl"], "kernel.dmesg_restrict", 1);
    sysctl::add_sysctl_check!("SYS_005", vec!["sysctl"], "kernel.printk", "3\t3\t3\t3");
    sysctl::add_sysctl_check!(
        "SYS_006",
        vec!["sysctl"],
        "kernel.perf_cpu_time_max_percent",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_007",
        vec!["sysctl"],
        "kernel.perf_event_max_sample_rate",
        1
    );
    // 2 or 3
    check::add_check(
        "SYS_008",
        "Ensure sysctl \"kernel.perf_event_paranoid\" >= 2",
        vec!["sysctl"],
        || {
            const EXPECTED: i32 = 2;
            match sysctl::get_sysctl_i32_value("kernel.perf_event_paranoid") {
                Ok(value) => {
                    if value >= EXPECTED {
                        (check::CheckState::Success, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failure,
                            Some(format!("{} > {}", value, EXPECTED)),
                        )
                    }
                }
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![sysctl::init_sysctl_config],
    );
    sysctl::add_sysctl_check!("SYS_009", vec!["sysctl"], "kernel.sysrq", 0);
    sysctl::add_sysctl_check!("SYS_010", vec!["sysctl"], "kernel.kexec_load_disabled", 1);
    sysctl::add_sysctl_check!(
        "SYS_011",
        vec!["sysctl", "bpf"],
        "kernel.unprivileged_bpf_disabled",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_012",
        vec!["sysctl", "bpf"],
        "net.core.bpf_jit_harden",
        2
    );
    sysctl::add_sysctl_check!("SYS_013", vec!["sysctl"], "kernel.panic_on_oops", 1);
    sysctl::add_sysctl_check!("SYS_014", vec!["sysctl"], "kernel.panic", "-1");
    sysctl::add_sysctl_check!("SYS_015", vec!["sysctl"], "kernel.modules_disabled", 1);
    // FIXME: only available on Debian, create custom rule to check if OS is debian, else ignore
    sysctl::add_sysctl_check!(
        "SYS_016",
        vec!["sysctl"],
        "kernel.unprivileged_userns_clone",
        0
    );
    // check::add_check(
    //     "SYS_016",
    //     "Ensure sysctl 'kernel.kptr_restrict' == 2",
    //     vec!["sysctl"],
    //     || sysctl::get_ssyctl_wrapper("kernel.unprivileged_userns_clone", 0),
    //     vec![sysctl::init_sysctl_config, os::init_os],
    // );

    // 2 or 3, CIS recommends 1
    check::add_check(
        "SYS_017",
        "Ensure sysctl \"kernel.yama.ptrace_scope\" >= 1",
        vec!["sysctl"],
        || {
            const EXPECTED: i32 = 1;
            match sysctl::get_sysctl_i32_value("kernel.yama.ptrace_scope") {
                Ok(value) => {
                    if value >= EXPECTED {
                        (check::CheckState::Success, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failure,
                            Some(format!("{} > {}", value, EXPECTED)),
                        )
                    }
                }
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![sysctl::init_sysctl_config],
    );
    sysctl::add_sysctl_check!("SYS_018", vec!["sysctl"], "kernel.io_uring_disabled", 2);
    sysctl::add_sysctl_check!(
        "SYS_019",
        vec!["sysctl"],
        "kernel.core_pattern",
        "|/bin/false"
    );
    sysctl::add_sysctl_check!("SYS_020", vec!["sysctl"], "kernel.core_uses_pid", 1);
    sysctl::add_sysctl_check!("SYS_021", vec!["sysctl"], "vm.unprivileged_userfaultfd", 0);
    sysctl::add_sysctl_check!("SYS_022", vec!["sysctl"], "vm.mmap_rnd_bits", 32);
    sysctl::add_sysctl_check!("SYS_023", vec!["sysctl"], "vm.mmap_rnd_compat_bits", 16);
    sysctl::add_sysctl_check!("SYS_024", vec!["sysctl"], "vm.mmap_min_addr", 65536);
    sysctl::add_sysctl_check!("SYS_025", vec!["sysctl"], "dev.tty.ldisc_autoload", 0);
    sysctl::add_sysctl_check!("SYS_026", vec!["sysctl"], "dev.tty.legacy_tiocsti", 0);
    sysctl::add_sysctl_check!("SYS_027", vec!["sysctl"], "vm.max_map_count", 1048576);
    sysctl::add_sysctl_check!("SYS_028", vec!["sysctl"], "vm.swappiness", 1);
    sysctl::add_sysctl_check!("SYS_029", vec!["sysctl", "CIS"], "fs.suid_dumpable", 0);
    sysctl::add_sysctl_check!("SYS_030", vec!["sysctl"], "fs.protected_fifos", 2);
    sysctl::add_sysctl_check!("SYS_031", vec!["sysctl"], "fs.protected_regular", 2);
    sysctl::add_sysctl_check!("SYS_032", vec!["sysctl"], "fs.protected_symlinks", 1);
    sysctl::add_sysctl_check!("SYS_033", vec!["sysctl"], "fs.protected_hardlinks", 1);
    check::add_check(
        "SYS_034",
        "Ensure sysctl \"fs.binfmt_misc.status\" = 0",
        vec!["sysctl"],
        || {
            let (status, message) = sysctl::check_sysctl("fs.binfmt_misc.status", 0);
            // ignore if not present
            if status == check::CheckState::Error {
                (check::CheckState::Success, None)
            } else {
                (status, message)
            }
        },
        vec![sysctl::init_sysctl_config],
    );
    sysctl::add_sysctl_check!("SYS_035", vec!["sysctl", "CIS"], "net.ipv4.ip_forward", 0);
    sysctl::add_sysctl_check!(
        "SYS_036",
        vec!["sysctl", "CIS"],
        "net.ipv4.conf.all.accept_source_route",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_037",
        vec!["sysctl", "CIS", "STIG"],
        "net.ipv4.conf.default.accept_source_route",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_038",
        vec!["sysctl", "CIS"],
        "net.ipv6.conf.all.accept_source_route",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_039",
        vec!["sysctl", "CIS"],
        "net.ipv6.conf.default.accept_source_route",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_040",
        vec!["sysctl", "CIS"],
        "net.ipv4.conf.all.accept_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_041",
        vec!["sysctl", "CIS", "STIG"],
        "net.ipv4.conf.default.accept_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_042",
        vec!["sysctl", "CIS"],
        "net.ipv4.conf.all.secure_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_043",
        vec!["sysctl", "CIS"],
        "net.ipv4.conf.default.secure_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_044",
        vec!["sysctl", "CIS"],
        "net.ipv4.conf.all.send_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_045",
        vec!["sysctl", "CIS"],
        "net.ipv4.conf.default.send_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_046",
        vec!["sysctl", "CIS"],
        "net.ipv6.conf.all.accept_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_047",
        vec!["sysctl", "CIS"],
        "net.ipv6.conf.default.accept_redirects",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_050",
        vec!["sysctl"],
        "net.ipv4.icmp_echo_ignore_all",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_051",
        vec!["sysctl"],
        "net.ipv6.icmp.echo_ignore_all",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_052",
        vec!["sysctl", "CIS"],
        "net.ipv4.icmp_echo_ignore_broadcasts",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_053",
        vec!["sysctl", "CIS", "STIG"],
        "net.ipv4.conf.all.rp_filter",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_054",
        vec!["sysctl", "CIS"],
        "net.ipv4.conf.default.rp_filter",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_055",
        vec!["sysctl", "CIS", "STIG"],
        "net.ipv4.icmp_ignore_bogus_error_responses",
        1
    );
    check::add_check(
        "SYS_056",
        "Ensure sysctl \"net.ipv4.icmp_ratelimit\" <= 100",
        vec!["sysctl"],
        || {
            const EXPECTED: i32 = 100;
            match sysctl::get_sysctl_i32_value("net.ipv4.icmp_ratelimit") {
                Ok(value) => {
                    if value <= EXPECTED {
                        (check::CheckState::Success, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failure,
                            Some(format!("{} > {}", value, EXPECTED)),
                        )
                    }
                }
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![sysctl::init_sysctl_config],
    );
    sysctl::add_sysctl_check!("SYS_057", vec!["sysctl"], "net.ipv4.icmp_ratemask", 88089);
    sysctl::add_sysctl_check!(
        "SYS_058",
        vec!["sysctl", "CIS"],
        "net.ipv4.tcp_syncookies",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_059",
        vec!["sysctl"],
        "net.ipv4.conf.all.accept_local",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_060",
        vec!["sysctl"],
        "net.ipv4.conf.all.shared_media",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_061",
        vec!["sysctl"],
        "net.ipv4.conf.default.shared_media",
        1
    );
    sysctl::add_sysctl_check!("SYS_062", vec!["sysctl"], "net.ipv4.conf.all.arp_filter", 1);
    sysctl::add_sysctl_check!("SYS_063", vec!["sysctl"], "net.ipv4.conf.all.arp_ignore", 2);
    sysctl::add_sysctl_check!(
        "SYS_064",
        vec!["sysctl"],
        "net.ipv4.conf.default.arp_ignore",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_065",
        vec!["sysctl"],
        "net.ipv4.conf.default.arp_announce",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_066",
        vec!["sysctl"],
        "net.ipv4.conf.all.arp_announce",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_067",
        vec!["sysctl"],
        "net.ipv4.conf.all.route_localnet",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_068",
        vec!["sysctl"],
        "net.ipv4.conf.all.drop_gratuitous_arp",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_069",
        vec!["sysctl"],
        "net.ipv4.ip_local_port_range",
        "32768\t65535"
    );
    sysctl::add_sysctl_check!("SYS_070", vec!["sysctl"], "net.ipv4.tcp_rfc1337", 1);
    sysctl::add_sysctl_check!(
        "SYS_071",
        vec!["sysctl", "CIS"],
        "net.ipv6.conf.all.forwarding",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_072",
        vec!["sysctl"],
        "net.ipv6.conf.default.forwarding",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_073",
        vec!["sysctl", "CIS"],
        "net.ipv6.conf.all.accept_ra",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_074",
        vec!["sysctl", "CIS"],
        "net.ipv6.conf.default.accept_ra",
        0
    );
    sysctl::add_sysctl_check!("SYS_075", vec!["sysctl"], "net.ipv4.tcp_timestamps", 0);
    sysctl::add_sysctl_check!(
        "SYS_076",
        vec!["sysctl", "CIS", "STIG"],
        "net.ipv4.conf.all.log_martians",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_077",
        vec!["sysctl", "CIS", "STIG"],
        "net.ipv4.conf.default.log_martians",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_078",
        vec!["sysctl"],
        "net.ipv6.conf.all.router_solicitations",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_079",
        vec!["sysctl"],
        "net.ipv6.conf.default.router_solicitations",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_080",
        vec!["sysctl"],
        "net.ipv6.conf.all.accept_ra_rtr_pref",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_081",
        vec!["sysctl"],
        "net.ipv6.conf.default.accept_ra_rtr_pref",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_082",
        vec!["sysctl"],
        "net.ipv6.conf.all.accept_ra_defrtr",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_083",
        vec!["sysctl"],
        "net.ipv6.conf.default.accept_ra_defrtr",
        0
    );
    sysctl::add_sysctl_check!("SYS_084", vec!["sysctl"], "net.ipv6.conf.all.autoconf", 0);
    sysctl::add_sysctl_check!(
        "SYS_085",
        vec!["sysctl"],
        "net.ipv6.conf.default.autoconf",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_086",
        vec!["sysctl"],
        "net.ipv6.conf.all.max_addresses",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_087",
        vec!["sysctl"],
        "net.ipv6.conf.default.max_addresses",
        1
    );
    sysctl::add_sysctl_check!(
        "SYS_088",
        vec!["sysctl", "bpf", "paranoid"],
        "net.core.bpf_jit_enable",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_089",
        vec!["sysctl", "paranoid"],
        "net.ipv4.tcp_sack",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_090",
        vec!["sysctl", "paranoid"],
        "net.ipv4.tcp_dsack",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_091",
        vec!["sysctl", "paranoid"],
        "net.ipv4.tcp_fack",
        0
    );
    sysctl::add_sysctl_check!(
        "SYS_092",
        vec!["sysctl", "paranoid"],
        "net.ipv6.conf.all.use_tempaddr",
        2
    );
    sysctl::add_sysctl_check!(
        "SYS_093",
        vec!["sysctl", "paranoid"],
        "net.ipv6.conf.default.use_tempaddr",
        2
    );
    // may break the upower daemon in Ubuntu
    check::add_check(
        "SYS_094",
        "Ensure sysctl \"user.max_user_namespaces\" <= 31231",
        vec!["sysctl"],
        || {
            const EXPECTED: i32 = 31231;
            match sysctl::get_sysctl_i32_value("user.max_user_namespaces") {
                Ok(value) => {
                    if value <= EXPECTED {
                        (check::CheckState::Success, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failure,
                            Some(format!("{} > {}", value, EXPECTED)),
                        )
                    }
                }
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![sysctl::init_sysctl_config],
    );
    check::add_check(
        "SYS_095",
        "Ensure sysctl \"kernel.warn_limit\" <= 100",
        vec!["sysctl"],
        || {
            const EXPECTED: i32 = 100;
            match sysctl::get_sysctl_i32_value("kernel.warn_limit") {
                Ok(value) => {
                    if value <= EXPECTED {
                        (check::CheckState::Success, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failure,
                            Some(format!("{} > {}", value, EXPECTED)),
                        )
                    }
                }
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![sysctl::init_sysctl_config],
    );
    check::add_check(
        "SYS_096",
        "Ensure sysctl \"kernel.oops_limit\" <= 100",
        vec!["sysctl"],
        || {
            const EXPECTED: i32 = 100;
            match sysctl::get_sysctl_i32_value("kernel.oops_limit") {
                Ok(value) => {
                    if value <= EXPECTED {
                        (check::CheckState::Success, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failure,
                            Some(format!("{} > {}", value, EXPECTED)),
                        )
                    }
                }
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![sysctl::init_sysctl_config],
    );

    check::add_check(
        "GRP_001",
        "Ensure group shadow empty or missing",
        vec!["group"],
        group::empty_gshadow,
        vec![],
    );
    check::add_check(
        "GRP_002",
        "Ensure no group has a password set",
        vec!["group"],
        group::no_password_in_group,
        vec![group::init_group],
    );
    check::add_check(
        "GRP_003",
        "Ensure that only root has GID 0",
        vec!["group"],
        group::one_gid_zero,
        vec![group::init_group],
    );
    check::add_check(
        "GRP_004",
        "Ensure no duplicate GIDs exist",
        vec!["group"],
        group::no_dup_gid,
        vec![group::init_group],
    );
    check::add_check(
        "GRP_005",
        "Ensure no duplicate group names exist",
        vec!["group"],
        group::no_dup_name,
        vec![group::init_group],
    );

    check::add_check(
        "SYD_001",
        "Ensure that systemd config \"CtrlAltDelBurstAction\" = \"none\"",
        vec!["systemd"],
        || systemd::get_systemd_config("CtrlAltDelBurstAction", "none"),
        vec![systemd::init_systemd_config],
    );

    check::add_check(
        "AUD_001",
        "Ensure \"auditd\" is running",
        vec!["audit"],
        || ps::is_running("auditd"),
        vec![ps::init_proc],
    );
    // check::add_check(
    //     "AUD_010",
    //     "Ensure that audit is configured with \"disk_full_action\" = \"HALT\"",
    //     vec!["audit"],
    //     || audit::check_audit_config("disk_full_action", "HALT"),
    //     vec![audit::init_audit_config],
    // );
    // check::add_check(
    //     "AUD_100",
    //     "Ensure audit rules are immutable",
    //     vec!["audit", "STIG"],
    //     || audit::check_audit_rule("-e 2"),
    //     vec![audit::init_audit_rules],
    // );
    // check::add_check(
    //     "AUD_101",
    //     "Ensure audit rule for sudo log file is present",
    //     vec!["audit"],
    //     || audit::check_audit_rule("-w /var/log/sudo.log -p wa -k log_file"),
    //     vec![audit::init_audit_rules],
    // );

    check::add_check(
        "AAR_001",
        "Ensure AppArmor is enabled",
        vec!["apparmor"],
        apparmor::apparmor_enabled,
        vec![],
    );

    check::add_check(
        "CAV_001",
        "Ensure ClamAV is installed",
        vec!["clamav"],
        clamav::clamav_installed,
        vec![],
    );

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

    check::add_check(
        "SYS_001",
        "Ensure no reboot is required",
        vec!["system"],
        kernel::check_reboot_required,
        vec![],
    );

    // https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/40_kernel_hardening.cfg
    check::add_check(
        "KNP_001",
        "Ensure that kernel flag \"slab_nomerge\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("slab_nomerge"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_002",
        "Ensure that kernel flag \"slab_debug=FZ\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("slab_debug=FZ"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_003",
        "Ensure that kernel flag \"page_poison=1\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("page_poison=1"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_004",
        "Ensure that kernel flag \"page_alloc.shuffle=1\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("page_alloc.shuffle=1"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_005",
        "Ensure that kernel flag \"init_on_alloc=1\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("init_on_alloc=1"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_006",
        "Ensure that kernel flag \"init_on_free=1\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("init_on_free=1"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_007",
        "Ensure that kernel flag \"pti=on\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("pti=on"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_008",
        "Ensure that kernel flag \"randomize_kstack_offset=on\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("randomize_kstack_offset=on"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_009",
        "Ensure that kernel flag \"vsyscall=none\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("vsyscall=none"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_010",
        "Ensure that kernel flag \"debugfs=off\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("debugfs=off"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_011",
        "Ensure that kernel flag \"oops=panic\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("oops=panic"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_012",
        "Ensure that kernel flag \"module.sig_enforce=1\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("module.sig_enforce=1"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_013",
        "Ensure that kernel flag \"lockdown=confidentiality\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("lockdown=confidentiality"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_014",
        "Ensure that kernel flag \"mce=0\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("mce=0"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_016",
        "Ensure that kernel flag \"kfence.sample_interval=100\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("kfence.sample_interval=100"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_017",
        "Ensure that kernel flag \"vdso32=0\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("vdso32=0"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_018",
        "Ensure that kernel flag \"amd_iommu=force_isolation\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("amd_iommu=force_isolation"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_019",
        "Ensure that kernel flag \"intel_iommu=on\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("intel_iommu=on"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_020",
        "Ensure that kernel flag \"iommu=force\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("iommu=force"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_021",
        "Ensure that kernel flag \"iommu.passthrough=0\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("iommu.passthrough=0"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_022",
        "Ensure that kernel flag \"iommu.strict=1\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("iommu.strict=1"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_023",
        "Ensure that kernel flag \"efi=disable_early_pci_dma\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("efi=disable_early_pci_dma"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_024",
        "Ensure that kernel flag \"random.trust_bootloader=off\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("random.trust_bootloader=off"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_025",
        "Ensure that kernel flag \"random.trust_cpu=off\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("random.trust_cpu=off"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_026",
        "Ensure that kernel flag \"extra_latent_entropy\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("extra_latent_entropy"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_028",
        "Ensure that kernel flag \"ipv6.disable=1\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("ipv6.disable=1"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_029",
        "Ensure that kernel flag \"ia32_emulation=0\" is present",
        vec!["kernel", "paranoid"],
        || kernel::check_kernel_params("ia32_emulation=0"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_016",
        "Ensure that kernel flag \"cfi=kcfi\" is present",
        vec!["kernel", "paranoid"],
        || kernel::check_kernel_params("cfi=kcfi"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_017",
        "Ensure that kernel flag \"random.trust_cpu=off\" is present",
        vec!["kernel", "paranoid"],
        || kernel::check_kernel_params("random.trust_cpu=off"),
        vec![kernel::init_kernel_params],
    );

    // from: kernel-hardening-checker
    // https://lwn.net/Articles/695991/
    check::add_check(
        "KNP_020",
        "Ensure that kernel flag \"hardened_usercopy=1\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("hardened_usercopy=1"),
        vec![kernel::init_kernel_params],
    );

    // Remount secure
    // https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/40_remount_secure.cfg
    check::add_check(
        "KNP_027",
        "Ensure that kernel flag \"remountsecure=3\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("remountsecure=3"),
        vec![kernel::init_kernel_params],
    );

    // X86 64 and 32 CPU mitigations
    // https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/40_cpu_mitigations.cfg
    check::add_check(
        "KNP_030",
        "Ensure that kernel flag \"mitigations=auto\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("mitigations=auto"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_030",
        "Ensure that kernel flag \"mitigations=auto,nosmt\" is present",
        vec!["kernel", "paranoid"],
        || kernel::check_kernel_params("mitigations=auto,nosmt"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_031",
        "Ensure that kernel flag \"nosmt=force\" is present",
        vec!["kernel", "paranoid"],
        || kernel::check_kernel_params("nosmt=force"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_032",
        "Ensure that kernel flag \"spectre_v2=on\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("spectre_v2=on"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_033",
        "Ensure that kernel flag \"spectre_bhi=on\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("spectre_bhi=on"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_034",
        "Ensure that kernel flag \"spec_store_bypass_disable=on\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("spec_store_bypass_disable=on"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_035",
        "Ensure that kernel flag \"l1tf=full,force\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("l1tf=full,force"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_036",
        "Ensure that kernel flag \"mds=full\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("mds=full"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_036",
        "Ensure that kernel flag \"mds=full,nosm\" is present",
        vec!["kernel", "paranoid"],
        || kernel::check_kernel_params("mds=full,nosm"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_037",
        "Ensure that kernel flag \"tsx=off\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("tsx=off"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_038",
        "Ensure that kernel flag \"tsx_async_abort=full\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("tsx_async_abort=full"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_038",
        "Ensure that kernel flag \"tsx_async_abort=full,nosmt\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("tsx_async_abort=full,nosmt"),
        vec![kernel::init_kernel_params],
    ); // TODO: paranoid
    check::add_check(
        "KNP_039",
        "Ensure that kernel flag \"kvm.nx_huge_pages=force\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("kvm.nx_huge_pages=force"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_040",
        "Ensure that kernel flag \"l1d_flush=on\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("l1d_flush=on"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_041",
        "Ensure that kernel flag \"mmio_stale_data=full\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("mmio_stale_data=full"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_041",
        "Ensure that kernel flag \"mmio_stale_data=full,nosmt\" is present",
        vec!["kernel", "paranoid"],
        || kernel::check_kernel_params("mmio_stale_data=full,nosmt"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_042",
        "Ensure that kernel flag \"retbleed=auto\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("retbleed=auto"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_042",
        "Ensure that kernel flag \"retbleed=auto,nosmt\" is present",
        vec!["kernel", "paranoid"],
        || kernel::check_kernel_params("retbleed=auto,nosmt"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_043",
        "Ensure that kernel flag \"spec_rstack_overflow=safe-ret\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("spec_rstack_overflow=safe-ret"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_044",
        "Ensure that kernel flag \"gather_data_sampling=force\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("gather_data_sampling=force"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_045",
        "Ensure that kernel flag \"reg_file_data_sampling=on\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("reg_file_data_sampling=on"),
        vec![kernel::init_kernel_params],
    );
    // from: kernel-hardening-checker
    check::add_check(
        "KNP_050",
        "Ensure that kernel flag \"spectre_v2_user=on\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("spectre_v2_user=on"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_051",
        "Ensure that kernel flag \"srbds=auto,nosmt\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("srbds=auto,nosmt"),
        vec![kernel::init_kernel_params],
    );

    // ARM CPU mitigations
    // "kpti=auto,nosmt");
    // "ssbd=force-on");
    // "rodata=full");

    // Quiet boot
    // https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/41_quiet_boot.cfg
    check::add_check(
        "KNP_060",
        "Ensure that kernel flag \"loglevel=0\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("loglevel=0"),
        vec![kernel::init_kernel_params],
    );
    check::add_check(
        "KNP_061",
        "Ensure that kernel flag \"quiet\" is present",
        vec!["kernel"],
        || kernel::check_kernel_params("quiet"),
        vec![kernel::init_kernel_params],
    );

    check::add_check(
        "GDM_001",
        "Ensure no automatic logon to the system via a GUI is possible",
        vec!["gdm"],
        gdm::no_gdm_auto_logon,
        vec![],
    );

    // check::add_check(
    //     "GRB_001",
    //     "Ensure that bootloader password is set",
    //     vec!["grub"],
    //     grub::password_is_set,
    //     vec![grub::init_grub_cfg],
    // );

    check::add_check(
        "USR_001",
        "Ensure that root is the only user with UID 0",
        vec!["user", "passwd"],
        users::no_uid_zero,
        vec![users::init_passwd],
    );
    check::add_check(
        "USR_002",
        "Ensure no duplicate user names exist",
        vec!["user", "passwd"],
        users::no_dup_username,
        vec![users::init_passwd],
    );
    check::add_check(
        "USR_003",
        "Ensure no duplicate UIDs exist",
        vec!["user", "passwd"],
        users::no_dup_uid,
        vec![users::init_passwd],
    );
    check::add_check(
        "USR_004",
        "Ensure that \"/etc/securetty\" is empty",
        vec!["user"],
        users::empty_securetty,
        vec![],
    );
    check::add_check(
        "USR_005",
        "Ensure no login is available on system accounts",
        vec!["user", "passwd"],
        users::no_login_sys_users,
        vec![users::init_passwd],
    );
    // check::add_check(
    //     "USR_006",
    //     "Ensure all passwords are hashed with yescrypt",
    //     vec!["user", "shadow"],
    //     users::yescrypt_hashes,
    //     vec![users::init_shadow],
    // );
    // check::add_check(
    //     "USR_007",
    //     "Ensure no accounts are locked, delete them",
    //     vec!["user", "shadow"],
    //     users::no_locked_account,
    //     vec![users::init_shadow],
    // );
    check::add_check(
        "USR_008",
        "Ensure that all home directories exist",
        vec!["user", "passwd"],
        users::no_missing_home,
        vec![users::init_passwd],
    );
    // check::add_check(
    //     "USR_009",
    //     "Ensure \"/etc/shadow\" password fields are not empty",
    //     vec!["user", "shadow"],
    //     users::no_empty_shadow_password,
    //     vec![users::init_shadow],
    // );
    check::add_check(
        "USR_010",
        "Ensure \"/etc/passwd\" password fields are not empty",
        vec!["user", "passwd"],
        users::no_empty_passwd_password,
        vec![users::init_shadow],
    );
    check::add_check(
        "USR_011",
        "Ensure accounts in \"/etc/passwd\" use shadowed passwords",
        vec!["user", "passwd"],
        users::no_password_in_passwd,
        vec![users::init_passwd],
    );

    // mounts
    check::add_check(
        "MNT_001",
        "Ensure mount point \"/boot\" exist",
        vec!["mount"],
        || mount::check_mount_present("/boot"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_002",
        "Ensure mount point \"/tmp\" exist",
        vec!["mount", "CIS"],
        || mount::check_mount_present("/tmp"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_003",
        "Ensure mount point \"/home\" exist",
        vec!["mount", "CIS"],
        || mount::check_mount_present("/home"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_004",
        "Ensure mount point \"/var\" exist",
        vec!["mount", "CIS"],
        || mount::check_mount_present("/var"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_005",
        "Ensure mount point \"/var/log\" exist",
        vec!["mount", "CIS"],
        || mount::check_mount_present("/var/log"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_006",
        "Ensure mount point \"/var/log/audit\" exist",
        vec!["mount", "CIS"],
        || mount::check_mount_present("/var/log/audit"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_007",
        "Ensure mount point \"/var/tmp\" exist",
        vec!["mount", "CIS"],
        || mount::check_mount_present("/var/tmp"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_008",
        "Ensure mount point \"/dev/shm\" exist",
        vec!["mount", "CIS"],
        || mount::check_mount_present("/dev/shm"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_020",
        "Ensure mount option \"nodev\" is set for \"/dev/shm\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/dev/shm", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_001",
        "Ensure mount option \"errors=remount-ro\" is set for \"/\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/", "errors=remount-ro"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_002",
        "Ensure mount option \"nodev\" is set for \"/boot\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/boot", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_003",
        "Ensure mount option \"nosuid\" is set for \"/boot\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/boot", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_004",
        "Ensure mount option \"noexec\" is set for \"/boot\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/boot", "noexec"),
        vec![mount::init_mounts],
    );
    // TODO: optional
    check::add_check(
        "MNT_005",
        "Ensure mount option \"noauto\" is set for \"/boot\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/boot", "noauto"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_006",
        "Ensure mount option \"nodev\" is set for \"/home\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/home", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_007",
        "Ensure mount option \"nosuid\" is set for \"/home\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/home", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_008",
        "Ensure mount option \"noexec\" is set for \"/home\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/home", "noexec"),
        vec![mount::init_mounts],
    ); // TODO: optional
    check::add_check(
        "MNT_009",
        "Ensure mount option \"nodev\" is set for \"/tmp\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/tmp", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_010",
        "Ensure mount option \"nosuid\" is set for \"/tmp\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/tmp", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_011",
        "Ensure mount option \"noexec\" is set for \"/tmp\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/tmp", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_012",
        "Ensure mount option \"nodev\" is set for \"/var\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/var", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_013",
        "Ensure mount option \"nosuid\" is set for \"/var\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/var", "nosuid"),
        vec![mount::init_mounts],
    );
    // TODO: optional
    check::add_check(
        "MNT_014",
        "Ensure mount option \"noexec\" is set for \"/var\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/var", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_015",
        "Ensure mount option \"nodev\" is set for \"/var/log\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_016",
        "Ensure mount option \"nosuid\" is set for \"/var/log\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_017",
        "Ensure mount option \"noexec\" is set for \"/var/log\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_018",
        "Ensure mount option \"nodev\" is set for \"/var/log/audit\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log/audit", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_019",
        "Ensure mount option \"nosuid\" is set for \"/var/log/audit\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log/audit", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_010",
        "Ensure mount option \"noexec\" is set for \"/var/log/audit\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log/audit", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_011",
        "Ensure mount option \"nodev\" is set for \"/var/tmp\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/var/tmp", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_012",
        "Ensure mount option \"nosuid\" is set for \"/var/tmp\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/var/tmp", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_013",
        "Ensure mount option \"noexec\" is set for \"/var/tmp\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/var/tmp", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_014",
        "Ensure mount option \"nodev\" is set for \"/proc\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/proc", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_015",
        "Ensure mount option \"nosuid\" is set for \"/proc\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/proc", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_016",
        "Ensure mount option \"noexec\" is set for \"/proc\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/proc", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_017",
        "Ensure mount option \"hidepid=invisible\" is set for \"/proc\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/proc", "hidepid=invisible"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_018",
        "Ensure mount option \"nosuid\" is set for \"/dev\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/dev", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_019",
        "Ensure mount option \"noexec\" is set for \"/dev\"",
        vec!["mount", "mount_option"],
        || mount::check_mount_option("/dev", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_020",
        "Ensure mount option \"nodev\" is set for \"/dev/shm\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/dev/shm", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_021",
        "Ensure mount option \"nosuid\" is set for \"/dev/shm\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/dev/shm", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_022",
        "Ensure mount option \"noexec\" is set for \"/dev/shm\"",
        vec!["mount", "mount_option", "CIS"],
        || mount::check_mount_option("/dev/shm", "noexec"),
        vec![mount::init_mounts],
    );

    // TODO: have two lists, one for servers and one for workstations
    modprobe::add_module_blacklisted_check_list!(
        // GrapheneOS:
        // https://github.com/GrapheneOS/infrastructure/blob/86e765944fc1a1b69e9ccf27de5c8693405fe46d/etc/modprobe.d/local.conf
        "snd_intel8x0",
        "sr_mod",
        "snd_intel8x0m",
        // https://github.com/Kicksecure/security-misc/blob/master/etc/modprobe.d/30_security-misc_blacklist.conf
        "cdrom",
        "amd76x_edac",
        "ath_pci",
        "evbug",
        "snd_aw2",
        "snd_pcsp",
        "usbkbd",
        "usbmouse",
    );

    // TODO: have two lists, one for servers and one for workstations
    modprobe::add_module_disabled_check_list!(
        // Ubuntu: either duplicates, or disabled
        // https://git.launchpad.net/ubuntu/+source/kmod/tree/debian/modprobe.d/blacklist.conf?h=ubuntu/disco

        // disabling prohibits kernel modules from starting
        // https://github.com/Kicksecure/security-misc/blob/master/etc/modprobe.d/30_security-misc_disable.conf
        "cfg80211",
        "intel_agp",
        "ip_tables",
        "mousedev",
        "psmouse",
        "tls",
        "virtio_balloon",
        "virtio_console",
        // Network protocols
        "af_802154",
        "appletalk",
        "dccp",
        "netrom",
        "rose",
        "n_hdlc",
        "ax25",
        // "brcm80211",
        "x25",
        "decnet",
        "econet",
        "ipx",
        "psnap",
        "p8023",
        "p8022",
        "eepro100",
        "eth1394",
        // Asynchronous Transfer Mode (ATM)
        "atm",
        "ueagle_atm",
        "usbatm",
        "xusbatm",
        "n_hdlc",
        // Controller Area Network (CAN) Protocol
        "c_can",
        "c_can_pci",
        "c_can_platform",
        "can",
        "can_bcm",
        "can_dev",
        "can_gw",
        "can_isotp",
        "can_raw",
        "can_j1939",
        "can327",
        "ifi_canfd",
        "janz_ican3",
        "m_can",
        "m_can_pci",
        "m_can_platform",
        "phy_can_transceiver",
        "slcan",
        "ucan",
        "vxcan",
        "vcan",
        // Transparent Inter Process Communication (TIPC)
        "tipc",
        "tipc_diag",
        // Reliable Datagram Sockets (RDS)
        "rds",
        "rds_rdma",
        "rds_tcp",
        // Stream Control Transmission Protocol (SCTP)
        "sctp",
        "sctp_diag",
        "adfs",
        "affs",
        "bfs",
        "befs",
        "cramfs",
        "efs",
        "erofs",
        "exofs",
        "freevxfs",
        "f2fs",
        "hfs",
        "hfsplus",
        "squashfs",
        "hpfs",
        "jfs",
        "jffs2",
        "minix",
        "nilfs2",
        "ntfs",
        "omfs",
        "qnx4",
        "qnx6",
        "sysv",
        "ufs",
        "udf",
        "reiserfs",
        // Network File Systems
        "ksmbd",
        "gfs2",
        // Common Internet File System (CIFS)
        "cifs",
        "cifs_arc4",
        "cifs_md4",
        // Network File System (NFS)
        "nfs",
        "nfs_acl",
        "nfs_layout_nfsv41_files",
        "nfs_layout_flexfiles",
        "nfsd",
        "nfsv2",
        "nfsv3",
        "nfsv4",
        "usb_storage",
        "vivid",
        "floppy",
        "joydev",
        // bluetooth
        // disable Bluetooth to reduce attack surface due to extended history of
        // security vulnerabilities
        "bluetooth",
        "bluetooth_6lowpan",
        "bt3c_cs",
        "btbcm",
        "btintel",
        "btmrvl",
        "btmrvl_sdio",
        "btmtk",
        "btmtksdio",
        "btmtkuart",
        "btnxpuart",
        "btqca",
        "btrsi",
        "btrtl",
        "btsdio",
        "btusb",
        "virtio_bt",
        // firewire (IEEE 1394)
        "dv1394",
        "firewire_core",
        "firewire_ohci",
        "firewire_net",
        "firewire_sbp2",
        "ohci1394",
        "raw1394",
        "sbp2",
        "video1394",
        // GPS
        "garmin_gps",
        "gnss",
        "gnss_mtk",
        "gnss_serial",
        "gnss_sirf",
        "gnss_ubx",
        "gnss_usb",
        // Intel Management Engine (ME)
        // disabling may lead to breakages in numerous places without clear
        // debugging/error messages, may cause issues with firmware updates,
        // security, power management, display, and DRM.
        // "mei",
        // "mei_gsc",
        // "mei_gsc_proxy",
        // "mei_hdcp",
        // "mei_me",
        // "mei_phy",
        // "mei_pxp",
        // "mei_txe",
        // "mei_vsc",
        // "mei_vsc_hw",
        // "mei_wdt",
        // "microread_mei",

        // Intel Platform Monitoring Technology (PMT) Telemetry
        "pmt_class",
        "pmt_crashlog",
        "pmt_telemetry",
        // Thunderbolt
        "intel_wmi_thunderbolt",
        "thunderbolt",
        "thunderbolt_net",
        // Miscellaneous
        "hamradio",
        // "msr",

        // Framebuffer (fbdev)
        // video drivers are known to be buggy, cause kernel panics, and are
        // generally only used by legacy devices
        "aty128fb",
        "atyfb",
        "cirrusfb",
        "cyber2000fb",
        "cyblafb",
        "gx1fb",
        "hgafb",
        "i810fb",
        "intelfb",
        "kyrofb",
        "lxfb",
        "matroxfb_bases",
        "neofb",
        "nvidiafb",
        "pm2fb",
        "radeonfb",
        "rivafb",
        "s1d13xxxfb",
        "savagefb",
        "sisfb",
        "sstfb",
        "tdfxfb",
        "tridentfb",
        "vesafb",
        "vfb",
        "viafb",
        "vt8623fb",
        "udlfb",
        // replaced modules
        "asus_acpi",
        "bcm43xx",
        "de4x5",
        "prism54",
        // USB Video Device Class
        "uvcvideo",
        // Ubuntu
        "arkfb",
        "matroxfb_base",
        "mb862xxfb",
        "pm3fb",
        "s3fb",
        "snd_mixer_oss",
        "acquirewdt",
        "advantech_ec_wdt",
        "advantechwdt",
        "alim1535_wdt",
        "cadence_wdt",
        "cpu5wdt",
        "da9055_wdt",
        "da9063_wdt",
        "dw_wdt",
        "eurotechwdt",
        "f71808e_wdt",
        "i6300esb",
        "iTCO_wdt",
        "ibmasr",
        "it8712f_wdt",
        "kempld_wdt",
        "max63xx_wdt",
        "mena21_wdt",
        "menz69_wdt",
        "ni903x_wdt",
        "nv_tco",
        "pc87413_wdt",
        "pcwd_usb",
        "rave_sp_wdt",
        "sbc60xxwdt",
        "sbc_fitpc2_wdt",
        "sch311x_wdt",
        "smsc37b787_wdt",
        "sp5100_tco",
        "twl4030_wdt",
        "w83627hf_wdt",
        "w83977f_wdt",
        "wdat_wdt",
        "wm831x_wdt",
        "xen_wdt",
        "snd_pcm_oss",
        "alim7101_wdt",
        "da9052_wdt",
        "da9062_wdt",
        "ebc_c384_wdt",
        "exar_wdt",
        "hpwdt",
        "iTCO_vendor_support",
        "ib700wdt",
        "ie6xx_wdt",
        "it87_wdt",
        "machzwd",
        "mei_wdt",
        "menf21bmc_wdt",
        "mlx_wdt",
        "nic7018_wdt",
        "of_xilinx_wdt",
        "pcwd_pci",
        "pretimeout_panic",
        "retu_wdt",
        "sbc_epx_c3",
        "sc1200wdt",
        "simatic_ipc_wdt",
        "softdog",
        "tqmx86_wdt",
        "via_wdt",
        "w83877f_wdt",
        "wafer5823wdt",
        "wdt_pci",
        "wm8350_wdt",
        "ziirave_wdt",
        "pcspkr",
        "ac97",
        "ac97_codec",
        "ac97_plugin_ad1980",
        "ad1848",
        "ad1889",
        "adlib_card",
        "aedsp16",
        "ali5455",
        "btaudio",
        "cmpci",
        "cs4232",
        "cs4281",
        "cs461x",
        "cs46xx",
        "emu10k1",
        "es1370",
        "es1371",
        "esssolo1",
        "forte",
        "gus",
        "i810_audio",
        "kahlua",
        "mad16",
        "maestro",
        "maestro3",
        "maui",
        "mpu401",
        "nm256_audio",
        "opl3",
        "opl3sa",
        "opl3sa2",
        "pas2",
        "pss",
        "rme96xx",
        "sb",
        "sb_lib",
        "sgalaxy",
        "sonicvibes",
        "sound",
        "sscape",
        "trident",
        "trix",
        "uart401",
        "uart6850",
        "via82cxxx_audio",
        "v_midi",
        "wavefront",
        "ymfpci",
        "ac97_plugin_wm97xx",
        "ad1816",
        "audio",
        "awe_wave",
        "dmasound_core",
        "dmasound_pmac",
        "harmony",
        "sequencer",
        "soundcard",
        "usb_midi",
        "microcode",
    );

    // check::add_check(
    //     "PAM_001",
    //     "Ensure password quality is checked",
    //     vec!["pam"],
    //     || pam::check_rule("passwd", "password", "requisite", "pam_pwquality"),
    //     vec![pam::init_pam],
    // );

    check::add_check(
        "LDF_001",
        "Ensure that login.defs \"ENCRYPT_METHOD\" = \"YESCRYPT\"",
        vec!["login_defs"],
        || login_defs::check_login_defs("ENCRYPT_METHOD", "YESCRYPT"),
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_002",
        "Ensure that login.defs \"SHA_CRYPT_MIN_ROUNDS\" = \"65536\"",
        vec!["login_defs"],
        || login_defs::check_login_defs("SHA_CRYPT_MIN_ROUNDS", "65536"),
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_003",
        "Ensure that login.defs \"PASS_MAX_DAYS\" <= 365",
        vec!["login_defs"],
        || {
            const EXPECTED: i32 = 365;
            match login_defs::get_login_defs("PASS_MAX_DAYS") {
                Ok(value) => match value.parse::<i32>() {
                    Ok(val) => {
                        if val <= EXPECTED {
                            (check::CheckState::Success, Some(format!("{}", val)))
                        } else {
                            (
                                check::CheckState::Failure,
                                Some(format!("{} > {}", val, EXPECTED)),
                            )
                        }
                    }
                    Err(error) => (check::CheckState::Error, Some(error.to_string())),
                },
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_004",
        "Ensure that login.defs \"PASS_MIN_DAYS\" >= 1",
        vec!["login_defs"],
        || {
            const EXPECTED: i32 = 1;
            match login_defs::get_login_defs("PASS_MIN_DAYS") {
                Ok(value) => match value.parse::<i32>() {
                    Ok(val) => {
                        if val >= EXPECTED {
                            (check::CheckState::Success, Some(format!("{}", val)))
                        } else {
                            (
                                check::CheckState::Failure,
                                Some(format!("{} < {}", val, EXPECTED)),
                            )
                        }
                    }
                    Err(error) => (check::CheckState::Error, Some(error.to_string())),
                },
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_005",
        "Ensure that login.defs \"PASS_WARN_AGE\" >= 7",
        vec!["login_defs"],
        || {
            const EXPECTED: i32 = 7;
            match login_defs::get_login_defs("PASS_WARN_AGE") {
                Ok(value) => match value.parse::<i32>() {
                    Ok(val) => {
                        if val >= EXPECTED {
                            (check::CheckState::Success, Some(format!("{}", val)))
                        } else {
                            (
                                check::CheckState::Failure,
                                Some(format!("{} < {}", val, EXPECTED)),
                            )
                        }
                    }
                    Err(error) => (check::CheckState::Error, Some(error.to_string())),
                },
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_006",
        "Ensure that login.defs \"SYSLOG_SU_ENAB\" = \"yes\"",
        vec!["login_defs"],
        || login_defs::check_login_defs("SYSLOG_SU_ENAB", "yes"),
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_007",
        "Ensure that login.defs \"SYSLOG_SG_ENAB\" = \"yes\"",
        vec!["login_defs"],
        || login_defs::check_login_defs("SYSLOG_SG_ENAB", "yes"),
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_008",
        "Ensure that login.defs \"UMASK\" = \"077\"",
        vec!["login_defs"],
        || login_defs::check_login_defs("UMASK", "077"),
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_009",
        "Ensure that login.defs \"LOGIN_RETRIES\" <= 10",
        vec!["login_defs"],
        || {
            const EXPECTED: i32 = 10;
            match login_defs::get_login_defs("LOGIN_RETRIES") {
                Ok(value) => match value.parse::<i32>() {
                    Ok(val) => {
                        if val <= EXPECTED {
                            (check::CheckState::Success, Some(format!("{}", val)))
                        } else {
                            (
                                check::CheckState::Failure,
                                Some(format!("{} > {}", val, EXPECTED)),
                            )
                        }
                    }
                    Err(error) => (check::CheckState::Error, Some(error.to_string())),
                },
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_010",
        "Ensure that login.defs \"LOGIN_TIMEOUT\" <= 60",
        vec!["login_defs"],
        || {
            const EXPECTED: i32 = 60;
            match login_defs::get_login_defs("LOGIN_TIMEOUT") {
                Ok(value) => match value.parse::<i32>() {
                    Ok(val) => {
                        if val <= EXPECTED {
                            (check::CheckState::Success, Some(format!("{}", val)))
                        } else {
                            (
                                check::CheckState::Failure,
                                Some(format!("{} > {}", val, EXPECTED)),
                            )
                        }
                    }
                    Err(error) => (check::CheckState::Error, Some(error.to_string())),
                },
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_011",
        "Ensure that login.defs \"FAILLOG_ENAB\" = \"yes\"",
        vec!["login_defs"],
        || login_defs::check_login_defs("FAILLOG_ENAB", "yes"),
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_012",
        "Ensure that login.defs \"LOG_OK_LOGINS\" = \"yes\"",
        vec!["login_defs"],
        || login_defs::check_login_defs("LOG_OK_LOGINS", "yes"),
        vec![login_defs::init_login_defs],
    );

    // TODO: only run checks if sudo is installed
    // check::add_check(
    //     "SUD_001",
    //     "Ensure that sudo default config \"noexec\" is set",
    //     vec!["sudo"],
    //     || sudo::check_sudo_defaults("noexec"),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_002",
    //     "Ensure that sudo default config \"requiretty\" is set",
    //     vec!["sudo"],
    //     || sudo::check_sudo_defaults("requiretty"),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_003",
    //     "Ensure that sudo default config \"use_pty\" is set",
    //     vec!["sudo", "CIS"],
    //     || sudo::check_sudo_defaults("use_pty"),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_004",
    //     "Ensure that sudo default config \"umask=0027\" is set",
    //     vec!["sudo"],
    //     || sudo::check_sudo_defaults("umask=0027"),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_005",
    //     "Ensure that sudo default config \"ignore_dot\" is set",
    //     vec!["sudo"],
    //     || sudo::check_sudo_defaults("ignore_dot"),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_006",
    //     "Ensure that sudo default config \"passwd_timeout=1\" is set",
    //     vec!["sudo"],
    //     || sudo::check_sudo_defaults("passwd_timeout=1"),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_007",
    //     "Ensure that sudo default config \"env_reset, timestamp_timeout=15\" is set",
    //     vec!["sudo"],
    //     || sudo::check_sudo_defaults("env_reset, timestamp_timeout=15"),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_008",
    //     "Ensure that sudo default config \"timestamp_timeout=15\" is set",
    //     vec!["sudo"],
    //     || sudo::check_sudo_defaults("timestamp_timeout=15"),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_009",
    //     "Ensure that sudo default config \"env_reset\" is set",
    //     vec!["sudo"],
    //     || sudo::check_sudo_defaults("env_reset"),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_010",
    //     "Ensure that sudo default config \"mail_badpass\" is set",
    //     vec!["sudo"],
    //     || sudo::check_sudo_defaults("mail_badpass"),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_011",
    //     "Ensure that sudo default config \"logfile=\"/var/log/sudo.log\"\" is set",
    //     vec!["sudo", "CIS"],
    //     || sudo::check_sudo_defaults("logfile=\"/var/log/sudo.log\""),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_012",
    //     "Ensure that sudo default config \":%sudo !noexec\" is set",
    //     vec!["sudo"],
    //     || sudo::check_sudo_defaults(":%sudo !noexec"),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_013",
    //     "Ensure that sudo default config \"lecture=\"always\"\" is set",
    //     vec!["sudo"],
    //     || sudo::check_sudo_defaults("lecture=\"always\""),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_014",
    //     "Ensure that sudo default config \"lecture_file=\"/usr/share/doc/sudo_lecture.txt\"\" is set",
    //     vec!["sudo"],
    //     // TODO: should also check the content of the file
    //     // TODO: get the file path from the value
    //     || sudo::check_sudo_defaults("lecture_file=\"/usr/share/doc/sudo_lecture.txt\""),
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_015",
    //     "Ensure that sudoers config does not contain \"NOPASSWD\"",
    //     vec!["sudo", "CIS"],
    //     sudo::check_has_no_nopaswd,
    //     vec![sudo::init_sudo],
    // );
    // check::add_check(
    //     "SUD_016",
    //     "Ensure that sudoers re authentication is not disabled",
    //     vec!["sudo"],
    //     sudo::check_re_authentication_not_disabled,
    //     vec![sudo::init_sudo],
    // );

    // check::add_check(
    //     "SSH_001",
    //     "Ensure that sshd is configured with \"fingerprinthash\" = \"SHA256\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("fingerprinthash", "SHA256"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_002",
    //     "Ensure that sshd is configured with \"syslogfacility\" = \"AUTH\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("syslogfacility", "AUTH"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_003",
    //     "Ensure that sshd is configured with \"loglevel\" = \"VERBOSE\"",
    //     vec!["sshd", "CIS", "mozilla"],
    //     || sshd::check_sshd_config("loglevel", "VERBOSE"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_004",
    //     "Ensure that sshd is configured with \"logingracetime\" <= 60",
    //     vec!["sshd", "CIS"],
    //     || {
    //         const EXPECTED: i32 = 60;
    //         match sshd::get_sshd_config("logingracetime") {
    //             Ok(str_value) => match str_value.parse::<i32>() {
    //                 Ok(value) => {
    //                     if value <= EXPECTED {
    //                         (check::CheckState::Success, Some(format!("{}", value)))
    //                     } else {
    //                         (
    //                             check::CheckState::Failure,
    //                             Some(format!("{} > {}", value, EXPECTED)),
    //                         )
    //                     }
    //                 }
    //                 Err(error) => (check::CheckState::Error, Some(error.to_string())),
    //             },
    //             Err(error) => (check::CheckState::Error, Some(error)),
    //         }
    //     },
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_005",
    //     "Ensure that sshd is configured with \"permitrootlogin\" = \"no\"",
    //     vec!["sshd", "CIS", "mozilla"],
    //     || sshd::check_sshd_config("permitrootlogin", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_006",
    //     "Ensure that sshd is configured with \"strictmodes\" = \"yes\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("strictmodes", "yes"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_007",
    //     "Ensure that sshd is configured with \"maxauthtries\" <= 2",
    //     vec!["sshd", "CIS"],
    //     || {
    //         const EXPECTED: i32 = 2;
    //         match sshd::get_sshd_config("maxauthtries") {
    //             Ok(str_value) => match str_value.parse::<i32>() {
    //                 Ok(value) => {
    //                     if value <= EXPECTED {
    //                         (check::CheckState::Success, Some(format!("{}", value)))
    //                     } else {
    //                         (
    //                             check::CheckState::Failure,
    //                             Some(format!("{} > {}", value, EXPECTED)),
    //                         )
    //                     }
    //                 }
    //                 Err(error) => (check::CheckState::Error, Some(error.to_string())),
    //             },
    //             Err(error) => (check::CheckState::Error, Some(error)),
    //         }
    //     },
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_008",
    //     "Ensure that sshd is configured with \"maxsessions\" <= 2",
    //     vec!["sshd", "CIS"],
    //     || {
    //         const EXPECTED: i32 = 2;
    //         match sshd::get_sshd_config("maxauthtries") {
    //             Ok(str_value) => match str_value.parse::<i32>() {
    //                 Ok(value) => {
    //                     if value <= EXPECTED {
    //                         (check::CheckState::Success, Some(format!("{}", value)))
    //                     } else {
    //                         (
    //                             check::CheckState::Failure,
    //                             Some(format!("{} > {}", value, EXPECTED)),
    //                         )
    //                     }
    //                 }
    //                 Err(error) => (check::CheckState::Error, Some(error.to_string())),
    //             },
    //             Err(error) => (check::CheckState::Error, Some(error)),
    //         }
    //     },
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_009",
    //     "Ensure that sshd is configured with \"hostbasedauthentication\" = \"no\"",
    //     vec!["sshd", "CIS"],
    //     || sshd::check_sshd_config("hostbasedauthentication", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_010",
    //     "Ensure that sshd is configured with \"ignorerhosts\" = \"yes\"",
    //     vec!["sshd", "CIS"],
    //     || sshd::check_sshd_config("ignorerhosts", "yes"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_011",
    //     "Ensure that sshd is configured with \"ignoreuserknownhosts\" = \"yes\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("", ""),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_012",
    //     "Ensure that sshd is configured with \"pubkeyauthentication\" = \"yes\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("pubkeyauthentication", "yes"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_013",
    //     "Ensure that sshd is configured with \"passwordauthentication\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("passwordauthentication", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_014",
    //     "Ensure that sshd is configured with \"kbdinteractiveauthentication\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("kbdinteractiveauthentication", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_015",
    //     "Ensure that sshd is configured with \"permitemptypasswords\" = \"no\"",
    //     vec!["sshd", "CIS", "STIG"],
    //     || sshd::check_sshd_config("permitemptypasswords", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_016",
    //     "Ensure that sshd is configured with \"kerberosauthentication\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("kerberosauthentication", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_017",
    //     "Ensure that sshd is configured with \"kerberosorlocalpasswd\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("kerberosorlocalpasswd", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_018",
    //     "Ensure that sshd is configured with \"kerberosticketcleanup\" = \"yes\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("kerberosticketcleanup", "yes"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_019",
    //     "Ensure that sshd is configured with \"gssapiauthentication\" = \"no\"",
    //     vec!["sshd", "CIS"],
    //     || sshd::check_sshd_config("gssapiauthentication", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_020",
    //     "Ensure that sshd is configured with \"gssapicleanupcredentials\" = \"yes\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("gssapicleanupcredentials", "yes"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_037",
    //     "Ensure that sshd is configured with \"usepam\" = \"yes\"",
    //     vec!["sshd", "CIS", "STIG"],
    //     || sshd::check_sshd_config("usepam", "yes"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_025",
    //     "Ensure that sshd is configured with \"disableforwarding\" = \"yes\"",
    //     vec!["sshd", "CIS"],
    //     || sshd::check_sshd_config("disableforwarding", "yes"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_021",
    //     "Ensure that sshd is configured with \"x11forwarding\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("x11forwarding", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_022",
    //     "Ensure that sshd is configured with \"allowagentforwarding\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("allowagentforwarding", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_023",
    //     "Ensure that sshd is configured with \"allowstreamlocalforwarding\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("allowstreamlocalforwarding", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_024",
    //     "Ensure that sshd is configured with \"allowtcpforwarding\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("allowtcpforwarding", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_026",
    //     "Ensure that sshd is configured with \"gatewayports\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("gatewayports", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_027",
    //     "Ensure that sshd is configured with \"x11uselocalhost\" = \"yes\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("x11uselocalhost", "yes"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_028",
    //     "Ensure that sshd is configured with \"printmotd\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("printmotd", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_029",
    //     "Ensure that sshd is configured with \"permituserenvironment\" = \"no\"",
    //     vec!["sshd", "CIS"],
    //     || sshd::check_sshd_config("permituserenvironment", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_030",
    //     "Ensure that sshd is configured with \"clientaliveinterval\" <= 15",
    //     vec!["sshd", "CIS"],
    //     || {
    //         const EXPECTED: i32 = 15;
    //         match sshd::get_sshd_config("maxauthtries") {
    //             Ok(str_value) => match str_value.parse::<i32>() {
    //                 Ok(value) => {
    //                     if value <= EXPECTED {
    //                         (check::CheckState::Success, Some(format!("{}", value)))
    //                     } else {
    //                         (
    //                             check::CheckState::Failure,
    //                             Some(format!("{} > {}", value, EXPECTED)),
    //                         )
    //                     }
    //                 }
    //                 Err(error) => (check::CheckState::Error, Some(error.to_string())),
    //             },
    //             Err(error) => (check::CheckState::Error, Some(error)),
    //         }
    //     },
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_031",
    //     "Ensure that sshd is configured with \"clientalivecountmax\" = \"0\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("clientalivecountmax", "0"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_032",
    //     "Ensure that sshd is configured with \"tcpkeepalive\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("tcpkeepalive", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_033",
    //     "Ensure that sshd is configured with \"usedns\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("usedns", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_034",
    //     "Ensure that sshd is configured with \"permittunnel\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("permittunnel", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_035",
    //     "Ensure that sshd is configured with \"maxstartups\" = \"10:30:60\"",
    //     vec!["sshd", "CIS"],
    //     || sshd::check_sshd_config("maxstartups", "10:30:60"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_036",
    //     "Ensure that sshd is configured with \"printlastlog\" = \"no\"",
    //     vec!["sshd"],
    //     || sshd::check_sshd_config("printlastlog", "no"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_037",
    //     "Ensure that sshd is configured with \"allowgroups\" = \"sshusers\"",
    //     vec!["sshd"],
    //     // TODO: ensure the group also exist
    //     || sshd::check_sshd_config("allowgroups", "sshusers"),
    //     vec![sshd::init_sshd_config],
    // );
    // TODO: make skip it depending based on version, OpenSSH 6.7+
    // check::add_check(
    //     "SSH_038",
    //     "Ensure that sshd is configured with \"kexalgorithms\" = \"curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256\"",
    //     vec!["sshd", "mozilla"],
    //     || sshd::check_sshd_config("kexalgorithms", "curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_039",
    //     "Ensure that sshd is configured with \"ciphers\" = \"chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\"",
    //     vec!["sshd", "mozilla"],
    //     || sshd::check_sshd_config("ciphers", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_040",
    //     "Ensure that sshd is configured with \"macs\" = \"hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com\"",
    //     vec!["sshd", "mozilla"],
    //     || sshd::check_sshd_config("macs", "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_041",
    //     "Ensure that sshd is configured with \"authenticationmethods\" = \"publickey\"",
    //     vec!["sshd", "mozilla"],
    //     || sshd::check_sshd_config("authenticationmethods", "publickey"),
    //     vec![sshd::init_sshd_config],
    // );
    // check::add_check(
    //     "SSH_042",
    //     "Ensure that sshd is configured with \"subsystem\" = \"sftp /usr/lib/ssh/sftp-server -f AUTHPRIV -l INFO\"",
    //     vec!["sshd", "mozilla"],
    //     || sshd::check_sshd_config("subsystem", "sftp /usr/lib/ssh/sftp-server -f AUTHPRIV -l INFO"),
    //     vec![sshd::init_sshd_config],
    // );
    // TODO: check the content of File: /etc/ssh/moduli from: https://infosec.mozilla.org/guidelines/openssh
    // TODO: add OpenSSH client rules: https://infosec.mozilla.org/guidelines/openssh#openssh-client
}
