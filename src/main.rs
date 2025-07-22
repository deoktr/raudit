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
mod config;
mod consts;
mod group;
mod sysctl;
mod systemd;
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
                            check::CheckState::Error,
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
                            check::CheckState::Error,
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
                            check::CheckState::Error,
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
                            check::CheckState::Error,
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
                            check::CheckState::Error,
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
                            check::CheckState::Error,
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

    // check::add_check(
    //     "AUD_010",
    //     "Ensure that audit is configured with \"disk_full_action\" = \"HALT\"",
    //     vec!["apparmor"],
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
}
