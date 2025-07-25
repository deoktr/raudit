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

use crate::*;
use clap::{Parser, ValueEnum};
use std::time::Instant;

/// Audit Linux systems security configurations
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Comma-separated list of tags to filter
    #[arg(long, value_delimiter = ',', num_args(0..))]
    tags: Option<Vec<String>>,

    /// Comma-separated list of ID prefixes to filter
    #[arg(long, value_delimiter = ',', num_args(0..))]
    filters: Option<Vec<String>>,

    /// Log level
    #[arg(long, value_enum, default_value_t = logger::LogLevel::Warn)]
    log_level: logger::LogLevel,

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

    /// Generate JSON output
    #[arg(long, value_enum, default_value_t = JsonMode::Off)]
    json: JsonMode,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum JsonMode {
    Short,
    Pretty,
    Off,
}

pub fn cli() {
    let now = Instant::now();

    let args = Cli::parse();

    config::set_colored_output(!args.no_colors);

    logger::set_log_level(args.log_level);

    add_all_checks();

    match args.tags {
        None => (),
        Some(ref tags) if tags.is_empty() => {
            check::print_tags();
            return;
        }
        Some(tags) => check::filter_tags(tags),
    }

    match args.filters {
        None => (),
        Some(ref filters) if filters.is_empty() => {
            check::print_id_prefixes();
            return;
        }
        Some(filters) => check::filter_id(filters),
    }

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

    if args.json == JsonMode::Off {
        if !args.no_print_checks {
            check::print_checks(args.no_print_success);
        }

        if !args.no_stats {
            check::calculate_stats();
            check::print_stats();
        }
    } else {
        check::calculate_stats();

        check::print_json(args.json == JsonMode::Pretty);
    }

    if !args.no_time {
        eprintln!("took: {}", utils::format_duration(now.elapsed()));
    }
}

// TODO: move related rules to specific files to make it easier to edit, search
// and modify
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
            const VAL: i32 = 2;
            match sysctl::get_sysctl_i32_value("kernel.perf_event_paranoid") {
                Ok(value) => {
                    if value >= VAL {
                        (check::CheckState::Success, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failure,
                            Some(format!("{} > {}", value, VAL)),
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
            const VAL: i32 = 1;
            match sysctl::get_sysctl_i32_value("kernel.yama.ptrace_scope") {
                Ok(value) => {
                    if value >= VAL {
                        (check::CheckState::Success, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failure,
                            Some(format!("{} > {}", value, VAL)),
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
    sysctl::add_sysctl_check!(
        "SYS_029",
        vec!["sysctl", "fs", "CIS"],
        "fs.suid_dumpable",
        0
    );
    sysctl::add_sysctl_check!("SYS_030", vec!["sysctl", "fs"], "fs.protected_fifos", 2);
    sysctl::add_sysctl_check!("SYS_031", vec!["sysctl", "fs"], "fs.protected_regular", 2);
    sysctl::add_sysctl_check!("SYS_032", vec!["sysctl", "fs"], "fs.protected_symlinks", 1);
    sysctl::add_sysctl_check!("SYS_033", vec!["sysctl", "fs"], "fs.protected_hardlinks", 1);
    check::add_check(
        "SYS_034",
        "Ensure sysctl \"fs.binfmt_misc.status\" = 0",
        vec!["sysctl", "fs"],
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
            const VAL: i32 = 100;
            match sysctl::get_sysctl_i32_value("net.ipv4.icmp_ratelimit") {
                Ok(value) => {
                    if value <= VAL {
                        (check::CheckState::Success, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failure,
                            Some(format!("{} > {}", value, VAL)),
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
            const VAL: i32 = 31231;
            match sysctl::get_sysctl_i32_value("user.max_user_namespaces") {
                Ok(value) => {
                    if value <= VAL {
                        (check::CheckState::Success, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failure,
                            Some(format!("{} > {}", value, VAL)),
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
            const VAL: i32 = 100;
            match sysctl::get_sysctl_i32_value("kernel.warn_limit") {
                Ok(value) => {
                    if value <= VAL {
                        (check::CheckState::Success, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failure,
                            Some(format!("{} > {}", value, VAL)),
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
            const VAL: i32 = 100;
            match sysctl::get_sysctl_i32_value("kernel.oops_limit") {
                Ok(value) => {
                    if value <= VAL {
                        (check::CheckState::Success, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Failure,
                            Some(format!("{} > {}", value, VAL)),
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
    check::add_check(
        "AUD_010",
        "Ensure that audit is configured with \"disk_full_action\" = \"HALT\"",
        vec!["audit"],
        || audit::check_audit_config("disk_full_action", "HALT"),
        vec![audit::init_audit_config],
    );
    check::add_check(
        "AUD_100",
        "Ensure audit rules are immutable",
        vec!["audit", "STIG"],
        || audit::check_audit_rule("-e 2"),
        vec![audit::init_audit_rules],
    );
    check::add_check(
        "AUD_101",
        "Ensure audit rule for sudo log file is present",
        vec!["audit"],
        || audit::check_audit_rule("-w /var/log/sudo.log -p wa -k log_file"),
        vec![audit::init_audit_rules],
    );

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
    // remount Secure provides enhanced security via mount options:
    // - 0 (no security): disable remount Secure
    // - 1 (low security): re-mount with nodev and nosuid only
    // - 2 (medium security): re-mount with nodev, nosuid, and noexec for most
    // mount points, excluding /home
    // - 3 (highest security): re-mount with nodev, nosuid, and noexec for all
    // mount points including /home
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
    // "kpti=auto,nosmt"
    // "ssbd=force-on"
    // "rodata=full"

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

    check::add_check(
        "GRB_001",
        "Ensure that bootloader password is set",
        vec!["grub"],
        grub::password_is_set,
        vec![grub::init_grub_cfg],
    );

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
    check::add_check(
        "USR_006",
        "Ensure all passwords are hashed with yescrypt",
        vec!["user", "shadow"],
        users::yescrypt_hashes,
        vec![users::init_shadow],
    );
    check::add_check(
        "USR_007",
        "Ensure no accounts are locked, delete them",
        vec!["user", "shadow"],
        users::no_locked_account,
        vec![users::init_shadow],
    );
    check::add_check(
        "USR_008",
        "Ensure that all home directories exist",
        vec!["user", "passwd"],
        users::no_missing_home,
        vec![users::init_passwd],
    );
    check::add_check(
        "USR_009",
        "Ensure \"/etc/shadow\" password fields are not empty",
        vec!["user", "shadow"],
        users::no_empty_shadow_password,
        vec![users::init_shadow],
    );
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
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/tmp"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_003",
        "Ensure mount point \"/home\" exist",
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/home"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_004",
        "Ensure mount point \"/var\" exist",
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/var"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_005",
        "Ensure mount point \"/var/log\" exist",
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/var/log"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_006",
        "Ensure mount point \"/var/log/audit\" exist",
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/var/log/audit"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_007",
        "Ensure mount point \"/var/tmp\" exist",
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/var/tmp"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_008",
        "Ensure mount point \"/dev/shm\" exist",
        vec!["mount", "fs", "CIS"],
        || mount::check_mount_present("/dev/shm"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_020",
        "Ensure mount option \"nodev\" is set for \"/dev/shm\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/dev/shm", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_001",
        "Ensure mount option \"errors=remount-ro\" is set for \"/\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/", "errors=remount-ro"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_002",
        "Ensure mount option \"nodev\" is set for \"/boot\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/boot", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_003",
        "Ensure mount option \"nosuid\" is set for \"/boot\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/boot", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_004",
        "Ensure mount option \"noexec\" is set for \"/boot\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/boot", "noexec"),
        vec![mount::init_mounts],
    );
    // TODO: optional
    check::add_check(
        "MNT_005",
        "Ensure mount option \"noauto\" is set for \"/boot\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/boot", "noauto"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_006",
        "Ensure mount option \"nodev\" is set for \"/home\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/home", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_007",
        "Ensure mount option \"nosuid\" is set for \"/home\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/home", "nosuid"),
        vec![mount::init_mounts],
    );
    // TODO: optional
    check::add_check(
        "MNT_008",
        "Ensure mount option \"noexec\" is set for \"/home\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/home", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_009",
        "Ensure mount option \"nodev\" is set for \"/tmp\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/tmp", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_010",
        "Ensure mount option \"nosuid\" is set for \"/tmp\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/tmp", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_011",
        "Ensure mount option \"noexec\" is set for \"/tmp\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/tmp", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_012",
        "Ensure mount option \"nodev\" is set for \"/var\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_013",
        "Ensure mount option \"nosuid\" is set for \"/var\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var", "nosuid"),
        vec![mount::init_mounts],
    );
    // TODO: optional
    check::add_check(
        "MNT_014",
        "Ensure mount option \"noexec\" is set for \"/var\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/var", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_015",
        "Ensure mount option \"nodev\" is set for \"/var/log\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_016",
        "Ensure mount option \"nosuid\" is set for \"/var/log\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_017",
        "Ensure mount option \"noexec\" is set for \"/var/log\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_018",
        "Ensure mount option \"nodev\" is set for \"/var/log/audit\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log/audit", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_019",
        "Ensure mount option \"nosuid\" is set for \"/var/log/audit\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log/audit", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_010",
        "Ensure mount option \"noexec\" is set for \"/var/log/audit\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/log/audit", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_011",
        "Ensure mount option \"nodev\" is set for \"/var/tmp\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/tmp", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_012",
        "Ensure mount option \"nosuid\" is set for \"/var/tmp\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/tmp", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_013",
        "Ensure mount option \"noexec\" is set for \"/var/tmp\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/var/tmp", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_014",
        "Ensure mount option \"nodev\" is set for \"/proc\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/proc", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_015",
        "Ensure mount option \"nosuid\" is set for \"/proc\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/proc", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_016",
        "Ensure mount option \"noexec\" is set for \"/proc\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/proc", "noexec"),
        vec![mount::init_mounts],
    );
    // `hidepid=2` is not supported by systemd, breaks polkit, GDM, etc.
    // https://wiki.archlinux.org/title/Security#hidepid
    // https://github.com/systemd/systemd/issues/12955#issuecomment-508490893
    // https://github.com/systemd/systemd/issues/20848#issuecomment-930185888
    check::add_check(
        "MNT_017",
        "Ensure mount option \"hidepid=invisible\" is set for \"/proc\"",
        vec!["mount", "fs", "mount_option", "paranoid"],
        || mount::check_mount_option("/proc", "hidepid=invisible"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_018",
        "Ensure mount option \"nosuid\" is set for \"/dev\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/dev", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_019",
        "Ensure mount option \"noexec\" is set for \"/dev\"",
        vec!["mount", "fs", "mount_option"],
        || mount::check_mount_option("/dev", "noexec"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_020",
        "Ensure mount option \"nodev\" is set for \"/dev/shm\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/dev/shm", "nodev"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_021",
        "Ensure mount option \"nosuid\" is set for \"/dev/shm\"",
        vec!["mount", "fs", "mount_option", "CIS"],
        || mount::check_mount_option("/dev/shm", "nosuid"),
        vec![mount::init_mounts],
    );
    check::add_check(
        "MNT_022",
        "Ensure mount option \"noexec\" is set for \"/dev/shm\"",
        vec!["mount", "fs", "mount_option", "CIS"],
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

    check::add_check(
        "KNC_038",
        "Ensure kernel build option \"CONFIG_EFI\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_EFI"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_042",
        "Ensure kernel build option \"CONFIG_CPU_SUP_AMD\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_CPU_SUP_AMD"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_043",
        "Ensure kernel build option \"CONFIG_CPU_SUP_INTEL\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_CPU_SUP_INTEL"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_044",
        "Ensure kernel build option \"CONFIG_MODULES\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MODULES"),
        vec![kconfig::init_kernel_build_config],
    ); // TODO: paranoid
    check::add_check(
        "KNC_045",
        "Ensure kernel build option \"CONFIG_DEVMEM\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DEVMEM"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_046",
        "Ensure kernel build option \"CONFIG_BPF_SYSCALL\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BPF_SYSCALL"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_047",
        "Ensure kernel build option \"CONFIG_BUG\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_BUG"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_049",
        "Ensure kernel build option \"CONFIG_THREAD_INFO_IN_TASK\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_THREAD_INFO_IN_TASK"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_050",
        "Ensure kernel build option \"CONFIG_IOMMU_SUPPORT\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_IOMMU_SUPPORT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_051",
        "Ensure kernel build option \"CONFIG_RANDOMIZE_BASE\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_RANDOMIZE_BASE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_052",
        "Ensure kernel build option \"CONFIG_LIST_HARDENED\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_LIST_HARDENED"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_053",
        "Ensure kernel build option \"CONFIG_RANDOM_KMALLOC_CACHES\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_RANDOM_KMALLOC_CACHES"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_054",
        "Ensure kernel build option \"CONFIG_SLAB_MERGE_DEFAULT\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SLAB_MERGE_DEFAULT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_055",
        "Ensure kernel build option \"CONFIG_PAGE_TABLE_CHECK\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_PAGE_TABLE_CHECK"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_056",
        "Ensure kernel build option \"CONFIG_PAGE_TABLE_CHECK_ENFORCED\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_PAGE_TABLE_CHECK_ENFORCED"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_057",
        "Ensure kernel build option \"CONFIG_BUG_ON_DATA_CORRUPTION\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_BUG_ON_DATA_CORRUPTION"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_058",
        "Ensure kernel build option \"CONFIG_SLAB_FREELIST_HARDENED\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SLAB_FREELIST_HARDENED"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_059",
        "Ensure kernel build option \"CONFIG_SLAB_FREELIST_RANDOM\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SLAB_FREELIST_RANDOM"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_060",
        "Ensure kernel build option \"CONFIG_SHUFFLE_PAGE_ALLOCATOR\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SHUFFLE_PAGE_ALLOCATOR"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_061",
        "Ensure kernel build option \"CONFIG_FORTIFY_SOURCE\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_FORTIFY_SOURCE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_065",
        "Ensure kernel build option \"CONFIG_INIT_ON_ALLOC_DEFAULT_ON\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_INIT_ON_ALLOC_DEFAULT_ON"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_066",
        "Ensure kernel build option \"CONFIG_STATIC_USERMODEHELPER\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_STATIC_USERMODEHELPER"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_067",
        "Ensure kernel build option \"CONFIG_SCHED_CORE\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SCHED_CORE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_068",
        "Ensure kernel build option \"CONFIG_SECURITY_LOCKDOWN_LSM\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_LOCKDOWN_LSM"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_069",
        "Ensure kernel build option \"CONFIG_SECURITY_LOCKDOWN_LSM_EARLY\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_LOCKDOWN_LSM_EARLY"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_070",
        "Ensure kernel build option \"CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY"),
        vec![kconfig::init_kernel_build_config],
    );

    // security policy
    check::add_check(
        "KNC_073",
        "Ensure kernel build option \"CONFIG_SECURITY\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECURITY"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_074",
        "Ensure kernel build option \"CONFIG_SECURITY_YAMA\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_YAMA"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_075",
        "Ensure kernel build option \"CONFIG_SECURITY_LANDLOCK\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_LANDLOCK"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_076",
        "Ensure kernel build option \"CONFIG_SECURITY_SELINUX_DISABLE\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_SELINUX_DISABLE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_077",
        "Ensure kernel build option \"CONFIG_SECURITY_SELINUX_BOOTPARAM\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_SELINUX_BOOTPARAM"),
        vec![kconfig::init_kernel_build_config],
    ); // TODO: set N
    check::add_check(
        "KNC_078",
        "Ensure kernel build option \"CONFIG_SECURITY_SELINUX_DEVELOP\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_SELINUX_DEVELOP"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_079",
        "Ensure kernel build option \"CONFIG_SECURITY_WRITABLE_HOOKS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_WRITABLE_HOOKS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_080",
        "Ensure kernel build option \"CONFIG_SECURITY_SELINUX_DEBUG\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_SELINUX_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_081",
        "Ensure kernel build option \"CONFIG_SECCOMP\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECCOMP"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_082",
        "Ensure kernel build option \"CONFIG_SECCOMP_FILTER\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECCOMP_FILTER"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_083",
        "Ensure kernel build option \"CONFIG_BPF_UNPRIV_DEFAULT_OFF\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_BPF_UNPRIV_DEFAULT_OFF"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_084",
        "Ensure kernel build option \"CONFIG_STRICT_DEVMEM\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_STRICT_DEVMEM"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_085",
        "Ensure kernel build option \"CONFIG_X86_INTEL_TSX_MODE_OFF\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_X86_INTEL_TSX_MODE_OFF"),
        vec![kconfig::init_kernel_build_config],
    );

    check::add_check(
        "KNC_087",
        "Ensure kernel build option \"CONFIG_SECURITY_DMESG_RESTRICT\" is set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_DMESG_RESTRICT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_088",
        "Ensure kernel build option \"CONFIG_ACPI_CUSTOM_METHOD\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_ACPI_CUSTOM_METHOD"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_089",
        "Ensure kernel build option \"CONFIG_COMPAT_BRK\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_COMPAT_BRK"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_090",
        "Ensure kernel build option \"CONFIG_DEVKMEM\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DEVKMEM"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_091",
        "Ensure kernel build option \"CONFIG_BINFMT_MISC\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BINFMT_MISC"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_092",
        "Ensure kernel build option \"CONFIG_INET_DIAG\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_INET_DIAG"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_093",
        "Ensure kernel build option \"CONFIG_KEXEC\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KEXEC"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_094",
        "Ensure kernel build option \"CONFIG_PROC_KCORE\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PROC_KCORE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_095",
        "Ensure kernel build option \"CONFIG_LEGACY_PTYS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_LEGACY_PTYS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_096",
        "Ensure kernel build option \"CONFIG_HIBERNATION\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_HIBERNATION"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_097",
        "Ensure kernel build option \"CONFIG_COMPAT\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_COMPAT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_098",
        "Ensure kernel build option \"CONFIG_IA32_EMULATION\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_IA32_EMULATION"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_099",
        "Ensure kernel build option \"CONFIG_X86_X32\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_X32"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_100",
        "Ensure kernel build option \"CONFIG_X86_X32_ABI\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_X32_ABI"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_101",
        "Ensure kernel build option \"CONFIG_MODIFY_LDT_SYSCALL\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MODIFY_LDT_SYSCALL"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_102",
        "Ensure kernel build option \"CONFIG_OABI_COMPAT\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_OABI_COMPAT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_103",
        "Ensure kernel build option \"CONFIG_X86_MSR\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_MSR"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_104",
        "Ensure kernel build option \"CONFIG_LEGACY_TIOCSTI\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_LEGACY_TIOCSTI"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_105",
        "Ensure kernel build option \"CONFIG_MODULE_FORCE_LOAD\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MODULE_FORCE_LOAD"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_106",
        "Ensure kernel build option \"CONFIG_DRM_LEGACY\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DRM_LEGACY"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_107",
        "Ensure kernel build option \"CONFIG_FB\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_FB"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_108",
        "Ensure kernel build option \"CONFIG_VT\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_VT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_109",
        "Ensure kernel build option \"CONFIG_BLK_DEV_FD\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_FD"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_110",
        "Ensure kernel build option \"CONFIG_BLK_DEV_FD_RAWCMD\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_FD_RAWCMD"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_111",
        "Ensure kernel build option \"CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_112",
        "Ensure kernel build option \"CONFIG_N_GSM\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_N_GSM"),
        vec![kconfig::init_kernel_build_config],
    );

    // grsec
    check::add_check(
        "KNC_116",
        "Ensure kernel build option \"CONFIG_ZSMALLOC_STAT\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_ZSMALLOC_STAT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_117",
        "Ensure kernel build option \"CONFIG_DEBUG_KMEMLEAK\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DEBUG_KMEMLEAK"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_118",
        "Ensure kernel build option \"CONFIG_BINFMT_AOUT\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BINFMT_AOUT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_119",
        "Ensure kernel build option \"CONFIG_KPROBE_EVENTS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KPROBE_EVENTS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_120",
        "Ensure kernel build option \"CONFIG_UPROBE_EVENTS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_UPROBE_EVENTS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_121",
        "Ensure kernel build option \"CONFIG_GENERIC_TRACER\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_GENERIC_TRACER"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_122",
        "Ensure kernel build option \"CONFIG_FUNCTION_TRACER\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_FUNCTION_TRACER"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_123",
        "Ensure kernel build option \"CONFIG_STACK_TRACER\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_STACK_TRACER"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_124",
        "Ensure kernel build option \"CONFIG_HIST_TRIGGERS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_HIST_TRIGGERS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_125",
        "Ensure kernel build option \"CONFIG_BLK_DEV_IO_TRACE\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_IO_TRACE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_126",
        "Ensure kernel build option \"CONFIG_PROC_VMCORE\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PROC_VMCORE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_127",
        "Ensure kernel build option \"CONFIG_PROC_PAGE_MONITOR\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PROC_PAGE_MONITOR"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_128",
        "Ensure kernel build option \"CONFIG_USELIB\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_USELIB"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_129",
        "Ensure kernel build option \"CONFIG_CHECKPOINT_RESTORE\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_CHECKPOINT_RESTORE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_130",
        "Ensure kernel build option \"CONFIG_USERFAULTFD\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_USERFAULTFD"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_131",
        "Ensure kernel build option \"CONFIG_HWPOISON_INJECT\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_HWPOISON_INJECT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_132",
        "Ensure kernel build option \"CONFIG_MEM_SOFT_DIRTY\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MEM_SOFT_DIRTY"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_133",
        "Ensure kernel build option \"CONFIG_DEVPORT\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DEVPORT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_134",
        "Ensure kernel build option \"CONFIG_DEBUG_FS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DEBUG_FS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_135",
        "Ensure kernel build option \"CONFIG_NOTIFIER_ERROR_INJECTION\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_NOTIFIER_ERROR_INJECTION"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_136",
        "Ensure kernel build option \"CONFIG_FAIL_FUTEX\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_FAIL_FUTEX"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_137",
        "Ensure kernel build option \"CONFIG_PUNIT_ATOM_DEBUG\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PUNIT_ATOM_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_138",
        "Ensure kernel build option \"CONFIG_ACPI_CONFIGFS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_ACPI_CONFIGFS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_139",
        "Ensure kernel build option \"CONFIG_EDAC_DEBUG\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_EDAC_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_140",
        "Ensure kernel build option \"CONFIG_DRM_I915_DEBUG\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DRM_I915_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_141",
        "Ensure kernel build option \"CONFIG_BCACHE_CLOSURES_DEBUG\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BCACHE_CLOSURES_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_142",
        "Ensure kernel build option \"CONFIG_DVB_C8SECTPFE\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DVB_C8SECTPFE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_143",
        "Ensure kernel build option \"CONFIG_MTD_SLRAM\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MTD_SLRAM"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_144",
        "Ensure kernel build option \"CONFIG_MTD_PHRAM\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MTD_PHRAM"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_145",
        "Ensure kernel build option \"CONFIG_IO_URING\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_IO_URING"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_146",
        "Ensure kernel build option \"CONFIG_KCMP\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KCMP"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_147",
        "Ensure kernel build option \"CONFIG_RSEQ\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_RSEQ"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_148",
        "Ensure kernel build option \"CONFIG_LATENCYTOP\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_LATENCYTOP"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_149",
        "Ensure kernel build option \"CONFIG_KCOV\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KCOV"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_150",
        "Ensure kernel build option \"CONFIG_PROVIDE_OHCI1394_DMA_INIT\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PROVIDE_OHCI1394_DMA_INIT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_151",
        "Ensure kernel build option \"CONFIG_SUNRPC_DEBUG\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SUNRPC_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_152",
        "Ensure kernel build option \"CONFIG_X86_16BIT\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_16BIT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_153",
        "Ensure kernel build option \"CONFIG_BLK_DEV_UBLK\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_UBLK"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_154",
        "Ensure kernel build option \"CONFIG_SMB_SERVER\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SMB_SERVER"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_155",
        "Ensure kernel build option \"CONFIG_XFS_ONLINE_SCRUB_STATS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_XFS_ONLINE_SCRUB_STATS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_156",
        "Ensure kernel build option \"CONFIG_CACHESTAT_SYSCALL\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_CACHESTAT_SYSCALL"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_157",
        "Ensure kernel build option \"CONFIG_PREEMPTIRQ_TRACEPOINTS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PREEMPTIRQ_TRACEPOINTS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_158",
        "Ensure kernel build option \"CONFIG_ENABLE_DEFAULT_TRACERS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_ENABLE_DEFAULT_TRACERS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_159",
        "Ensure kernel build option \"CONFIG_PROVE_LOCKING\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PROVE_LOCKING"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_160",
        "Ensure kernel build option \"CONFIG_TEST_DEBUG_VIRTUAL\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_TEST_DEBUG_VIRTUAL"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_161",
        "Ensure kernel build option \"CONFIG_MPTCP\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MPTCP"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_162",
        "Ensure kernel build option \"CONFIG_TLS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_TLS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_163",
        "Ensure kernel build option \"CONFIG_TIPC\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_TIPC"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_164",
        "Ensure kernel build option \"CONFIG_IP_SCTP\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_IP_SCTP"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_165",
        "Ensure kernel build option \"CONFIG_KGDB\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KGDB"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_166",
        "Ensure kernel build option \"CONFIG_PTDUMP_DEBUGFS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PTDUMP_DEBUGFS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_167",
        "Ensure kernel build option \"CONFIG_X86_PTDUMP\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_PTDUMP"),
        vec![kconfig::init_kernel_build_config],
    );

    // clipos
    check::add_check(
        "KNC_170",
        "Ensure kernel build option \"CONFIG_STAGING\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_STAGING"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_171",
        "Ensure kernel build option \"CONFIG_KSM\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KSM"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_172",
        "Ensure kernel build option \"CONFIG_KALLSYMS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KALLSYMS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_173",
        "Ensure kernel build option \"CONFIG_KEXEC_FILE\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KEXEC_FILE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_174",
        "Ensure kernel build option \"CONFIG_CRASH_DUMP\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_CRASH_DUMP"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_175",
        "Ensure kernel build option \"CONFIG_USER_NS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_USER_NS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_176",
        "Ensure kernel build option \"CONFIG_X86_CPUID\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_CPUID"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_177",
        "Ensure kernel build option \"CONFIG_X86_IOPL_IOPERM\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_IOPL_IOPERM"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_178",
        "Ensure kernel build option \"CONFIG_ACPI_TABLE_UPGRADE\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_ACPI_TABLE_UPGRADE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_179",
        "Ensure kernel build option \"CONFIG_EFI_CUSTOM_SSDT_OVERLAYS\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_EFI_CUSTOM_SSDT_OVERLAYS"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_180",
        "Ensure kernel build option \"CONFIG_AIO\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_AIO"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_181",
        "Ensure kernel build option \"CONFIG_MAGIC_SYSRQ\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MAGIC_SYSRQ"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_182",
        "Ensure kernel build option \"CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_183",
        "Ensure kernel build option \"CONFIG_MAGIC_SYSRQ_SERIAL\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MAGIC_SYSRQ_SERIAL"),
        vec![kconfig::init_kernel_build_config],
    );

    // grapheneos
    check::add_check(
        "KNC_187",
        "Ensure kernel build option \"CONFIG_EFI_TEST\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_EFI_TEST"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_188",
        "Ensure kernel build option \"CONFIG_MMIOTRACE_TEST\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MMIOTRACE_TEST"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_189",
        "Ensure kernel build option \"CONFIG_KPROBES\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KPROBES"),
        vec![kconfig::init_kernel_build_config],
    );

    check::add_check(
        "KNC_191",
        "Ensure kernel build option \"CONFIG_MMIOTRACE\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MMIOTRACE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_192",
        "Ensure kernel build option \"CONFIG_LIVEPATCH\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_LIVEPATCH"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_193",
        "Ensure kernel build option \"CONFIG_IP_DCCP\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_IP_DCCP"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_194",
        "Ensure kernel build option \"CONFIG_FTRACE\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_FTRACE"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_195",
        "Ensure kernel build option \"CONFIG_VIDEO_VIVID\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_VIDEO_VIVID"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_196",
        "Ensure kernel build option \"CONFIG_INPUT_EVBUG\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_INPUT_EVBUG"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_197",
        "Ensure kernel build option \"CONFIG_CORESIGHT\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_CORESIGHT"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_198",
        "Ensure kernel build option \"CONFIG_XFS_SUPPORT_V4\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_XFS_SUPPORT_V4"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_199",
        "Ensure kernel build option \"CONFIG_BLK_DEV_WRITE_MOUNTED\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_WRITE_MOUNTED"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_200",
        "Ensure kernel build option \"CONFIG_FAULT_INJECTION\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_FAULT_INJECTION"),
        vec![kconfig::init_kernel_build_config],
    );
    check::add_check(
        "KNC_201",
        "Ensure kernel build option \"CONFIG_LKDTM\" is not set",
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_LKDTM"),
        vec![kconfig::init_kernel_build_config],
    );

    check::add_check(
        "PAM_001",
        "Ensure PAM service \"passwd\" has rule \"account required pam_unix\"",
        vec!["pam"],
        || pam::check_rule("passwd", "account", "required", "pam_unix"),
        vec![pam::init_pam],
    );
    check::add_check(
        "PAM_002",
        "Ensure PAM service \"passwd\" has rule \"password required pam_pwquality\"",
        vec!["pam"],
        || pam::check_rule("passwd", "password", "required", "pam_pwquality"),
        vec![pam::init_pam],
    );
    check::add_check(
        "PAM_015",
        "Ensure PAM service \"su\" has rule \"auth required pam_wheel\"",
        vec!["pam"],
        || pam::check_rule("su", "auth", "required", "pam_wheel"),
        vec![pam::init_pam],
    );
    check::add_check(
        "PAM_024",
        "Ensure PAM service \"login\" has rule \"auth required pam_faillock\"",
        vec!["pam"],
        || pam::check_rule("login", "auth", "required", "pam_faillock"),
        vec![pam::init_pam],
    );
    check::add_check(
        "PAM_030",
        "Ensure PAM service \"login\" has rule \"auth optional pam_faildelay\"",
        vec!["pam"],
        || pam::check_rule("login", "auth", "optional", "pam_faildelay"),
        vec![pam::init_pam],
    );

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
            const VAL: i32 = 365;
            match login_defs::get_login_defs("PASS_MAX_DAYS") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val <= VAL {
                                (check::CheckState::Success, Some(format!("{}", val)))
                            } else {
                                (
                                    check::CheckState::Failure,
                                    Some(format!("{} > {}", val, VAL)),
                                )
                            }
                        }
                        Err(error) => (check::CheckState::Error, Some(error.to_string())),
                    },
                    None => (check::CheckState::Error, None),
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
            const VAL: i32 = 1;
            match login_defs::get_login_defs("PASS_MIN_DAYS") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val >= VAL {
                                (check::CheckState::Success, Some(format!("{}", val)))
                            } else {
                                (
                                    check::CheckState::Failure,
                                    Some(format!("{} < {}", val, VAL)),
                                )
                            }
                        }
                        Err(error) => (check::CheckState::Error, Some(error.to_string())),
                    },
                    None => (check::CheckState::Error, None),
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
            const VAL: i32 = 7;
            match login_defs::get_login_defs("PASS_WARN_AGE") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val >= VAL {
                                (check::CheckState::Success, Some(format!("{}", val)))
                            } else {
                                (
                                    check::CheckState::Failure,
                                    Some(format!("{} < {}", val, VAL)),
                                )
                            }
                        }
                        Err(error) => (check::CheckState::Error, Some(error.to_string())),
                    },
                    None => (check::CheckState::Error, None),
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
            const VAL: i32 = 10;
            match login_defs::get_login_defs("LOGIN_RETRIES") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val <= VAL {
                                (check::CheckState::Success, Some(format!("{}", val)))
                            } else {
                                (
                                    check::CheckState::Failure,
                                    Some(format!("{} > {}", val, VAL)),
                                )
                            }
                        }
                        Err(error) => (check::CheckState::Error, Some(error.to_string())),
                    },
                    None => (check::CheckState::Error, None),
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
            const VAL: i32 = 60;
            match login_defs::get_login_defs("LOGIN_TIMEOUT") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val <= VAL {
                                (check::CheckState::Success, Some(format!("{}", val)))
                            } else {
                                (
                                    check::CheckState::Failure,
                                    Some(format!("{} > {}", val, VAL)),
                                )
                            }
                        }
                        Err(error) => (check::CheckState::Error, Some(error.to_string())),
                    },
                    None => (check::CheckState::Error, None),
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

    // check::add_check(
    //     "LIB_001",
    //     "Ensure \"libhardened_malloc\" hardened malloc is used system wide",
    //     vec!["malloc"],
    //     malloc::has_libhardened_malloc,
    //     vec![malloc::init_ld_so_preload],
    // );
    check::add_check(
        "LIB_001",
        "Ensure \"scudo\" hardened malloc is used system wide",
        vec!["malloc"],
        malloc::has_scudo_malloc,
        vec![malloc::init_ld_so_preload],
    );

    // TODO: only run checks if sudo is installed
    check::add_check(
        "SUD_001",
        "Ensure that sudo default config \"noexec\" is set",
        vec!["sudo"],
        || sudo::check_sudo_defaults("noexec"),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_002",
        "Ensure that sudo default config \"requiretty\" is set",
        vec!["sudo"],
        || sudo::check_sudo_defaults("requiretty"),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_003",
        "Ensure that sudo default config \"use_pty\" is set",
        vec!["sudo", "CIS"],
        || sudo::check_sudo_defaults("use_pty"),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_004",
        "Ensure that sudo default config \"umask=0027\" is set",
        vec!["sudo"],
        || sudo::check_sudo_defaults("umask=0027"),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_005",
        "Ensure that sudo default config \"ignore_dot\" is set",
        vec!["sudo"],
        || sudo::check_sudo_defaults("ignore_dot"),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_006",
        "Ensure that sudo default config \"passwd_timeout=1\" is set",
        vec!["sudo"],
        || sudo::check_sudo_defaults("passwd_timeout=1"),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_007",
        "Ensure that sudo default config \"env_reset, timestamp_timeout=15\" is set",
        vec!["sudo"],
        || sudo::check_sudo_defaults("env_reset, timestamp_timeout=15"),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_008",
        "Ensure that sudo default config \"timestamp_timeout=15\" is set",
        vec!["sudo"],
        || sudo::check_sudo_defaults("timestamp_timeout=15"),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_009",
        "Ensure that sudo default config \"env_reset\" is set",
        vec!["sudo"],
        || sudo::check_sudo_defaults("env_reset"),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_010",
        "Ensure that sudo default config \"mail_badpass\" is set",
        vec!["sudo"],
        || sudo::check_sudo_defaults("mail_badpass"),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_011",
        "Ensure that sudo default config \"logfile=\"/var/log/sudo.log\"\" is set",
        vec!["sudo", "CIS"],
        || sudo::check_sudo_defaults("logfile=\"/var/log/sudo.log\""),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_012",
        "Ensure that sudo default config \":%sudo !noexec\" is set",
        vec!["sudo"],
        || sudo::check_sudo_defaults(":%sudo !noexec"),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_013",
        "Ensure that sudo default config \"lecture=\"always\"\" is set",
        vec!["sudo"],
        || sudo::check_sudo_defaults("lecture=\"always\""),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_014",
        "Ensure that sudo default config \"lecture_file=\"/usr/share/doc/sudo_lecture.txt\"\" is set",
        vec!["sudo"],
        // TODO: should also check the content of the file
        // TODO: get the file path from the value
        || sudo::check_sudo_defaults("lecture_file=\"/usr/share/doc/sudo_lecture.txt\""),
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_015",
        "Ensure that sudoers config does not contain \"NOPASSWD\"",
        vec!["sudo", "CIS"],
        sudo::check_has_no_nopaswd,
        vec![sudo::init_sudo],
    );
    check::add_check(
        "SUD_016",
        "Ensure that sudoers re authentication is not disabled",
        vec!["sudo"],
        sudo::check_re_authentication_not_disabled,
        vec![sudo::init_sudo],
    );

    // TODO: check for configuration file permissions
    check::add_check(
        "SSH_001",
        "Ensure that sshd is configured with \"fingerprinthash\" = \"SHA256\"",
        vec!["sshd"],
        || sshd::check_sshd_config("fingerprinthash", "SHA256"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_002",
        "Ensure that sshd is configured with \"syslogfacility\" = \"AUTH\"",
        vec!["sshd"],
        || sshd::check_sshd_config("syslogfacility", "AUTH"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_003",
        "Ensure that sshd is configured with \"loglevel\" = \"VERBOSE\"",
        vec!["sshd", "CIS", "mozilla"],
        || sshd::check_sshd_config("loglevel", "VERBOSE"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_004",
        "Ensure that sshd is configured with \"logingracetime\" <= 60",
        vec!["sshd", "CIS"],
        || {
            const VAL: i32 = 60;
            match sshd::get_sshd_config("logingracetime") {
                Ok(str_value) => match str_value.parse::<i32>() {
                    Ok(value) => {
                        if value <= VAL {
                            (check::CheckState::Success, Some(format!("{}", value)))
                        } else {
                            (
                                check::CheckState::Failure,
                                Some(format!("{} > {}", value, VAL)),
                            )
                        }
                    }
                    Err(error) => (check::CheckState::Error, Some(error.to_string())),
                },
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_005",
        "Ensure that sshd is configured with \"permitrootlogin\" = \"no\"",
        vec!["sshd", "CIS", "mozilla"],
        || sshd::check_sshd_config("permitrootlogin", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_006",
        "Ensure that sshd is configured with \"strictmodes\" = \"yes\"",
        vec!["sshd"],
        || sshd::check_sshd_config("strictmodes", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_007",
        "Ensure that sshd is configured with \"maxauthtries\" <= 2",
        vec!["sshd", "CIS"],
        || {
            const VAL: i32 = 2;
            match sshd::get_sshd_config("maxauthtries") {
                Ok(str_value) => match str_value.parse::<i32>() {
                    Ok(value) => {
                        if value <= VAL {
                            (check::CheckState::Success, Some(format!("{}", value)))
                        } else {
                            (
                                check::CheckState::Failure,
                                Some(format!("{} > {}", value, VAL)),
                            )
                        }
                    }
                    Err(error) => (check::CheckState::Error, Some(error.to_string())),
                },
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_008",
        "Ensure that sshd is configured with \"maxsessions\" <= 2",
        vec!["sshd", "CIS"],
        || {
            const VAL: i32 = 2;
            match sshd::get_sshd_config("maxauthtries") {
                Ok(str_value) => match str_value.parse::<i32>() {
                    Ok(value) => {
                        if value <= VAL {
                            (check::CheckState::Success, Some(format!("{}", value)))
                        } else {
                            (
                                check::CheckState::Failure,
                                Some(format!("{} > {}", value, VAL)),
                            )
                        }
                    }
                    Err(error) => (check::CheckState::Error, Some(error.to_string())),
                },
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_009",
        "Ensure that sshd is configured with \"hostbasedauthentication\" = \"no\"",
        vec!["sshd", "CIS"],
        || sshd::check_sshd_config("hostbasedauthentication", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_010",
        "Ensure that sshd is configured with \"ignorerhosts\" = \"yes\"",
        vec!["sshd", "CIS"],
        || sshd::check_sshd_config("ignorerhosts", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_011",
        "Ensure that sshd is configured with \"ignoreuserknownhosts\" = \"yes\"",
        vec!["sshd"],
        || sshd::check_sshd_config("", ""),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_012",
        "Ensure that sshd is configured with \"pubkeyauthentication\" = \"yes\"",
        vec!["sshd"],
        || sshd::check_sshd_config("pubkeyauthentication", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_013",
        "Ensure that sshd is configured with \"passwordauthentication\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("passwordauthentication", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_014",
        "Ensure that sshd is configured with \"kbdinteractiveauthentication\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("kbdinteractiveauthentication", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_015",
        "Ensure that sshd is configured with \"permitemptypasswords\" = \"no\"",
        vec!["sshd", "CIS", "STIG"],
        || sshd::check_sshd_config("permitemptypasswords", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_016",
        "Ensure that sshd is configured with \"kerberosauthentication\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("kerberosauthentication", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_017",
        "Ensure that sshd is configured with \"kerberosorlocalpasswd\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("kerberosorlocalpasswd", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_018",
        "Ensure that sshd is configured with \"kerberosticketcleanup\" = \"yes\"",
        vec!["sshd"],
        || sshd::check_sshd_config("kerberosticketcleanup", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_019",
        "Ensure that sshd is configured with \"gssapiauthentication\" = \"no\"",
        vec!["sshd", "CIS"],
        || sshd::check_sshd_config("gssapiauthentication", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_020",
        "Ensure that sshd is configured with \"gssapicleanupcredentials\" = \"yes\"",
        vec!["sshd"],
        || sshd::check_sshd_config("gssapicleanupcredentials", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_037",
        "Ensure that sshd is configured with \"usepam\" = \"yes\"",
        vec!["sshd", "CIS", "STIG"],
        || sshd::check_sshd_config("usepam", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_025",
        "Ensure that sshd is configured with \"disableforwarding\" = \"yes\"",
        vec!["sshd", "CIS"],
        || sshd::check_sshd_config("disableforwarding", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_021",
        "Ensure that sshd is configured with \"x11forwarding\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("x11forwarding", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_022",
        "Ensure that sshd is configured with \"allowagentforwarding\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("allowagentforwarding", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_023",
        "Ensure that sshd is configured with \"allowstreamlocalforwarding\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("allowstreamlocalforwarding", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_024",
        "Ensure that sshd is configured with \"allowtcpforwarding\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("allowtcpforwarding", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_026",
        "Ensure that sshd is configured with \"gatewayports\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("gatewayports", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_027",
        "Ensure that sshd is configured with \"x11uselocalhost\" = \"yes\"",
        vec!["sshd"],
        || sshd::check_sshd_config("x11uselocalhost", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_028",
        "Ensure that sshd is configured with \"printmotd\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("printmotd", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_029",
        "Ensure that sshd is configured with \"permituserenvironment\" = \"no\"",
        vec!["sshd", "CIS"],
        || sshd::check_sshd_config("permituserenvironment", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_030",
        "Ensure that sshd is configured with \"clientaliveinterval\" <= 15",
        vec!["sshd", "CIS"],
        || {
            const VAL: i32 = 15;
            match sshd::get_sshd_config("maxauthtries") {
                Ok(str_value) => match str_value.parse::<i32>() {
                    Ok(value) => {
                        if value <= VAL {
                            (check::CheckState::Success, Some(format!("{}", value)))
                        } else {
                            (
                                check::CheckState::Failure,
                                Some(format!("{} > {}", value, VAL)),
                            )
                        }
                    }
                    Err(error) => (check::CheckState::Error, Some(error.to_string())),
                },
                Err(error) => (check::CheckState::Error, Some(error)),
            }
        },
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_031",
        "Ensure that sshd is configured with \"clientalivecountmax\" = \"0\"",
        vec!["sshd"],
        || sshd::check_sshd_config("clientalivecountmax", "0"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_032",
        "Ensure that sshd is configured with \"tcpkeepalive\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("tcpkeepalive", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_033",
        "Ensure that sshd is configured with \"usedns\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("usedns", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_034",
        "Ensure that sshd is configured with \"permittunnel\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("permittunnel", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_035",
        "Ensure that sshd is configured with \"maxstartups\" = \"10:30:60\"",
        vec!["sshd", "CIS"],
        || sshd::check_sshd_config("maxstartups", "10:30:60"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_036",
        "Ensure that sshd is configured with \"printlastlog\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("printlastlog", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_037",
        "Ensure that sshd is configured with \"allowgroups\" = \"sshusers\"",
        vec!["sshd"],
        // TODO: ensure the group also exist
        || sshd::check_sshd_config("allowgroups", "sshusers"),
        vec![sshd::init_sshd_config],
    );
    // TODO: make skip it depending based on version, OpenSSH 6.7+
    check::add_check(
        "SSH_038",
        "Ensure that sshd is configured with \"kexalgorithms\" = \"curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256\"",
        vec!["sshd", "mozilla"],
        || sshd::check_sshd_config("kexalgorithms", "curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_039",
        "Ensure that sshd is configured with \"ciphers\" = \"chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\"",
        vec!["sshd", "mozilla"],
        || sshd::check_sshd_config("ciphers", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_040",
        "Ensure that sshd is configured with \"macs\" = \"hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com\"",
        vec!["sshd", "mozilla"],
        || sshd::check_sshd_config("macs", "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_041",
        "Ensure that sshd is configured with \"authenticationmethods\" = \"publickey\"",
        vec!["sshd", "mozilla"],
        || sshd::check_sshd_config("authenticationmethods", "publickey"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_042",
        "Ensure that sshd is configured with \"subsystem\" = \"sftp /usr/lib/ssh/sftp-server -f AUTHPRIV -l INFO\"",
        vec!["sshd", "mozilla"],
        || sshd::check_sshd_config("subsystem", "sftp /usr/lib/ssh/sftp-server -f AUTHPRIV -l INFO"),
        vec![sshd::init_sshd_config],
    );
    // TODO: check the content of File: /etc/ssh/moduli from: https://infosec.mozilla.org/guidelines/openssh
    // TODO: add OpenSSH client rules: https://infosec.mozilla.org/guidelines/openssh#openssh-client

    check::add_check(
        "SHL_001",
        "Ensure automatic logout from shells is configured",
        vec!["shell"],
        shell::check_shell_timeout,
        vec![],
    );
}
