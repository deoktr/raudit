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
    )
    .with_description("Restrict kernel address visibility via /proc and other interfaces, regardless of user privileges, kernel pointers expose specific locations in kernel memory, will hide kernel symbol addresses in /proc/kallsyms.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_002",
        vec!["sysctl", "server", "workstation"],
        "kernel.ftrace_enabled",
        0
    )
    .with_description("Disable ftrace debugging.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_003",
        vec!["sysctl", "CIS", "server", "workstation"],
        "kernel.randomize_va_space",
        2
    )
    .with_description("Enable ASLR for mmap base, stack, VDSO pages, and heap, forces shared libraries to be loaded to random addresses start location. Can lead to breakages with legacy applications.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_004",
        vec!["sysctl", "server", "workstation"],
        "kernel.dmesg_restrict",
        1
    )
    .with_description("Restrict access to the kernel log buffer to users with CAP_SYSLOG, kernel logs often contain sensitive information such as kernel pointers.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_005",
        vec!["sysctl", "server", "workstation"],
        "kernel.printk",
        "3\t3\t3\t3"
    )
    .with_description("Prevent kernel information leaks in the console during boot must be used in conjunction with kernel boot parameters.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_006",
        vec!["sysctl", "server", "workstation"],
        "kernel.perf_cpu_time_max_percent",
        1
    )
    .register();

    sysctl::add_sysctl_check!(
        "SYS_007",
        vec!["sysctl", "server", "workstation"],
        "kernel.perf_event_max_sample_rate",
        1
    )
    .register();
    // 2 or 3
    check::Check::new(
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
    )
    .with_description("Restricts kernel profiling to users with CAP_PERFMON, the performance events system should not be accessible by unprivileged users, they add considerable kernel attack surface. Can be 2 or 3.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_009",
        vec!["sysctl", "server", "workstation"],
        "kernel.sysrq",
        0
    )
    .with_description("Disable the SysRq key to prevent leakage of kernel information, the Secure Attention Key (SAK) can no longer be utilized.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_010",
        vec!["sysctl", "server", "workstation", "tails"],
        "kernel.kexec_load_disabled",
        1
    )
    .with_description("Disables kexec, which can be used to replace the running kernel, which is only useful for live kernel patching without rebooting.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_011",
        vec!["sysctl", "bpf", "server", "workstation"],
        "kernel.unprivileged_bpf_disabled",
        1
    )
    .with_description(
        "Restrict eBPF access to CAP_BPF. This will prevent trace and the debug of BPF programs.",
    )
    .register();

    sysctl::add_sysctl_check!(
        "SYS_012",
        vec!["sysctl", "bpf", "server", "workstation", "tails"],
        "net.core.bpf_jit_harden",
        2
    )
    .with_description("Enable eBPF associated JIT compiler hardening.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_013",
        vec!["sysctl", "server", "workstation"],
        "kernel.panic_on_oops",
        1
    )
    .with_description("Force the kernel to panic on \"oopses\", can sometimes potentially indicate and thwart certain kernel exploitation attempts, also cause panics on machine check exceptions. Some bad drivers can cause harmless oopses which result in system crash.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_014",
        vec!["sysctl", "server", "workstation"],
        "kernel.panic",
        "-1"
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_015",
        vec!["sysctl", "server", "workstation"],
        "kernel.modules_disabled",
        1
    )
    .register();
    // FIXME: only available on Debian, create custom rule to check if OS is debian, else ignore
    // NOTE: prevents Podman from working rootless
    sysctl::add_sysctl_check!(
        "SYS_016",
        vec!["sysctl", "server", "workstation"],
        "kernel.unprivileged_userns_clone",
        0
    )
    .register();
    // check::Check::new(
    //     "SYS_016",
    //     "Ensure sysctl 'kernel.unprivileged_userns_clone' == 0",
    //     vec!["sysctl", "server", "workstation"],
    //     || sysctl::get_ssyctl_wrapper("kernel.unprivileged_userns_clone", 0),
    //     vec![sysctl::init_sysctl_config, os::init_os],
    // ).register();

    // 2 or 3, CIS recommends 1
    check::Check::new(
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
    )
    .with_description("Limit ptrace() as it enables programs to inspect and modify other active processes, prevents native code debugging which some programs use as a method to detect tampering, may cause breakages in 'anti-cheat' software and programs running under Proton/WINE.
  - 1: Avoid non-ancestor ptrace access to running processes and their creds.
  - 2: Restrict ptrace access to processes with CAP_SYS_PTRACE.
  - 3: Completely disable ptrace.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_018",
        vec!["sysctl", "server", "workstation"],
        "kernel.io_uring_disabled",
        2
    )
    .with_description("Disable asynchronous I/O for all processes, leading cause of numerous kernel exploits disabling will reduce the read/write performance of storage devices. Applicable when using Linux kernel >= 6.6")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_019",
        vec!["sysctl", "server", "workstation"],
        "kernel.core_pattern",
        "|/bin/false"
    )
    .with_description("Disable core dump files by preventing any pattern names, this setting may be overwritten by systemd and is not comprehensive core dumps are also disabled in security-misc via other means.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_020",
        vec!["sysctl", "server", "workstation"],
        "kernel.core_uses_pid",
        1
    )
    .with_description("Set core dump file name to \"core.PID\" instead of \"core\" as a form of defense-in-depth, if core dumps are permitted, only useful if PID listings are hidden from non-root users.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_021",
        vec!["sysctl", "server", "workstation"],
        "vm.unprivileged_userfaultfd",
        0
    )
    .with_description("Restrict the userfaultfd() syscall to users with SYS_CAP_PTRACE reduces the likelihood of use-after-free exploits from heap sprays.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_022",
        vec!["sysctl", "server", "workstation", "tails"],
        "vm.mmap_rnd_bits",
        32
    )
    .with_description("Maximize bits of entropy for improved effectiveness of mmap ASLR the maximum number of bits depends on CPU architecture.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_023",
        vec!["sysctl", "server", "workstation", "tails"],
        "vm.mmap_rnd_compat_bits",
        16
    )
    .with_description("Maximize bits of entropy for improved effectiveness of mmap ASLR the maximum number of bits depends on CPU architecture.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_024",
        vec!["sysctl", "server", "workstation"],
        "vm.mmap_min_addr",
        65536
    )
    .with_description("A kernel null dereference bugs could accidentally operate based on the information in the first couple of pages of memory, userspace processes should not be allowed to write to them. Provide defense in depth against future potential kernel bugs.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_025",
        vec!["sysctl", "server", "workstation"],
        "dev.tty.ldisc_autoload",
        0
    )
    .with_description("Restrict loading TTY line disciplines to users with CAP_SYS_MODULE.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_026",
        vec!["sysctl", "server", "workstation"],
        "dev.tty.legacy_tiocsti",
        0
    )
    .with_description("Disable the use of legacy TIOCSTI operations which can be used to inject keypresses, can lead to privilege escalation by pushing characters into a controlling TTY. Will break out-dated screen readers that continue to rely on this legacy functionality.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_027",
        vec!["sysctl", "server", "workstation"],
        "vm.max_map_count",
        1048576
    )
    .with_description("Increase the maximum number of memory map areas a process is permitted to utilize. Can lead to addresses performance, crash, and start-up issues for some memory-intensive applications. Required to accommodate the very large number of guard pages created by hardened_malloc.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_028",
        vec!["sysctl", "server", "workstation"],
        "vm.swappiness",
        1
    )
    .with_description("Limit the copying of memory to the swap device only if absolutely necessary, minimizes the likelihood of writing potentially sensitive contents to disk, not recommended to set to zero since this disables periodic write behavior.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_029",
        vec!["sysctl", "fs", "CIS", "server", "workstation"],
        "fs.suid_dumpable",
        0
    )
    .with_description("Prevent setuid processes or otherwise protected/tainted binaries from creating core dumps, any process which has changed privilege levels or is execute-only will not be dumped.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_030",
        vec!["sysctl", "fs", "server", "workstation"],
        "fs.protected_fifos",
        2
    )
    .with_description("Disallow writes to files in world-writable sticky directories unless owned by the directory owner, also applies to group-writable sticky directories to make data spoofing attacks more difficult prevents unintentional writes to attacker-controlled files.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_031",
        vec!["sysctl", "fs", "server", "workstation"],
        "fs.protected_regular",
        2
    )
    .with_description("Disallow writes to files in world-writable sticky directories unless owned by the directory owner, also applies to group-writable sticky directories to make data spoofing attacks more difficult prevents unintentional writes to attacker-controlled files.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_032",
        vec!["sysctl", "fs", "server", "workstation"],
        "fs.protected_symlinks",
        1
    )
    .with_description("Prevent symlink creation by users who do not have read/write/ownership of source file, only allow symlinks to be followed when outside of world-writable sticky directories. Hardens cross-privilege boundaries if root process follows a hardlink/symlink belonging to another user, this mitigates many symlink-based TOCTOU races in world-writable directories like /tmp.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_033",
        vec!["sysctl", "fs", "server", "workstation"],
        "fs.protected_hardlinks",
        1
    )
    .with_description("Prevent hardlink creation by users who do not have read/write/ownership of source file, only allow hardlink to be followed when outside of world-writable sticky directories. Hardens cross-privilege boundaries if root process follows a hardlink/symlink belonging to another user, this mitigates many hardlink-based TOCTOU races in world-writable directories like /tmp.")
    .register();

    check::Check::new(
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
    )
    .with_description("Disable the miscellaneous binary format virtual file system to prevent unintended code execution.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_035",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.ip_forward",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_036",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.accept_source_route",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_037",
        vec!["sysctl", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.default.accept_source_route",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_038",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.accept_source_route",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_039",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.default.accept_source_route",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_040",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.accept_redirects",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_041",
        vec!["sysctl", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.default.accept_redirects",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_042",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.secure_redirects",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_043",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.default.secure_redirects",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_044",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.send_redirects",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_045",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.default.send_redirects",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_046",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.accept_redirects",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_047",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.default.accept_redirects",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_050",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.icmp_echo_ignore_all",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_051",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.icmp.echo_ignore_all",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_052",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.icmp_echo_ignore_broadcasts",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_053",
        vec!["sysctl", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.all.rp_filter",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_054",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.conf.default.rp_filter",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_055",
        vec!["sysctl", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.icmp_ignore_bogus_error_responses",
        1
    )
    .register();
    check::Check::new(
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
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_057",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.icmp_ratemask",
        88089
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_058",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv4.tcp_syncookies",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_059",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.accept_local",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_060",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.shared_media",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_061",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.default.shared_media",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_062",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.arp_filter",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_063",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.arp_ignore",
        2
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_064",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.default.arp_ignore",
        2
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_065",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.default.arp_announce",
        2
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_066",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.arp_announce",
        2
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_067",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.route_localnet",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_068",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.drop_gratuitous_arp",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_069",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.ip_local_port_range",
        "32768\t65535"
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_070",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.tcp_rfc1337",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_071",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.forwarding",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_072",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.forwarding",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_073",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.accept_ra",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_074",
        vec!["sysctl", "CIS", "server", "workstation"],
        "net.ipv6.conf.default.accept_ra",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_075",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.tcp_timestamps",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_076",
        vec!["sysctl", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.all.log_martians",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_077",
        vec!["sysctl", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.default.log_martians",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_078",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.all.router_solicitations",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_079",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.router_solicitations",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_080",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.all.accept_ra_rtr_pref",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_081",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.accept_ra_rtr_pref",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_082",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.all.accept_ra_defrtr",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_083",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.accept_ra_defrtr",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_084",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.all.autoconf",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_085",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.autoconf",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_086",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.all.max_addresses",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_087",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.max_addresses",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_088",
        vec!["sysctl", "bpf", "paranoid", "server", "workstation"],
        "net.core.bpf_jit_enable",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_089",
        vec!["sysctl", "paranoid", "server", "workstation"],
        "net.ipv4.tcp_sack",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_090",
        vec!["sysctl", "paranoid", "server", "workstation"],
        "net.ipv4.tcp_dsack",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_091",
        vec!["sysctl", "paranoid", "server", "workstation"],
        "net.ipv4.tcp_fack",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_092",
        vec!["sysctl", "paranoid", "server", "workstation"],
        "net.ipv6.conf.all.use_tempaddr",
        2
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_093",
        vec!["sysctl", "paranoid", "server", "workstation"],
        "net.ipv6.conf.default.use_tempaddr",
        2
    )
    .register();

    check::Check::new(
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
    )
    .with_description("Cut attack surface by limiting the number of user namespaces. May break the upower daemon in Ubuntu.")
    .register();

    check::Check::new(
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
    )
    .with_description("Will have no effects if kernel param \"oops=panic\" is set, but is a better default if it's not.")
    .register();

    check::Check::new(
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
    )
    .with_description("Will have no effects if kernel param \"oops=panic\" is set, but is a better default if it's not.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_097",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.tcp_synack_retries",
        5
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_098",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.icmp.echo_ignore_anycast",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_099",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.icmp.echo_ignore_multicast",
        1
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_100",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.forwarding",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_101",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.default.forwarding",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_102",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.all.mc_forwarding",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_103",
        vec!["sysctl", "server", "workstation"],
        "net.ipv4.conf.default.mc_forwarding",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_104",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.all.mc_forwarding",
        0
    )
    .register();
    sysctl::add_sysctl_check!(
        "SYS_105",
        vec!["sysctl", "server", "workstation"],
        "net.ipv6.conf.default.mc_forwarding",
        0
    )
    .register();
}
