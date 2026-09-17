// sources:
// - tails: https://tails.net/contribute/design/kernel_hardening/

use crate::check;
use crate::check::Severity;
use crate::modules::sysctl;

pub fn add_checks() {
    // Note disabling IPv6 via 'net.ipv6.conf.all.disable_ipv6' is not included
    // as a rule even if it's a CIS rule, this is because it does not increase
    // the security
    sysctl::add_sysctl_check!(
        "SYS_001",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation", "tails"],
        "kernel.kptr_restrict",
        // TODO: allow for 1 as well
        2
    )
    .with_description("Restrict kernel address visibility via /proc and other interfaces, regardless of user privileges, kernel pointers expose specific locations in kernel memory, will hide kernel symbol addresses in /proc/kallsyms.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_002",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.ftrace_enabled",
        0
    )
    .with_description("Disable ftrace debugging. Ftrace provides tracing facilities for the kernel that can expose sensitive information. Disabling it breaks kernel tracing and profiling tools (e.g. perf, bpftrace) that rely on ftrace.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_003",
        Severity::Medium,
        vec!["sysctl", "KSPP", "CIS", "server", "workstation"],
        "kernel.randomize_va_space",
        2
    )
    .with_description("Enable ASLR for mmap base, stack, VDSO pages, and heap. Forces shared libraries to be loaded at random addresses. May cause breakages with legacy applications.")
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#kernel-address-space-layout-randomization-kaslr")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_004",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        "kernel.dmesg_restrict",
        1
    )
    .with_description("Restrict access to the kernel log buffer to users with CAP_SYSLOG. Kernel logs often contain sensitive information such as kernel pointers. Non-root users and scripts that read dmesg will no longer work.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_005",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.printk",
        "3\t3\t3\t3"
    )
    .with_description("Prevent kernel information leaks in the console during boot. Must be used in conjunction with kernel boot parameters.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_006",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.perf_cpu_time_max_percent",
        1
    )
    .with_description("Cap perf CPU usage. Without a low cap, perf and perf-based tracing/profiling can consume excessive CPU on busy systems, increasing attack surface for DoS via heavy tracing workloads.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_007",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.perf_event_max_sample_rate",
        1
    )
    .with_description("Cap perf sample rate. Uncapped rates produce timing oracles and let unprivileged perf users dominate the perf subsystem, slowing security-relevant workloads.")
    .register();

    // 2 or 3
    check::Check::new(
        "SYS_008",
        "Ensure sysctl \"kernel.perf_event_paranoid\" = 2 or 3",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        || {
            match sysctl::get_sysctl_i32_value("kernel.perf_event_paranoid") {
                Ok(value) => {
                    if value == 2 || value == 3 {
                        (check::CheckState::Pass, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Fail,
                            Some(format!("{} != 2 or 3", value)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("Restrict kernel profiling to users with CAP_PERFMON. The performance events system should not be accessible by unprivileged users, as it adds considerable kernel attack surface. Can be 2 or 3.")
    .with_fix("Add \"kernel.perf_event_paranoid = 2\" (or 3) in \"/etc/sysctl.d/*.conf\" and run \"sysctl --system\".")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_009",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.sysrq",
        0
    )
    .with_description("Disable the SysRq key to prevent leakage of kernel information. The Secure Attention Key (SAK) can no longer be utilized.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_010",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation", "tails"],
        "kernel.kexec_load_disabled",
        1
    )
    .with_description("Disable kexec. Kexec can be used to replace the running kernel, which is only useful for live kernel patching without rebooting.")
    .register();

    // TODO: ignore if using Podman or Docker rootless
    sysctl::add_sysctl_check!(
        "SYS_011",
        Severity::Medium,
        vec!["sysctl", "bpf", "KSPP", "server", "workstation"],
        "kernel.unprivileged_bpf_disabled",
        1
    )
    .with_description(
        "Restrict eBPF access to CAP_BPF. This prevents tracing and debugging of BPF programs. Breaks unprivileged BPF programs (e.g. rootless containers, network monitoring tools), leave it to 0 if using rootless containers.",
    )
    .register();

    sysctl::add_sysctl_check!(
        "SYS_012",
        Severity::High,
        vec!["sysctl", "bpf", "KSPP", "server", "workstation", "tails"],
        "net.core.bpf_jit_harden",
        2
    )
    .with_description("Enable eBPF JIT compiler hardening. Hardens the JIT compiler against exploitation. Adds a performance penalty to BPF program execution.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_013",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.panic_on_oops",
        1
    )
    .with_description("Force the kernel to panic on oopses. This can potentially indicate and thwart certain kernel exploitation attempts, and also causes panics on machine check exceptions. Some bad drivers can cause harmless oopses which result in system crash.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_014",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.panic",
        "-1"
    )
    .with_description("Reboot immediately on kernel panic. A panic could indicate an exploitation attempt. Appropriate for security-critical hosts where the safe response to a corruption-detected event is reboot, not stay-up.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_015",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        "kernel.modules_disabled",
        1
    )
    .with_description("Permanently disable module loading once set. Any later attempt by an attacker (even with CAP_SYS_MODULE and root) to load a module is rejected by the kernel. This could prevent loading backdoor or vulnerable modules. For systems needing hot-add drivers, it prevents legitimate module loading.")
    .register();

    // FIXME: only available on some kernels
    // NOTE: prevents Docker and Podman from working rootless
    sysctl::add_sysctl_check!(
        "SYS_016",
        Severity::High,
        vec!["sysctl", "server", "workstation"],
        "kernel.unprivileged_userns_clone",
        0
    )
    .with_description("Disable unprivileged user namespaces. Unprivileged userns_clone greatly increases the attack surface for local privilege escalation. Note that disabling this will prevent Docker and Podman from working rootless.")
    .with_link("https://gitlab.com/apparmor/apparmor/-/wikis/unprivileged_userns_restriction")
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
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        || {
            const VAL: i32 = 1;
            match sysctl::get_sysctl_i32_value("kernel.yama.ptrace_scope") {
                Ok(value) => {
                    if value >= VAL {
                        (check::CheckState::Pass, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Fail,
                            Some(format!("{} > {}", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("Limit ptrace() as it enables programs to inspect and modify other active processes. Prevents native code debugging which some programs use as a method to detect tampering. May cause breakages in anti-cheat software and programs running under Proton/WINE.
  - 1: Avoid non-ancestor ptrace access to running processes and their creds.
  - 2: Restrict ptrace access to processes with CAP_SYS_PTRACE.
  - 3: Completely disable ptrace.")
    .with_fix("Add \"kernel.yama.ptrace_scope = 1\" (or 2 or 3) in \"/etc/sysctl.d/*.conf\" and run \"sysctl --system\".")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_018",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.io_uring_disabled",
        2
    )
    .with_description("Disable asynchronous I/O for all processes. io_uring is a leading cause of numerous kernel exploits. Disabling will reduce the read/write performance of storage devices. Applicable when using Linux kernel >= 6.6.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_019",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.core_pattern",
        "|/bin/false"
    )
    .with_description("Disable core dump files by preventing any pattern names. This prevents post-mortem debugging of crashing processes. This setting may be overwritten by systemd.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_020",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.core_uses_pid",
        1
    )
    .with_description("Set core dump file name to \"core.PID\" instead of \"core\" as a form of defense-in-depth. Only useful if PID listings are hidden from non-root users and core dumps are permitted.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_021",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        "vm.unprivileged_userfaultfd",
        0
    )
    .with_description("Restrict the userfaultfd() syscall to users with SYS_CAP_PTRACE. Reduces the likelihood of use-after-free exploits from heap sprays. Breaks applications that rely on userfaultfd for user-space paging (e.g. some Java GCs, game engines, databases with memory-mapped files).")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_022",
        Severity::Medium,
        vec!["sysctl", "server", "workstation", "tails"],
        "vm.mmap_rnd_bits",
        32
    )
    .with_description("Maximize bits of entropy for improved effectiveness of mmap ASLR. The maximum number of bits depends on CPU architecture.")
    .register();

    // TODO: either set vm.mmap_rnd_bits or vm.mmap_rnd_compat_bits ?
    sysctl::add_sysctl_check!(
        "SYS_023",
        Severity::Medium,
        vec!["sysctl", "server", "workstation", "tails"],
        "vm.mmap_rnd_compat_bits",
        16
    )
    .with_description("Maximize bits of entropy for improved effectiveness of mmap ASLR. The maximum number of bits depends on CPU architecture.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_024",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "vm.mmap_min_addr",
        65536
    )
    .with_description("Prevent userspace processes from mapping the first few pages of memory. A kernel null dereference bug could accidentally operate based on information in the first couple of pages. Provides defense in depth against future potential kernel bugs. May break some legacy applications or Wine that map low memory addresses.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_025",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        "dev.tty.ldisc_autoload",
        0
    )
    .with_description("Restrict loading TTY line disciplines to users with CAP_SYS_MODULE. Prevents unprivileged users from loading arbitrary line disciplines. May break software that relies on dynamically loading TTY line disciplines (e.g. some serial port tools, pppd).")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_026",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        "dev.tty.legacy_tiocsti",
        0
    )
    .with_description("Disable legacy TIOCSTI operations. These can be used to inject keypresses, leading to privilege escalation by pushing characters into a controlling TTY. Will break outdated screen readers that continue to rely on this legacy functionality.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_027",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "vm.max_map_count",
        1048576
    )
    .with_description("Increase the maximum number of memory map areas a process is permitted to utilize. Can lead to performance, crash, and start-up issues for some memory-intensive applications. Required to accommodate the very large number of guard pages created by hardened_malloc.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_028",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "vm.swappiness",
        1
    )
    .with_description("Limit swapping to only when absolutely necessary. Minimizes the likelihood of writing potentially sensitive contents to disk. Not recommended to set to zero since this disables periodic write behavior.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_029",
        Severity::Medium,
        vec!["sysctl", "fs", "KSPP", "CIS", "server", "workstation"],
        "fs.suid_dumpable",
        0
    )
    .with_description("Prevent setuid processes or otherwise protected/tainted binaries from creating core dumps. Any process which has changed privilege levels or is execute-only will not be dumped. Provides defense-in-depth if core dumps are permitted.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_030",
        Severity::Medium,
        vec!["sysctl", "fs", "KSPP", "server", "workstation"],
        "fs.protected_fifos",
        2
    )
    .with_description("Disallow writes to files in world-writable sticky directories unless owned by the directory owner. Also applies to group-writable sticky directories to make data spoofing attacks more difficult and prevents unintentional writes to attacker-controlled files.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_031",
        Severity::Medium,
        vec!["sysctl", "fs", "KSPP", "server", "workstation"],
        "fs.protected_regular",
        2
    )
    .with_description("Disallow writes to files in world-writable sticky directories unless owned by the directory owner. Also applies to group-writable sticky directories to make data spoofing attacks more difficult and prevents unintentional writes to attacker-controlled files.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_032",
        Severity::Medium,
        vec!["sysctl", "fs", "KSPP", "server", "workstation"],
        "fs.protected_symlinks",
        1
    )
    .with_description("Prevent symlink creation by users who do not have read/write/ownership of source file. Only allow symlinks to be followed when outside of world-writable sticky directories. Hardens cross-privilege boundaries if root process follows a hardlink/symlink belonging to another user. This mitigates many symlink-based TOCTOU races in world-writable directories like /tmp.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_033",
        Severity::Medium,
        vec!["sysctl", "fs", "KSPP", "server", "workstation"],
        "fs.protected_hardlinks",
        1
    )
    .with_description("Prevent hardlink creation by users who do not have read/write/ownership of source file. Only allow hardlinks to be followed when outside of world-writable sticky directories. Hardens cross-privilege boundaries if root process follows a hardlink/symlink belonging to another user. This mitigates many hardlink-based TOCTOU races in world-writable directories like /tmp.")
    .register();

    check::Check::new(
        "SYS_034",
        "Ensure sysctl \"fs.binfmt_misc.status\" = 0",
        Severity::Medium,
        vec!["sysctl", "fs", "server", "workstation"],
        || {
            let (status, message) = sysctl::check_sysctl("fs.binfmt_misc.status", 0);
            // ignore if not present
            if status == check::CheckState::Warning {
                (check::CheckState::Pass, None)
            } else {
                (status, message)
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("Disable the miscellaneous binary format virtual file system to prevent unintended code execution. Breaks the ability to execute foreign binary formats via binfmt_misc (e.g. QEMU user-mode emulation for running ARM binaries on x86, running .exe via Wine).")
    .with_fix("Add \"fs.binfmt_misc.status = 0\" in \"/etc/sysctl.d/*.conf\" and run \"sysctl --system\".")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_035",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.ip_forward",
        0
    )
    .with_description("Disable IPv4 packet forwarding. Non-routers should not forward packets, as it enables the host to be used as a pivot for network-level attacks.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_036",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.accept_source_route",
        0
    )
    .with_description("Disable acceptance of source-routed packets. Source routing allows the sender to specify the path, which could be used to bypass network security controls. Breaks legacy diagnostic tools (e.g. traceroute with source routing).")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_037",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.default.accept_source_route",
        0
    )
    .with_description("Disable acceptance of source-routed packets. Source routing allows the sender to specify the path, which could be used to bypass network security controls. Breaks legacy diagnostic tools (e.g. traceroute with source routing).")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_038",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.accept_source_route",
        0
    )
    .with_description("Disable acceptance of IPv6 source-routed packets. Source routing allows the sender to specify the path, which could be used to bypass network security controls. Breaks legacy diagnostic tools (e.g. traceroute with source routing).")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_039",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.default.accept_source_route",
        0
    )
    .with_description("Disable acceptance of IPv6 source-routed packets. Source routing allows the sender to specify the path, which could be used to bypass network security controls. Breaks legacy diagnostic tools (e.g. traceroute with source routing).")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_040",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.accept_redirects",
        0
    )
    .with_description("Disable acceptance of ICMP redirects. Prevents the system from learning better routes from network routers. May break connectivity on networks that rely on ICMP redirects for optimal routing.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_041",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.default.accept_redirects",
        0
    )
    .with_description("Disable acceptance of ICMP redirects. Prevents the system from learning better routes from network routers. May break connectivity on networks that rely on ICMP redirects for optimal routing.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_042",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.secure_redirects",
        0
    )
    .with_description("Disable acceptance of secure ICMP redirects. Prevents the system from learning better routes from trusted gateways. May break connectivity on networks that rely on ICMP redirects for optimal routing.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_043",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.default.secure_redirects",
        0
    )
    .with_description("Disable acceptance of secure ICMP redirects. Prevents the system from learning better routes from trusted gateways. May break connectivity on networks that rely on ICMP redirects for optimal routing.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_044",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.send_redirects",
        0
    )
    .with_description("Disable sending of ICMP redirects. The system will no longer inform hosts of better routes. Breaks optimal routing on networks where this host acts as a gateway.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_045",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.default.send_redirects",
        0
    )
    .with_description("Disable sending of ICMP redirects. The system will no longer inform hosts of better routes. Breaks optimal routing on networks where this host acts as a gateway.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_046",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.accept_redirects",
        0
    )
    .with_description("Disable sending of IPv6 ICMP redirects. The system will no longer inform hosts of better routes. Breaks optimal routing on IPv6 networks where this host acts as a gateway.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_047",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.default.accept_redirects",
        0
    )
    .with_description("Disable sending of IPv6 ICMP redirects. The system will no longer inform hosts of better routes. Breaks optimal routing on IPv6 networks where this host acts as a gateway.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_050",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.icmp_echo_ignore_all",
        1
    )
    .with_description("Drop all incoming ICMP. Reduces network-based fingerprinting at the cost of ping-based diagnostics.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_051",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.icmp.echo_ignore_all",
        1
    )
    .with_description("Drop all incoming ICMPv6. Reduces network-based fingerprinting at the cost of ping-based diagnostics.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_052",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.icmp_echo_ignore_broadcasts",
        1
    )
    .with_description("Ignore ICMP echo broadcasts (smurf attacks). Broadcasting ping requests causes all hosts to reply, enabling denial-of-service amplification.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_053",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.all.rp_filter",
        1
    )
    .with_description("Enable strict reverse path filtering. Drop packets where the source address is not routable via the interface they arrived on. Prevents IP spoofing. May break asymmetric routing setups where incoming and outgoing traffic uses different interfaces.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_054",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.default.rp_filter",
        1
    )
    .with_description("Enable strict reverse path filtering. Drop packets where the source address is not routable via the interface they arrived on. Prevents IP spoofing. May break asymmetric routing setups where incoming and outgoing traffic uses different interfaces.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_055",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.icmp_ignore_bogus_error_responses",
        1
    )
    .with_description(
        "Ignore bogus ICMP error responses to avoid flooding logs with meaningless entries.",
    )
    .register();

    check::Check::new(
        "SYS_056",
        "Ensure sysctl \"net.ipv4.icmp_ratelimit\" <= 100",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        || {
            const VAL: i32 = 100;
            match sysctl::get_sysctl_i32_value("net.ipv4.icmp_ratelimit") {
                Ok(value) => {
                    if value <= VAL {
                        (check::CheckState::Pass, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Fail,
                            Some(format!("{} > {}", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("Rate-limit outgoing ICMP error replies. Blocks ICMP-rate side channels and slows network-scan reconnaissance.")
    .with_fix("Add \"net.ipv4.icmp_ratelimit = 100\" (or lower) in \"/etc/sysctl.d/*.conf\" and run \"sysctl --system\".")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_057",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.icmp_ratemask",
        88089
    )
    .with_description("Select which ICMP types are subject to rate limiting. Mask 88089 covers the common reconnaissance-aiding types.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_058",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.tcp_syncookies",
        1
    )
    .with_description("Enable TCP SYN cookies to mitigate TCP SYN flood attacks. When the SYN queue is exhausted, the kernel uses cookies instead of dropping connections. SYN cookies do not support TCP extensions (window scaling, selective ACKs) which can reduce throughput on high-bandwidth or lossy links.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_059",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.accept_local",
        0
    )
    .with_description("Disable accepting packets with local source addresses. Prevents source-address spoofing attacks from the local network.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_060",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.shared_media",
        0
    )
    .with_description("Disable handling of RFC 1620 shared-media ICMP redirects. May break connectivity on shared-media networks (e.g. ATM, some VLAN configurations) that rely on these redirects.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_061",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.shared_media",
        0
    )
    .with_description("Disable handling of RFC 1620 shared-media ICMP redirects. May break connectivity on shared-media networks (e.g. ATM, some VLAN configurations) that rely on these redirects.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_062",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.arp_filter",
        1
    )
    .with_description("Enable ARP filtering. Respond to ARP requests only if the target IP is configured on the receiving interface. Prevents ARP confusion on multi-homed hosts. May break connectivity on some multi-homed setups where ARP responses are expected on all interfaces.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_063",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.arp_ignore",
        2
    )
    .with_description("Ignore ARP requests for addresses not on the receiving interface. Prevents the host from responding to ARP for addresses on other interfaces. May break connectivity on networks where ARP responses are expected on all interfaces (e.g. some load balancer configurations).")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_064",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.arp_ignore",
        2
    )
    .with_description("Ignore ARP requests for addresses not on the receiving interface. Prevents the host from responding to ARP for addresses on other interfaces. May break connectivity on networks where ARP responses are expected on all interfaces (e.g. some load balancer configurations).")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_065",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.arp_announce",
        2
    )
    .with_description("Use the most restrictive ARP announcement mode. May break connectivity on some network configurations where the less restrictive ARP announcement modes are expected.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_066",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.arp_announce",
        2
    )
    .with_description("Use the most restrictive ARP announcement mode. May break connectivity on some network configurations where the less restrictive ARP announcement modes are expected.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_067",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.route_localnet",
        0
    )
    .with_description("Disable routing of 127.0.0.0/8 to external networks. Prevents local net traffic from being routed outside the host.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_068",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.drop_gratuitous_arp",
        1
    )
    .with_description(
        "Drop gratuitous ARP (GARP) packets. Gratuitous ARP can be used in ARP-poisoning attacks.",
    )
    .register();

    sysctl::add_sysctl_check!(
        "SYS_069",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.ip_local_port_range",
        "32768\t65535"
    )
    .with_description("Set the ephemeral port range to the full 32768–65535. Reserves more ports for the kernel and reduces accidental conflicts with low-numbered service ports.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_070",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.tcp_rfc1337",
        1
    )
    .with_description("Enable RFC 1337 behavior to mitigate TIME_WAIT assassination attacks. Prevents old duplicate segments from interfering with new connections.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_071",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.forwarding",
        0
    )
    .with_description("Disable IPv6 packet forwarding. Non-routers should not forward packets, as it enables the host to be used as a pivot for network-level attacks.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_072",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.forwarding",
        0
    )
    .with_description("Disable IPv6 packet forwarding. Non-routers should not forward packets, as it enables the host to be used as a pivot for network-level attacks.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_073",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.accept_ra",
        0
    )
    .with_description("Disable acceptance of IPv6 Router Advertisements (RAs). Rogue RAs can redirect traffic or provide malicious network configuration. IPv6 SLAAC configuration may stop working.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_074",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.default.accept_ra",
        0
    )
    .with_description("Disable acceptance of IPv6 Router Advertisements (RAs). Rogue RAs can redirect traffic or provide malicious network configuration. IPv6 SLAAC configuration may stop working.")
    .register();

    // TODO: remove? mostly not a problem anymore?
    // sysctl::add_sysctl_check!(
    //     "SYS_075",
    //     Severity::High,
    //     vec!["sysctl", "ipv4", "server", "workstation"],
    //     "net.ipv4.tcp_timestamps",
    //     0
    // )
    // .register();

    sysctl::add_sysctl_check!(
        "SYS_076",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.all.log_martians",
        1
    )
    .with_description("Log packets with impossible source addresses. Martian packets indicate spoofing attempts or misconfigurations. Increases log volume and disk I/O; under heavy spoofing traffic this can fill disk or slow the system.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_077",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.default.log_martians",
        1
    )
    .with_description("Log packets with impossible source addresses. Martian packets indicate spoofing attempts or misconfigurations. Increases log volume and disk I/O; under heavy spoofing traffic this can fill disk or slow the system.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_078",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.router_solicitations",
        0
    )
    .with_description("Disable IPv6 Router Solicitation (RS). Prevents the host from requesting router information, reducing network fingerprinting. IPv6 SLAAC configuration may stop working, and IPv6 connectivity may be delayed until the next unsolicited RA arrives.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_079",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.router_solicitations",
        0
    )
    .with_description("Disable IPv6 Router Solicitation (RS). Prevents the host from requesting router information, reducing network fingerprinting. IPv6 SLAAC configuration may stop working, and IPv6 connectivity may be delayed until the next unsolicited RA arrives.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_080",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.accept_ra_rtr_pref",
        0
    )
    .with_description("Ignore router preference in IPv6 Router Advertisements. The system will no longer prefer higher-priority routers, which may result in suboptimal routing on networks with multiple IPv6 routers.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_081",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.accept_ra_rtr_pref",
        0
    )
    .with_description("Ignore router preference in Router Advertisements by default. The system will no longer prefer higher-priority routers, which may result in suboptimal routing on networks with multiple IPv6 routers.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_082",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.accept_ra_defrtr",
        0
    )
    .with_description("Disable learning default router from IPv6 RAs. Prevents rogue routers from hijacking default gateway. IPv6 connectivity will be lost unless a default gateway is statically configured.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_083",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.accept_ra_defrtr",
        0
    )
    .with_description("Disable learning default router from Router Advertisements by default. IPv6 connectivity will be lost unless a default gateway is statically configured.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_084",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.autoconf",
        0
    )
    .with_description(
        "Disable IPv6 autoconfiguration. Prevents automatic address assignment from rogue RAs. IPv6 addresses will no longer be automatically assigned, breaking IPv6 connectivity unless addresses are manually configured.",
    )
    .register();

    sysctl::add_sysctl_check!(
        "SYS_085",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.autoconf",
        0
    )
    .with_description("Disable IPv6 autoconfiguration by default. Prevents automatic address assignment from rogue Router Advertisements. IPv6 addresses will no longer be automatically assigned, breaking IPv6 connectivity unless addresses are manually configured.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_086",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.max_addresses",
        1
    )
    .with_description("Limit IPv6 addresses per interface to 1. Reduces attack surface from SLAAC-assigned addresses. Services requiring multiple IPv6 addresses (e.g. multi-homed hosting, certain DNS setups) will not work.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_087",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.max_addresses",
        1
    )
    .with_description("Limit IPv6 addresses per interface to 1 by default. Reduces attack surface from SLAAC-assigned addresses. Services requiring multiple IPv6 addresses (e.g. multi-homed hosting, certain DNS setups) will not work.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_088",
        Severity::High,
        vec!["sysctl", "bpf", "paranoid", "server", "workstation"],
        "net.core.bpf_jit_enable",
        0
    )
    .with_description("Disable the eBPF JIT compiler. JIT compilation of BPF programs has been a source of kernel exploits. Falls back to the BPF interpreter, which is significantly slower and increases CPU usage for BPF-heavy workloads (e.g. network filtering, tracing, container runtimes).")
    .register();

    // TODO: remove? was temp fix for 2019 CVEs
    // sysctl::add_sysctl_check!(
    //     "SYS_089",
    //     Severity::High,
    //     vec!["sysctl", "ipv4", "paranoid", "server", "workstation"],
    //     "net.ipv4.tcp_sack",
    //     0
    // )
    // .register();

    // TODO: remove?
    // sysctl::add_sysctl_check!(
    //     "SYS_090",
    //     Severity::High,
    //     vec!["sysctl", "ipv4", "paranoid", "server", "workstation"],
    //     "net.ipv4.tcp_dsack",
    //     0
    // )
    // .register();

    // TODO: remove? deprecated?
    // sysctl::add_sysctl_check!(
    //     "SYS_091",
    //     Severity::High,
    //     vec!["sysctl", "ipv4", "paranoid", "server", "workstation"],
    //     "net.ipv4.tcp_fack",
    //     0
    // )
    // .register();

    sysctl::add_sysctl_check!(
        "SYS_092",
        Severity::High,
        vec!["sysctl", "ipv6", "paranoid", "server", "workstation"],
        "net.ipv6.conf.all.use_tempaddr",
        2
    )
    .with_description("Always use temporary IPv6 addresses for outgoing connections. Prevents long-term tracking via stable IPv6 addresses.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_093",
        Severity::High,
        vec!["sysctl", "ipv6", "paranoid", "server", "workstation"],
        "net.ipv6.conf.default.use_tempaddr",
        2
    )
    .with_description("Use temporary IPv6 addresses by default. Prevents long-term tracking via stable IPv6 addresses.")
    .register();

    check::Check::new(
        "SYS_094",
        "Ensure sysctl \"user.max_user_namespaces\" <= 31231",
        Severity::High,
        vec!["sysctl", "KSPP", "server", "workstation"],
        || {
            const VAL: i32 = 31231;
            match sysctl::get_sysctl_i32_value("user.max_user_namespaces") {
                Ok(value) => {
                    if value <= VAL {
                        (check::CheckState::Pass, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Fail,
                            Some(format!("{} > {}", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("Limit the number of user namespaces to reduce attack surface. May break the upower daemon in Ubuntu. KSPP recommends 0 to completely disable user namespaces.")
    .with_fix("Add \"user.max_user_namespaces = 31231\" (or lower) in \"/etc/sysctl.d/*.conf\" and run \"sysctl --system\".")
    .register();

    // TODO: after v6.2
    check::Check::new(
        "SYS_095",
        "Ensure sysctl \"kernel.warn_limit\" <= 100",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        || {
            const VAL: i32 = 100;
            match sysctl::get_sysctl_i32_value("kernel.warn_limit") {
                Ok(value) => {
                    if value <= VAL {
                        (check::CheckState::Pass, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Fail,
                            Some(format!("{} > {}", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("Reboot after n kernel warnings. Will have no effect if kernel param \"oops=panic\" is set, but is a better default if it is not. Adjust to your tolerance, KSPP default is 1.")
    .with_fix("Add \"kernel.warn_limit = 100\" (or lower) in \"/etc/sysctl.d/*.conf\" and run \"sysctl --system\".")
    .register();

    check::Check::new(
        "SYS_096",
        "Ensure sysctl \"kernel.oops_limit\" <= 100",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        || {
            const VAL: i32 = 100;
            match sysctl::get_sysctl_i32_value("kernel.oops_limit") {
                Ok(value) => {
                    if value <= VAL {
                        (check::CheckState::Pass, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Fail,
                            Some(format!("{} > {}", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("Reboot after n kernel BUG/Oops. Will have no effect if kernel param \"oops=panic\" is set, but is a better default if it is not. Adjust to your tolerance, KSPP default is 1.")
    .with_fix("Add \"kernel.oops_limit = 100\" (or lower) in \"/etc/sysctl.d/*.conf\" and run \"sysctl --system\".")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_097",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.tcp_synack_retries",
        5
    )
    .with_description("Limit TCP SYN-ACK retries. High values waste resources and enable slow-DoS attacks by holding half-open connections.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_098",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.icmp.echo_ignore_anycast",
        1
    )
    .with_description("Ignore ICMP echo to anycast addresses. Prevents fingerprinting and abuse of anycast addresses. Breaks network diagnostic tools (e.g. ping) to anycast addresses.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_099",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.icmp.echo_ignore_multicast",
        1
    )
    .with_description("Ignore ICMP echo to multicast addresses. Breaks network diagnostic tools (e.g. ping) to multicast addresses.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_100",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.forwarding",
        0
    )
    .with_description("Disable IPv4 packet forwarding on all interfaces. Non-routers should not forward packets. The system can no longer act as a router, NAT gateway, or VPN server forwarding IPv4 traffic.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_101",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.forwarding",
        0
    )
    .with_description("Disable IPv4 packet forwarding by default on new interfaces. Non-routers should not forward packets. The system can no longer act as a router, NAT gateway, or VPN server forwarding IPv4 traffic on newly added interfaces.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_102",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.mc_forwarding",
        0
    )
    .with_description(
        "Disable IPv4 multicast forwarding. Non-routers should not forward multicast traffic. Breaks IPv4 multicast routing (e.g. IPTV, mDNS reflectors).",
    )
    .register();

    sysctl::add_sysctl_check!(
        "SYS_103",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.mc_forwarding",
        0
    )
    .with_description("Disable IPv4 multicast forwarding by default. Non-routers should not forward multicast traffic. Breaks IPv4 multicast routing (e.g. IPTV, mDNS reflectors) on new interfaces.")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_104",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.mc_forwarding",
        0
    )
    .with_description("Disable IPv6 multicast forwarding. Non-routers should not forward multicast traffic. Breaks IPv6 multicast routing (e.g. mDNS, SSDP).")
    .register();

    sysctl::add_sysctl_check!(
        "SYS_105",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.mc_forwarding",
        0
    )
    .with_description("Disable IPv6 multicast forwarding by default. Non-routers should not forward multicast traffic. Breaks IPv6 multicast routing (e.g. mDNS, SSDP) on new interfaces.")
    .register();
}
