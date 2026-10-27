use crate::check;
use crate::check::Severity;
use crate::modules::sysctl;

pub fn add_checks() {
    sysctl::add_sysctl_check!(
        "SYK_001",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation", "tails"],
        "kernel.kptr_restrict",
        // TODO: allow for 1 as well
        2
    )
    .with_description("Restrict kernel address visibility via `/proc` and other interfaces, regardless of user privileges, kernel pointers expose specific locations in kernel memory, will hide kernel symbol addresses in `/proc/kallsyms`.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_002",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.ftrace_enabled",
        0
    )
    .with_description("Disable ftrace debugging. Ftrace provides tracing facilities for the kernel that can expose sensitive information. Disabling it breaks kernel tracing and profiling tools (e.g. perf, bpftrace) that rely on ftrace.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_003",
        Severity::Medium,
        vec!["sysctl", "KSPP", "CIS", "server", "workstation"],
        "kernel.randomize_va_space",
        2
    )
    .with_description("Enable ASLR for mmap base, stack, VDSO pages, and heap. Forces shared libraries to be loaded at random addresses. May cause breakages with legacy applications.")
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/sysctl/kernel.rst#randomize_va_space")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_004",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        "kernel.dmesg_restrict",
        1
    )
    .with_description("Restrict access to the kernel log buffer to users with `CAP_SYSLOG`. Kernel logs often contain sensitive information such as kernel pointers. Non-root users and scripts that read dmesg will no longer work.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_005",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.printk",
        "3\t3\t3\t3"
    )
    .with_description("Prevent kernel information leaks in the console during boot. Must be used in conjunction with kernel boot parameters.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_006",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.perf_cpu_time_max_percent",
        1
    )
    .with_description("Cap perf CPU usage. Without a low cap, perf and perf-based tracing/profiling can consume excessive CPU on busy systems, increasing attack surface for DoS via heavy tracing workloads.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_007",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.perf_event_max_sample_rate",
        1
    )
    .with_description("Cap perf sample rate. Uncapped rates produce timing oracles and let unprivileged perf users dominate the perf subsystem, slowing security-relevant workloads.")
    .register();

    // 2 or 3
    check::Check::new(
        "SYK_008",
        "Ensure sysctl `kernel.perf_event_paranoid` = 2 or 3",
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
    .with_description("Restrict kernel profiling to users with `CAP_PERFMON`. The performance events system should not be accessible by unprivileged users, as it adds considerable kernel attack surface. Can be 2 or 3.")
    .with_fix("Add `kernel.perf_event_paranoid = 2` (or 3) in `/etc/sysctl.d/*.conf` and run `sysctl --system`.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_009",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.sysrq",
        0
    )
    .with_description("Disable the SysRq magic keys. From the physical console, or from `/proc/sysrq-trigger` as root, they otherwise allow kernel memory and task dumps, forced remounts, syncs and reboots, leaking kernel information and disrupting availability. The Secure Attention Key (SAK) can no longer be utilized.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_010",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation", "tails"],
        "kernel.kexec_load_disabled",
        1
    )
    .with_description("Disable kexec. Kexec can be used to replace the running kernel, which is only useful for live kernel patching without rebooting.")
    .register();

    // TODO: ignore if using Podman or Docker rootless
    // 1 or 2
    check::Check::new(
        "SYK_011",
        "Ensure sysctl `kernel.unprivileged_bpf_disabled` = 1 or 2",
        Severity::Medium,
        vec!["sysctl", "bpf", "KSPP", "server", "workstation"],
        || {
            match sysctl::get_sysctl_i32_value("kernel.unprivileged_bpf_disabled") {
                Ok(value) => {
                    if value == 1 || value == 2 {
                        (check::CheckState::Pass, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Fail,
                            Some(format!("{} != 1 or 2", value)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description(
        "Restrict the bpf() syscall to users with `CAP_BPF`, unprivileged BPF is a major local privilege escalation surface. Can be 1 or 2, where 2 makes the restriction permanent until reboot. Breaks unprivileged BPF programs (e.g. rootless containers, network monitoring tools), leave it to 0 if using rootless containers.",
    )
    .with_fix("Add `kernel.unprivileged_bpf_disabled = 1` (or 2) in `/etc/sysctl.d/*.conf` and run `sysctl --system`.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_012",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.panic_on_oops",
        1
    )
    .with_description("Force the kernel to panic on oopses. This can potentially indicate and thwart certain kernel exploitation attempts, and also causes panics on machine check exceptions. Some bad drivers can cause harmless oopses which result in system crash.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_013",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.panic",
        "-1"
    )
    .with_description("Reboot immediately on kernel panic. A panic could indicate an exploitation attempt. Appropriate for security-critical hosts where the safe response to a corruption-detected event is reboot, not stay-up.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_014",
        Severity::High,
        vec!["sysctl", "KSPP", "server", "workstation"],
        "kernel.modules_disabled",
        1
    )
    .with_description("Permanently disable module loading once set. Any later attempt by an attacker, even with `CAP_SYS_MODULE` and root, to load a module is rejected by the kernel. This could prevent loading backdoor or vulnerable modules. For systems needing hot-add drivers, it prevents legitimate module loading.")
    .register();

    // FIXME: only available on some kernels
    sysctl::add_sysctl_check!(
        "SYK_015",
        Severity::High,
        vec!["sysctl", "server", "workstation"],
        "kernel.unprivileged_userns_clone",
        0
    )
    .with_description("Disable unprivileged user namespaces. Unprivileged userns_clone greatly increases the attack surface for local privilege escalation. Note that disabling this will prevent Docker and Podman from working rootless.")
    .with_link("https://gitlab.com/apparmor/apparmor/-/wikis/unprivileged_userns_restriction")
    .register();

    // 2 or 3, CIS recommends 1
    check::Check::new(
        "SYK_016",
        "Ensure sysctl `kernel.yama.ptrace_scope` >= 1",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        || {
            const VAL: i32 = 1;
            match sysctl::get_sysctl_i32_value("kernel.yama.ptrace_scope") {
                Ok(val) => {
                    if val >= VAL {
                        (check::CheckState::Pass, Some(format!("{}", val)))
                    } else {
                        (
                            check::CheckState::Fail,
                            Some(format!("{} > {}", val, VAL)),
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
  - 2: Restrict ptrace access to processes with `CAP_SYS_PTRACE`.
  - 3: Completely disable ptrace.")
    .with_fix("Add `kernel.yama.ptrace_scope = 1` (or 2 or 3) in `/etc/sysctl.d/*.conf` and run `sysctl --system`.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_017",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.io_uring_disabled",
        2
    )
    .with_description("Disable the io_uring interface for all processes (2 = disabled for everyone, 1 = restricted to privileged users). io_uring is a leading cause of numerous kernel exploits. Only applications using io_uring are affected, other asynchronous I/O (io_submit, POSIX AIO) keeps working, but io_uring users fall back to slower read/write paths. Applicable when using Linux kernel >= 6.6.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_018",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.core_pattern",
        "|/bin/false"
    )
    .with_description("Disable core dumps by piping them to `/bin/false`, which discards them. Core dumps capture secrets such as keys and the memory of privileged processes, and a piped pattern runs a root program on every crash, a classic persistence vector. This prevents post-mortem debugging of crashing processes. This setting may be overwritten by systemd-coredump.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_019",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.core_uses_pid",
        1
    )
    .with_description("Set core dump file name to `core.PID` instead of `core` as a form of defense-in-depth. Only useful if PID listings are hidden from non-root users and core dumps are permitted.")
    .register();

    // TODO: verify kernel version to be above v6.2
    check::Check::new(
        "SYK_020",
        "Ensure sysctl `kernel.warn_limit` >= 1 and <= 100",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        || {
            const VAL: i32 = 100;
            match sysctl::get_sysctl_i32_value("kernel.warn_limit") {
                Ok(value) => {
                    if (1..=VAL).contains(&value) {
                        (check::CheckState::Pass, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Fail,
                            Some(format!("{} is not in [1..{}]", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("Panic after n kernel warnings, a warning often means reachable memory corruption and continuing risks further exploitation. 0 disables the warning count entirely and is the kernel default, so it must be non-zero, while 1 is equivalent to `kernel.panic_on_warn=1`. The panic only reboots when `kernel.panic` is non-zero. Will have no effect if kernel param `oops=panic` is set, but is a better default if it is not. Adjust to your tolerance, KSPP default is 1. Requires Linux kernel >= 6.2.")
    .with_fix("Add `kernel.warn_limit = 100` (any value between 1 and 100) in `/etc/sysctl.d/*.conf` and run `sysctl --system`.")
    .register();

    // TODO: kernel >= 6.2
    check::Check::new(
        "SYK_021",
        "Ensure sysctl `kernel.oops_limit` >= 1 and <= 100",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        || {
            const VAL: i32 = 100;
            match sysctl::get_sysctl_i32_value("kernel.oops_limit") {
                Ok(value) => {
                    if (1..=VAL).contains(&value) {
                        (check::CheckState::Pass, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Fail,
                            Some(format!("{} is not in [1..{}]", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("Panic after n kernel BUG/Oops, continuing in a corrupted state risks further exploitation. 0 disables the oops count entirely, so it must be non-zero, while 1 is equivalent to `kernel.panic_on_oops=1`. The panic only reboots when `kernel.panic` is non-zero. Will have no effect if kernel param `oops=panic` is set, but is a better default if it is not. Adjust to your tolerance, KSPP default is 1.")
    .with_fix("Add `kernel.oops_limit = 100` (any value between 1 and 100) in `/etc/sysctl.d/*.conf` and run `sysctl --system`.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_022",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.print-fatal-signals",
        0
    )
    .with_description("Do not log signal, PC, SP and code of fatally-signalled processes to the kernel log. Such dumps leak process state to any dmesg reader.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_023",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.printk_devkmsg",
        "off"
    )
    .with_description("Block userspace writes to `/dev/kmsg`, preventing log spoofing and anti-forensics. Breaks legitimate kmsg writers (e.g. early systemd status messages).")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_024",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.stack_tracer_enabled",
        0
    )
    .with_description("Keep the ftrace-based stack tracer off. Pure debug facility with runtime overhead and kernel-state exposure.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_025",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.ftrace_dump_on_oops",
        0
    )
    .with_description("Do not dump the ftrace buffer to the console on oops. The console is a physical-attack channel and the dump contains kernel state.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_026",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.tracepoint_printk",
        0
    )
    .with_description("Do not route tracepoint output into printk/dmesg. Debug facility that floods logs with kernel internals.")
    .register();

    check::Check::new(
        "SYK_027",
        "Ensure sysctl `kernel.seccomp.actions_logged` is not empty",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        || {
            match sysctl::get_sysctl_str_value("kernel.seccomp.actions_logged") {
                Ok(value) => {
                    if value.trim().is_empty() {
                        (check::CheckState::Fail, Some("empty".to_string()))
                    } else {
                        (check::CheckState::Pass, Some(value))
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("Keep the shipped seccomp audit-logging list non-empty (kill_process kill_thread trap errno user_notif trace log). Emptying it blinds monitoring of seccomp-blocked exploitation attempts.")
    .with_fix("Set `kernel.seccomp.actions_logged` to the shipped default list in `/etc/sysctl.d/*.conf` and run `sysctl --system`.")
    .register();

    check::Check::new(
        "SYK_028",
        "Ensure sysctl `kernel.io_uring_group` = -1 or 0",
        Severity::Informational,
        vec!["sysctl", "server", "workstation"],
        || {
            match sysctl::get_sysctl_i32_value("kernel.io_uring_group") {
                Ok(value) => {
                    if value == -1 || value == 0 {
                        (check::CheckState::Pass, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Fail,
                            Some(format!("{} != -1 or 0", value)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("GID exempted from io_uring_disabled = 2. Leave unset (-1, or 0) so no group bypasses the io_uring restriction.")
    .with_fix("Add `kernel.io_uring_group = -1` in `/etc/sysctl.d/*.conf` and run `sysctl --system`.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_029",
        Severity::High,
        vec!["sysctl", "server", "workstation"],
        "kernel.apparmor_restrict_unprivileged_userns",
        1
    )
    .with_description("Restrict unprivileged user namespaces to processes with an AppArmor profile that allows them. Confined rootless containers still work, compared to `kernel.unprivileged_userns_clone = 0`.")
    .with_link("https://gitlab.com/apparmor/apparmor/-/wikis/unprivileged_userns_restriction")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_030",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "kernel.apparmor_restrict_unprivileged_unconfined",
        1
    )
    .with_description("Prevent unprivileged processes from spawning unconfined AppArmor children. Keeps the userns/jail restrictions from being trivially escaped into an unconfined process.")
    .with_link("https://gitlab.com/apparmor/apparmor/-/wikis/unprivileged_userns_restriction")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_031",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        "kernel.panic_on_warn",
        1
    )
    .with_description("Panic on kernel WARNings: WARN_ON often means reachable memory corruption, panicking stops continued exploitation. Prone to false-positive reboots from noisy drivers.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_032",
        Severity::Medium,
        vec!["sysctl", "STIG", "server", "workstation"],
        "kernel.unknown_nmi_panic",
        1
    )
    .with_description("Panic on an unexplained NMI, which can indicate a hardware fault or an attack on the platform. Some hardware emits benign NMIs and will crash-loop.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_033",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.panic_on_unrecovered_nmi",
        1
    )
    .with_description("Panic on unrecovered NMI instead of ignoring it. Fail-fast on possible hardware or exploitation events.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_034",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.panic_on_io_nmi",
        1
    )
    .with_description("Panic when an I/O-channel NMI (hardware error path) cannot be handled.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_035",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.hardlockup_panic",
        1
    )
    .with_description("Panic on hard lockups (requires the NMI watchdog). A kernel hard lockup can indicate exploitation.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_036",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.split_lock_mitigate",
        1
    )
    .with_description("Keep split-lock mitigation on (>= 6.4): processes issuing split locks are throttled instead of degrading the whole machine (DoS). Some HPC/realtime workloads need 0.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_037",
        Severity::Informational,
        vec!["sysctl", "server", "workstation"],
        "kernel.panic_on_rcu_stall",
        1
    )
    .with_description("Optional fail-fast on RCU stalls, which can indicate kernel deadlock or exploiter loops. False-positive prone.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_038",
        Severity::Informational,
        vec!["sysctl", "server", "workstation"],
        "kernel.nmi_watchdog",
        1
    )
    .with_description("Keep the NMI lockup detector enabled (prerequisite for hardlockup detection). Small performance cost.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_039",
        Severity::Informational,
        vec!["sysctl", "server", "workstation"],
        "kernel.watchdog",
        1
    )
    .with_description("Keep the lockup detectors enabled (prerequisite for hardlockup detection). Small performance cost.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_040",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.modprobe",
        "/sbin/modprobe"
    )
    .with_description("Binary the kernel executes as root for module autoloading. If replaced, any autoload trigger (an unprivileged socket() call, device open) runs the attacker binary, even with modules_disabled = 1. Verify untampered.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_041",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.hotplug",
        ""
    )
    .with_description("Legacy uevent helper, must stay empty (udev handles events over netlink). A set value executes as root on hotplug events.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_042",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.poweroff_cmd",
        "/sbin/poweroff"
    )
    .with_description("Helper executed as root at poweroff. Verify untampered, a replaced value means root code execution at shutdown.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_043",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.ctrl-alt-del",
        0
    )
    .with_description("Route Ctrl-Alt-Del to init/systemd for a graceful reboot. 1 reboots immediately without syncing when pressed at the console (availability, data corruption).")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_044",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "kernel.shm_rmid_forced",
        1
    )
    .with_description("Destroy SysV shared-memory segments when the last process detaches. Prevents stale segments holding secrets from outliving their owners. Changes classic SysV semantics some legacy apps rely on.")
    .register();

    sysctl::add_sysctl_check!(
        "SYK_200",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "abi.vsyscall32",
        0
    )
    .with_description("Disable vsyscalls to reduce attack surface as they have been replaced by vDSO vulnerable to ROP attacks as vsyscalls are located at fixed addresses in memory. Specific to x86_64 arch. Breaks very old binaries (pre-glibc 2.22) and some legacy applications that rely on vsyscalls.")
    .register();

    sysctl::add_sysctl_check!(
        "SYF_001",
        Severity::Medium,
        vec!["sysctl", "fs", "KSPP", "CIS", "server", "workstation"],
        "fs.suid_dumpable",
        0
    )
    .with_description("Prevent setuid processes or otherwise protected/tainted binaries from creating core dumps. Any process which has changed privilege levels or is execute-only will not be dumped. Provides defense-in-depth if core dumps are permitted.")
    .register();

    sysctl::add_sysctl_check!(
        "SYF_002",
        Severity::Medium,
        vec!["sysctl", "fs", "KSPP", "server", "workstation"],
        "fs.protected_fifos",
        2
    )
    .with_description("Disallow `O_CREAT` opens of FIFOs in world-writable sticky directories unless the owner of the directory is also the owner of the file, so an attacker cannot trick a privileged process into writing into a FIFO they control. Value 2 extends this to group-writable sticky directories. Makes data spoofing attacks more difficult and prevents unintentional writes to attacker-controlled files.")
    .register();

    sysctl::add_sysctl_check!(
        "SYF_003",
        Severity::Medium,
        vec!["sysctl", "fs", "KSPP", "server", "workstation"],
        "fs.protected_regular",
        2
    )
    .with_description("Disallow `O_CREAT` opens of regular files in world-writable sticky directories unless the owner of the directory is also the owner of the file, so an attacker cannot pre-create a file that a privileged process then truncates and writes into. Value 2 extends this to group-writable sticky directories. Makes data spoofing attacks more difficult and prevents unintentional writes to attacker-controlled files.")
    .register();

    sysctl::add_sysctl_check!(
        "SYF_004",
        Severity::Medium,
        vec!["sysctl", "fs", "KSPP", "server", "workstation"],
        "fs.protected_symlinks",
        1
    )
    .with_description("Restrict following symlinks in world-writable sticky directories: a symlink is only followed when it is outside such a directory, when the process following it owns it, or when the directory owner owns it. Symlink creation itself is unaffected. Hardens cross-privilege boundaries when a privileged process follows a symlink belonging to another user, mitigating many symlink-based TOCTOU races in world-writable directories like `/tmp`.")
    .register();

    sysctl::add_sysctl_check!(
        "SYF_005",
        Severity::Medium,
        vec!["sysctl", "fs", "KSPP", "server", "workstation"],
        "fs.protected_hardlinks",
        1
    )
    .with_description("Restrict hardlink creation to users who already own the source file, or who have both read and write access to it. Applies system-wide, not only in sticky directories. Hardens cross-privilege boundaries when a privileged process accesses a file another user has hardlinked to it, mitigating many hardlink-based TOCTOU races and information leaks.")
    .register();

    check::Check::new(
        "SYF_006",
        "Ensure sysctl `fs.binfmt_misc.status` = 0",
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
    .with_fix("Add `fs.binfmt_misc.status = 0` in `/etc/sysctl.d/*.conf` and run `sysctl --system`.")
    .register();

    sysctl::add_sysctl_check!(
        "SYF_007",
        Severity::Low,
        vec!["sysctl", "fs", "server", "workstation"],
        "fs.verity.require_signatures",
        1
    )
    .with_description("When fs-verity is used, require a valid signature over the verity digest before a file can be opened. Otherwise any Merkle tree is trusted. Only meaningful on systems using fs-verity.")
    .register();

    sysctl::add_sysctl_check!(
        "SYV_001",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        "vm.unprivileged_userfaultfd",
        0
    )
    .with_description("Restrict the `userfaultfd()` syscall to users with `CAP_SYS_PTRACE`. Reduces the likelihood of use-after-free exploits from heap sprays. Breaks applications that rely on userfaultfd for user-space paging (e.g. some Java GCs, game engines, databases with memory-mapped files).")
    .register();

    sysctl::add_sysctl_check!(
        "SYV_002",
        Severity::Medium,
        vec!["sysctl", "server", "workstation", "tails"],
        "vm.mmap_rnd_bits",
        32
    )
    .with_description("Maximize bits of entropy for improved effectiveness of mmap ASLR. The maximum number of bits depends on CPU architecture.")
    .register();

    // TODO: either set vm.mmap_rnd_bits or vm.mmap_rnd_compat_bits ?
    sysctl::add_sysctl_check!(
        "SYV_003",
        Severity::Medium,
        vec!["sysctl", "server", "workstation", "tails"],
        "vm.mmap_rnd_compat_bits",
        16
    )
    .with_description("Maximize bits of entropy for improved effectiveness of mmap ASLR. The maximum number of bits depends on CPU architecture.")
    .register();

    sysctl::add_sysctl_check!(
        "SYV_004",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "vm.mmap_min_addr",
        65536
    )
    .with_description("Prevent userspace processes from mapping the first few pages of memory. A kernel null dereference bug could accidentally operate based on information in the first couple of pages. Provides defense in depth against future potential kernel bugs. May break some legacy applications or Wine that map low memory addresses.")
    .register();

    sysctl::add_sysctl_check!(
        "SYV_005",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "vm.max_map_count",
        1048576
    )
    .with_description("Increase the maximum number of memory map areas a process is permitted to utilize. Required to accommodate the very large number of guard pages created by hardened_malloc. At low values, memory-intensive applications hit mmap failures, start-up errors and crashes; raising the limit only costs a slightly larger per-process memory footprint.")
    .register();

    sysctl::add_sysctl_check!(
        "SYV_006",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "vm.swappiness",
        1
    )
    .with_description("Limit swapping to only when absolutely necessary. Minimizes the likelihood of writing potentially sensitive contents to disk. Not recommended to set to zero since this disables periodic write behavior.")
    .register();

    sysctl::add_sysctl_check!(
        "SYV_007",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "vm.legacy_va_layout",
        0
    )
    .with_description(
        "Non-zero forces the legacy 2.4 mmap layout, weakening ASLR. Ensure it stays 0.",
    )
    .register();

    sysctl::add_sysctl_min_check!(
        "SYV_008",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "vm.memfd_noexec",
        1
    )
    .with_description("Create memfds non-executable (>= 6.3): 1 = noexec by default, 2 = enforced (MFD_ALLOW_EXEC rejected). memfd_create is a staple of fileless-malware execution. Breaks JITs that legitimately exec from memfds.")
    .register();

    sysctl::add_sysctl_check!(
        "SYV_009",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "vm.oom_dump_tasks",
        0
    )
    .with_description("Suppress the OOM-killer task dump (pid/uid/name/rss of every process) into the kernel log. Information leak about running workloads, costs OOM forensics.")
    .register();

    sysctl::add_sysctl_check!(
        "SYV_010",
        Severity::Informational,
        vec!["sysctl", "server", "workstation"],
        "vm.panic_on_oom",
        0
    )
    .with_description("Panicking turns memory-exhaustion DoS into a reboot. Appropriate only for fail-fast clusters where failover or kdump analysis is preferred over the OOM killer.")
    .register();

    sysctl::add_sysctl_check!(
        "SYE_001",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        "dev.tty.ldisc_autoload",
        0
    )
    .with_description("Restrict loading TTY line disciplines to users with `CAP_SYS_MODULE`. Prevents unprivileged users from loading arbitrary line disciplines. May break software that relies on dynamically loading TTY line disciplines (e.g. some serial port tools, pppd).")
    .register();

    sysctl::add_sysctl_check!(
        "SYE_002",
        Severity::Medium,
        vec!["sysctl", "KSPP", "server", "workstation"],
        "dev.tty.legacy_tiocsti",
        0
    )
    .with_description("Disable legacy TIOCSTI operations. These can be used to inject keypresses, leading to privilege escalation by pushing characters into a controlling TTY. Will break outdated screen readers that continue to rely on this legacy functionality.")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYE_003",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "dev.hpet.max-user-freq",
        64
    )
    .with_description("Cap the interrupt rate unprivileged users can request from the HPET. Prevents interrupt-storm DoS and a high-resolution timing source.")
    .register();

    check::Check::new(
        "SYU_001",
        "Ensure sysctl `user.max_user_namespaces` <= 31231",
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
    .with_description("Limit the number of user namespaces to reduce attack surface. May break the upower daemon. KSPP recommends 0 to completely disable user namespaces.")
    .with_fix("Add `user.max_user_namespaces = 31231` (or lower) in `/etc/sysctl.d/*.conf` and run `sysctl --system`.")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYU_002",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "user.max_cgroup_namespaces",
        21136
    )
    .with_description("Per-type namespace quota limiting namespace-exhaustion DoS from unprivileged users. Keep the distro default or lower, 0 disables the namespace type entirely (breaks containers).")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYU_003",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "user.max_ipc_namespaces",
        21136
    )
    .with_description("Per-type namespace quota limiting namespace-exhaustion DoS from unprivileged users. Keep the distro default or lower, 0 disables the namespace type entirely (breaks containers).")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYU_004",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "user.max_mnt_namespaces",
        21136
    )
    .with_description("Per-type namespace quota limiting namespace-exhaustion DoS from unprivileged users. Keep the distro default or lower, 0 disables the namespace type entirely (breaks containers).")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYU_005",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "user.max_net_namespaces",
        21136
    )
    .with_description("Per-type namespace quota limiting namespace-exhaustion DoS from unprivileged users. Keep the distro default or lower, 0 disables the namespace type entirely (breaks containers).")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYU_006",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "user.max_pid_namespaces",
        21136
    )
    .with_description("Per-type namespace quota limiting namespace-exhaustion DoS from unprivileged users. Keep the distro default or lower, 0 disables the namespace type entirely (breaks containers).")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYU_007",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "user.max_time_namespaces",
        21136
    )
    .with_description("Per-type namespace quota limiting namespace-exhaustion DoS from unprivileged users. Keep the distro default or lower, 0 disables the namespace type entirely (breaks containers).")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYU_008",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "user.max_uts_namespaces",
        21136
    )
    .with_description("Per-type namespace quota limiting namespace-exhaustion DoS from unprivileged users. Keep the distro default or lower, 0 disables the namespace type entirely (breaks containers).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_001",
        Severity::High,
        vec!["sysctl", "bpf", "KSPP", "server", "workstation", "tails"],
        "net.core.bpf_jit_harden",
        2
    )
    .with_description("Enable eBPF JIT compiler hardening. Hardens the JIT compiler against exploitation. Adds a performance penalty to BPF program execution.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_002",
        Severity::High,
        vec!["sysctl", "bpf", "paranoid", "server", "workstation"],
        "net.core.bpf_jit_enable",
        0
    )
    .with_description("Disable the eBPF JIT compiler. JIT compilation of BPF programs has been a source of kernel exploits. Falls back to the BPF interpreter, which is significantly slower and increases CPU usage for BPF-heavy workloads (e.g. network filtering, tracing, container runtimes).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_003",
        Severity::Low,
        vec!["sysctl", "bpf", "KSPP", "server", "workstation"],
        "net.core.bpf_jit_kallsyms",
        0
    )
    .with_description("Do not export JITed BPF image addresses through `/proc/kallsyms`. Root-only readable, reports Warning when audited as non-root.")
    .register();

    check::Check::new(
        "SYN_004",
        "Ensure sysctl `net.core.bpf_jit_limit` != 0",
        Severity::Low,
        vec!["sysctl", "bpf", "KSPP", "server", "workstation"],
        || {
            match sysctl::get_sysctl_i32_value("net.core.bpf_jit_limit") {
                Ok(value) => {
                    if value != 0 {
                        (check::CheckState::Pass, Some(format!("{}", value)))
                    } else {
                        (check::CheckState::Fail, Some("0".to_string()))
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("Cap memory allocatable to the BPF JIT (JIT-spray and DoS containment). On x86-64 the dedicated JIT region already bounds it, KSPP still recommends an explicit non-zero cap. Root-only readable, reports Warning when audited as non-root.")
    .with_fix("Add `net.core.bpf_jit_limit` with a non-zero workload-tuned value in `/etc/sysctl.d/*.conf` and run `sysctl --system`.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_005",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "net.core.devconf_inherit_init_net",
        1
    )
    .with_description("New network namespaces inherit interface sysctls (rp_filter, redirects, source route...) from init_net instead of weaker kernel defaults. Containers then start with the host's hardened values.")
    .register();

    sysctl::add_sysctl_min_check!(
        "SYN_006",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "net.core.fb_tunnels_only_for_init_net",
        1
    )
    .with_description("Create fallback tunnel devices (sit0, ip6tnl0, ip_vti0...) only in the init namespace (1) or nowhere (2). Removes unused tunnel attack surface from every container namespace.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_007",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "net.core.xfrm_larval_drop",
        1
    )
    .with_description("IPsec hosts: drop packets while an SA is still being resolved instead of letting them flow in the clear. Keep the default 1.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_050",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.ip_forward",
        0
    )
    .with_description("Disable IPv4 packet forwarding. Non-routers should not forward packets, as it enables the host to be used as a pivot for network-level attacks.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_051",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.accept_source_route",
        0
    )
    .with_description("Disable acceptance of source-routed packets. Source routing allows the sender to specify the path, which could be used to bypass network security controls. Breaks legacy diagnostic tools (e.g. traceroute with source routing).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_052",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.default.accept_source_route",
        0
    )
    .with_description("Disable acceptance of source-routed packets. Source routing allows the sender to specify the path, which could be used to bypass network security controls. Breaks legacy diagnostic tools (e.g. traceroute with source routing).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_053",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.accept_redirects",
        0
    )
    .with_description("Disable acceptance of ICMP redirects. Prevents the system from learning better routes from network routers. May break connectivity on networks that rely on ICMP redirects for optimal routing.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_054",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.default.accept_redirects",
        0
    )
    .with_description("Disable acceptance of ICMP redirects. Prevents the system from learning better routes from network routers. May break connectivity on networks that rely on ICMP redirects for optimal routing.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_055",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.secure_redirects",
        0
    )
    .with_description("Disable acceptance of secure ICMP redirects. Prevents the system from learning better routes from trusted gateways. May break connectivity on networks that rely on ICMP redirects for optimal routing.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_056",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.default.secure_redirects",
        0
    )
    .with_description("Disable acceptance of secure ICMP redirects. Prevents the system from learning better routes from trusted gateways. May break connectivity on networks that rely on ICMP redirects for optimal routing.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_057",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.all.send_redirects",
        0
    )
    .with_description("Disable sending of ICMP redirects. The system will no longer inform hosts of better routes. Breaks optimal routing on networks where this host acts as a gateway.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_058",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.default.send_redirects",
        0
    )
    .with_description("Disable sending of ICMP redirects. The system will no longer inform hosts of better routes. Breaks optimal routing on networks where this host acts as a gateway.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_059",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.icmp_echo_ignore_all",
        1
    )
    .with_description("Drop all incoming ICMP echo requests (ping). Other ICMP types are unaffected. Reduces network-based fingerprinting at the cost of ping-based diagnostics.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_060",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.icmp_echo_ignore_broadcasts",
        1
    )
    .with_description("Ignore ICMP echo broadcasts (smurf attacks). Broadcasting ping requests causes all hosts to reply, enabling denial-of-service amplification.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_061",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.all.rp_filter",
        1
    )
    .with_description("Enable strict reverse path filtering. Drop packets where the source address is not routable via the interface they arrived on. Prevents IP spoofing. May break asymmetric routing setups where incoming and outgoing traffic uses different interfaces.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_062",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.conf.default.rp_filter",
        1
    )
    .with_description("Enable strict reverse path filtering. Drop packets where the source address is not routable via the interface they arrived on. Prevents IP spoofing. May break asymmetric routing setups where incoming and outgoing traffic uses different interfaces.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_063",
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
        "SYN_064",
        "Ensure sysctl `net.ipv4.icmp_ratelimit` >= 1 and <= 100",
        Severity::Medium,
        vec!["sysctl", "ipv4", "server", "workstation"],
        || {
            const VAL: i32 = 100;
            match sysctl::get_sysctl_i32_value("net.ipv4.icmp_ratelimit") {
                Ok(value) => {
                    if (1..=VAL).contains(&value) {
                        (check::CheckState::Pass, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Fail,
                            Some(format!("{} is not in [1..{}]", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("Rate-limit outgoing ICMP error replies, in milliseconds between replies per type. The kernel default is 1000. Blocks ICMP-rate side channels and slows network-scan reconnaissance. Must be non-zero, 0 disables the rate limiting entirely.")
    .with_fix("Add `net.ipv4.icmp_ratelimit = 100` (any value between 1 and 100) in `/etc/sysctl.d/*.conf` and run `sysctl --system`.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_065",
        Severity::Medium,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.icmp_ratemask",
        88089
    )
    .with_description("Select which ICMP types are subject to the `net.ipv4.icmp_ratelimit` limit, as a bitmask of ICMP types. Mask 88089 covers the reconnaissance-aiding types (echo reply, destination unreachable, source quench, time exceeded, parameter problem, timestamp reply).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_066",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "server", "workstation"],
        "net.ipv4.tcp_syncookies",
        1
    )
    .with_description("Enable TCP SYN cookies to mitigate TCP SYN flood attacks. When the SYN queue is exhausted, the kernel uses cookies instead of dropping connections. SYN cookies do not support TCP extensions (window scaling, selective ACKs) which can reduce throughput on high-bandwidth or lossy links.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_067",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.accept_local",
        0
    )
    .with_description("Disable accepting packets with local source addresses. Prevents source-address spoofing attacks from the local network.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_068",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.shared_media",
        0
    )
    .with_description("Disable handling of RFC 1620 shared-media ICMP redirects. May break connectivity on shared-media networks (e.g. ATM, some VLAN configurations) that rely on these redirects.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_069",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.shared_media",
        0
    )
    .with_description("Disable handling of RFC 1620 shared-media ICMP redirects. May break connectivity on shared-media networks (e.g. ATM, some VLAN configurations) that rely on these redirects.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_070",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.arp_filter",
        1
    )
    .with_description("Enable ARP filtering. Answer an ARP request on an interface only if the kernel would route a packet from the requester's address back out that same interface, which needs source-based routing policies when several interfaces share a subnet. Prevents ARP confusion on multi-homed hosts. May break connectivity on some multi-homed setups where ARP responses are expected on all interfaces.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_071",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.arp_ignore",
        2
    )
    .with_description("Restrict ARP replies. Value 2 only answers when the target IP is configured on the receiving interface AND the sender IP is on the same subnet as that interface, value 1 omits the same-subnet requirement and value 0 answers for any local address. Prevents the host from answering ARP for addresses on other interfaces and blocks ARP-based reconnaissance. May break connectivity on networks where ARP responses are expected on all interfaces (e.g. some load balancer configurations).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_072",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.arp_ignore",
        2
    )
    .with_description("Restrict ARP replies. Value 2 only answers when the target IP is configured on the receiving interface and the sender IP is on the same subnet as that interface, value 1 omits the same-subnet requirement and value 0 answers for any local address. Prevents the host from answering ARP for addresses on other interfaces and blocks ARP-based reconnaissance. May break connectivity on networks where ARP responses are expected on all interfaces (e.g. some load balancer configurations).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_073",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.arp_announce",
        2
    )
    .with_description("Use the most restrictive ARP announcement mode. May break connectivity on some network configurations where the less restrictive ARP announcement modes are expected.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_074",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.arp_announce",
        2
    )
    .with_description("Use the most restrictive ARP announcement mode. May break connectivity on some network configurations where the less restrictive ARP announcement modes are expected.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_075",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.route_localnet",
        0
    )
    .with_description("Disable routing of `127.0.0.0/8` to external networks. Prevents local net traffic from being routed outside the host.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_076",
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
        "SYN_077",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.ip_local_port_range",
        "32768\t65535"
    )
    .with_description("Set the ephemeral port range to the full 32768–65535. Reserves more ports for the kernel and reduces accidental conflicts with low-numbered service ports.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_078",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.tcp_rfc1337",
        1
    )
    .with_description("Enable RFC 1337 behavior to mitigate TIME_WAIT assassination attacks. Prevents old duplicate segments from interfering with new connections.")
    .register();

    // TODO: remove? mostly not a problem anymore?
    // sysctl::add_sysctl_check!(
    //     "SYN_079",
    //     Severity::High,
    //     vec!["sysctl", "ipv4", "server", "workstation"],
    //     "net.ipv4.tcp_timestamps",
    //     0
    // )
    // .register();

    sysctl::add_sysctl_check!(
        "SYN_080",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.all.log_martians",
        1
    )
    .with_description("Log packets with impossible source addresses. Martian packets indicate spoofing attempts or misconfigurations. Increases log volume and disk I/O; under heavy spoofing traffic this can fill disk or slow the system.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_081",
        Severity::High,
        vec!["sysctl", "ipv4", "CIS", "STIG", "server", "workstation"],
        "net.ipv4.conf.default.log_martians",
        1
    )
    .with_description("Log packets with impossible source addresses. Martian packets indicate spoofing attempts or misconfigurations. Increases log volume and disk I/O; under heavy spoofing traffic this can fill disk or slow the system.")
    .register();

    // TODO: remove? was temp fix for 2019 CVEs
    // sysctl::add_sysctl_check!(
    //     "SYN_082",
    //     Severity::High,
    //     vec!["sysctl", "ipv4", "paranoid", "server", "workstation"],
    //     "net.ipv4.tcp_sack",
    //     0
    // )
    // .register();

    // TODO: remove?
    // sysctl::add_sysctl_check!(
    //     "SYN_083",
    //     Severity::High,
    //     vec!["sysctl", "ipv4", "paranoid", "server", "workstation"],
    //     "net.ipv4.tcp_dsack",
    //     0
    // )
    // .register();

    // TODO: remove? deprecated?
    // sysctl::add_sysctl_check!(
    //     "SYN_084",
    //     Severity::High,
    //     vec!["sysctl", "ipv4", "paranoid", "server", "workstation"],
    //     "net.ipv4.tcp_fack",
    //     0
    // )
    // .register();

    sysctl::add_sysctl_check!(
        "SYN_085",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.tcp_synack_retries",
        5
    )
    .with_description("Limit TCP SYN-ACK retries for incoming connections. High values waste resources and enable slow-DoS attacks by holding half-open connections.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_086",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.forwarding",
        0
    )
    .with_description("Disable IPv4 packet forwarding on all interfaces. Non-routers should not forward packets. The system can no longer act as a router, NAT gateway, or VPN server forwarding IPv4 traffic.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_087",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.forwarding",
        0
    )
    .with_description("Disable IPv4 packet forwarding by default on new interfaces. Non-routers should not forward packets. The system can no longer act as a router, NAT gateway, or VPN server forwarding IPv4 traffic on newly added interfaces.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_088",
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
        "SYN_089",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.mc_forwarding",
        0
    )
    .with_description("Disable IPv4 multicast forwarding by default. Non-routers should not forward multicast traffic. Breaks IPv4 multicast routing (e.g. IPTV, mDNS reflectors) on new interfaces.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_090",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.bc_forwarding",
        0
    )
    .with_description("Disable broadcast forwarding on all interfaces (amplification and pivot vector). Only meaningful while unicast forwarding is on.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_091",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.bc_forwarding",
        0
    )
    .with_description("Disable broadcast forwarding by default (amplification and pivot vector). Only meaningful while unicast forwarding is on.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_092",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.route_localnet",
        0
    )
    .with_description("conf.default counterpart of SYN_075: never route 127.0.0.0/8 onto external networks. Loopback-routable hosts are trivially spoofable/MITM-able.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_093",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.accept_local",
        0
    )
    .with_description("conf.default counterpart of SYN_067: reject packets with this host's own source address arriving externally (local-net spoofing).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_094",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.arp_filter",
        1
    )
    .with_description("conf.default counterpart of SYN_070: answer ARP only when the target IP is configured on the receiving interface. Prevents ARP confusion on multi-homed hosts.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_095",
        Severity::High,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.drop_gratuitous_arp",
        1
    )
    .with_description("conf.default counterpart of SYN_076: drop gratuitous ARP. GARP is the canonical ARP-cache-poisoning vehicle.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_096",
        Severity::Medium,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.arp_accept",
        0
    )
    .with_description("Refuse to create ARP entries from gratuitous ARP that do not match an existing entry (cache-poisoning mitigation). VRRP/keepalived failover needs 1 on the backup node.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_097",
        Severity::Medium,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.arp_accept",
        0
    )
    .with_description("Refuse to create ARP entries from gratuitous ARP that do not match an existing entry by default (cache-poisoning mitigation). VRRP/keepalived failover needs 1 on the backup node.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_098",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.proxy_arp",
        0
    )
    .with_description(
        "Do not answer ARP on behalf of other hosts. Enables MITM and pivoting if turned on.",
    )
    .register();

    sysctl::add_sysctl_check!(
        "SYN_099",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.proxy_arp",
        0
    )
    .with_description("Do not answer ARP on behalf of other hosts by default. Enables MITM and pivoting if turned on.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_100",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.proxy_arp_pvlan",
        0
    )
    .with_description("Private-VLAN variant of proxy ARP. Keep disabled.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_101",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.proxy_arp_pvlan",
        0
    )
    .with_description("Private-VLAN variant of proxy ARP. Keep disabled by default.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_102",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.bootp_relay",
        0
    )
    .with_description("Do not relay BOOTP broadcasts (obsolete relay feature).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_103",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.bootp_relay",
        0
    )
    .with_description("Do not relay BOOTP broadcasts by default (obsolete relay feature).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_104",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.drop_unicast_in_l2_multicast",
        1
    )
    .with_description("Drop unicast IP packets encapsulated in L2 multicast/broadcast frames. Such frames have no legitimate use and appear in spoofing/evasion tricks.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_105",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.drop_unicast_in_l2_multicast",
        1
    )
    .with_description("Drop unicast IP packets encapsulated in L2 multicast/broadcast frames by default. Such frames have no legitimate use and appear in spoofing/evasion tricks.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_106",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.disable_policy",
        0
    )
    .with_description("Keep IPsec policy checking enabled per interface. 1 exempts traffic from xfrm policy (catastrophic on IPsec hosts).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_107",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.disable_policy",
        0
    )
    .with_description("Keep IPsec policy checking enabled per interface by default. 1 exempts traffic from xfrm policy (catastrophic on IPsec hosts).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_108",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.all.disable_xfrm",
        0
    )
    .with_description("Keep locally-generated traffic subject to IPsec transforms. 1 lets local packets bypass encryption policy.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_109",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.conf.default.disable_xfrm",
        0
    )
    .with_description("Keep locally-generated traffic subject to IPsec transforms by default. 1 lets local packets bypass encryption policy.")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYN_110",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.icmp_msgs_per_sec",
        1000
    )
    .with_description("Global cap on outbound ICMP message generation. Prevents the host being driven as a reflector/amplifier.")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYN_111",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.icmp_msgs_burst",
        50
    )
    .with_description("Burst companion of icmp_msgs_per_sec. Keep the default 50.")
    .register();

    sysctl::add_sysctl_min_check!(
        "SYN_112",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.ip_unprivileged_port_start",
        1024
    )
    .with_description("Lowering it lets unprivileged processes bind well-known service ports (impersonation/MITM on the host). Keep the default 1024.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_113",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.ping_group_range",
        "1\t0"
    )
    .with_description("Disable unprivileged ICMP echo sockets (empty range). Forcing setuid/capable ping(8) shrinks attack surface but breaks sandboxed ping.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_114",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.tcp_fastopen",
        0
    )
    .with_description("Disable TCP Fast Open (default 1 client-enabled). Removes the TFO cookie/SYN fast-path (historic bug source, usable for SYN spoofing). Small latency cost for repeat connections.")
    .register();

    sysctl::add_sysctl_min_check!(
        "SYN_115",
        Severity::Informational,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.tcp_min_snd_mss",
        48
    )
    .with_description(
        "Keep the minimum outgoing MSS floor from the CVE-2019-11477 (SACK Panic) fixes.",
    )
    .register();

    sysctl::add_sysctl_min_check!(
        "SYN_116",
        Severity::Informational,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.tcp_challenge_ack_limit",
        1000
    )
    .with_description("Challenge-ACK limit against CVE-2016-5696 blind in-window attacks. Do not lower it on old kernels (INT_MAX on >= 5.19).")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYN_117",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.ipfrag_time",
        15
    )
    .with_description("Shrink the fragment reassembly window (default 30). Fragments are a DoS and IDS-evasion vehicle, shorter retention limits both.")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYN_118",
        Severity::Low,
        vec!["sysctl", "ipv4", "server", "workstation"],
        "net.ipv4.ipfrag_high_thresh",
        4194304
    )
    .with_description("Cap memory held for reassembling IPv4 fragments. Beyond it fragments are dropped instead of exhausting RAM. Lower on small hosts.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_200",
        Severity::Informational,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.disable_ipv6",
        1
    )
    .with_description("Disable IPv6 support on all interfaces. Informational only: CIS recommends it when IPv6 is not required, but turning the protocol off is not a security improvement over a hardened dual-stack host, the neighbor discovery, router advertisement and source routing checks already close the on-link attack paths, and the ipv6 module stays loaded so its code paths remain reachable in the kernel. Deletes every IPv6 address including `::1`, which breaks dual-stack services, container and VM networking, and applications that bind or resolve localhost over IPv6. Interfaces created later inherit `net.ipv6.conf.default.disable_ipv6`, and `ipv6.disable=1` on the kernel command line or blacklisting the ipv6 module is required to keep the stack out of the kernel entirely.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_201",
        Severity::Informational,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.default.disable_ipv6",
        1
    )
    .with_description("Disable IPv6 by default on interfaces created after this is applied, such as container veth pairs, tunnels, VLANs and bridges, which inherit `net.ipv6.conf.default` and would otherwise come up with IPv6 enabled. Informational only: as with `net.ipv6.conf.all.disable_ipv6`, turning the protocol off is not a security improvement over a hardened dual-stack host, the neighbor discovery, router advertisement and source routing checks already close the on-link attack paths, and the ipv6 module stays loaded so its code paths remain reachable in the kernel. New interfaces keep no IPv6 address, not even a link-local one, which breaks IPv6 for containers, VMs and tunnels that expect it, and `ipv6.disable=1` on the kernel command line or blacklisting the ipv6 module is still required to keep the stack out of the kernel entirely.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_202",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.accept_source_route",
        0
    )
    .with_description("Disable acceptance of IPv6 source-routed packets. Source routing allows the sender to specify the path, which could be used to bypass network security controls. Breaks legacy diagnostic tools (e.g. traceroute with source routing).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_203",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.default.accept_source_route",
        0
    )
    .with_description("Disable acceptance of IPv6 source-routed packets. Source routing allows the sender to specify the path, which could be used to bypass network security controls. Breaks legacy diagnostic tools (e.g. traceroute with source routing).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_204",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.accept_redirects",
        0
    )
    .with_description("Disable acceptance of IPv6 ICMP redirects. Prevents the system from learning better routes from routers, which an attacker on the link could otherwise use to rewrite the routing table and man-in-the-middle traffic. May break connectivity on IPv6 networks that rely on redirects for optimal routing.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_205",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.default.accept_redirects",
        0
    )
    .with_description("Disable acceptance of IPv6 ICMP redirects. Prevents the system from learning better routes from routers, which an attacker on the link could otherwise use to rewrite the routing table and man-in-the-middle traffic. May break connectivity on IPv6 networks that rely on redirects for optimal routing.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_206",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.icmp.echo_ignore_all",
        1
    )
    .with_description("Drop all incoming ICMPv6 echo requests (ping). Only the echo type is ignored, the rest of ICMPv6 is untouched since IPv6 depends on it for neighbor discovery and path MTU discovery. Reduces network-based fingerprinting at the cost of ping-based diagnostics.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_207",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.forwarding",
        0
    )
    .with_description("Disable IPv6 packet forwarding. Non-routers should not forward packets, as it enables the host to be used as a pivot for network-level attacks.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_208",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.forwarding",
        0
    )
    .with_description("Disable IPv6 packet forwarding. Non-routers should not forward packets, as it enables the host to be used as a pivot for network-level attacks.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_209",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.all.accept_ra",
        0
    )
    .with_description("Disable acceptance of IPv6 Router Advertisements (RAs). Rogue RAs can redirect traffic or provide malicious network configuration. IPv6 SLAAC configuration may stop working.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_210",
        Severity::High,
        vec!["sysctl", "ipv6", "CIS", "server", "workstation"],
        "net.ipv6.conf.default.accept_ra",
        0
    )
    .with_description("Disable acceptance of IPv6 Router Advertisements (RAs). Rogue RAs can redirect traffic or provide malicious network configuration. IPv6 SLAAC configuration may stop working.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_211",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.router_solicitations",
        0
    )
    .with_description("Disable IPv6 Router Solicitation (RS). Prevents the host from requesting router information, reducing network fingerprinting. IPv6 SLAAC configuration may stop working, and IPv6 connectivity may be delayed until the next unsolicited RA arrives.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_212",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.router_solicitations",
        0
    )
    .with_description("Disable IPv6 Router Solicitation (RS). Prevents the host from requesting router information, reducing network fingerprinting. IPv6 SLAAC configuration may stop working, and IPv6 connectivity may be delayed until the next unsolicited RA arrives.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_213",
        Severity::Informational,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.accept_ra_rtr_pref",
        0
    )
    .with_description("Ignore RFC 4191 router preference in IPv6 Router Advertisements. The system will no longer prefer higher-priority routers, which may result in suboptimal routing on networks with multiple IPv6 routers.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_214",
        Severity::Informational,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.accept_ra_rtr_pref",
        0
    )
    .with_description("Ignore RFC 4191 router preference in Router Advertisements by default. The system will no longer prefer higher-priority routers, which may result in suboptimal routing on networks with multiple IPv6 routers.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_215",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.accept_ra_defrtr",
        0
    )
    .with_description("Disable learning default router from IPv6 RAs. Prevents rogue routers from hijacking default gateway. IPv6 connectivity will be lost unless a default gateway is statically configured.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_216",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.accept_ra_defrtr",
        0
    )
    .with_description("Disable learning default router from Router Advertisements by default. IPv6 connectivity will be lost unless a default gateway is statically configured.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_217",
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
        "SYN_218",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.autoconf",
        0
    )
    .with_description("Disable IPv6 autoconfiguration by default. Prevents automatic address assignment from rogue Router Advertisements. IPv6 addresses will no longer be automatically assigned, breaking IPv6 connectivity unless addresses are manually configured.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_219",
        Severity::Medium,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.max_addresses",
        1
    )
    .with_description("Limit IPv6 addresses per interface to 1. Reduces attack surface from SLAAC-assigned addresses. Services requiring multiple IPv6 addresses (e.g. multi-homed hosting, certain DNS setups) will not work.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_220",
        Severity::Medium,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.max_addresses",
        1
    )
    .with_description("Limit IPv6 addresses per interface to 1 by default. Reduces attack surface from SLAAC-assigned addresses. Services requiring multiple IPv6 addresses (e.g. multi-homed hosting, certain DNS setups) will not work.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_221",
        Severity::Informational,
        vec!["sysctl", "ipv6", "paranoid", "server", "workstation"],
        "net.ipv6.conf.all.use_tempaddr",
        2
    )
    .with_description("Always use temporary IPv6 addresses for outgoing connections. Prevents long-term tracking via stable IPv6 addresses.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_222",
        Severity::Informational,
        vec!["sysctl", "ipv6", "paranoid", "server", "workstation"],
        "net.ipv6.conf.default.use_tempaddr",
        2
    )
    .with_description("Use temporary IPv6 addresses by default. Prevents long-term tracking via stable IPv6 addresses.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_223",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.icmp.echo_ignore_anycast",
        1
    )
    .with_description("Ignore ICMPv6 echo requests sent to anycast addresses. Prevents fingerprinting and abuse of anycast addresses. Breaks network diagnostic tools (e.g. ping) to anycast addresses.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_224",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.icmp.echo_ignore_multicast",
        1
    )
    .with_description("Ignore ICMPv6 echo requests sent to multicast addresses. Prevents the host from being driven as a smurf-style amplifier and reduces fingerprinting. Breaks network diagnostic tools (e.g. ping) to multicast addresses.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_225",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.mc_forwarding",
        0
    )
    .with_description("Disable IPv6 multicast forwarding. Non-routers should not forward multicast traffic. Breaks IPv6 multicast routing (e.g. mDNS, SSDP).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_226",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.mc_forwarding",
        0
    )
    .with_description("Disable IPv6 multicast forwarding by default. Non-routers should not forward multicast traffic. Breaks IPv6 multicast routing (e.g. mDNS, SSDP) on new interfaces.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_227",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.accept_ra_from_local",
        0
    )
    .with_description("Never accept RAs sourced from link-local addresses (rogue-RA hardening, only relevant if RAs are accepted at all).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_228",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.accept_ra_from_local",
        0
    )
    .with_description("Never accept RAs sourced from link-local addresses by default (rogue-RA hardening, only relevant if RAs are accepted at all).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_229",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.disable_policy",
        0
    )
    .with_description("Keep IPsec policy checking enabled for IPv6.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_230",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.disable_policy",
        0
    )
    .with_description("Keep IPsec policy checking enabled for IPv6 by default.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_231",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.drop_unicast_in_l2_multicast",
        1
    )
    .with_description("IPv6 counterpart of the IPv4 option: drop unicast packets in L2 multicast/broadcast frames.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_232",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.drop_unicast_in_l2_multicast",
        1
    )
    .with_description("IPv6 counterpart of the IPv4 option: drop unicast packets in L2 multicast/broadcast frames by default.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_233",
        Severity::Medium,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.accept_untracked_na",
        0
    )
    .with_description("Do not create/refresh neighbor-cache entries from unsolicited untracked NAs. Accepting them is a direct ND cache-poisoning (on-link MITM) vector. Keep default 0.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_234",
        Severity::Medium,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.accept_untracked_na",
        0
    )
    .with_description("Do not create/refresh neighbor-cache entries from unsolicited untracked NAs by default. Accepting them is a direct ND cache-poisoning (on-link MITM) vector.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_235",
        Severity::Medium,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.drop_unsolicited_na",
        1
    )
    .with_description("Drop unsolicited NAs entirely (stronger rogue-ND protection). Breaks legitimate address-move announcements used by some failover/VRRP setups.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_236",
        Severity::Medium,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.drop_unsolicited_na",
        1
    )
    .with_description("Drop unsolicited NAs entirely by default (stronger rogue-ND protection). Breaks legitimate address-move announcements used by some failover/VRRP setups.")
    .register();

    sysctl::add_sysctl_min_check!(
        "SYN_237",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.accept_dad",
        1
    )
    .with_description("Keep Duplicate Address Detection on (2 additionally disables the address when DAD fails). Prevents address-confusion accidents and some on-link spoofing.")
    .register();

    sysctl::add_sysctl_min_check!(
        "SYN_238",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.accept_dad",
        1
    )
    .with_description("Keep Duplicate Address Detection on by default (2 additionally disables the address when DAD fails). Prevents address-confusion accidents and some on-link spoofing.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_239",
        Severity::Informational,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.enhanced_dad",
        1
    )
    .with_description("Keep the DAD nonce enabled. Blocks off-link DAD spoofing (forged DAD responses disabling an address).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_240",
        Severity::Informational,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.enhanced_dad",
        1
    )
    .with_description("Keep the DAD nonce enabled by default. Blocks off-link DAD spoofing (forged DAD responses disabling an address).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_241",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.suppress_frag_ndisc",
        1
    )
    .with_description("Keep RFC 6980 behavior: NDP packets arriving in fragments are ignored (fragment-based ND attacks).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_242",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.suppress_frag_ndisc",
        1
    )
    .with_description("Keep RFC 6980 behavior by default: NDP packets arriving in fragments are ignored (fragment-based ND attacks).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_243",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.proxy_ndp",
        0
    )
    .with_description(
        "Do not answer neighbor solicitations on behalf of other hosts (NDP MITM/pivot).",
    )
    .register();

    sysctl::add_sysctl_check!(
        "SYN_244",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.proxy_ndp",
        0
    )
    .with_description("Do not answer neighbor solicitations on behalf of other hosts by default (NDP MITM/pivot).")
    .register();

    sysctl::add_sysctl_min_check!(
        "SYN_245",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.addr_gen_mode",
        2
    )
    .with_description("Use RFC 7217 stable-privacy addresses (2 or 3) instead of EUI-64, which embeds the MAC (stable cross-network tracking identifier). Applies to new interfaces, existing ones must be reconfigured.")
    .register();

    sysctl::add_sysctl_min_check!(
        "SYN_246",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.addr_gen_mode",
        2
    )
    .with_description("Use RFC 7217 stable-privacy addresses (2 or 3) by default instead of EUI-64, which embeds the MAC (stable cross-network tracking identifier).")
    .register();

    check::Check::new(
        "SYN_247",
        "Ensure sysctl `net.ipv6.icmp.ratelimit` >= 1 and <= 100",
        Severity::High,
        vec!["sysctl", "ipv6", "server", "workstation"],
        || {
            const VAL: i32 = 100;
            match sysctl::get_sysctl_i32_value("net.ipv6.icmp.ratelimit") {
                Ok(value) => {
                    if (1..=VAL).contains(&value) {
                        (check::CheckState::Pass, Some(format!("{}", value)))
                    } else {
                        (
                            check::CheckState::Fail,
                            Some(format!("{} is not in [1..{}]", value, VAL)),
                        )
                    }
                }
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sysctl::init_sysctl_config],
    )
    .with_description("ICMPv6 twin of SYN_064: rate-limit outgoing ICMPv6 errors to block rate side channels and slow reconnaissance. Kernel default 100. Must be non-zero, 0 disables the rate limiting entirely.")
    .with_fix("Add `net.ipv6.icmp.ratelimit = 100` (any value between 1 and 100) in `/etc/sysctl.d/*.conf` and run `sysctl --system`.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_248",
        Severity::Informational,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.icmp.ratemask",
        "0-1,3-127"
    )
    .with_description("ICMPv6 types covered by ratelimit, a range list (not the IPv4 bitmask). Default 0-1,3-127 covers all types except Packet Too Big (type 2, needed for PMTUD).")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYN_249",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.max_dst_opts_number",
        8
    )
    .with_description("Cap destination options per packet. Unlimited options are a parsing-DoS and IDS-evasion vector.")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYN_250",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.max_hbh_opts_number",
        8
    )
    .with_description("Cap hop-by-hop options per packet. HBH headers are processed by every router on the path (amplified DoS).")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYN_251",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.max_dst_opts_length",
        65536
    )
    .with_description("Cap total destination-options length. The INT_MAX default allows huge option blobs to burn CPU.")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYN_252",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.max_hbh_length",
        65536
    )
    .with_description("Cap total hop-by-hop-options length. The INT_MAX default allows huge option blobs to burn CPU.")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYN_253",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.ip6frag_time",
        15
    )
    .with_description("Shrink the IPv6 fragment reassembly window (default 60). Fragments are a DoS and IDS-evasion vehicle, shorter retention limits both.")
    .register();

    sysctl::add_sysctl_max_check!(
        "SYN_254",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.ip6frag_high_thresh",
        4194304
    )
    .with_description("Cap memory held for IPv6 fragment reassembly. Beyond it fragments are dropped instead of exhausting RAM.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_255",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.seg6_enabled",
        0
    )
    .with_description("Keep SRv6 (segment routing) disabled. Every enabled extension-header routing mode is additional parser attack surface.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_256",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.seg6_enabled",
        0
    )
    .with_description("Keep SRv6 (segment routing) disabled by default. Every enabled extension-header routing mode is additional parser attack surface.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_257",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.rpl_seg_enabled",
        0
    )
    .with_description("Keep RPL source routing disabled (same rationale as seg6_enabled).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_258",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.rpl_seg_enabled",
        0
    )
    .with_description(
        "Keep RPL source routing disabled by default (same rationale as seg6_enabled).",
    )
    .register();

    sysctl::add_sysctl_check!(
        "SYN_259",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.all.ioam6_enabled",
        0
    )
    .with_description("Keep in-situ OAM disabled (same rationale as seg6_enabled).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_260",
        Severity::Low,
        vec!["sysctl", "ipv6", "server", "workstation"],
        "net.ipv6.conf.default.ioam6_enabled",
        0
    )
    .with_description("Keep in-situ OAM disabled by default (same rationale as seg6_enabled).")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_350",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "net.netfilter.nf_conntrack_tcp_be_liberal",
        0
    )
    .with_description("Keep strict TCP window tracking. Out-of-window segments are marked INVALID and dropped by policy firewalls (blind RST/SYN-injection hardening). 1 accepts them, weakening stateful filtering.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_351",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "net.netfilter.nf_conntrack_tcp_ignore_invalid_rst",
        0
    )
    .with_description("Keep marking out-of-window RSTs INVALID (default). Combined with an INVALID-drop rule this defeats blind RST teardown of tracked connections.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_352",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "net.netfilter.nf_conntrack_tcp_loose",
        0
    )
    .with_description("Do not pick up mid-stream connections as ESTABLISHED. Strict mode forces every connection through NEW-state rules. Breaks asymmetric routing and firewall failover.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_353",
        Severity::Low,
        vec!["sysctl", "server", "workstation"],
        "net.netfilter.nf_conntrack_checksum",
        1
    )
    .with_description("Keep L4 checksum verification of incoming packets. Corrupt packets become INVALID instead of being tracked. Small CPU cost, mostly moot with NIC checksum offload.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_354",
        Severity::Informational,
        vec!["sysctl", "server", "workstation"],
        "net.netfilter.nf_conntrack_log_invalid",
        0
    )
    .with_description("Detection option: log INVALID packets per protocol (255 = any). Very noisy under scan/attack, keep off by default.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_355",
        Severity::Informational,
        vec!["sysctl", "server", "workstation"],
        "net.netfilter.nf_hooks_lwtunnel",
        0
    )
    .with_description("One-way switch (cannot be disabled once enabled). Leave off unless lightweight-tunnel netfilter hooks are required.")
    .register();

    sysctl::add_sysctl_check!(
        "SYN_400",
        Severity::Medium,
        vec!["sysctl", "server", "workstation"],
        "net.mptcp.enabled",
        0
    )
    .with_description("MPTCP, an unused second TCP stack is pure attack surface with a steady CVE history. Alternatively blacklist the mptcp module.")
    .register();
}
