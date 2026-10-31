use crate::check;
use crate::check::Severity;
use crate::modules::{arch, kconfig, kernel};

fn fix_disabled(config: &str) -> String {
    format!(
        "Recompile the kernel with `{}` disabled, and reboot.",
        config
    )
}

fn fix_is_set(config: &str) -> String {
    fix_value(config, "y")
}

/// Fix of the checks expecting an exact value, for options that are not
/// booleans, like `CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=0x0`.
fn fix_value(config: &str, value: &str) -> String {
    format!(
        "Recompile the kernel with `{}={}` in the .config (or set in kconfig). Alternatively some distributions have hardened kernels with different compilation options.",
        config, value
    )
}

pub fn add_checks() {
    // TODO: add a warning when we cannot read kconfig to rebuild with it
    // enabled, otherwise all of those checks could go un-checked

    check::Check::new(
        "KNC_002",
        "Ensure kernel build option `CONFIG_EFI` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_EFI"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Disable EFI runtime services support in the kernel. Removes the EFI runtime interface reachable from userspace (`/sys/firmware/efi/efivars`, `efi_test`), which allows firmware variables to be rewritten, boot entries to be replaced and Secure Boot policy to be tampered with. Only relevant on UEFI systems: the machine still boots through the bootloader, but the kernel can no longer read or write EFI variables, breaking `efibootmgr`, `fwupd` firmware updates, `mokutil`/MOK enrolment, the EFI framebuffer console (`efifb`). Keep it on hosts that manage firmware from the OS.")
    .with_fix(&fix_disabled("CONFIG_EFI"))
    .register();

    check::Check::new(
        "KNC_003",
        "Ensure kernel build option `CONFIG_CPU_SUP_AMD` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_CPU_SUP_AMD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Remove AMD-specific CPU support code. Only safe on a kernel image that runs exclusively on non-AMD x86 CPUs: without vendor detection the kernel skips AMD errata workarounds, microcode loading and the AMD-specific speculative execution mitigations, and `amd-pstate`, `k10temp` and similar drivers stop working. Do not disable it on a shared or generic kernel build.")
    .with_fix(&fix_disabled("CONFIG_CPU_SUP_AMD"))
    .register();

    check::Check::new(
        "KNC_004",
        "Ensure kernel build option `CONFIG_CPU_SUP_INTEL` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_CPU_SUP_INTEL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Remove Intel-specific CPU support code. Only safe on a kernel image that runs exclusively on non-Intel x86 CPUs: without vendor detection the kernel skips Intel errata workarounds, microcode loading, the Intel-specific speculative execution mitigations, `intel_pstate`, `coretemp` and RAPL, and Intel-only options such as `CONFIG_X86_INTEL_TSX_MODE_OFF` become unavailable. Do not disable it on a shared or generic kernel build.")
    .with_fix(&fix_disabled("CONFIG_CPU_SUP_INTEL"))
    .register();

    check::Check::new(
        "KNC_005",
        "Ensure kernel build option `CONFIG_MODULES` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional", "paranoid"],
        || kconfig::check_option_is_not_set("CONFIG_MODULES"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Build every driver, filesystem and protocol into the kernel image so that no loadable module support exists at all. This removes the whole module loading path, so not even root with `CAP_SYS_MODULE` can insert a backdoored or vulnerable module at runtime, and module signature checks become irrelevant. Only practical on a purpose-built kernel: every device needed by the hardware must be built in (large image, rebuild for any hardware change), out-of-tree and DKMS drivers (NVIDIA, VirtualBox, ZFS), most GPU stacks and anything expecting `/lib/modules` stop working.")
    .with_fix(&fix_disabled("CONFIG_MODULES"))
    .register();

    check::Check::new(
        "KNC_006",
        "Ensure kernel build option `CONFIG_DEVMEM` is not set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_DEVMEM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove `/dev/mem` from the kernel entirely. It otherwise gives root raw access to all physical memory, which defeats KASLR, allows reading kernel credentials and lets a compromised root process patch the running kernel. Stronger than `CONFIG_STRICT_DEVMEM`, which only restricts `/dev/mem` to non-RAM regions and makes this check moot when disabled. Breaks tools that poke hardware through `/dev/mem`: `flashrom`, vendor diagnostics, some BIOS/DMI readers (`dmidecode` falls back to `/sys/firmware/dmi/tables`) and legacy X.org drivers.")
    .with_fix(&fix_disabled("CONFIG_DEVMEM"))
    .register();

    check::Check::new(
        "KNC_007",
        "Ensure kernel build option `CONFIG_BPF_SYSCALL` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_BPF_SYSCALL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the `bpf()` syscall so no BPF program can be loaded into the kernel at all. eBPF runs in kernel context and its verifier has been the source of many local privilege escalations, so this is the only complete mitigation. Breaks everything built on eBPF: `bpftrace`, Cilium, Falco, `tc`/XDP filtering, `systemd` cgroup/socket controls and the tracing backends of `perf`. Classic BPF socket filters and seccomp filters keep working. Only suitable for hosts that need no eBPF.")
    .with_fix(&fix_disabled("CONFIG_BPF_SYSCALL"))
    .register();

    check::Check::new(
        "KNC_008",
        "Ensure kernel build option `CONFIG_BUG` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_BUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Keep the `BUG()`/`BUG_ON()` assertions compiled in so the kernel panics when it detects an impossible internal state instead of continuing with corrupted data structures that an attacker can escalate from. Costs a little kernel size, and the trade-off is availability: any `BUG()` reachable from unprivileged userspace becomes a denial of service, so pair it with `kernel.panic` and `kernel.panic_on_oops` settings to reboot cleanly. For systems where staying up matters more than not running a corrupted kernel, a `BUG()`-free build is the deliberate alternative.")
    .with_fix(&fix_is_set("CONFIG_BUG"))
    .register();

    check::Check::new(
        "KNC_009",
        "Ensure kernel build option `CONFIG_THREAD_INFO_IN_TASK` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_THREAD_INFO_IN_TASK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Move `thread_info` out of the kernel stack and into `task_struct`. A kernel stack overflow otherwise lands directly on `thread_info`, letting an attacker flip task flags (the classic `addr_limit` overwrite) to escalate privileges; with it, the same overflow only corrupts stack data. Prerequisite for `CONFIG_VMAP_STACK` and only offered on architectures that support it (x86, arm64, riscv and a few others), so an absent option means it is not available for this build. Cost is negligible.")
    .with_fix(&fix_is_set("CONFIG_THREAD_INFO_IN_TASK"))
    .register();

    check::Check::new(
        "KNC_010",
        "Ensure kernel build option `CONFIG_IOMMU_SUPPORT` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_IOMMU_SUPPORT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Compile in the IOMMU framework so device DMA can be restricted to the memory explicitly granted to it. Without it the `intel_iommu=on`/`amd_iommu=on` kernel command line parameters do nothing, and any malicious or compromised peripheral (FireWire, Thunderbolt, PCIe card, USB4 dock) can read and write all of RAM. Only useful when the CPU and chipset actually provide an IOMMU (VT-d/AMD-Vi), it is enabled in firmware and turned on from the command line. Costs some DMA throughput in strict mode, and devices needing unrestricted DMA (certain GPUs, capture cards) may require passthrough mode.")
    .with_fix(&fix_is_set("CONFIG_IOMMU_SUPPORT"))
    .register();

    check::Check::new(
        "KNC_011",
        "Ensure kernel build option `CONFIG_RANDOMIZE_MEMORY` is set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_RANDOMIZE_MEMORY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Randomize the base of the kernel memory sections on every boot: the direct physical mapping (`page_offset_base`), the vmalloc region and the vmemmap region. Image KASLR (`CONFIG_RANDOMIZE_BASE`) alone leaves those at fixed offsets, so a single leaked kernel pointer is enough to derive physical addresses, which is what page spraying, use-after-free reclaim and direct map gadgets rely on. `nokaslr` on the kernel command line disables it whatever the build is. Costs a little boot time.")
    .with_fix(&fix_is_set("CONFIG_RANDOMIZE_MEMORY"))
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#kernel-address-space-layout-randomization-kaslr")
    .register();

    check::Check::new(
        "KNC_012",
        "Ensure kernel build option `CONFIG_RANDOMIZE_BASE` is set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_RANDOMIZE_BASE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Enable Kernel Address Space Layout Randomization (KASLR), randomizing the physical and virtual base of the kernel image at every boot so exploits cannot hardcode kernel addresses. Entropy is limited (roughly 1 GiB at 64 KiB granularity on x86_64) and KASLR is routinely defeated by information leaks, so it only pays off together with pointer hiding (`kernel.kptr_restrict`), `CONFIG_RANDOMIZE_MEMORY` and `nokaslr` absent from the kernel command line. Costs a little boot time and makes fixed-address kernel debugging assumptions invalid; x86 and arm64.")
    .with_fix(&fix_is_set("CONFIG_RANDOMIZE_BASE"))
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#kernel-address-space-layout-randomization-kaslr")
    .register();

    check::Check::new(
        "KNC_013",
        "Ensure kernel build option `CONFIG_LIST_HARDENED` is set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_LIST_HARDENED"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 6, 0)))
    .with_description("Always compile in the cheap integrity checks on kernel doubly linked list operations, so a `list_del()` on an entry whose `prev`/`next` no longer point back at it is caught instead of performing an attacker-controlled unlink. Corrupted lists are a classic exploitation primitive. Detection only warns unless `CONFIG_BUG_ON_DATA_CORRUPTION` is also set, in which case the kernel panics. Negligible cost; this is the lighter sibling of `CONFIG_DEBUG_LIST`.")
    .with_fix(&fix_is_set("CONFIG_LIST_HARDENED"))
    .register();

    check::Check::new(
        "KNC_014",
        "Ensure kernel build option `CONFIG_RANDOM_KMALLOC_CACHES` is set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_RANDOM_KMALLOC_CACHES"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((7, 2, 0)))
    .skip_when(|| kernel::skip_kernel_before((6, 6, 0)))
    .with_description("Give each process a randomly selected set of `kmalloc` caches so that objects freed by one subsystem are not trivially reallocated by another, making cross-cache use-after-free and heap-spraying attacks much harder. Requires SLUB. The partitioned caches are never merged with each other, but every other cache in the kernel still is unless `CONFIG_SLAB_MERGE_DEFAULT=n` or `slab_nomerge` is used, so the two belong together. Costs extra memory for the duplicated caches and slightly worse locality.")
    .with_fix(&fix_is_set("CONFIG_RANDOM_KMALLOC_CACHES"))
    .register();

    check::Check::new(
        "KNC_015",
        "Ensure kernel build option `CONFIG_KMALLOC_PARTITION_CACHES` is set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_KMALLOC_PARTITION_CACHES"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((7, 2, 0)))
    .with_description("Give each process a randomly selected set of `kmalloc` caches so that objects freed by one subsystem are not trivially reallocated by another, making cross-cache use-after-free and heap-spraying attacks much harder. Requires SLUB. The partitioned caches are never merged with each other, but every other cache in the kernel still is unless `CONFIG_SLAB_MERGE_DEFAULT=n` or `slab_nomerge` is used, so the two belong together. Costs extra memory for the duplicated caches and slightly worse locality.")
    .with_fix(&fix_is_set("CONFIG_KMALLOC_PARTITION_CACHES"))
    .register();

    check::Check::new(
        "KNC_016",
        "Ensure kernel build option `CONFIG_SLAB_MERGE_DEFAULT` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_SLAB_MERGE_DEFAULT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Stop slab caches with the same size and characteristics from being merged into each other, so a heap overflow or use-after-free in one cache cannot reach the objects of an unrelated subsystem that happens to share it: with merging enabled any allocation of a matching size is a valid target and the cache layout is predictable, which is what cross-cache reclaim techniques rely on. This makes no-merge the build-time default, so it holds even when the bootloader entry is edited, and `slab_nomerge` is then redundant rather than mandatory; note that `slab_merge`/`slub_merge` on the kernel command line re-enables merging whatever the build is. Costs extra memory for the duplicated caches and slightly worse locality, and it is the counterpart of `CONFIG_RANDOM_KMALLOC_CACHES`, which only partitions the normal `kmalloc` caches. SLUB only.")
    .with_fix(&fix_disabled("CONFIG_SLAB_MERGE_DEFAULT"))
    .register();

    check::Check::new(
        "KNC_017",
        "Ensure kernel build option `CONFIG_PAGE_TABLE_CHECK` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional", "paranoid"],
        || kconfig::check_option_is_set("CONFIG_PAGE_TABLE_CHECK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 17, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "arm64", "riscv64", "riscv32"]))
    .with_description("Compile in the page table checking framework, which validates the refcount and mapping state of every page as it is added to or removed from a page table, catching double mappings of the same page, use-after-free and double-free of pages. It is off at runtime unless `CONFIG_PAGE_TABLE_CHECK_ENFORCED` is set or `page_table_check=on` is passed on the kernel command line. Costs measurable overhead and extra memory per page on mapping changes, so it is mainly an assurance or debugging feature.")
    .register();

    check::Check::new(
        "KNC_018",
        "Ensure kernel build option `CONFIG_PAGE_TABLE_CHECK_ENFORCED` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional", "paranoid"],
        || kconfig::check_option_is_set_not_missing("CONFIG_PAGE_TABLE_CHECK_ENFORCED"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 17, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "arm64", "riscv64", "riscv32"]))
    .with_description("Turn page table checking on at boot without needing `page_table_check=on` on the kernel command line, so it cannot be disabled by whoever edits the bootloader entry. Requires `CONFIG_PAGE_TABLE_CHECK`. Same cost as the framework itself: extra memory and overhead on every page map and unmap, and once enforced it cannot be turned off at runtime. Only worth it where a corrupted mapping must be caught immediately rather than after the fact.")
    .with_fix(&fix_is_set("CONFIG_PAGE_TABLE_CHECK_ENFORCED"))
    .register();

    check::Check::new(
        "KNC_019",
        "Ensure kernel build option `CONFIG_BUG_ON_DATA_CORRUPTION` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_BUG_ON_DATA_CORRUPTION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Make the integrity checks that detect corrupted kernel data structures (hardened lists, slab freelist validation, page table checks and other `CHECK_DATA_CORRUPTION` users) panic immediately instead of only logging a warning, so an exploit cannot keep running after it has already corrupted memory. Requires the individual hardening options to be compiled in to have anything to trigger. The drawback is availability: any corruption, including a harmless driver bug, becomes an instant crash, so it belongs on hosts that can tolerate a hard reboot (set `kernel.panic` so the machine reboots automatically).")
    .with_fix(&fix_is_set("CONFIG_BUG_ON_DATA_CORRUPTION"))
    .register();

    check::Check::new(
        "KNC_020",
        "Ensure kernel build option `CONFIG_SLAB_FREELIST_HARDENED` is set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_SLAB_FREELIST_HARDENED"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Obfuscate and validate SLUB freelist pointers so an out-of-bounds write or use-after-free on a heap object cannot redirect the next allocation to an attacker-chosen address; a corrupted pointer is detected instead of being followed. Negligible performance cost and no compatibility impact, so there is no reason to leave it off. SLUB only, and it complements `CONFIG_SLAB_FREELIST_RANDOM` as the baseline heap hardening pair.")
    .with_fix(&fix_is_set("CONFIG_SLAB_FREELIST_HARDENED"))
    .register();

    check::Check::new(
        "KNC_021",
        "Ensure kernel build option `CONFIG_SLAB_FREELIST_RANDOM` is set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_SLAB_FREELIST_RANDOM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Randomize the order of objects on each SLUB freelist when a cache is created, so allocations are no longer handed out in a predictable order and the usual `kmalloc` spraying and use-after-free reclaim techniques stop being reliable. Costs a few cycles per cache creation and slightly worsens locality; no functional impact. The order is fixed per boot, so it complements rather than replaces `CONFIG_RANDOM_KMALLOC_CACHES` and `slab_nomerge`.")
    .with_fix(&fix_is_set("CONFIG_SLAB_FREELIST_RANDOM"))
    .register();

    check::Check::new(
        "KNC_022",
        "Ensure kernel build option `CONFIG_SHUFFLE_PAGE_ALLOCATOR` is set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_SHUFFLE_PAGE_ALLOCATOR"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 2, 0)))
    .with_description("Shuffle the page allocator free lists at boot and on memory hotplug so the physical page order is not deterministic, which limits attacks that infer where sensitive data lives or that try to land a page at a guessed physical address. Must additionally be enabled at runtime with `page_alloc.shuffle=1`, otherwise the build option alone does nothing.")
    .with_fix(&fix_is_set("CONFIG_SHUFFLE_PAGE_ALLOCATOR"))
    .register();

    check::Check::new(
        "KNC_023",
        "Ensure kernel build option `CONFIG_FORTIFY_SOURCE` is set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_FORTIFY_SOURCE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Enable `_FORTIFY_SOURCE` bounds checking for the kernel's `memcpy`, `strcpy`, `sprintf`, `bitmap_*` and similar helpers: overflows are rejected at compile time when the destination size is known and at runtime otherwise, turning a silent heap or stack overflow into a detected failure. Requires a compiler providing `__builtin_object_size` and only covers calls whose size the compiler can determine, so it is a mitigation, not a guarantee. Costs a little kernel size with negligible runtime overhead. A detected overflow aborts the operation (or panics with `CONFIG_BUG_ON_DATA_CORRUPTION`), so poorly written out-of-tree modules may start failing loudly.")
    .with_fix(&fix_is_set("CONFIG_FORTIFY_SOURCE"))
    .register();

    check::Check::new(
        "KNC_024",
        "Ensure kernel build option `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_INIT_ON_ALLOC_DEFAULT_ON"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 3, 0)))
    .with_description("Zero every heap and page allocation by default, so memory freed by one subsystem cannot be read back by another: it closes information leaks from uninitialized allocations and makes use-after-free reads return zeros instead of keys, pointers or credentials. This only sets the default, `init_on_alloc=0` on the kernel command line can still turn it off. Costs a memset per allocation, typically a few percent on allocation-heavy workloads. Pair with `init_on_free=1` and stack initialization for full coverage.")
    .with_fix(&fix_is_set("CONFIG_INIT_ON_ALLOC_DEFAULT_ON"))
    .register();

    check::Check::new(
        "KNC_025",
        "Ensure kernel build option `CONFIG_STATIC_USERMODEHELPER` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_STATIC_USERMODEHELPER"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Route every kernel-initiated userspace program (module autoloading, core dump handlers, firmware loading, hotplug, poweroff) through one compiled-in path, so root cannot redirect kernel execution by rewriting `/proc/sys/kernel/modprobe`, `/proc/sys/kernel/core_pattern` or the hotplug helper. Also requires `CONFIG_STATIC_USERMODEHELPER_PATH` to point at a real helper: the default empty string disables all usermode helpers, which silently breaks module autoloading, core dumps and firmware loading unless the helper exists in the initramfs.")
    .with_fix(&fix_is_set("CONFIG_STATIC_USERMODEHELPER"))
    .register();

    check::Check::new(
        "KNC_026",
        "Ensure kernel build option `CONFIG_SCHED_CORE` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_SCHED_CORE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 14, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32", "arm64", "arm32"]))
    .with_description("Enable core scheduling, which guarantees that only tasks sharing a scheduling cookie run simultaneously on the SMT siblings of one physical core, mitigating cross-hyperthread side channels without disabling SMT entirely. Useful only when untrusted code shares a core (co-located VMs or containers). Enabling the option protects nothing by itself: userspace must assign cookies through the cgroup v2 `cpu.core_sched` interface or `prctl(PR_SCHED_CORE)`. Costs scheduler overhead and throughput when untrusted tasks are forced apart; disabling SMT (`nosmt`) is the simpler alternative.")
    .with_fix(&fix_is_set("CONFIG_SCHED_CORE"))
    .register();

    check::Check::new(
        "KNC_027",
        "Ensure kernel build option `CONFIG_SECURITY_LOCKDOWN_LSM` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_LOCKDOWN_LSM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 4, 0)))
    .with_description("Compile in the lockdown LSM, which enforces a boundary between root and the kernel by refusing operations that would let userspace modify or inspect the running kernel: `/dev/mem`, `/dev/kmem`, `/dev/port`, MSR and IOPL access, unsigned modules, kexec of an unverified image, ACPI table overrides, tracefs, kprobes, `/proc/kcore` and more. Needs a mode to be selected at boot (`CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY`, the `lockdown=` parameter, or Secure Boot). Breaks anything relying on those interfaces: hardware flashing tools, GPU and driver debugging, `perf` and `bpftrace`, out-of-tree module loading and kdump in confidentiality mode.")
    .with_fix(&fix_is_set("CONFIG_SECURITY_LOCKDOWN_LSM"))
    .register();

    check::Check::new(
        "KNC_028",
        "Ensure kernel build option `CONFIG_SECURITY_LOCKDOWN_LSM_EARLY` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_LOCKDOWN_LSM_EARLY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 4, 0)))
    .with_description("Initialize the lockdown LSM as an early LSM so it is already enforcing before the rest of the kernel and the initramfs run, closing the window where early-boot interfaces (EFI variables, initrd-supplied ACPI tables) could be abused before lockdown becomes active. Requires `CONFIG_SECURITY_LOCKDOWN_LSM` and the LSM to appear early in `CONFIG_LSM`/`lsm=`. No cost beyond initialization order; without it lockdown still works but takes effect later in boot.")
    .with_fix(&fix_is_set("CONFIG_SECURITY_LOCKDOWN_LSM_EARLY"))
    .register();

    check::Check::new(
        "KNC_029",
        "Ensure kernel build option `CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY` is set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 4, 0)))
    .with_description("Force lockdown into confidentiality mode from the earliest boot stage, with no way for root to relax it at runtime. On top of integrity mode it also blocks anything that could leak kernel secrets: `/proc/kcore`, kprobes, tracefs, `perf` sampling of kernel data, MSR and I/O port reads, BPF kernel-memory reads, hibernation and `/dev/mem`. Requires `CONFIG_SECURITY_LOCKDOWN_LSM`. Breaks live debugging, performance profiling and crash dumping, so it is intended for hosts where the machine may be physically compromised but the data must stay secret.")
    .with_fix(&fix_is_set("CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY"))
    .register();

    // security policy
    check::Check::new(
        "KNC_030",
        "Ensure kernel build option `CONFIG_SECURITY` is set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_SECURITY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Enable the LSM hook framework that every Linux Security Module (SELinux, AppArmor, Smack, TOMOYO, Landlock, Yama, lockdown, BPF LSM) plugs into. Without it the kernel offers only DAC and no mandatory access control at all, which makes every other security-module check moot. Costs a few indirect calls per hook (largely mitigated by static calls), so there is no practical reason to disable it outside a minimal single-purpose image.")
    .with_fix(&fix_is_set("CONFIG_SECURITY"))
    .register();

    check::Check::new(
        "KNC_031",
        "Ensure kernel build option `CONFIG_SECURITY_YAMA` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_YAMA"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Enable the Yama LSM, which adds the `ptrace` restrictions controlled by `/proc/sys/kernel/yama/ptrace_scope` plus sticky child-reaper protections, limiting process inspection and injection between unrelated processes (credential dumping, debugger-based hijacking). Requires `CONFIG_SECURITY` and Yama listed in `CONFIG_LSM`/`lsm=` to be active. At scope 1 it breaks debuggers attaching to non-child processes, some crash reporters and anti-cheat/DRM software; scope 3 disables `ptrace` entirely. Most distributions ship it enabled at scope 1.")
    .with_fix(&fix_is_set("CONFIG_SECURITY_YAMA"))
    .register();

    check::Check::new(
        "KNC_032",
        "Ensure kernel build option `CONFIG_SECURITY_LANDLOCK` is set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_LANDLOCK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 13, 0)))
    .with_description("Enable the Landlock LSM, which lets unprivileged processes sandbox themselves by installing rules that restrict their own file (and, on newer kernels, network) access and cannot be relaxed afterwards. Requires `CONFIG_SECURITY` and Landlock listed in `CONFIG_LSM`/`lsm=`. No cost for processes that do not use it, but sandboxed applications lose access outside their declared rules, which can look like unexplained permission errors.")
    .with_fix(&fix_is_set("CONFIG_SECURITY_LANDLOCK"))
    .register();

    check::Check::new(
        "KNC_033",
        "Ensure kernel build option `CONFIG_SECURITY_SELINUX_DISABLE` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_SELINUX_DISABLE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 4, 0)))
    .with_description("Remove the runtime disable interface for SELinux (`/sys/fs/selinux/disable`), so root cannot silently turn mandatory access control off and must reboot instead. Only applies to kernels that still have the option (upstream removed it) and only when SELinux is built in. Costs nothing, but breaks the unsupported practice of disabling SELinux without a reboot, so recovery from a broken policy must be done by relabeling or from external media.")
    .with_fix("Recompile the kernel with `# CONFIG_SECURITY_SELINUX_DISABLE is not set` in .config and reboot.")
    .register();

    check::Check::new(
        "KNC_034",
        "Ensure kernel build option `CONFIG_SECURITY_SELINUX_BOOTPARAM` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_SELINUX_BOOTPARAM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove support for the `selinux=` kernel command line parameter, so MAC cannot be switched off by editing a bootloader entry, which is trivial for anyone with physical access or a writable `/boot`. Only applies to kernels that still have the option (upstream removed it) and only with SELinux built in. Drawback: the usual rescue path for a broken policy or a mislabeled filesystem disappears, so recovery requires external media or an offline relabel.")
    .with_fix(&fix_disabled("CONFIG_SECURITY_SELINUX_BOOTPARAM"))
    .register();

    check::Check::new(
        "KNC_035",
        "Ensure kernel build option `CONFIG_SECURITY_SELINUX_DEVELOP` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_SELINUX_DEVELOP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove support for SELinux permissive mode, so the policy always enforces and a compromised root cannot run `setenforce 0` to log denials instead of blocking them; per-domain permissive types (`semanage permissive -a`) disappear too. Requires a fully tested policy: every denial that was previously only logged becomes a hard failure, which makes this unsuitable while a policy is still being developed. Only relevant with SELinux built in.")
    .with_fix(&fix_disabled("CONFIG_SECURITY_SELINUX_DEVELOP"))
    .register();

    check::Check::new(
        "KNC_036",
        "Ensure kernel build option `CONFIG_SECURITY_WRITABLE_HOOKS` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_WRITABLE_HOOKS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 4, 0)))
    .with_description("Make the LSM hook heads read-only after boot so a loadable module cannot register or replace security hooks to bypass mandatory access control. Only meaningful on kernels that still expose the option (upstream dropped it once all in-tree LSMs became static). Costs nothing when only built-in LSMs are used, but breaks out-of-tree security modules that register hooks from a module.")
    .with_fix(&fix_disabled("CONFIG_SECURITY_WRITABLE_HOOKS"))
    .register();

    check::Check::new(
        "KNC_037",
        "Ensure kernel build option `CONFIG_SECURITY_SELINUX_DEBUG` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_SELINUX_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 6, 0)))
    .with_description("Remove the SELinux AVC debugging code, which adds verbose denial and cache instrumentation that slows down access vector lookups and leaks policy internals. The symbol only exists since v6.6, where the AVC debugging code was split out of `CONFIG_SECURITY_SELINUX`; older kernels have no such option, so the check is skipped there.")
    .with_fix(&fix_disabled("CONFIG_SECURITY_SELINUX_DEBUG"))
    .register();

    check::Check::new(
        "KNC_038",
        "Ensure kernel build option `CONFIG_SECCOMP` is set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_SECCOMP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Enable the seccomp syscall-filtering infrastructure. Without it no process can restrict its own syscall set, which containers, `systemd` `SystemCallFilter=`, browsers and sandboxed daemons rely on to shrink the kernel surface they can reach. Costs nothing when unused. Note that strict seccomp mode alone only allows `read`, `write`, `_exit` and `sigreturn`; `CONFIG_SECCOMP_FILTER` is what real software uses.")
    .with_fix(&fix_is_set("CONFIG_SECCOMP"))
    .register();

    check::Check::new(
        "KNC_039",
        "Ensure kernel build option `CONFIG_SECCOMP_FILTER` is set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_SECCOMP_FILTER"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Enable BPF-based seccomp filters (`SECCOMP_SET_MODE_FILTER`), the mechanism used by Docker and Podman default profiles, `systemd` sandboxing, Chromium, Firefox and most language runtimes to drop syscalls they never call. Every filter shrinks the reachable syscall table, so kernel bugs in unused syscalls cannot be triggered. Requires `CONFIG_SECCOMP`; it uses classic BPF, so it keeps working even when `CONFIG_BPF_SYSCALL` is disabled. Filters are inherited and can never be relaxed, so an over-strict profile breaks the application permanently for that process tree.")
    .with_fix(&fix_is_set("CONFIG_SECCOMP_FILTER"))
    .register();

    check::Check::new(
        "KNC_040",
        "Ensure kernel build option `CONFIG_BPF_UNPRIV_DEFAULT_OFF` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_BPF_UNPRIV_DEFAULT_OFF"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 13, 0)))
    .with_description("Make unprivileged BPF off by default (`kernel.unprivileged_bpf_disabled` starts at 1) while still letting root re-enable it. The unprivileged eBPF verifier is the most exploited local privilege escalation surface in recent kernels, and several distributions now disable it outright. Requires `CONFIG_BPF_SYSCALL`. Breaks unprivileged eBPF users, notably rootless Podman and Docker with certain network setups and some monitoring agents; if eBPF is not needed at all, removing `CONFIG_BPF_SYSCALL` entirely is stronger. If the option is absent, the kernel either predates it or has made the behaviour unconditional.")
    .with_fix(&fix_is_set("CONFIG_BPF_UNPRIV_DEFAULT_OFF"))
    .register();

    check::Check::new(
        "KNC_041",
        "Ensure kernel build option `CONFIG_STRICT_DEVMEM` is set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_STRICT_DEVMEM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Restrict `/dev/mem` to non-RAM regions (BIOS/EFI data areas and PCI/MMIO space) so userspace cannot read or write system memory even as root. This is the minimum acceptable setting; removing `/dev/mem` entirely with `CONFIG_DEVMEM=n` is stronger and makes this check moot. The remaining MMIO access still allows device-level attacks unless `CONFIG_IO_STRICT_DEVMEM` is also set. Breaks only tools that read RAM through `/dev/mem`, such as some memory forensics utilities.")
    .with_fix(&fix_is_set("CONFIG_STRICT_DEVMEM"))
    .register();

    check::Check::new(
        "KNC_042",
        "Ensure kernel build option `CONFIG_X86_INTEL_TSX_MODE_OFF` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_X86_INTEL_TSX_MODE_OFF"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 4, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Boot with Intel TSX (Transactional Synchronization Extensions) disabled, the default-deny setting for a feature implicated in TAA, RTM-abort and other speculative execution side channels that leak data across security boundaries. Requires `CONFIG_CPU_SUP_INTEL`, so it is unavailable when Intel CPU support is compiled out, and it is Intel x86 only. Costs the performance TSX gives lock-elision-heavy workloads (databases, JVM and GCC built with `-mrtm`), which silently fall back. It is still overridable with `tsx=on` on the kernel command line, so check that too.")
    .with_fix(&fix_is_set("CONFIG_X86_INTEL_TSX_MODE_OFF"))
    .register();

    check::Check::new(
        "KNC_043",
        "Ensure kernel build option `CONFIG_SECURITY_DMESG_RESTRICT` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_DMESG_RESTRICT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Require `CAP_SYSLOG` to read the kernel ring buffer (`dmesg`, `/dev/kmsg`, `syslog(2)`). Kernel logs routinely contain kernel pointers, driver state and hardware details that defeat KASLR and fingerprint the machine. Breaks unprivileged monitoring agents, user scripts calling `dmesg` and some crash reporters; journald keeps working because it runs privileged. Overlaps with the `kernel.dmesg_restrict` sysctl, which is the runtime equivalent and can be relaxed by root, while this build option cannot.")
    .with_fix(&fix_is_set("CONFIG_SECURITY_DMESG_RESTRICT"))
    .register();

    check::Check::new(
        "KNC_044",
        "Ensure kernel build option `CONFIG_ACPI_CUSTOM_METHOD` is not set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_ACPI_CUSTOM_METHOD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 9, 0)))
    .with_description("Remove `/sys/kernel/debug/acpi/custom_method`, which lets root write and execute arbitrary AML bytecode in kernel context - a documented privilege escalation and Secure Boot bypass, since AML is not signature verified. Nothing outside firmware development needs it. Only reachable when debugfs is mounted, so it is defence in depth on top of `CONFIG_DEBUG_FS=n` and lockdown.")
    .with_fix("Recompile the kernel with `# CONFIG_ACPI_CUSTOM_METHOD is not set` in .config and reboot.")
    .register();

    check::Check::new(
        "KNC_045",
        "Ensure kernel build option `CONFIG_COMPAT_BRK` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_COMPAT_BRK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Drop the legacy behaviour of keeping the `brk` segment at a fixed address for compatibility with pre-ELF binaries, so the heap base gets full ASLR entropy and heap spraying against a predictable `brk` stops working. Breaks only ancient binaries that assume a fixed heap address (a.out-era or very old statically linked programs); nothing built against a modern glibc is affected.")
    .with_fix(&fix_disabled("CONFIG_COMPAT_BRK"))
    .register();

    // TODO: remove?
    check::Check::new(
        "KNC_046",
        "Ensure kernel build option `CONFIG_DEVKMEM` is not set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_DEVKMEM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((5, 13, 0)))
    .with_description("Remove `/dev/kmem`, which gave anyone able to open the node direct read and write access to kernel virtual memory, defeating every kernel self-protection feature at once. Deprecated upstream and off by default for many years, so nothing legitimate needs it; obsolete debugging tools should use a crash dump or kgdb instead. If the option is absent, the kernel removed it entirely and the check reports a warning.")
    .with_fix(&fix_disabled("CONFIG_DEVKMEM"))
    .register();

    check::Check::new(
        "KNC_047",
        "Ensure kernel build option `CONFIG_BINFMT_MISC` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_BINFMT_MISC"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the `binfmt_misc` handler, which executes arbitrary file types through a registered interpreter. Because registration is done from userspace and the interpreter path is honoured regardless of mount options, it has been used to bypass execution restrictions and to escape containers that mount `binfmt_misc`. Breaks Wine, QEMU user-mode emulation (cross-architecture containers), Mono/.NET wrappers, Java launchers relying on it, and containers expecting `/proc/sys/fs/binfmt_misc` to be populated.")
    .with_fix(&fix_disabled("CONFIG_BINFMT_MISC"))
    .register();

    check::Check::new(
        "KNC_048",
        "Ensure kernel build option `CONFIG_INET_DIAG` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_INET_DIAG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the netlink `INET_DIAG`/`SOCK_DIAG` interface used to enumerate sockets and their state. It leaks connection metadata (peers, ports, timers, memory usage) that lets an unprivileged process fingerprint traffic or detect other users' sessions, and its netlink attribute parsing has had several vulnerabilities. Breaks `ss`, `netstat` variants that use sock_diag, and network monitoring agents; `/proc/net/tcp` still exists unless it is hidden separately.")
    .with_fix(&fix_disabled("CONFIG_INET_DIAG"))
    .register();

    check::Check::new(
        "KNC_049",
        "Ensure kernel build option `CONFIG_KEXEC` is not set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_KEXEC"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the `kexec_load()` syscall, so a new kernel image cannot be loaded and jumped into without going through firmware. This blocks root from replacing the running kernel. A standard persistence technique and a Secure Boot bypass, since the loaded image is not verified by firmware. Breaks kdump and fast-reboot workflows (`kexec -e`); also check `CONFIG_KEXEC_FILE`, the signed-image variant, which must be off too for this to hold.")
    .with_fix(&fix_disabled("CONFIG_KEXEC"))
    .register();

    check::Check::new(
        "KNC_050",
        "Ensure kernel build option `CONFIG_PROC_KCORE` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_PROC_KCORE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove `/proc/kcore`, the ELF view of all kernel memory that root, and any container that mounts `/proc` without masking it, can use to extract keys, credentials and kernel addresses, defeating KASLR and lockdown confidentiality mode. Breaks `crash`, live-kernel `gdb` and some forensic tools.")
    .with_fix(&fix_disabled("CONFIG_PROC_KCORE"))
    .register();

    check::Check::new(
        "KNC_051",
        "Ensure kernel build option `CONFIG_LEGACY_PTYS` is not set",
        Severity::Low,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_LEGACY_PTYS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove BSD-style legacy pseudo-terminals (`/dev/ptyXX` and `/dev/ttyXX`), which use a fixed guessable naming scheme, a hard-coded limit and none of the permission handling of devpts.")
    .with_fix(&fix_disabled("CONFIG_LEGACY_PTYS"))
    .register();

    check::Check::new(
        "KNC_052",
        "Ensure kernel build option `CONFIG_HIBERNATION` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_HIBERNATION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove suspend-to-disk support. A hibernation image is a full copy of RAM written to the swap partition, containing keys, credentials and unlocked disk material, and it is recoverable from a lost or stolen machine; restoring an image can also roll back kernel state. Breaks `systemctl hibernate` and laptop workflows that rely on it. Suspend-to-RAM (`CONFIG_SUSPEND`) is unaffected, and the check is only meaningful on machines that actually offer hibernation.")
    .with_fix(&fix_disabled("CONFIG_HIBERNATION"))
    .register();

    check::Check::new(
        "KNC_053",
        "Ensure kernel build option `CONFIG_COMPAT` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_COMPAT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_arch(&["x86_64", "x86_32"]))
    .with_description("Remove the 32-bit compatibility syscall layer on a 64-bit kernel, shrinking the reachable syscall table because compat syscalls carry their own argument-marshalling code and have had a steady stream of bugs. Breaks every 32-bit binary: 32-bit containers, Steam and Wine, multiarch chroots and legacy vendor software.")
    .with_fix(&fix_disabled("CONFIG_COMPAT"))
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#reduced-access-to-syscalls")
    .register();

    check::Check::new(
        "KNC_054",
        "Ensure kernel build option `CONFIG_IA32_EMULATION` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_IA32_EMULATION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Remove the x86_64 32-bit syscall entry points and the associated compat signal, vDSO and ptrace handling. That body of code is rarely exercised and has had many CVEs, so removing it eliminates a whole syscall entry path. Note it does not stop 32-bit instructions from running in user mode, only 32-bit syscalls. Breaks all i386 binaries and 32-bit containers, and prevents a 32-bit userspace from booting.")
    .with_fix(&fix_disabled("CONFIG_IA32_EMULATION"))
    .register();

    check::Check::new(
        "KNC_055",
        "Ensure kernel build option `CONFIG_X86_X32` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_X86_X32"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((5, 18, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Remove the x32 ABI (32-bit pointers with the 64-bit syscall table), which adds another syscall entry path with its own compat argument handling. This is the old name of the option: v5.18 renamed it to `CONFIG_X86_X32_ABI`, so the check is skipped on newer kernels.")
    .with_fix(&fix_disabled("CONFIG_X86_X32"))
    .register();

    check::Check::new(
        "KNC_056",
        "Ensure kernel build option `CONFIG_X86_X32_ABI` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_X86_X32_ABI"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 18, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Remove the x32 ABI (32-bit pointers with the 64-bit syscall table), a separate syscall entry path with its own compat argument-marshalling code that has produced vulnerabilities. Breaks x32 binaries; no mainstream distribution ships an x32 userland, so the practical impact is nil.")
    .with_fix(&fix_disabled("CONFIG_X86_X32_ABI"))
    .register();

    check::Check::new(
        "KNC_057",
        "Ensure kernel build option `CONFIG_MODIFY_LDT_SYSCALL` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_MODIFY_LDT_SYSCALL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Remove the `modify_ldt()` syscall, which lets a process install arbitrary local descriptor table entries. Custom segments have been the basis of several local privilege escalations and information leaks (bypassing SMAP/SMEP-style protections, leaking kernel data). Breaks Wine and DOSEMU-style software that needs custom LDT entries for 16-bit or win32 TLS emulation, and any legacy 16-bit support.")
    .with_fix(&fix_disabled("CONFIG_MODIFY_LDT_SYSCALL"))
    .register();

    check::Check::new(
        "KNC_058",
        "Ensure kernel build option `CONFIG_OABI_COMPAT` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_OABI_COMPAT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["arm32"]))
    .with_description("Remove the ARM old-ABI (OABI) compatibility syscalls (`arm_ftruncate64`, OABI `sendfile`, `semop`, `mmap2` and friends), which add untested syscall paths to a kernel that only needs to run EABI binaries.")
    .with_fix(&fix_disabled("CONFIG_OABI_COMPAT"))
    .register();

    check::Check::new(
        "KNC_059",
        "Ensure kernel build option `CONFIG_X86_MSR` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_X86_MSR"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Remove the `msr` device (`/dev/cpu/*/msr`), which lets root read and write arbitrary model-specific registers. Through it an attacker can flip security-relevant CPU feature bits, re-enable disabled mitigations such as TSX, or read platform secrets exposed in MSRs, defeating kernel-side hardening. Breaks `rdmsr`/`wrmsr` (msr-tools), `turbostat`, `mcelog` in some modes, microcode helpers and vendor CPU diagnostics; `/proc/cpuinfo` and perf counters cover most of the same ground. x86 only.")
    .with_fix(&fix_disabled("CONFIG_X86_MSR"))
    .register();

    check::Check::new(
        "KNC_060",
        "Ensure kernel build option `CONFIG_LEGACY_TIOCSTI` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_LEGACY_TIOCSTI"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 2, 0)))
    .with_description("Remove the `TIOCSTI` ioctl, which pushes a byte into the terminal input queue as if the user had typed it. A process that keeps a tty open across a privilege change can inject commands into a root shell, a well-known escape from `su`, leftover `ssh` sessions and some container runtimes. Requires a kernel that provides the option (added in 6.2, where the `dev.tty.legacy_tiocsti` sysctl also appeared). Breaks the few tools that drive terminals by injection, such as serial console automation and some multiplexer paste paths.")
    .with_fix(&fix_disabled("CONFIG_LEGACY_TIOCSTI"))
    .register();

    check::Check::new(
        "KNC_061",
        "Ensure kernel build option `CONFIG_MODULE_FORCE_LOAD` is not set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_MODULE_FORCE_LOAD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove support for forcing a module to load (`modprobe --force`, `insmod -f`) when its vermagic or signature does not match the running kernel. Forced loading runs code built for a different ABI, can crash the kernel and is a way around version and signature checks. Requires `CONFIG_MODULES`. Breaks nothing legitimate: only out-of-tree drivers loaded against a kernel they were not built for, and DKMS workarounds that relied on force loading.")
    .with_fix(&fix_disabled("CONFIG_MODULE_FORCE_LOAD"))
    .register();

    check::Check::new(
        "KNC_062",
        "Ensure kernel build option `CONFIG_DRM_LEGACY` is not set",
        Severity::Low,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_DRM_LEGACY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 8, 0)))
    .with_description("Remove the pre-KMS legacy DRM drivers (i810, i830, legacy i915, mga, r128, savage, sis, tdfx, via) and their ioctls. They have been unmaintained for well over a decade and contain use-after-free and overflow bugs reachable by any local user with access to a DRI device node. Breaks only hardware old enough to have no KMS driver; anything from roughly the last 15 years uses the modern DRM path.")
    .with_fix(&fix_disabled("CONFIG_DRM_LEGACY"))
    .register();

    check::Check::new(
        "KNC_063",
        "Ensure kernel build option `CONFIG_FB` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_FB"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the legacy framebuffer layer (`/dev/fb*`). Its drivers (vesafb, vga16fb, simplefb fallbacks, matrox and similar) are unmaintained, run in kernel context and have been a source of local privilege escalations; modern systems use DRM/KMS instead. Breaks framebuffer consoles and tools that read `/dev/fb0` (`fbi`, kiosk setups, screensavers), `uvesafb`/`simplefb` early boot graphics on some firmware, and embedded LCD drivers. Only disable it when the display path is fully DRM based.")
    .with_fix(&fix_disabled("CONFIG_FB"))
    .register();

    check::Check::new(
        "KNC_064",
        "Ensure kernel build option `CONFIG_VT` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_VT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the virtual terminal subsystem (`/dev/tty0` to `/dev/tty63`, the VT console and its ioctl and console-switching code, which has had several local privilege escalations). This removes the local text console entirely: no `getty` on tty1, no keyboard SysRq, no text output on the graphics card. Only appropriate for headless appliances managed exclusively over SSH or a serial console, and it makes recovery without out-of-band access much harder.")
    .with_fix(&fix_disabled("CONFIG_VT"))
    .register();

    check::Check::new(
        "KNC_065",
        "Ensure kernel build option `CONFIG_BLK_DEV_FD` is not set",
        Severity::Low,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_FD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the floppy driver. It is unmaintained, runs with full kernel privileges on hardware almost nobody has, and has had use-after-free bugs reachable by any local user who can open `/dev/fd0`. It also removes the option of booting an attacker-supplied floppy. Breaks real floppy drives and, on some virtual machines, the emulated floppy used to pass data to the guest, so check that nothing in the VM configuration depends on it.")
    .with_fix(&fix_disabled("CONFIG_BLK_DEV_FD"))
    .register();

    check::Check::new(
        "KNC_066",
        "Ensure kernel build option `CONFIG_BLK_DEV_FD_RAWCMD` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_FD_RAWCMD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 18, 0)))
    .with_description("Remove the `FDRAWCMD` ioctl of the floppy driver, which issues arbitrary raw commands to the floppy controller and can be abused for DMA-style attacks and controller confusion. Only exists when `CONFIG_BLK_DEV_FD` is built; with the whole driver off the option disappears and this check reports a warning. Breaks low-level floppy utilities such as `fdformat` and other raw-command tools.")
    .with_fix(&fix_disabled("CONFIG_BLK_DEV_FD_RAWCMD"))
    .register();

    check::Check::new(
        "KNC_067",
        "Ensure kernel build option `CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 3, 0)))
    .skip_when(|| kernel::skip_kernel_before((5, 2, 0)))
    .with_description("Disable the legacy DRM context and ioctl path in the Nouveau driver, kept only for pre-KMS userspace (DRI1-era Mesa). It contained a use-after-free reachable by any local user with access to the DRI node. Breaks DRI1-era userspace on NVIDIA cards driven by nouveau; every modern Mesa works without it. Only relevant when nouveau is built at all.")
    .with_fix(&fix_disabled("CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT"))
    .register();

    check::Check::new(
        "KNC_068",
        "Ensure kernel build option `CONFIG_N_GSM` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_N_GSM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the GSM 07.10 multiplexing tty line discipline, used to split one serial link to a cellular modem into several virtual channels. Its frame parsing code has had multiple memory-corruption bugs and is reachable by any user who can open a serial tty and set a line discipline on it. Breaks modems and embedded telecom gear that use 07.10 muxing (some ModemManager configurations); irrelevant on hosts without such hardware.")
    .with_fix(&fix_disabled("CONFIG_N_GSM"))
    .register();

    // grsec
    check::Check::new(
        "KNC_069",
        "Ensure kernel build option `CONFIG_ZSMALLOC_STAT` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_ZSMALLOC_STAT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the debugfs statistics exported per zsmalloc pool (the compressed page allocator behind zram and zswap). They disclose allocation counts and sizes that help an attacker groom the heap, and add another debugfs surface. Only exists when zsmalloc is built (zram/zswap); otherwise the check reports a warning. Costs nothing but the ability to measure compression efficiency when tuning.")
    .with_fix(&fix_disabled("CONFIG_ZSMALLOC_STAT"))
    .register();

    check::Check::new(
        "KNC_070",
        "Ensure kernel build option `CONFIG_DEBUG_KMEMLEAK` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_DEBUG_KMEMLEAK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the kernel memory leak detector, which tracks every allocation in a tree, exports it through `/sys/kernel/debug/kmemleak` and can be told to scan or poison memory on demand. It is a development tool with a large performance overhead that also discloses detailed kernel heap layout. Breaks leak hunting, which should be done on a debug build instead.")
    .with_fix(&fix_disabled("CONFIG_DEBUG_KMEMLEAK"))
    .register();

    check::Check::new(
        "KNC_071",
        "Ensure kernel build option `CONFIG_BINFMT_AOUT` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_BINFMT_AOUT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 1, 0)))
    .with_description("Remove the a.out executable format loader. Its parsing of the obsolete format (together with `uselib`, `CONFIG_USELIB`) has been the basis of classic local root exploits, and no software ships a.out binaries any more.")
    .register();

    check::Check::new(
        "KNC_072",
        "Ensure kernel build option `CONFIG_KPROBE_EVENTS` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_KPROBE_EVENTS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove kprobe-based trace events (`kprobe_events` in tracefs), which let root create probes at almost any kernel address and read register and argument values. That is both an information leak (kernel pointers, function arguments) and a code-patching primitive. Requires kprobes, so it disappears when `CONFIG_KPROBES` is off. Breaks `bpftrace`, `perf probe`, SystemTap-style tooling and many observability agents.")
    .with_fix(&fix_disabled("CONFIG_KPROBE_EVENTS"))
    .register();

    check::Check::new(
        "KNC_073",
        "Ensure kernel build option `CONFIG_UPROBE_EVENTS` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_UPROBE_EVENTS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove uprobe trace events, the ability to attach a probe to a userspace binary from the tracing filesystem. It allows transparent instrumentation of any process, including privileged ones, and its perf-event interface has had several bugs. Requires uprobes, which are pulled in by `CONFIG_BPF_EVENTS`. Breaks `perf probe` on userspace binaries, `bpftrace uprobe:`, USDT-based tracing and language-runtime profilers.")
    .with_fix(&fix_disabled("CONFIG_UPROBE_EVENTS"))
    .register();

    check::Check::new(
        "KNC_074",
        "Ensure kernel build option `CONFIG_GENERIC_TRACER` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_GENERIC_TRACER"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the generic tracer framework that most ftrace tracers are built on (function-graph, irqsoff, wakeup, sched tracers and their tracefs interface). It exposes kernel internals and provides writable tracing controls. Requires the tracing framework to be present, and is largely redundant once `CONFIG_FTRACE` is off. Breaks ftrace and `perf` based profiling, `trace-cmd`, latency analysis and many APM agents.")
    .with_fix(&fix_disabled("CONFIG_GENERIC_TRACER"))
    .register();

    check::Check::new(
        "KNC_075",
        "Ensure kernel build option `CONFIG_FUNCTION_TRACER` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_FUNCTION_TRACER"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the function tracer, which compiles every kernel function with an entry hook so calls can be redirected at runtime. Besides leaking control flow and arguments, the machinery that patches live kernel text is itself an attack surface and is what tracing-based rootkits use. Note that other features select the underlying ftrace infrastructure (`CONFIG_LIVEPATCH`, kprobes-on-ftrace), so they are lost too. Breaks `trace-cmd`, `perf ftrace` and function-graph profiling.")
    .with_fix(&fix_disabled("CONFIG_FUNCTION_TRACER"))
    .register();

    check::Check::new(
        "KNC_076",
        "Ensure kernel build option `CONFIG_STACK_TRACER` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_STACK_TRACER"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the stack tracer, which measures the maximum kernel stack depth per function and publishes it in `stack_max` under tracefs, exposing call-graph information. Depends on `CONFIG_FUNCTION_TRACER`; without it the option is absent and this check reports a warning. Breaks stack-usage analysis used for kernel stack size tuning - a development-time activity.")
    .with_fix(&fix_disabled("CONFIG_STACK_TRACER"))
    .register();

    check::Check::new(
        "KNC_077",
        "Ensure kernel build option `CONFIG_HIST_TRIGGERS` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_HIST_TRIGGERS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove histogram triggers in tracefs, which let root build arbitrary in-kernel aggregations on trace events through string-parsing interfaces. That parsing code has had several vulnerabilities and the results leak kernel event data. Requires the tracing framework. Breaks `trace-cmd hist`, some performance-analysis workflows and monitoring scripts that avoid eBPF by using triggers.")
    .with_fix(&fix_disabled("CONFIG_HIST_TRIGGERS"))
    .register();

    check::Check::new(
        "KNC_078",
        "Ensure kernel build option `CONFIG_BLK_DEV_IO_TRACE` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_IO_TRACE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove blktrace support (`blk_dev_io_trace` and the per-device `trace` files), which records every block I/O with timestamps for anyone able to read them. The resulting data reveals I/O patterns detailed enough to infer file access and database activity. Breaks `blktrace`, `blkparse`, `btt` and block-layer performance analysis.")
    .with_fix(&fix_disabled("CONFIG_BLK_DEV_IO_TRACE"))
    .register();

    check::Check::new(
        "KNC_079",
        "Ensure kernel build option `CONFIG_PROC_VMCORE` is not set or missing",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        // can be missing if CONFIG_PROC_FS & CONFIG_CRASH_DUMP are not set
        || kconfig::check_option_is_not_set_or_missing("CONFIG_PROC_VMCORE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove `/proc/vmcore`, the ELF view of the crashed kernel's memory exposed to the kdump capture kernel. Anyone who can read it, or boot the capture kernel, recovers keys, credentials and the entire memory image of the previous kernel. Requires `CONFIG_CRASH_DUMP`; disabling this and `CONFIG_CRASH_DUMP` removes crash analysis entirely, so it is only appropriate where post-mortem debugging is done by other means.")
    .with_fix(&fix_disabled("CONFIG_PROC_VMCORE"))
    .register();

    check::Check::new(
        "KNC_080",
        "Ensure kernel build option `CONFIG_PROC_PAGE_MONITOR` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_PROC_PAGE_MONITOR"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove `/proc/<pid>/pagemap`, `/proc/<pid>/cleared_refs`, `/proc/kpagecount` and `/proc/kpageflags`. `pagemap` exposes the physical frame number behind every virtual page, which enables Rowhammer-style attacks and defeats address-space randomization assumptions (this is why the interface was already restricted to `CAP_SYS_ADMIN`). Breaks memory-analysis tools (`page-types`), CRIU checkpoint/restore (`CONFIG_CHECKPOINT_RESTORE`), some garbage-collected runtimes and userspace Rowhammer tests.")
    .with_fix(&fix_disabled("CONFIG_PROC_PAGE_MONITOR"))
    .register();

    check::Check::new(
        "KNC_081",
        "Ensure kernel build option `CONFIG_USELIB` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_USELIB"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 16, 0)))
    .with_description("Remove the `uselib()` syscall, an a.out-era way to load a shared library into the current process from an absolute path. It bypasses the normal dynamic loader (and with it some auditing and namespace restrictions) and was the target of classic local root exploits.")
    .with_fix(&fix_disabled("CONFIG_USELIB"))
    .register();

    check::Check::new(
        "KNC_082",
        "Ensure kernel build option `CONFIG_CHECKPOINT_RESTORE` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_CHECKPOINT_RESTORE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the extra `/proc` interfaces and syscalls that CRIU needs to freeze and restore a process (`map_files`, `ns_last_pid`, extra `fdinfo` fields, relaxed `pagemap` access). They let a process learn and manipulate other processes' memory layout and PID allocation. Breaks CRIU and everything built on it: container checkpoint and live migration (`runc checkpoint`, Podman/LXC), some application-level checkpointing and long-running job migration.")
    .with_fix(&fix_disabled("CONFIG_CHECKPOINT_RESTORE"))
    .register();

    check::Check::new(
        "KNC_083",
        "Ensure kernel build option `CONFIG_USERFAULTFD` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_USERFAULTFD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the `userfaultfd` syscall, which lets a process handle its own page faults in userspace. It is the standard primitive for winning kernel race conditions and for making use-after-free exploitation reliable, which is why unprivileged access is already off by default (`vm.unprivileged_userfaultfd=0`). Breaks CRIU restore and post-copy live VM migration (QEMU); if those are needed, keep the option and rely on the sysctl restriction instead.")
    .with_fix(&fix_disabled("CONFIG_USERFAULTFD"))
    .register();

    check::Check::new(
        "KNC_084",
        "Ensure kernel build option `CONFIG_HWPOISON_INJECT` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_HWPOISON_INJECT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the debugfs interface that injects hardware memory errors into arbitrary pages (`hwpoison-inject`). It lets root force page offlining and corruption and exercise memory-error handling paths that have their own bugs. Depends on `CONFIG_MEMORY_FAILURE`; without it the option is absent and the check reports a warning. Breaks RAS/ECC error-path testing, which is a development and hardware validation activity.")
    .with_fix(&fix_disabled("CONFIG_HWPOISON_INJECT"))
    .register();

    check::Check::new(
        "KNC_085",
        "Ensure kernel build option `CONFIG_MEM_SOFT_DIRTY` is not set or missing",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_MEM_SOFT_DIRTY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove soft-dirty page tracking (the `clear_refs` bit and the corresponding `pagemap` flag), which reports every page written since the last clear. It discloses write patterns of other processes and is a building block for checkpoint/restore attacks. Requires `CONFIG_PROC_PAGE_MONITOR` and is only useful with `CONFIG_CHECKPOINT_RESTORE`. Breaks CRIU incremental memory dumps and any userspace tool that tracks dirty pages.")
    .with_fix(&fix_disabled("CONFIG_MEM_SOFT_DIRTY"))
    .register();

    check::Check::new(
        "KNC_086",
        "Ensure kernel build option `CONFIG_DEVPORT` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_DEVPORT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove `/dev/port`, which gives raw x86 I/O port access (`in`/`out` instructions) to whoever can open it. Direct port access bypasses every kernel driver and can reprogram timers, the CMOS/NVRAM, the keyboard controller or Super-I/O chips. Breaks low-level hardware utilities, some firmware flashing and diagnostic tools, and legacy X.org port access. x86 only; overlaps with `CONFIG_X86_IOPL_IOPERM`, which removes the syscalls behind it.")
    .with_fix(&fix_disabled("CONFIG_DEVPORT"))
    .register();

    check::Check::new(
        "KNC_087",
        "Ensure kernel build option `CONFIG_DEBUG_FS` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_DEBUG_FS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Do not compile debugfs in at all. `/sys/kernel/debug` is a collection of unhardened interfaces (ACPI custom methods, page-table dumps, blktrace, driver and allocator statistics) that are often protected by nothing more than being root-only, and have been the source of many local privilege escalations; lockdown only covers part of it. Not compiling it is stronger than simply not mounting it, since the interfaces then do not exist. Breaks a surprising amount of legitimate tooling: wireless driver debugging, GPU and NVMe diagnostics, `powertop`-style statistics and some vendor drivers that require debugfs to initialize.")
    .with_fix(&fix_disabled("CONFIG_DEBUG_FS"))
    .register();

    check::Check::new(
        "KNC_088",
        "Ensure kernel build option `CONFIG_NOTIFIER_ERROR_INJECTION` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_NOTIFIER_ERROR_INJECTION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the debugfs modules that inject failures into kernel notifier chains (CPU hotplug, memory hotplug, PM, netdev). They exist to test error paths, but from root they force arbitrary subsystem failures and drive rarely-tested code that has its own bugs. Requires `CONFIG_DEBUG_FS` and the notifier error injection option to exist. Breaks error-path testing only.")
    .with_fix(&fix_disabled("CONFIG_NOTIFIER_ERROR_INJECTION"))
    .register();

    check::Check::new(
        "KNC_089",
        "Ensure kernel build option `CONFIG_FAIL_FUTEX` is not set or missing",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_FAIL_FUTEX"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the fault-injection support for futexes (`fail_futex` under debugfs), which forces futex operations to fail. It is a testing facility that also provides a way to destabilize any process using futexes and to exercise rarely-tested error paths. Requires `CONFIG_FAULT_INJECTION` and debugfs; without them the option is absent. Breaks futex error-path testing only.")
    .with_fix(&fix_disabled("CONFIG_FAIL_FUTEX"))
    .register();

    check::Check::new(
        "KNC_090",
        "Ensure kernel build option `CONFIG_PUNIT_ATOM_DEBUG` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_PUNIT_ATOM_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the debug interface for the Intel Atom P-Unit (the power management microcontroller), which exposes its mailbox registers through debugfs and allows power-management state to be read and written. Only exists on Intel Atom/Quark-class platforms; elsewhere the option is absent and the check reports a warning. Breaks P-Unit and power-management debugging on those SoCs.")
    .with_fix(&fix_disabled("CONFIG_PUNIT_ATOM_DEBUG"))
    .register();

    check::Check::new(
        "KNC_091",
        "Ensure kernel build option `CONFIG_ACPI_CONFIGFS` is not set",
        Severity::Low,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_ACPI_CONFIGFS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove configfs-based ACPI table loading (`/sys/kernel/config/acpi/table`), which lets root install arbitrary AML at runtime - kernel code execution from userspace, and a Secure Boot bypass because the table is not signed. Requires `CONFIG_CONFIGFS` and ACPI. Breaks firmware and AML development workflows and hardware bring-up; nothing in normal operation uses it.")
    .with_fix(&fix_disabled("CONFIG_ACPI_CONFIGFS"))
    .register();

    check::Check::new(
        "KNC_092",
        "Ensure kernel build option `CONFIG_EDAC_DEBUG` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_EDAC_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the EDAC (Error Detection And Correction) debug knobs, which add extra debugfs files and assertions to the memory-error reporting drivers. Only present when an EDAC driver is built; otherwise the check reports a warning. Breaks verbose ECC debugging; the normal EDAC sysfs counters stay available.")
    .with_fix(&fix_disabled("CONFIG_EDAC_DEBUG"))
    .register();

    check::Check::new(
        "KNC_093",
        "Ensure kernel build option `CONFIG_DRM_I915_DEBUG` is not set or missing",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_DRM_I915_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the i915 debug-only code: extra debugfs entries, GEM object dumping, selftests and validation that only matter while developing the driver. They leak GPU state and enlarge an already large attack surface. Intel GPUs only, the option is absent elsewhere. Breaks i915 debugging and the parts of `intel-gpu-tools` that need those interfaces.")
    .with_fix(&fix_disabled("CONFIG_DRM_I915_DEBUG"))
    .register();

    check::Check::new(
        "KNC_094",
        "Ensure kernel build option `CONFIG_BCACHE_CLOSURES_DEBUG` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_BCACHE_CLOSURES_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 7, 0)))
    .with_description("Remove bcache closure debugging, which tracks every closure object and exposes them in debugfs. Only relevant when bcache is built; otherwise the option is absent and the check reports a warning. Breaks bcache internals debugging; normal bcache operation and its sysfs statistics are unaffected.")
    .with_fix(&fix_disabled("CONFIG_BCACHE_CLOSURES_DEBUG"))
    .register();

    check::Check::new(
        "KNC_095",
        "Ensure kernel build option `CONFIG_DVB_C8SECTPFE` is not set or missing",
        Severity::Low,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_DVB_C8SECTPFE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 19, 0)))
    .with_description("Remove the STMicroelectronics C8SECTPFE DVB frontend driver, used only on STiH4xx set-top-box SoCs. Dead hardware support still adds a media-driver attack surface. Absent on kernels that do not build the STi DVB stack. Breaks digital TV capture on those SoCs only.")
    .with_fix(&fix_disabled("CONFIG_DVB_C8SECTPFE"))
    .register();

    check::Check::new(
        "KNC_096",
        "Ensure kernel build option `CONFIG_MTD_SLRAM` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_MTD_SLRAM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the SLRAM driver, which turns a raw memory region into an MTD flash device. Such a mapping gives userspace unfiltered access to that physical memory range and is only used on ancient embedded boards. Requires MTD support; absent otherwise. Breaks accessing SRAM or flash-like regions through MTD on those boards.")
    .with_fix(&fix_disabled("CONFIG_MTD_SLRAM"))
    .register();

    check::Check::new(
        "KNC_097",
        "Ensure kernel build option `CONFIG_MTD_PHRAM` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_MTD_PHRAM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the `phram` driver, which maps a physical address range given on the kernel command line or as a module parameter as an MTD device. It is an easy way to obtain unfiltered physical memory access from userspace. Requires MTD support; absent otherwise. Breaks embedded setups that use phram to expose a firmware or ramdisk region as a flash device.")
    .with_fix(&fix_disabled("CONFIG_MTD_PHRAM"))
    .register();

    check::Check::new(
        "KNC_098",
        "Ensure kernel build option `CONFIG_IO_URING` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_IO_URING"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 1, 0)))
    .with_description("Remove io_uring entirely. Its asynchronous submission and completion machinery has produced a long stream of local privilege escalations, which is why many distributions and large deployments disable it for unprivileged users through `kernel.io_uring_disabled`. Compiling it out is the only mitigation that cannot be relaxed at runtime. Breaks every application using it: `liburing`-based software, database asynchronous I/O paths (PostgreSQL, MariaDB, RocksDB), Node.js and Deno, Samba, QEMU `aio=io_uring` and some container storage drivers, which fall back to slower paths. If io_uring is required, keep the option and set `kernel.io_uring_disabled=2` instead (needs Linux >= 6.6).")
    .with_fix(&fix_disabled("CONFIG_IO_URING"))
    .register();

    check::Check::new(
        "KNC_099",
        "Ensure kernel build option `CONFIG_KCMP` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_KCMP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 12, 0)))
    .with_description("Remove the `kcmp()` syscall, which compares kernel objects (files, mm, fs, io, epoll, signalfd) of two processes to determine whether they are shared. It is an information leak used to fingerprint other processes' file descriptors and memory and to make exploits more reliable. It is selected by `CONFIG_CHECKPOINT_RESTORE` on most kernels, so it usually disappears together with that option. Breaks CRIU.")
    .with_fix(&fix_disabled("CONFIG_KCMP"))
    .register();

    check::Check::new(
        "KNC_100",
        "Ensure kernel build option `CONFIG_RSEQ` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_RSEQ"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove restartable sequences, the `rseq()` syscall and its per-thread area that let userspace run critical sections without atomics. It is a large and subtle ABI with a history of serious bugs, and it adds another kernel-written per-thread structure. Breaks glibc >= 2.35 optimizations and performance-critical runtimes: per-CPU data structures in modern allocators, Ceph, DPDK, LTTng-UST tracing and some databases. glibc falls back to slower paths, so expect measurable regressions on allocator-heavy workloads; only disable it when that cost is acceptable.")
    .with_fix(&fix_disabled("CONFIG_RSEQ"))
    .register();

    check::Check::new(
        "KNC_101",
        "Ensure kernel build option `CONFIG_LATENCYTOP` is not set",
        Severity::Low,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_LATENCYTOP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove LatencyTOP, which tracks the cause of every scheduling delay per task and exports it in `/proc/latency_stats` and `/proc/<pid>/latency_stats`. It adds overhead on every tracked event and exposes internal blocking reasons. Requires the scheduler debug infrastructure. Breaks the `latencytop` tool; use ftrace or perf on a debug build instead.")
    .with_fix(&fix_disabled("CONFIG_LATENCYTOP"))
    .register();

    check::Check::new(
        "KNC_102",
        "Ensure kernel build option `CONFIG_KCOV` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_KCOV"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove KCOV, the coverage collection interface under debugfs built for syzkaller. It exports per-task kernel code coverage, which helps an attacker refine an exploit, and requires instrumenting the whole kernel at compile time, costing performance and memory. Breaks fuzzing and coverage-guided testing, which belong in dedicated builds rather than production kernels.")
    .with_fix(&fix_disabled("CONFIG_KCOV"))
    .register();

    check::Check::new(
        "KNC_103",
        "Ensure kernel build option `CONFIG_PROVIDE_OHCI1394_DMA_INIT` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_PROVIDE_OHCI1394_DMA_INIT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the OHCI-1394 DMA init option, which enables physical DMA access over FireWire very early in boot so a remote debugger can read memory. FireWire DMA is the classic physical-access attack: any device on the bus can read and write all of RAM, so also keep remote DMA off and enable IOMMU protection. Only present on kernels that still build the legacy `ohci1394` driver. Breaks early-boot debugging over FireWire.")
    .with_fix(&fix_disabled("CONFIG_PROVIDE_OHCI1394_DMA_INIT"))
    .register();

    check::Check::new(
        "KNC_104",
        "Ensure kernel build option `CONFIG_SUNRPC_DEBUG` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_SUNRPC_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the SunRPC/NFS debug interfaces (`rpcdebug` and the extra debugfs and sysfs knobs), which expose RPC state and add code only exercised by developers. Requires NFS/SunRPC to be built; absent otherwise. Breaks `rpcdebug` and low-level NFS troubleshooting; normal NFS operation and statistics are unaffected.")
    .with_fix(&fix_disabled("CONFIG_SUNRPC_DEBUG"))
    .register();

    check::Check::new(
        "KNC_105",
        "Ensure kernel build option `CONFIG_X86_16BIT` is not set or missing",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_X86_16BIT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Remove support for 16-bit code segments on x86_64 (16-bit tasks created through `modify_ldt` and the associated segment handling). That emulation path is small, rarely tested and has been involved in privilege-escalation bugs. Breaks 16-bit userspace binaries (DOSEMU and similar); it does not affect the kernel's own real-mode boot code. Goes together with `CONFIG_MODIFY_LDT_SYSCALL`.")
    .with_fix(&fix_disabled("CONFIG_X86_16BIT"))
    .register();

    check::Check::new(
        "KNC_106",
        "Ensure kernel build option `CONFIG_BLK_DEV_UBLK` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_UBLK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 0, 0)))
    .with_description("Remove ublk, the io_uring-based userspace block device driver. It lets a userspace daemon back a block device, combining two large attack surfaces (io_uring and the block layer), which is why several distributions restrict it. Requires `CONFIG_IO_URING`; absent when io_uring is off. Breaks ublk-based storage backends (Ceph ublk, userspace LVM or SPDK targets, `ublksrv`).")
    .with_fix(&fix_disabled("CONFIG_BLK_DEV_UBLK"))
    .register();

    check::Check::new(
        "KNC_107",
        "Ensure kernel build option `CONFIG_SMB_SERVER` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_SMB_SERVER"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 15, 0)))
    .with_description("Remove ksmbd, the in-kernel SMB3 server. It is a large network-facing parser that has already had several remote pre-authentication vulnerabilities, and it duplicates what Samba does in userspace where a compromise is contained. Absent on kernels older than 5.15, in which case the check reports a warning. Breaks kernel-based SMB sharing (`ksmbd-tools`); use Samba instead.")
    .with_fix(&fix_disabled("CONFIG_SMB_SERVER"))
    .register();

    check::Check::new(
        "KNC_108",
        "Ensure kernel build option `CONFIG_XFS_ONLINE_SCRUB_STATS` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_XFS_ONLINE_SCRUB_STATS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 6, 0)))
    .with_description("Remove the statistics collection for XFS online metadata scrubbing, exported through debugfs. It only exists when `CONFIG_XFS_ONLINE_SCRUB` and debugfs are enabled, so on most kernels the option is absent and the check reports a warning. Breaks scrub performance statistics only; `xfs_scrub` itself keeps working.")
    .with_fix(&fix_disabled("CONFIG_XFS_ONLINE_SCRUB_STATS"))
    .register();

    check::Check::new(
        "KNC_109",
        "Ensure kernel build option `CONFIG_CACHESTAT_SYSCALL` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_CACHESTAT_SYSCALL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 5, 0)))
    .with_description("Remove the `cachestat()` syscall, which reports how many pages of a file are cached, dirty, evicted or written back. It is a side channel: an unprivileged process can infer which files another process is reading and when. Requires Linux >= 6.5; older kernels report `param not present` (warning). Breaks I/O monitoring tools that use it (recent bcc/bpftrace `cachestat`, some storage diagnostics); `mincore` and `/proc/meminfo` remain for coarser statistics.")
    .with_fix(&fix_disabled("CONFIG_CACHESTAT_SYSCALL"))
    .register();

    check::Check::new(
        "KNC_110",
        "Ensure kernel build option `CONFIG_PREEMPTIRQ_TRACEPOINTS` is not set or missing",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_PREEMPTIRQ_TRACEPOINTS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the preempt and interrupt disable/enable tracepoints used by the `irqsoff`, `preemptoff` and `preemptirq_delay` tracers. They add hooks on every interrupt and preemption-disable (measurable overhead on IRQ-heavy systems) and expose scheduling internals. Often selected by lockdep (`CONFIG_PROVE_LOCKING`) or by architecture configs, so it can reappear after a rebuild. Breaks latency tracers such as `trace-cmd record -p irqsoff`.")
    .with_fix(&fix_disabled("CONFIG_PREEMPTIRQ_TRACEPOINTS"))
    .register();

    check::Check::new(
        "KNC_111",
        "Ensure kernel build option `CONFIG_ENABLE_DEFAULT_TRACERS` is not set or missing",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_ENABLE_DEFAULT_TRACERS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Skip compiling in the default set of tracers (function, function-graph, irqsoff, sched-switch and friends), which reduces kernel size and the tracefs surface. Individual tracers can still be selected, so this is a size and attack-surface measure rather than a complete removal. Requires `CONFIG_GENERIC_TRACER` to not be set, and is largely redundant once `CONFIG_FTRACE` is off. Breaks nothing except tools that expect a default tracer to be present at boot.")
    .with_fix(&fix_disabled("CONFIG_ENABLE_DEFAULT_TRACERS"))
    .register();

    check::Check::new(
        "KNC_112",
        "Ensure kernel build option `CONFIG_PROVE_LOCKING` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_PROVE_LOCKING"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove lockdep, the lock dependency validator. It instruments every lock acquire and release, costs noticeable CPU and a large amount of memory, and exposes lock ordering and kernel internals through `/proc/lockdep*` and tracefs. It also selects other debug options (`LOCK_STAT`, `PREEMPTIRQ_TRACEPOINTS`), pulling attack surface back in. Breaks lock-ordering debugging: keep it in test builds, not in production.")
    .with_fix(&fix_disabled("CONFIG_PROVE_LOCKING"))
    .register();

    check::Check::new(
        "KNC_113",
        "Ensure kernel build option `CONFIG_TEST_DEBUG_VIRTUAL` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_TEST_DEBUG_VIRTUAL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the self-test that validates `virt_to_phys()`/`phys_to_virt()` round-trips across the kernel linear mapping. It exists only for debugging memory management changes and requires `CONFIG_DEBUG_VIRTUAL`; absent otherwise. Breaks nothing but that boot-time test.")
    .with_fix(&fix_disabled("CONFIG_TEST_DEBUG_VIRTUAL"))
    .register();

    check::Check::new(
        "KNC_114",
        "Ensure kernel build option `CONFIG_MPTCP` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_MPTCP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 6, 0)))
    .with_description("Remove Multipath TCP support. It is a large, relatively new protocol implementation reachable from any local socket (`IPPROTO_MPTCP`), has had several memory-corruption vulnerabilities, and is rarely used outside specific mobile or bonding deployments. Breaks MPTCP clients and servers (`mptcpize`, multipath bonding setups); plain TCP is unaffected.")
    .with_fix(&fix_disabled("CONFIG_MPTCP"))
    .register();

    check::Check::new(
        "KNC_115",
        "Ensure kernel build option `CONFIG_TLS` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_TLS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove kernel TLS offload, which moves record encryption into the kernel. It has had multiple vulnerabilities, including a bug that could leak plaintext across connections, and adds a crypto path reachable from any socket option. Breaks kTLS acceleration used by nginx offload configurations, Ceph messenger v2, Samba and some storage stacks, which fall back to userspace OpenSSL at a performance cost. Only disable it on hosts that never use kTLS.")
    .with_fix(&fix_disabled("CONFIG_TLS"))
    .register();

    check::Check::new(
        "KNC_116",
        "Ensure kernel build option `CONFIG_TIPC` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_TIPC"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove TIPC, the cluster-oriented IPC protocol used mainly in telecom equipment. It is reachable over UDP and dedicated bearers, has had several remote and local memory-corruption bugs, and is unused outside those deployments. Breaks TIPC applications only.")
    .with_fix(&fix_disabled("CONFIG_TIPC"))
    .register();

    check::Check::new(
        "KNC_117",
        "Ensure kernel build option `CONFIG_IP_SCTP` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_IP_SCTP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove SCTP. It becomes reachable from the network as soon as a socket exists, has a long history of remote and local vulnerabilities, and is only needed by specific telephony (SIGTRAN, DIAMETER) and clustering software. Breaks those applications; TCP and UDP users are unaffected. When the distribution ships it as a module, also blacklist it (see the modprobe checks).")
    .with_fix(&fix_disabled("CONFIG_IP_SCTP"))
    .register();

    check::Check::new(
        "KNC_118",
        "Ensure kernel build option `CONFIG_KGDB` is not set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_KGDB"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove KGDB, the in-kernel gdb stub. It provides full read and write access to kernel memory and registers over a serial (`kgdboc`) or network (`kgdboe`) link and can be entered from an NMI, so anyone with console access can take over the machine. Breaks kernel debugging with gdb; use a debug build or a virtual machine instead. Lockdown confidentiality mode also refuses to run with it enabled.")
    .with_fix(&fix_disabled("CONFIG_KGDB"))
    .register();

    check::Check::new(
        "KNC_119",
        "Ensure kernel build option `CONFIG_PTDUMP_DEBUGFS` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_PTDUMP_DEBUGFS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 6, 0)))
    .with_description("Remove the debugfs page-table dump (`page_tables/kernel`), which prints the entire kernel page table with physical addresses and permissions - a ready-made KASLR bypass and a map of everything writable. Requires `CONFIG_DEBUG_FS` and the architecture page-table dump code. Breaks the inspection used when debugging kernel memory protections, including the `CONFIG_DEBUG_WX` boot warning.")
    .with_fix(&fix_disabled("CONFIG_PTDUMP_DEBUGFS"))
    .register();

    check::Check::new(
        "KNC_120",
        "Ensure kernel build option `CONFIG_X86_PTDUMP` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_X86_PTDUMP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((5, 6, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Remove the x86 page-table dump support that backs the debugfs page-table interface (`CONFIG_PTDUMP_DEBUGFS`), leaking kernel virtual and physical layout with permissions. Note that `CONFIG_DEBUG_WX` and `CONFIG_EFI_PGT_DUMP` depend on it, so disabling it also removes the boot-time warning about writable and executable mappings - a trade-off worth making on a hardened build. x86 only.")
    .with_fix(&fix_disabled("CONFIG_X86_PTDUMP"))
    .register();

    // clipos
    check::Check::new(
        "KNC_121",
        "Ensure kernel build option `CONFIG_STAGING` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_STAGING"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove all staging drivers: code that is in the tree but explicitly not held to normal kernel quality or review standards. They are a disproportionate source of bugs and are reachable by simply plugging in (or emulating) a USB or PCI device. Breaks hardware that still depends on a staging driver: some Realtek Wi-Fi (rtl8188eu, rtl8723bs), certain Raspberry Pi codecs and Android/Chromebook platforms, and a few USB dongles. Check `lsmod` and `dmesg` before disabling it on embedded or vendor hardware.")
    .with_fix(&fix_disabled("CONFIG_STAGING"))
    .register();

    check::Check::new(
        "KNC_122",
        "Ensure kernel build option `CONFIG_KSM` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_KSM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove Kernel Samepage Merging, which scans anonymous memory and merges identical pages. Merged pages are a cross-VM side channel (flush+reload style attacks, and write-time monitoring of merges to infer another tenant's activity), so it should be off on any host running VMs from different owners. Only meaningful where KSM could run at all. Breaks memory-overcommit strategies that rely on deduplication (dense VDI hosting), which then need proportionally more RAM.")
    .with_fix(&fix_disabled("CONFIG_KSM"))
    .register();

    check::Check::new(
        "KNC_123",
        "Ensure kernel build option `CONFIG_KALLSYMS` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_KALLSYMS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the kernel symbol table export (`/proc/kallsyms`) and symbol names in oops and stack-trace output. It hands an attacker the address of every kernel function, defeating KASLR for anyone who can read it and simplifying ROP gadget selection. Costs a lot of operability: oops messages, `dmesg` stack traces, `perf` and ftrace symbolization, `crash` and most kernel debugging output become bare addresses. Only disable it on hosts with a separate debug workflow; `kernel.kptr_restrict` is the less destructive alternative.")
    .with_fix(&fix_disabled("CONFIG_KALLSYMS"))
    .register();

    check::Check::new(
        "KNC_124",
        "Ensure kernel build option `CONFIG_KEXEC_FILE` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_KEXEC_FILE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove `kexec_file_load()`, the syscall that loads a kernel image from a file descriptor with signature verification. Together with `CONFIG_KEXEC` it removes every way to jump into a new kernel without a firmware reset, blocking kernel replacement by root. Breaks kdump, because the capture kernel is loaded with `kexec_file_load`, and on UEFI with Secure Boot it is the only permitted path, so disabling both makes crash dumping impossible.")
    .with_fix(&fix_disabled("CONFIG_KEXEC_FILE"))
    .register();

    check::Check::new(
        "KNC_125",
        "Ensure kernel build option `CONFIG_CRASH_DUMP` is not set or missing",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_CRASH_DUMP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove crash dump (kdump) support, which lets a capture kernel boot into the crashed kernel's memory and expose it as `/proc/vmcore`. A crash dump contains everything that was in RAM, keys, credentials, disk encryption material, so on a machine an attacker can reset, kdump is an easy extraction path. Breaks kdump entirely, meaning kernel crashes can no longer be analysed post-mortem. Only relevant where a crash kernel is actually reserved (`crashkernel=` on the kernel command line).")
    .with_fix(&fix_disabled("CONFIG_CRASH_DUMP"))
    .register();

    check::Check::new(
        "KNC_126",
        "Ensure kernel build option `CONFIG_USER_NS` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_USER_NS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove user namespaces so no unprivileged process can create a namespace in which it is root. Unprivileged user namespaces are the entry point for a large share of recent local privilege escalations, because they expose interfaces that are otherwise root-only (netfilter, overlayfs, io_uring, mounts). This is the strongest but most disruptive option: it breaks rootless Podman and Docker, Flatpak, Snap and most application sandboxes (Chromium, Firefox, bubblewrap), `systemd-nspawn` and any container runtime that is not fully privileged. Where rootless containers must keep working, prefer the sysctl `kernel.unprivileged_userns_clone=0` or the Apparmor/`userns` restriction, which can be relaxed per application.")
    .with_fix(&fix_disabled("CONFIG_USER_NS"))
    .register();

    check::Check::new(
        "KNC_127",
        "Ensure kernel build option `CONFIG_X86_CPUID` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_X86_CPUID"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Remove the `cpuid` device (`/dev/cpu/*/cpuid`), which lets userspace execute the `cpuid` instruction with arbitrary leaves through the kernel. It leaks platform details useful for fingerprinting and for choosing microarchitecture-specific attacks, and its ioctl surface has had bugs. Breaks `cpuid`(1), some licensing and DRM schemes, vendor CPU tools and feature-detection utilities; most of the same information is available in `/proc/cpuinfo`. x86 only.")
    .with_fix(&fix_disabled("CONFIG_X86_CPUID"))
    .register();

    check::Check::new(
        "KNC_128",
        "Ensure kernel build option `CONFIG_X86_IOPL_IOPERM` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_X86_IOPL_IOPERM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 5, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Remove the `iopl()` and `ioperm()` syscalls, which grant direct I/O port access and, at IOPL 3, the ability to execute privileged instructions from userspace, bypassing kernel drivers and protections - a long-standing local root vector. Also covers `CONFIG_DEVPORT`. Breaks legacy X.org video drivers (vesa, vga) on old hardware, BIOS flashing utilities, DOS emulators such as DOSEMU and `iopl`-using diagnostics; modern DRM-based graphics do not need it. x86 only.")
    .with_fix(&fix_disabled("CONFIG_X86_IOPL_IOPERM"))
    .register();

    check::Check::new(
        "KNC_129",
        "Ensure kernel build option `CONFIG_ACPI_TABLE_UPGRADE` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_ACPI_TABLE_UPGRADE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the ability to override ACPI tables from an initrd CPIO blob. It allows anyone who can modify the initramfs, or trick the bootloader, to inject arbitrary AML that runs in kernel context at boot and is not covered by Secure Boot verification of the kernel image. Requires `CONFIG_ACPI` and an initrd; CPU microcode loading uses a separate mechanism and keeps working. Breaks firmware and AML development workflows that rely on table overrides.")
    .with_fix(&fix_disabled("CONFIG_ACPI_TABLE_UPGRADE"))
    .register();

    check::Check::new(
        "KNC_130",
        "Ensure kernel build option `CONFIG_EFI_CUSTOM_SSDT_OVERLAYS` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_EFI_CUSTOM_SSDT_OVERLAYS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 8, 0)))
    .with_description("Remove loading of custom ACPI SSDT overlays from EFI variables, which is another way to get unsigned AML executed by the kernel at boot, bypassing module signature enforcement and Secure Boot. Requires `CONFIG_EFI` and ACPI. Breaks the vendor SSDT overlay tuning workflow used by some DSDT/SSDT patching guides for laptop power management.")
    .with_fix(&fix_disabled("CONFIG_EFI_CUSTOM_SSDT_OVERLAYS"))
    .register();

    check::Check::new(
        "KNC_131",
        "Ensure kernel build option `CONFIG_AIO` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_AIO"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the legacy POSIX asynchronous I/O interface (`io_setup`/`io_submit`). The code is old, rarely exercised and has had use-after-free bugs. Breaks applications linked against libaio: some database and storage stacks (older MySQL with `innodb_use_native_aio`, Samba, Ceph, QEMU `aio=native`), which fall back to synchronous or thread-pool I/O at a performance cost. Check what uses libaio before disabling it, and note that io_uring is not a drop-in replacement for these paths.")
    .with_fix(&fix_disabled("CONFIG_AIO"))
    .register();

    check::Check::new(
        "KNC_132",
        "Ensure kernel build option `CONFIG_MAGIC_SYSRQ` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_MAGIC_SYSRQ"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove Magic SysRq handling entirely. SysRq lets anyone with keyboard or serial console access dump tasks and registers, show memory information, force remounts, sync, kill all processes and reboot, which is both an information leak and a denial of service; `/proc/sysrq-trigger` exposes the same to root. Breaks emergency recovery on a hung machine (sync, remount read-only, OOM kill, reboot), which is why many operators keep it: restricting the mask (`CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE`) or the serial path (`CONFIG_MAGIC_SYSRQ_SERIAL`) is the less destructive alternative.")
    .with_fix(&fix_disabled("CONFIG_MAGIC_SYSRQ"))
    .register();

    check::Check::new(
        "KNC_133",
        "Ensure kernel build option `CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE` is set to `0x0`",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_value("CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE", "0x0"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Set the default SysRq function mask to `0x0` so no SysRq command works until root explicitly enables some through `/proc/sys/kernel/sysrq`. This keeps the recovery path available while removing the default information-leak and denial-of-service surface from anyone at the console. The option is a bitmask and not a boolean, and distributions ship it with a subset of the functions enabled (`0x01b6` on Ubuntu), so this check compares the value instead of looking for a disabled option. Requires `CONFIG_MAGIC_SYSRQ`; when SysRq is removed entirely with `CONFIG_MAGIC_SYSRQ=n` the option disappears and the check is skipped. Drawback: an emergency sync, remount or reboot needs a prior sysctl change, so it is unsuitable on unattended machines without out-of-band access.")
    .with_fix(&fix_value("CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE", "0x0"))
    .register();

    check::Check::new(
        "KNC_134",
        "Ensure kernel build option `CONFIG_MAGIC_SYSRQ_SERIAL` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_MAGIC_SYSRQ_SERIAL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove SysRq handling on serial consoles. A serial port is often reachable from a management network, a BMC console or a physically adjacent host, and SysRq over serial needs no login. Requires `CONFIG_MAGIC_SYSRQ` and a serial console. Breaks recovery over the serial console, which is usually the last resort on headless servers, so pair it with IPMI/BMC access or a documented power-cycle procedure.")
    .with_fix(&fix_disabled("CONFIG_MAGIC_SYSRQ_SERIAL"))
    .register();

    // grapheneos
    check::Check::new(
        "KNC_135",
        "Ensure kernel build option `CONFIG_EFI_TEST` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_EFI_TEST"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the EFI test driver (`/dev/efi_test`), which exposes EFI runtime services directly to userspace so test suites can call `GetVariable`/`SetVariable`. That is firmware write access for any process able to open the node, and has been used to reconfigure or brick machines. Requires `CONFIG_EFI`. Breaks the EFI Self Test application and firmware tooling; nothing in normal operation uses it.")
    .with_fix(&fix_disabled("CONFIG_EFI_TEST"))
    .register();

    check::Check::new(
        "KNC_136",
        "Ensure kernel build option `CONFIG_MMIOTRACE_TEST` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_MMIOTRACE_TEST"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the mmiotrace self-test module, which exercises MMIO tracing by touching dummy device mappings. Test-only code running in kernel context; requires `CONFIG_MMIOTRACE`, so it disappears together with the tracer. Breaks nothing but the mmiotrace test.")
    .with_fix(&fix_disabled("CONFIG_MMIOTRACE_TEST"))
    .register();

    check::Check::new(
        "KNC_137",
        "Ensure kernel build option `CONFIG_KPROBES` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_KPROBES"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the kprobes infrastructure, which patches live kernel text with breakpoints so probes can run at almost any instruction. It underpins ftrace-based probing, SystemTap, `perf probe` and `bpftrace` kprobes, and the breakpoint handler it installs is itself an exploitable path with several CVEs to its name. Breaks all of those tools plus kernel livepatch (`CONFIG_LIVEPATCH` depends on it). Only suitable on an audited production host that accepts losing dynamic tracing.")
    .with_fix(&fix_disabled("CONFIG_KPROBES"))
    .register();

    check::Check::new(
        "KNC_138",
        "Ensure kernel build option `CONFIG_MMIOTRACE` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_MMIOTRACE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove mmiotrace, which traces a driver's memory-mapped I/O accesses by marking pages not-present and handling the resulting faults in kernel context. It is a driver reverse-engineering tool built on the tracer framework. Breaks driver development and reverse-engineering workflows; nothing in production uses it.")
    .with_fix(&fix_disabled("CONFIG_MMIOTRACE"))
    .register();

    check::Check::new(
        "KNC_139",
        "Ensure kernel build option `CONFIG_LIVEPATCH` is not set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_LIVEPATCH"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove kernel live patching (`kpatch`, kGraft-style patch modules), which replaces functions in the running kernel with code from a loaded module. By design it is an arbitrary kernel-code injection interface for root, so it defeats lockdown, module signature enforcement and any assumption that running kernel text is immutable. Breaks live patching services (kpatch, Canonical Livepatch, SUSE livepatching), meaning every kernel security fix requires a reboot. Depends on `CONFIG_KPROBES`-based ftrace; only worth it on hosts that must never reboot.")
    .with_fix(&fix_disabled("CONFIG_LIVEPATCH"))
    .register();

    check::Check::new(
        "KNC_140",
        "Ensure kernel build option `CONFIG_IP_DCCP` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_IP_DCCP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 16, 0)))
    .with_description("Remove DCCP (Datagram Congestion Control Protocol). It is almost never used, is reachable from the network as soon as a socket is created, and its option parsing has had several remote memory-corruption and uninitialised-memory-leak bugs. Breaks DCCP applications, which in practice means nothing outside research setups. When the distribution ships it as a module, also blacklist it (see the modprobe checks).")
    .with_fix(&fix_disabled("CONFIG_IP_DCCP"))
    .register();

    check::Check::new(
        "KNC_141",
        "Ensure kernel build option `CONFIG_FTRACE` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_FTRACE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the ftrace framework: the function tracer, tracefs, dynamic event registration and the text-patching machinery behind them. It exposes kernel control flow and arguments, lets root redirect kernel functions, and is used by both exploits and kernel rootkits. Other features select it (`CONFIG_LIVEPATCH`, kprobes-on-ftrace, some IRQ-latency debugging), so it can be pulled back in. Breaks `perf` tracepoints, `trace-cmd`, most `bpftrace` probes, latency analysis and APM agents built on ftrace.")
    .with_fix(&fix_disabled("CONFIG_FTRACE"))
    .register();

    check::Check::new(
        "KNC_142",
        "Ensure kernel build option `CONFIG_VIDEO_VIVID` is not set or missing",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_VIDEO_VIVID"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the Virtual Video Test Driver (vivid), a V4L2/DVB/CEC device simulated entirely in software. It appears to any local user as a real video device and implements a large amount of complex parsing, which has produced several local privilege escalations while being useful only for testing. Requires the V4L2 test drivers menu. Breaks V4L2 and CEC development and CI pipelines that use vivid as a fake camera.")
    .with_fix(&fix_disabled("CONFIG_VIDEO_VIVID"))
    .register();

    check::Check::new(
        "KNC_143",
        "Ensure kernel build option `CONFIG_INPUT_EVBUG` is not set",
        Severity::Low,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_INPUT_EVBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 14, 0)))
    .with_description("Remove the evbug input handler, which logs every input event - including every keystroke - to the kernel ring buffer. Wherever `dmesg` is readable that is a keylogger, and even restricted it writes secrets into logs. It is a debugging handler with no production use. Breaks input event debugging; use `evtest` in userspace instead.")
    .with_fix(&fix_disabled("CONFIG_INPUT_EVBUG"))
    .register();

    check::Check::new(
        "KNC_144",
        "Ensure kernel build option `CONFIG_CORESIGHT` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_CORESIGHT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["arm32", "arm64"]))
    .with_description("Remove ARM CoreSight, the on-chip debug and trace infrastructure (ETM, ETB, STM, TPIU) exposed through sysfs and perf. It can trace the execution of other processes and of the kernel, and is reachable by perf users in some configurations. ARM and arm64 only; the option is absent on x86, where this check reports a warning. Breaks hardware-assisted profiling and SoC bring-up debugging.")
    .with_fix(&fix_disabled("CONFIG_CORESIGHT"))
    .register();

    check::Check::new(
        "KNC_145",
        "Ensure kernel build option `CONFIG_XFS_SUPPORT_V4` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_XFS_SUPPORT_V4"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 10, 0)))
    .with_description("Remove support for the XFS version 4 on-disk format, a pre-2005 layout without CRC protection that upstream has deprecated. Unprotected metadata makes a corrupted or maliciously crafted filesystem image more likely to damage the kernel when mounted. Requires XFS to be built. Breaks mounting any XFS filesystem created before v5 became the default (RHEL 6 era and older); such filesystems must be backed up and recreated with a current `mkfs.xfs`.")
    .with_fix(&fix_disabled("CONFIG_XFS_SUPPORT_V4"))
    .register();

    check::Check::new(
        "KNC_146",
        "Ensure kernel build option `CONFIG_BLK_DEV_WRITE_MOUNTED` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_WRITE_MOUNTED"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 8, 0)))
    .with_description("Forbid writes through the block device node of a mounted filesystem. Writing underneath a live filesystem desynchronizes the page cache from the on-disk state and can be used to bypass filesystem permissions and integrity, for example rewriting a file that DAC says is read-only or injecting data into a mounted image. Requires Linux >= 6.9 for the option to exist. Breaks legitimate low-level workflows: `dd` onto a mounted device, repair tools run while mounted, some LVM/RAID resynchronization helpers and VM disk imaging scripts.")
    .with_fix(&fix_disabled("CONFIG_BLK_DEV_WRITE_MOUNTED"))
    .register();

    check::Check::new(
        "KNC_147",
        "Ensure kernel build option `CONFIG_FAULT_INJECTION` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_FAULT_INJECTION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the fault injection framework, which lets root force allocation failures, I/O errors, syscall failures and disk errors on demand (`fail_*` under debugfs, per-task `should_fail`). It is a testing facility that also provides a ready-made way to destabilize the system and to drive rarely-tested error paths. Several other debug options depend on it (`FAIL_FUTEX`, `FAIL_MAKE_REQUEST`, `FAIL_IO_TIMEOUT`). Breaks kernel-level error-path testing and chaos engineering.")
    .with_fix(&fix_disabled("CONFIG_FAULT_INJECTION"))
    .register();

    check::Check::new(
        "KNC_148",
        "Ensure kernel build option `CONFIG_LKDTM` is not set",
        Severity::Low,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_not_set("CONFIG_LKDTM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the Linux Kernel Dump Test Module, which exposes debugfs entries that deliberately crash, corrupt memory, hang or panic the kernel on demand. It is meant for validating crash-dump setups, but anyone with debugfs access can trigger a crash or exercise corruption paths. Requires `CONFIG_DEBUG_FS`. Breaks kdump and crash testing.")
    .with_fix(&fix_disabled("CONFIG_LKDTM"))
    .register();

    check::Check::new(
        "KNC_149",
        "Ensure kernel build option `CONFIG_STRICT_KERNEL_RWX` is set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_STRICT_KERNEL_RWX"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Map kernel text and read-only data as non-writable (and non-executable data as non-executable) once boot is complete, so an arbitrary write primitive cannot patch kernel code or subvert `const` data such as syscall tables and credential structures; without it a single out-of-bounds write becomes code execution. Costs a little boot time to set up the page protections. Breaks out-of-tree modules or debugging tricks that expect to write to kernel text, and some live-patching setups. Requires architecture support and should always be on.")
    .with_fix(&fix_is_set("CONFIG_STRICT_KERNEL_RWX"))
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#executable-code-and-read-only-data-must-not-be-writable")
    .register();

    check::Check::new(
        "KNC_150",
        "Ensure kernel build option `CONFIG_STRICT_MODULE_RWX` is set",
        Severity::High,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_STRICT_MODULE_RWX"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Apply the same W^X protection to loaded modules: module text becomes non-writable and read-only data non-writable after the module is loaded, so an attacker with an arbitrary write cannot patch module code (a common target, since modules are often less hardened than the core kernel). Requires `CONFIG_MODULES`; nothing legitimate needs writable module text, but some out-of-tree drivers and self-modifying kernel modules fail to load.")
    .with_fix(&fix_is_set("CONFIG_STRICT_MODULE_RWX"))
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#executable-code-and-read-only-data-must-not-be-writable")
    .register();

    check::Check::new(
        "KNC_151",
        "Ensure kernel build option `CONFIG_MODULE_SIG_FORCE` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MODULE_SIG_FORCE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Refuse to load any module that is not signed with a key built into the kernel, so even root cannot inject arbitrary kernel code through the module loader. Stronger than `module.sig_enforce=1` on the kernel command line, which anyone able to edit the bootloader entry can simply delete. Requires `CONFIG_MODULES` and a signing key plus build pipeline: all out-of-tree and DKMS drivers (NVIDIA, VirtualBox, ZFS), locally built modules and unsigned vendor modules stop loading, often silently at boot. Moot when module support is disabled entirely with `CONFIG_MODULES=n`.")
    .with_fix(&fix_is_set("CONFIG_MODULE_SIG_FORCE"))
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#restricting-access-to-kernel-modules")
    .register();

    check::Check::new(
        "KNC_152",
        "Ensure kernel build option `CONFIG_KSTACK_ERASE` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_KSTACK_ERASE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 17, 0)))
    .with_description("Erase the kernel stack before it is handed to another task, so leftovers from a previous execution (kernel pointers, credentials, key material in uninitialized stack slots) cannot be recovered through a use-after-free or an uninitialized-variable read. Complements allocation-time zeroing (`CONFIG_INIT_ON_ALLOC_DEFAULT_ON`/`init_on_alloc=1`) and stack initialization options. Costs one memset per stack reuse, negligible in practice. It is selected automatically on architectures that support it, so an absent option means the kernel does not provide it rather than that hardening was turned off, and the check is skipped in that case. Kernels that still ship the stackleak GCC plugin instead of it are covered by `CONFIG_GCC_PLUGIN_STACKLEAK`.")
    .with_fix(&fix_is_set("CONFIG_KSTACK_ERASE"))
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#memory-poisoning")
    .register();

    check::Check::new(
        "KNC_153",
        "Ensure kernel build option `CONFIG_STACKPROTECTOR` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "KSPP"],
        || kconfig::check_option_is_set("CONFIG_STACKPROTECTOR"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("The stack protector adds a canary to functions with large stack frames, turning most linear stack overflows into a panic instead of a control-flow hijack. `CONFIG_STACKPROTECTOR_STRONG` implies it; this check only verifies that some stack protector is compiled in, `CONFIG_STACKPROTECTOR_STRONG` being the variant worth having, so a kernel with only the weak heuristic passes here.")
    .with_fix(&fix_is_set("CONFIG_STACKPROTECTOR"))
    .register();

    check::Check::new(
        "KNC_154",
        "Ensure kernel build option `CONFIG_STACKPROTECTOR_STRONG` is set",
        Severity::Medium,
        vec!["kernel", "kconfig"],
        || kconfig::check_option_is_set("CONFIG_STACKPROTECTOR_STRONG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("The strong stack protector variant instruments every function that uses an addressable stack array, which covers far more of the kernel than the regular heuristic, at a negligible performance cost.")
    .with_fix(&fix_is_set("CONFIG_STACKPROTECTOR_STRONG"))
    .register();

    check::Check::new(
        "KNC_155",
        "Ensure kernel build option `CONFIG_CFI_PERMISSIVE` is not set or missing",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_CFI_PERMISSIVE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 13, 0)))
    .with_description("Make Clang's Control Flow Integrity stop the kernel instead of only warning about it. In permissive mode a failed indirect call type check is logged and execution continues, so the mitigation reports an exploit in progress rather than preventing it; upstream documents the option as a development aid for finding type mismatches. Requires `CONFIG_CFI_CLANG`, so it is absent from GCC builds and the check is skipped. No cost when disabled.")
    .with_fix(&fix_disabled("CONFIG_CFI_PERMISSIVE"))
    .register();

    check::Check::new(
        "KNC_156",
        "Ensure kernel build option `CONFIG_CFI_AUTO_DEFAULT` is not set or missing",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_CFI_AUTO_DEFAULT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 11, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Decide on Clang CFI explicitly instead of letting the build turn it on based on the toolchain. With the option enabled, whether a kernel gets forward-edge CFI depends on the compiler that built it, so two images from the same `.config` can differ in their protections, and a rebuild with a different compiler silently loses the mitigation. Only exists on kernels offering `CONFIG_CFI_CLANG`, so the check is skipped elsewhere. No cost when disabled.")
    .with_fix(&fix_disabled("CONFIG_CFI_AUTO_DEFAULT"))
    .register();

    check::Check::new(
        "KNC_157",
        "Ensure kernel build option `CONFIG_HARDENED_USERCOPY_FALLBACK` is not set or missing",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_HARDENED_USERCOPY_FALLBACK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((5, 16, 0)))
    .with_description("Turn `CONFIG_HARDENED_USERCOPY` violations into warnings. With the fallback enabled a copy that should have been rejected is logged and performed anyway, which keeps a broken driver working but lets the oversized `copy_to_user`/`copy_from_user` through, so the validation stops preventing anything and only produces logs. Requires `CONFIG_HARDENED_USERCOPY`. No cost when disabled.")
    .with_fix(&fix_disabled("CONFIG_HARDENED_USERCOPY_FALLBACK"))
    .register();

    check::Check::new(
        "KNC_158",
        "Ensure kernel build option `CONFIG_HARDENED_USERCOPY_PAGESPAN` is not set or missing",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_HARDENED_USERCOPY_PAGESPAN"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((5, 19, 0)))
    .with_description("Additionally reject copies that span more than one separately allocated page. Upstream treats it as a debugging aid rather than a security requirement: legitimate callers do cross page boundaries (some filesystems, drivers and the network stack), so enabling it trades false positive panics for little extra coverage on top of `CONFIG_HARDENED_USERCOPY`. Requires `CONFIG_HARDENED_USERCOPY`, absent on kernels that dropped it.")
    .with_fix(&fix_disabled("CONFIG_HARDENED_USERCOPY_PAGESPAN"))
    .register();

    check::Check::new(
        "KNC_159",
        "Ensure kernel build option `CONFIG_KSTACK_ERASE_RUNTIME_DISABLE` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_KSTACK_ERASE_RUNTIME_DISABLE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 17, 0)))
    .with_description("Remove the `stack_erasing=off` boot parameter so kernel stack erasing cannot be switched off at boot by whoever edits the bootloader entry. The erasing itself is `CONFIG_KSTACK_ERASE`, this option only exists to disable it while debugging, and it is the reason a hardened build can still run without the mitigation. Absent on kernels that do not offer it, in which case there is nothing to disable and the check is skipped. No cost when disabled.")
    .with_fix(&fix_disabled("CONFIG_KSTACK_ERASE_RUNTIME_DISABLE"))
    .register();

    check::Check::new(
        "KNC_160",
        "Ensure kernel build option `CONFIG_KSTACK_ERASE_METRICS` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_KSTACK_ERASE_METRICS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 17, 0)))
    .with_description("Stop measuring how long stack erasing takes. It is a development instrument that keeps per-task counters and prints them on exit, useful to evaluate the cost of `CONFIG_KSTACK_ERASE` but protecting nothing, and it leaks timing information about kernel stack usage. Costs memory in `task_struct` and a few cycles per stack switch. Absent on kernels that do not offer it.")
    .with_fix(&fix_disabled("CONFIG_KSTACK_ERASE_METRICS"))
    .register();

    check::Check::new(
        "KNC_161",
        "Ensure kernel build option `CONFIG_STACKLEAK_RUNTIME_DISABLE` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_STACKLEAK_RUNTIME_DISABLE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 17, 0)))
    .with_description("The stackleak GCC plugin counterpart of `CONFIG_KSTACK_ERASE_RUNTIME_DISABLE`: removes the `stackleak=off` boot parameter so the plugin's stack erasing cannot be disabled at boot. Requires `CONFIG_GCC_PLUGIN_STACKLEAK`, which the kernel replaced with `CONFIG_KSTACK_ERASE` on the architectures that support it, so the option is absent from most builds and the check is skipped.")
    .with_fix(&fix_disabled("CONFIG_STACKLEAK_RUNTIME_DISABLE"))
    .register();

    check::Check::new(
        "KNC_162",
        "Ensure kernel build option `CONFIG_STACKLEAK_METRICS` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_STACKLEAK_METRICS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 17, 0)))
    .with_description("The stackleak GCC plugin counterpart of `CONFIG_KSTACK_ERASE_METRICS`: per-task counters measuring the cost of the plugin's stack erasing, printed on exit. Development instrumentation that protects nothing and leaks timing information. Requires `CONFIG_GCC_PLUGIN_STACKLEAK`, absent from most builds.")
    .with_fix(&fix_disabled("CONFIG_STACKLEAK_METRICS"))
    .register();

    // The hardened UBSAN combination is array bounds checking with traps,
    // `CONFIG_UBSAN_BOUNDS=y` and `CONFIG_UBSAN_TRAP=y`, and every other
    // sanitizer off: the ones below catch undefined behaviour that is common
    // and intentional in kernel code, so they report noise and, with traps
    // enabled, turn harmless driver bugs into panics.
    check::Check::new(
        "KNC_163",
        "Ensure kernel build option `CONFIG_UBSAN_ALIGNMENT` is not set or missing",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_UBSAN_ALIGNMENT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Stop checking for misaligned pointer accesses. Upstream warns that it produces many false positives on architectures handling unaligned access efficiently, and an unaligned access is not an attacker controlled primitive on its own. It also cannot be combined with `CONFIG_UBSAN_TRAP`, so enabling it forces the trap based sanitizers off. Requires `CONFIG_UBSAN`, and it is enabled by default on architectures without efficient unaligned access.")
    .with_fix(&fix_disabled("CONFIG_UBSAN_ALIGNMENT"))
    .register();

    check::Check::new(
        "KNC_164",
        "Ensure kernel build option `CONFIG_UBSAN_BOOL` is not set or missing",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_UBSAN_BOOL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 11, 0)))
    .with_description("Stop trapping or warning on a `bool` loaded with a value other than 0 or 1. Kernel code does this deliberately when reading hardware registers, firmware tables and packed on-disk structures, so the reports are dominated by noise, and loading a non canonical boolean is not an exploitable condition by itself. Enabled by default with `CONFIG_UBSAN`, which is why distributions ship it on.")
    .with_fix(&fix_disabled("CONFIG_UBSAN_BOOL"))
    .register();

    check::Check::new(
        "KNC_165",
        "Ensure kernel build option `CONFIG_UBSAN_DIV_ZERO` is not set or missing",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_UBSAN_DIV_ZERO"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 11, 0)))
    .with_description("Stop checking for integer division by zero. It is redundant with the kernel's existing exception handling, the divide error already kills the offending context or panics, and it only adds a more detailed message; it is also unavailable on Clang builds. Requires `CONFIG_UBSAN`.")
    .with_fix(&fix_disabled("CONFIG_UBSAN_DIV_ZERO"))
    .register();

    check::Check::new(
        "KNC_166",
        "Ensure kernel build option `CONFIG_UBSAN_ENUM` is not set or missing",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_UBSAN_ENUM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 11, 0)))
    .with_description("Stop trapping or warning on an out of range enum load. Same noise problem as `CONFIG_UBSAN_BOOL`: enums read from hardware, ACPI tables or on-disk structures routinely carry values outside the declared set, and the load itself is not a vulnerability. Enabled by default with `CONFIG_UBSAN`, which is why distributions ship it on.")
    .with_fix(&fix_disabled("CONFIG_UBSAN_ENUM"))
    .register();

    check::Check::new(
        "KNC_167",
        "Ensure kernel build option `CONFIG_UBSAN_INTEGER_WRAP` is not set or missing",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_UBSAN_INTEGER_WRAP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 15, 0)))
    .with_description("Stop trapping or warning on unsigned integer overflow. The kernel relies on wrapping unsigned arithmetic everywhere, from jiffies comparisons to hash mixing and ring buffer indices, so this is a pure noise source with traps enabled. Requires `CONFIG_UBSAN`.")
    .with_fix(&fix_disabled("CONFIG_UBSAN_INTEGER_WRAP"))
    .register();

    check::Check::new(
        "KNC_168",
        "Ensure kernel build option `CONFIG_UBSAN_SHIFT` is not set or missing",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_UBSAN_SHIFT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 11, 0)))
    .with_description("Stop checking for bit-shift overflows and shifts of a signed value into the sign bit. Shifts with an attacker controlled width are worth catching in the few places they exist, but kernel wide the reports are dominated by harmless driver arithmetic, so KSPP keeps only array bounds checking with traps. Enabled by default with `CONFIG_UBSAN`, which is why distributions ship it on.")
    .with_fix(&fix_disabled("CONFIG_UBSAN_SHIFT"))
    .register();

    check::Check::new(
        "KNC_169",
        "Ensure kernel build option `CONFIG_UBSAN_SIGNED_WRAP` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_UBSAN_SIGNED_WRAP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| kernel::skip_kernel_since((6, 15, 0)))
    .with_description("Stop trapping or warning on signed integer overflow. Signed overflow is undefined behaviour, but the kernel is built expecting wrapping semantics and relies on it in places, so the checks mostly report noise instead of exploitable conditions. Requires `CONFIG_UBSAN`, and it is absent from kernels that dropped the option.")
    .with_fix(&fix_disabled("CONFIG_UBSAN_SIGNED_WRAP"))
    .register();

    check::Check::new(
        "KNC_170",
        "Ensure kernel build option `CONFIG_UBSAN_UNREACHABLE` is not set or missing",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set_or_missing("CONFIG_UBSAN_UNREACHABLE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 11, 0)))
    .with_description("Stop trapping or warning when the compiler reaches a point it was told could not happen. The kernel's own `unreachable()` and `BUG()` paths already cover the impossible states it cares about, and a report here means a correctness bug in the code that made the promise, not a hardening control that was missing. Requires `CONFIG_UBSAN`.")
    .with_fix(&fix_disabled("CONFIG_UBSAN_UNREACHABLE"))
    .register();

    check::Check::new(
        "KNC_171",
        "Ensure kernel build option `CONFIG_HARDENED_USERCOPY` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_HARDENED_USERCOPY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Validate the size and the kind of memory behind every `copy_to_user`/`copy_from_user`, so a copy that points at a slab object smaller than the requested length, at several separate pages or at kernel text is rejected instead of leaking kernel memory or letting userspace write past an allocation. Requires an allocator providing object sizes (SLUB or SLAB). Keep `CONFIG_HARDENED_USERCOPY_FALLBACK` off, otherwise violations are logged and the copy is performed anyway.")
    .with_fix(&fix_is_set("CONFIG_HARDENED_USERCOPY"))
    .register();

    check::Check::new(
        "KNC_172",
        "Ensure kernel build option `CONFIG_HARDENED_USERCOPY_DEFAULT_ON` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_HARDENED_USERCOPY_DEFAULT_ON"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 15, 0)))
    .with_description("Make the `CONFIG_HARDENED_USERCOPY` checks active from boot instead of waiting for `hardened_usercopy=1` on the kernel command line, so they cannot be turned off by whoever edits the bootloader entry. No cost beyond the checks themselves.")
    .with_fix(&fix_is_set("CONFIG_HARDENED_USERCOPY_DEFAULT_ON"))
    .register();

    check::Check::new(
        "KNC_173",
        "Ensure kernel build option `CONFIG_INIT_ON_FREE_DEFAULT_ON` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_INIT_ON_FREE_DEFAULT_ON"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 3, 0)))
    .with_description("Zero heap objects and pages when they are freed by default, so freed memory cannot be read back through a use-after-free and stale data does not survive into the next allocation. It is the counterpart of `CONFIG_INIT_ON_ALLOC_DEFAULT_ON`, and `init_on_free=0` on the kernel command line can still turn it off. Costs a memset per free, a few percent on allocation-heavy workloads.")
    .with_fix(&fix_is_set("CONFIG_INIT_ON_FREE_DEFAULT_ON"))
    .register();

    check::Check::new(
        "KNC_174",
        "Ensure kernel build option `CONFIG_INIT_STACK_ALL_ZERO` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_INIT_STACK_ALL_ZERO"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 9, 0)))
    .with_description("Initialize every stack variable to zero at function entry, the strongest of the `CONFIG_INIT_STACK_*` choices, which removes the uninitialized stack variable class of information leaks and makes control-flow hijacks through a stale stack slot harder. Requires compiler support (`-ftrivial-auto-var-init=zero`), and the weaker `CONFIG_INIT_STACK_ALL_PATTERN` only fills with a recognizable pattern. Costs a little on functions with large frames.")
    .with_fix(&fix_is_set("CONFIG_INIT_STACK_ALL_ZERO"))
    .register();

    check::Check::new(
        "KNC_175",
        "Ensure kernel build option `CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 13, 0)))
    .with_description("Randomize the kernel stack offset on every syscall entry by default, so the position of a stack buffer is not fixed across calls and a stack overflow cannot be aimed at a precise address. The `randomize_kstack_offset=off` boot parameter can still disable it. Costs a fraction of a percent of syscall latency.")
    .with_fix(&fix_is_set("CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT"))
    .register();

    check::Check::new(
        "KNC_176",
        "Ensure kernel build option `CONFIG_ZERO_CALL_USED_REGS` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ZERO_CALL_USED_REGS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 15, 0)))
    .with_description("Clear the caller-used registers on function return, so kernel pointers and key material are not left in registers where a later speculative execution or a leaked register dump could pick them up. Requires compiler support (`-fzero-call-used-regs`), absent otherwise. Costs a little code size and a few instructions per return.")
    .with_fix(&fix_is_set("CONFIG_ZERO_CALL_USED_REGS"))
    .register();

    check::Check::new(
        "KNC_177",
        "Ensure kernel build option `CONFIG_CFI_CLANG` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set_not_missing("CONFIG_CFI_CLANG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 13, 0)))
    .with_description("Enable Clang's forward-edge Control Flow Integrity, which checks that every indirect call targets a function with a compatible type, turning a hijacked function pointer into a detected failure instead of arbitrary code execution. Requires a Clang-built kernel with LTO, so the option is absent from GCC builds, and `CONFIG_CFI_PERMISSIVE` has to stay off for violations to be fatal. Costs build time and a little runtime overhead, and breaks out-of-tree modules that are not built with the same flags.")
    .with_fix(&fix_is_set("CONFIG_CFI_CLANG"))
    .register();

    check::Check::new(
        "KNC_178",
        "Ensure kernel build option `CONFIG_SHADOW_CALL_STACK` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_SHADOW_CALL_STACK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 8, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64", "riscv64", "riscv32"]))
    .with_description("Keep return addresses in a separate shadow stack that neither userspace nor a linear overflow of the kernel stack can reach, so overwriting the return address of the running function stops working as an exploit primitive. arm64 and riscv with compiler support; costs a reserved register (x18 on arm64) and a little memory per task. The x86 equivalent is `CONFIG_X86_KERNEL_IBT` for the forward edge and Intel CET shadow stacks for the backward edge.")
    .with_fix(&fix_is_set("CONFIG_SHADOW_CALL_STACK"))
    .register();

    check::Check::new(
        "KNC_179",
        "Ensure kernel build option `CONFIG_RANDSTRUCT_FULL` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_RANDSTRUCT_FULL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 19, 0)))
    .with_description("Randomize the layout of marked structures at build time, so an exploit cannot hardcode the offset of a function pointer, a credential field or a lock inside them. Requires a compiler supporting the randstruct pass, and out-of-tree modules have to be rebuilt with the same seed. The lighter `RANDSTRUCT_PERFORMANCE` variant only randomizes fields in separate cachelines.")
    .with_fix(&fix_is_set("CONFIG_RANDSTRUCT_FULL"))
    .register();

    check::Check::new(
        "KNC_180",
        "Ensure kernel build option `CONFIG_GCC_PLUGIN_LATENT_ENTROPY` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_GCC_PLUGIN_LATENT_ENTROPY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Mix build-time random constants generated by the GCC plugin into the early boot entropy pool, which helps systems that boot with little entropy (embedded boards, virtual machines cloning the same state). Requires GCC plugin support. Costs a negligible amount of kernel size and a little boot time.")
    .with_fix(&fix_is_set("CONFIG_GCC_PLUGIN_LATENT_ENTROPY"))
    .register();

    check::Check::new(
        "KNC_181",
        "Ensure kernel build option `CONFIG_KFENCE` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_KFENCE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 12, 0)))
    .with_description("Compile in the sampling memory error detector, which guards a small pool of allocations with inaccessible pages and catches use-after-free, double-free and out-of-bounds writes in production at a fraction of KASAN's cost. Costs the pool memory (`CONFIG_KFENCE_NUM_OBJECTS`) and near zero CPU. Needs `CONFIG_KFENCE_SAMPLE_INTERVAL` or the `kfence.sample_interval` boot parameter to be non-zero, otherwise nothing is sampled after boot.")
    .with_fix(&fix_is_set("CONFIG_KFENCE"))
    .register();

    check::Check::new(
        "KNC_182",
        "Ensure kernel build option `CONFIG_KFENCE_SAMPLE_INTERVAL` is set to `100`",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_value("CONFIG_KFENCE_SAMPLE_INTERVAL", "100"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 12, 0)))
    .with_description("Let KFENCE redirect an allocation into its guarded pool every 100 ms, the interval KSPP recommends. A much larger interval means the detector almost never fires, and `0` disables sampling entirely so only the objects allocated at boot stay guarded. The `kfence.sample_interval=100` boot parameter reaches the same state at runtime and overrides the build value.")
    .with_fix(&fix_value("CONFIG_KFENCE_SAMPLE_INTERVAL", "100"))
    .register();

    check::Check::new(
        "KNC_183",
        "Ensure kernel build option `CONFIG_UBSAN_BOUNDS` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set_not_missing("CONFIG_UBSAN_BOUNDS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 7, 0)))
    .with_description("Instrument array indexing so an out-of-bounds access is detected, which is the part of UBSan catching exploitable conditions rather than benign undefined behaviour. Pairs with `CONFIG_UBSAN_TRAP` to make a report fatal, and with the other UBSan checks left off, since their reports are dominated by intentional kernel idioms. Costs a little code size and a few percent of performance.")
    .with_fix(&fix_is_set("CONFIG_UBSAN_BOUNDS"))
    .register();

    check::Check::new(
        "KNC_184",
        "Ensure kernel build option `CONFIG_UBSAN_LOCAL_BOUNDS` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set_not_missing("CONFIG_UBSAN_LOCAL_BOUNDS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 10, 0)))
    .with_description("Extend bounds checking to accesses through a local stack object, catching overflows of stack arrays that `CONFIG_UBSAN_BOUNDS` alone misses. Clang only; on GCC the equivalent coverage comes from the compiler's own array bounds checks.")
    .with_fix(&fix_is_set("CONFIG_UBSAN_LOCAL_BOUNDS"))
    .register();

    check::Check::new(
        "KNC_185",
        "Ensure kernel build option `CONFIG_UBSAN_TRAP` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set_not_missing("CONFIG_UBSAN_TRAP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 7, 0)))
    .with_description("Make a UBSan violation call `BUG()` instead of printing a warning and continuing, so a detected out-of-bounds access cannot be exploited after having been reported. Requires `CONFIG_BUG`, and turns every sanitizer report into a crash, which is why only the bounds checks should be enabled alongside it.")
    .with_fix(&fix_is_set("CONFIG_UBSAN_TRAP"))
    .register();

    check::Check::new(
        "KNC_186",
        "Ensure kernel build option `CONFIG_UBSAN_SANITIZE_ALL` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_UBSAN_SANITIZE_ALL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 9, 0)))
    .with_description("Instrument the whole kernel with UBSan instead of only the files that opt in, so the bounds checks reach every subsystem including the ones nobody thought to enable them for. Costs code size and a little performance; since v6.9 instrumenting the whole kernel is the default once UBSan is enabled and the option is gone, so the check is skipped there.")
    .with_fix(&fix_is_set("CONFIG_UBSAN_SANITIZE_ALL"))
    .register();

    check::Check::new(
        "KNC_187",
        "Ensure kernel build option `CONFIG_DEBUG_VIRTUAL` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_DEBUG_VIRTUAL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Check that every address handed to `virt_to_page` and friends really is in the kernel's linear mapping, catching driver bugs that turn a stray or userspace pointer into a bogus `struct page`. Costs measurable overhead on the page lookup path, so it is an assurance feature rather than a free one.")
    .with_fix(&fix_is_set("CONFIG_DEBUG_VIRTUAL"))
    .register();

    check::Check::new(
        "KNC_188",
        "Ensure kernel build option `CONFIG_DEBUG_SG` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_DEBUG_SG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Validate scatterlist tables on every operation, catching drivers that build an invalid entry list, which would otherwise let a DMA, crypto or block operation read or write outside the buffers it was given. Costs extra fields per entry and checks on each sg call.")
    .with_fix(&fix_is_set("CONFIG_DEBUG_SG"))
    .register();

    check::Check::new(
        "KNC_189",
        "Ensure kernel build option `CONFIG_DEBUG_NOTIFIERS` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_DEBUG_NOTIFIERS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Check that a notifier chain is not corrupted while it is being walked, which matters because a fake callback inserted into a chain is a classic privilege escalation target. Costs a lot: a read lock and disabled preemption around every notifier call, so it is a debugging option rather than a production one.")
    .with_fix(&fix_is_set("CONFIG_DEBUG_NOTIFIERS"))
    .register();

    check::Check::new(
        "KNC_190",
        "Ensure kernel build option `CONFIG_DEBUG_CREDENTIALS` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_DEBUG_CREDENTIALS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 7, 0)))
    .with_description("Validate the reference count and a poison value of every `struct cred` on each use, catching use-after-free of credentials, which is directly exploitable for privilege escalation. Removed from the kernel in v6.7, so the check is skipped on newer kernels.")
    .with_fix(&fix_is_set("CONFIG_DEBUG_CREDENTIALS"))
    .register();

    check::Check::new(
        "KNC_191",
        "Ensure kernel build option `CONFIG_SCHED_STACK_END_CHECK` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_SCHED_STACK_END_CHECK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Verify the canary at the end of a kernel stack when a task is scheduled in and out, so a stack overflow is detected at the next context switch instead of silently corrupting whatever sits next to the stack. Negligible cost.")
    .with_fix(&fix_is_set("CONFIG_SCHED_STACK_END_CHECK"))
    .register();

    check::Check::new(
        "KNC_192",
        "Ensure kernel build option `CONFIG_PAGE_POISONING_ZERO` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_PAGE_POISONING_ZERO"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((5, 11, 0)))
    .with_description("Use zero instead of the `0xAA` pattern when page poisoning is enabled, so a freed page does not carry a recognizable marker and the zeroed pages stay cheap to compress or deduplicate. Only meaningful with `page_poison=1` on the kernel command line; `CONFIG_INIT_ON_FREE_DEFAULT_ON` is the more direct way to get the same property.")
    .with_fix(&fix_is_set("CONFIG_PAGE_POISONING_ZERO"))
    .register();

    check::Check::new(
        "KNC_193",
        "Ensure kernel build option `CONFIG_SLAB_BUCKETS` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_SLAB_BUCKETS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 11, 0)))
    .with_description("Give each allocation its own bucket instead of packing objects of different subsystems onto shared slab pages, which limits what a heap overflow or a use-after-free can reach and complements the cache partitioning of `CONFIG_RANDOM_KMALLOC_CACHES`. Costs memory for the partially filled buckets and slightly worse locality.")
    .with_fix(&fix_is_set("CONFIG_SLAB_BUCKETS"))
    .register();

    check::Check::new(
        "KNC_194",
        "Ensure kernel build option `CONFIG_MODULE_SIG` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MODULE_SIG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Verify a cryptographic signature on every module before loading it. Without it anything with `CAP_SYS_MODULE`, or a writable initramfs, can insert arbitrary kernel code, and `CONFIG_MODULE_SIG_FORCE` cannot be used at all. Costs a little boot time for the verification and requires the signing key to be built in.")
    .with_fix(&fix_is_set("CONFIG_MODULE_SIG"))
    .register();

    check::Check::new(
        "KNC_195",
        "Ensure kernel build option `CONFIG_MODULE_SIG_ALL` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MODULE_SIG_ALL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Sign every module during the build instead of leaving it to a later step, so turning on `CONFIG_MODULE_SIG_FORCE` does not lock out the kernel's own modules. Costs nothing at runtime.")
    .with_fix(&fix_is_set("CONFIG_MODULE_SIG_ALL"))
    .register();

    check::Check::new(
        "KNC_196",
        "Ensure kernel build option `CONFIG_MODULE_SIG_SHA512` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MODULE_SIG_SHA512"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Use SHA-512 for module signatures instead of the default SHA-256, raising the cost of forging a signature for a slightly slower verification. The chosen hash is also recorded in `CONFIG_MODULE_SIG_HASH`.")
    .with_fix(&fix_is_set("CONFIG_MODULE_SIG_SHA512"))
    .register();

    check::Check::new(
        "KNC_197",
        "Ensure kernel build option `CONFIG_MODULE_SIG_SHA3_512` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MODULE_SIG_SHA3_512"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 7, 0)))
    .with_description("Use SHA3-512 for module signatures, which relies on a different construction than the SHA-2 family, so a break in SHA-2 would not immediately allow forging modules. Costs slightly slower signing and verification.")
    .with_fix(&fix_is_set("CONFIG_MODULE_SIG_SHA3_512"))
    .register();

    check::Check::new(
        "KNC_198",
        "Ensure kernel build option `CONFIG_INTEL_IOMMU_DEFAULT_ON` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_INTEL_IOMMU_DEFAULT_ON"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Turn the Intel IOMMU on by default instead of waiting for `intel_iommu=on` on the kernel command line, so DMA isolation and the mitigations built on it are active even when the bootloader entry is edited. Requires `CONFIG_IOMMU_SUPPORT` and VT-d hardware; costs DMA throughput in strict mode, and devices needing unrestricted DMA may require passthrough.")
    .with_fix(&fix_is_set("CONFIG_INTEL_IOMMU_DEFAULT_ON"))
    .register();

    check::Check::new(
        "KNC_199",
        "Ensure kernel build option `CONFIG_INTEL_IOMMU_SVM` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_INTEL_IOMMU_SVM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Enable shared virtual memory on the Intel IOMMU, letting a device DMA through a process page table under IOMMU protection instead of needing a pinned identity-mapped region. Needed by accelerators and some compute drivers; x86 with VT-d only.")
    .with_fix(&fix_is_set("CONFIG_INTEL_IOMMU_SVM"))
    .register();

    check::Check::new(
        "KNC_200",
        "Ensure kernel build option `CONFIG_AMD_IOMMU_V2` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_AMD_IOMMU_V2"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 7, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("The AMD IOMMUv2 page table support used for shared virtual memory with AMD devices. Dropped from the kernel in v6.7, where the functionality moved into the main AMD IOMMU driver, so the check is skipped on newer kernels.")
    .with_fix(&fix_is_set("CONFIG_AMD_IOMMU_V2"))
    .register();

    check::Check::new(
        "KNC_201",
        "Ensure kernel build option `CONFIG_EFI_DISABLE_PCI_DMA` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_EFI_DISABLE_PCI_DMA"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 6, 0)))
    .with_description("Stop the EFI runtime services from performing DMA while the kernel takes over at boot, closing the window where firmware or a malicious PCIe device could write into memory the kernel is not protecting yet. No effect on systems without `CONFIG_EFI`.")
    .with_fix(&fix_is_set("CONFIG_EFI_DISABLE_PCI_DMA"))
    .register();

    check::Check::new(
        "KNC_202",
        "Ensure kernel build option `CONFIG_RESET_ATTACK_MITIGATION` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_RESET_ATTACK_MITIGATION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Ask the firmware to clear memory on the next cold boot, limiting what an attacker with physical access can recover from RAM after a reset (the TCG platform reset attack mitigation). Needs `CONFIG_EFI` and firmware that honours the request, otherwise it does nothing.")
    .with_fix(&fix_is_set("CONFIG_RESET_ATTACK_MITIGATION"))
    .register();

    check::Check::new(
        "KNC_203",
        "Ensure kernel build option `CONFIG_MITIGATION_SLS` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_SLS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Enable the Straight-Line-Speculation mitigation, which stops the CPU from speculatively executing past an unconditional branch or return, the behaviour behind CVE-2021-26341 on some AMD parts. Costs a little performance, and the option is absent on CPUs and kernels that do not implement it. Was named `CONFIG_SLS` in the first releases.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_SLS"))
    .register();

    check::Check::new(
        "KNC_204",
        "Ensure kernel build option `CONFIG_X86_USER_SHADOW_STACK` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_X86_USER_SHADOW_STACK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 6, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Enable Intel CET shadow stacks for userspace, giving each process a hardware-protected copy of its return addresses so a stack overflow cannot redirect control flow. Requires CET-capable hardware and libc support; the kernel-side forward-edge counterpart is `CONFIG_X86_KERNEL_IBT`. x86_64 only.")
    .with_fix(&fix_is_set("CONFIG_X86_USER_SHADOW_STACK"))
    .register();

    check::Check::new(
        "KNC_205",
        "Ensure kernel build option `CONFIG_ARM64_SW_TTBR0_PAN` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM64_SW_TTBR0_PAN"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Emulate Privileged Access Never in software by keeping a disabled translation table base in `TTBR0` while the kernel runs, so a kernel bug cannot dereference a userspace address by accident. Used on arm64 parts without hardware PAN, which `CONFIG_ARM64_PAN` covers; costs a register write on each user to kernel transition.")
    .with_fix(&fix_is_set("CONFIG_ARM64_SW_TTBR0_PAN"))
    .register();

    check::Check::new(
        "KNC_206",
        "Ensure kernel build option `CONFIG_KASAN_HW_TAGS` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_KASAN_HW_TAGS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 11, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Use the arm64 Memory Tagging Extension for KASAN, tagging allocations and pointers in hardware to catch use-after-free and out-of-bounds with far less overhead than software KASAN, which makes it usable on production images. Needs MTE-capable hardware; `CONFIG_ARM64_MTE` is the userspace side of the same feature.")
    .with_fix(&fix_is_set("CONFIG_KASAN_HW_TAGS"))
    .register();

    check::Check::new(
        "KNC_207",
        "Ensure kernel build option `CONFIG_PROC_MEM_NO_FORCE` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_PROC_MEM_NO_FORCE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 12, 0)))
    .with_description("Remove the forced write access to another process's memory through `/proc/pid/mem`, which otherwise lets root and anything able to ptrace write into a running process even when it is protected, a common code injection and privilege escalation path. Breaks debuggers and tooling that patch a live process through `/proc/pid/mem`.")
    .with_fix(&fix_is_set("CONFIG_PROC_MEM_NO_FORCE"))
    .register();

    check::Check::new(
        "KNC_208",
        "Ensure kernel build option `CONFIG_DEBUG_WX` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_DEBUG_WX"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Report every writable and executable kernel mapping at boot and on module load, which is how a missing `CONFIG_STRICT_KERNEL_RWX` or a module allocating W+X memory is found, and W+X kernel memory is what turns a write primitive into code execution. Costs a page table walk at boot. Renamed to `CONFIG_ARM_DEBUG_WX` on 32-bit arm.")
    .with_fix(&fix_is_set("CONFIG_DEBUG_WX"))
    .register();

    check::Check::new(
        "KNC_209",
        "Ensure kernel build option `CONFIG_ARM_DEBUG_WX` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM_DEBUG_WX"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm32"]))
    .with_description("The arm name of `CONFIG_DEBUG_WX` since v6.9: report writable and executable kernel mappings at boot. Present on 32-bit arm kernels and absent elsewhere, where `CONFIG_DEBUG_WX` is the option to check.")
    .with_fix(&fix_is_set("CONFIG_ARM_DEBUG_WX"))
    .register();

    check::Check::new(
        "KNC_210",
        "Ensure kernel build option `CONFIG_VMAP_STACK` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_VMAP_STACK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Allocate kernel stacks from vmalloc memory with a guard page around them, so a stack overflow faults immediately instead of silently corrupting whatever is adjacent, which is the primitive behind most stack based privilege escalations. Requires `CONFIG_THREAD_INFO_IN_TASK`; costs a little on the stack allocation path and forbids DMA to stack buffers, which some old drivers still attempt.")
    .with_fix(&fix_is_set("CONFIG_VMAP_STACK"))
    .register();

    check::Check::new(
        "KNC_211",
        "Ensure kernel build option `CONFIG_LEGACY_VSYSCALL_NONE` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_LEGACY_VSYSCALL_NONE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Remove the vsyscall page entirely instead of emulating it or leaving it executable. The page sits at a fixed address in every process and contains `gettimeofday`, `time` and `getcpu` stubs, which makes it a reliable source of gadgets for return-oriented programming; `CONFIG_LEGACY_VSYSCALL_NONE` is the only setting that removes it. Breaks binaries linked against glibc older than 2.14, which call the vsyscall entry points directly.")
    .with_fix(&fix_is_set("CONFIG_LEGACY_VSYSCALL_NONE"))
    .register();

    check::Check::new(
        "KNC_212",
        "Ensure kernel build option `CONFIG_X86_VSYSCALL_EMULATION` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_X86_VSYSCALL_EMULATION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Stop emulating the vsyscall page in the kernel, so `vsyscall=emulate` on the kernel command line cannot bring back a fixed-address executable page in every process. Requires `CONFIG_LEGACY_VSYSCALL_NONE` to be the build choice; the option is x86_64 only. Emulation is what keeps pre-2.14 glibc binaries working, so disabling it drops that compatibility.")
    .with_fix(&fix_disabled("CONFIG_X86_VSYSCALL_EMULATION"))
    .register();

    check::Check::new(
        "KNC_213",
        "Ensure kernel build option `CONFIG_COMPAT_VDSO` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_COMPAT_VDSO"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Do not fall back to the compat vDSO for 32-bit processes, which is mapped at a fixed address and therefore a predictable source of gadgets, the same problem as the vsyscall page. Only exists on kernels with 32-bit emulation support; a real compat vDSO is what should be used instead.")
    .with_fix(&fix_disabled("CONFIG_COMPAT_VDSO"))
    .register();

    check::Check::new(
        "KNC_214",
        "Ensure kernel build option `CONFIG_IO_STRICT_DEVMEM` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set_not_missing("CONFIG_IO_STRICT_DEVMEM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Refuse `/dev/mem` access to memory regions a driver has already claimed through the resource tree, on top of `CONFIG_STRICT_DEVMEM` which only keeps root away from RAM. Without it a compromised root process can write into the MMIO region of a live device and reach hardware directly, bypassing every driver-level check. Breaks vendor tools that poke reserved device memory through `/dev/mem` while the driver is loaded; unbinding the driver restores access.")
    .with_fix(&fix_is_set("CONFIG_IO_STRICT_DEVMEM"))
    .register();

    check::Check::new(
        "KNC_215",
        "Ensure kernel build option `CONFIG_LDISC_AUTOLOAD` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_LDISC_AUTOLOAD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 1, 0)))
    .with_description("Stop the kernel from automatically loading a line discipline module when a program asks for one by number through `TIOCSETD`. Autoloading let an unprivileged user with a pty pull in an unused protocol module and reach its code, which is how several local privilege escalations started. Programs that need a specific line discipline keep working when the module is already loaded or built in.")
    .with_fix(&fix_disabled("CONFIG_LDISC_AUTOLOAD"))
    .register();

    check::Check::new(
        "KNC_216",
        "Ensure kernel build option `CONFIG_BPF_JIT_ALWAYS_ON` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_BPF_JIT_ALWAYS_ON"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the BPF interpreter and always compile classic and extended BPF programs through the JIT, so the `net.core.bpf_jit_enable=0` sysctl cannot switch to the interpreter, which has been the target of spray and spraying-adjacent bugs of its own. Requires `CONFIG_BPF_SYSCALL` or socket filters to be compiled in, and costs JIT compile time for every program. Meaningless when BPF is removed entirely with `CONFIG_BPF_SYSCALL=n`.")
    .with_fix(&fix_is_set("CONFIG_BPF_JIT_ALWAYS_ON"))
    .register();

    check::Check::new(
        "KNC_217",
        "Ensure kernel build option `CONFIG_COREDUMP` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional", "paranoid"],
        || kconfig::check_option_is_not_set("CONFIG_COREDUMP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the core dump mechanism from the kernel, so a crashing process cannot leave its address space, including keys, credentials and decrypted data, in a file readable by another user or shipped away by a crash reporter. Breaks debugging entirely (no `coredumpctl`, no gdb on a core file), crash reporters and anything relying on `RLIMIT_CORE`.")
    .with_fix(&fix_disabled("CONFIG_COREDUMP"))
    .register();

    check::Check::new(
        "KNC_218",
        "Ensure kernel build option `CONFIG_KVM` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional", "paranoid"],
        || kconfig::check_option_is_not_set("CONFIG_KVM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the kernel virtual machine support, which is a large attack surface reachable from an unprivileged user with access to `/dev/kvm` and from guests through the device emulation. Only for hosts that never run virtual machines or containers relying on nested virtualization: it breaks QEMU, libvirt, Vagrant, Android emulators, `kata-containers` and Windows sandboxes.")
    .with_fix(&fix_disabled("CONFIG_KVM"))
    .register();

    check::Check::new(
        "KNC_219",
        "Ensure kernel build option `CONFIG_IA32_EMULATION_DEFAULT_DISABLED` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_IA32_EMULATION_DEFAULT_DISABLED"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 7, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Keep the x86_64 32-bit syscall entry points compiled in but disabled at boot, so the compat entry code, which has had several privilege escalation bugs, is unreachable unless `ia32_emulation=on` is passed. Only relevant when `CONFIG_IA32_EMULATION` is kept, though removing it is stronger: this option then disappears and the check is skipped. Breaks 32-bit binaries by default.")
    .with_fix(&fix_is_set("CONFIG_IA32_EMULATION_DEFAULT_DISABLED"))
    .register();

    check::Check::new(
        "KNC_220",
        "Ensure kernel build option `CONFIG_TRIM_UNUSED_KSYMS` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_TRIM_UNUSED_KSYMS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Do not export kernel symbols that nothing in this build uses, which shrinks the set of functions reachable from a loaded module and from `kallsyms`-guided exploitation. Requires every needed module to be known at build time: out-of-tree and DKMS modules (NVIDIA, VirtualBox, ZFS) fail to load because the symbols they import are gone. Meaningless when module support is removed entirely with `CONFIG_MODULES=n`.")
    .with_fix(&fix_is_set("CONFIG_TRIM_UNUSED_KSYMS"))
    .register();

    check::Check::new(
        "KNC_221",
        "Ensure kernel build option `CONFIG_CRYPTO_USER_API` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_CRYPTO_USER_API"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the AF_ALG socket interface, which exposes the kernel crypto implementations to any unprivileged process and has been the source of several use-after-free and race bugs. Breaks applications doing crypto through AF_ALG instead of a userspace library, which is rare: `cryptsetup` and `openssl` use it only when built with the engine enabled.")
    .with_fix(&fix_disabled("CONFIG_CRYPTO_USER_API"))
    .register();

    check::Check::new(
        "KNC_222",
        "Ensure kernel build option `CONFIG_CRYPTO_USER_API_AEAD` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_CRYPTO_USER_API_AEAD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the AEAD part of the AF_ALG socket interface (`CRYPTO_USER_API`), which lets unprivileged processes drive kernel AEAD ciphers and has carried its share of memory safety bugs. Breaks applications that use AF_ALG for authenticated encryption.")
    .with_fix(&fix_disabled("CONFIG_CRYPTO_USER_API_AEAD"))
    .register();

    check::Check::new(
        "KNC_223",
        "Ensure kernel build option `CONFIG_CRYPTO_USER_API_HASH` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_CRYPTO_USER_API_HASH"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the hash part of the AF_ALG socket interface (`CRYPTO_USER_API`), the path used by `openssl`'s AF_ALG engine and by some integrity measurement tools. Breaks those applications, which fall back to userspace implementations.")
    .with_fix(&fix_disabled("CONFIG_CRYPTO_USER_API_HASH"))
    .register();

    check::Check::new(
        "KNC_224",
        "Ensure kernel build option `CONFIG_CRYPTO_USER_API_RNG` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_CRYPTO_USER_API_RNG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the random number generator part of the AF_ALG socket interface (`CRYPTO_USER_API`), reachable by any unprivileged process. Breaks applications drawing kernel random numbers through a socket instead of `getrandom()`.")
    .with_fix(&fix_disabled("CONFIG_CRYPTO_USER_API_RNG"))
    .register();

    check::Check::new(
        "KNC_225",
        "Ensure kernel build option `CONFIG_CRYPTO_USER_API_RNG_CAVP` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_CRYPTO_USER_API_RNG_CAVP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 10, 0)))
    .with_description("Remove the CAVP testing interface of the AF_ALG random number generator, which exists only for FIPS certification testing and adds options to a socket any process can open. Breaks the CAVP validation test runs and nothing else.")
    .with_fix(&fix_disabled("CONFIG_CRYPTO_USER_API_RNG_CAVP"))
    .register();

    check::Check::new(
        "KNC_226",
        "Ensure kernel build option `CONFIG_CRYPTO_USER_API_SKCIPHER` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_CRYPTO_USER_API_SKCIPHER"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Remove the symmetric cipher part of the AF_ALG socket interface (`CRYPTO_USER_API`), which lets unprivileged processes drive kernel ciphers and has had several reference counting bugs. Breaks applications using AF_ALG for encryption.")
    .with_fix(&fix_disabled("CONFIG_CRYPTO_USER_API_SKCIPHER"))
    .register();

    check::Check::new(
        "KNC_227",
        "Ensure kernel build option `CONFIG_CRYPTO_USER_API_ENABLE_OBSOLETE` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_CRYPTO_USER_API_ENABLE_OBSOLETE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 10, 0)))
    .with_description("Keep the obsolete crypto algorithms out of the AF_ALG socket interface, so an unprivileged process cannot reach implementations that are only kept for compatibility and are no longer maintained against side channels or memory bugs. Breaks users of those legacy ciphers through AF_ALG.")
    .with_fix(&fix_disabled("CONFIG_CRYPTO_USER_API_ENABLE_OBSOLETE"))
    .register();

    check::Check::new(
        "KNC_228",
        "Ensure kernel build option `CONFIG_DEBUG_CLOSURES` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_DEBUG_CLOSURES"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 7, 0)))
    .with_description("Remove the closure debugging instrumentation of the bcache and bcachefs code, which keeps per-closure state and dumps it on request, exposing internal kernel state and slowing the fast path. Breaks nothing but the debugging of those subsystems.")
    .with_fix(&fix_disabled("CONFIG_DEBUG_CLOSURES"))
    .register();

    check::Check::new(
        "KNC_229",
        "Ensure kernel build option `CONFIG_ARM_PTDUMP_DEBUGFS` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_ARM_PTDUMP_DEBUGFS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((4, 16, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm32"]))
    .with_description("Remove the arm32 debugfs page table dumper, the counterpart of `CONFIG_PTDUMP_DEBUGFS` on the architectures that select `ARCH_HAS_PTDUMP`, which walks the kernel page tables and prints every mapping with its physical address, defeating KASLR and handing an attacker a map of the kernel. Named `CONFIG_ARM_PTDUMP` before v4.16. Breaks the `page_tables` debugfs interface used to audit mappings.")
    .with_fix(&fix_disabled("CONFIG_ARM_PTDUMP_DEBUGFS"))
    .register();

    check::Check::new(
        "KNC_230",
        "Ensure kernel build option `CONFIG_ARM_PTDUMP_DEBUGFS` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_ARM_PTDUMP_DEBUGFS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["arm64", "arm32"]))
    .with_description("Remove the debugfs interface of the arm page table dumper (`CONFIG_ARM_PTDUMP`), which is what makes the kernel page table readable from userspace by root, and through a mounted debugfs by anything that reaches it. Breaks the `page_tables` debugfs files.")
    .with_fix(&fix_disabled("CONFIG_ARM_PTDUMP_DEBUGFS"))
    .register();

    check::Check::new(
        "KNC_231",
        "Ensure kernel build option `CONFIG_SECCOMP_CACHE_DEBUG` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_SECCOMP_CACHE_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 11, 0)))
    .with_description("Remove the debugfs file listing how a seccomp filter was compiled into the architecture's instruction cache, which exposes the filter logic of a sandboxed process to anything able to read debugfs. Breaks nothing but seccomp filter debugging.")
    .with_fix(&fix_disabled("CONFIG_SECCOMP_CACHE_DEBUG"))
    .register();

    check::Check::new(
        "KNC_232",
        "Ensure kernel build option `CONFIG_CRASH_DM_CRYPT` is not set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        // can be missing if CONFIG_CRASH_DUMP is not set
        || kconfig::check_option_is_not_set_or_missing("CONFIG_CRASH_DM_CRYPT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 16, 0)))
    .with_description("Remove the ability to dump dm-crypt volumes into a crash kernel, which requires the encryption keys to be handed to the capture kernel and written where the crash dump ends up. Breaks kdump based recovery of encrypted volumes; a dump of an encrypted system then contains the ciphertext only.")
    .with_fix(&fix_disabled("CONFIG_CRASH_DM_CRYPT"))
    .register();

    check::Check::new(
        "KNC_233",
        "Ensure kernel build option `CONFIG_LSM` enables a major MAC LSM",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_value_contains("CONFIG_LSM", &["apparmor", "selinux", "smack", "tomoyo"]),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 1, 0)))
    .with_description("Have at least one of the major mandatory access control LSMs in the boot order, since compiling one in (`CONFIG_SECURITY_APPARMOR`, `CONFIG_SECURITY_SELINUX`, `CONFIG_SECURITY_SMACK`, `CONFIG_SECURITY_TOMOYO`) is not enough: an LSM absent from `CONFIG_LSM` is never initialized and its policy is never enforced. Distributions ship several compiled in and choose one here, AppArmor on Ubuntu and SUSE, SELinux on Fedora, RHEL and Debian. The `lsm=` kernel command line parameter overrides the build list, and the order matters because the hooks run in it.")
    .with_fix("Recompile the kernel with one of `apparmor`, `selinux`, `smack` or `tomoyo` in the `CONFIG_LSM` list, or pass `lsm=` on the kernel command line. Alternatively some distributions have hardened kernels with different compilation options.")
    .register();

    check::Check::new(
        "KNC_234",
        "Ensure kernel build option `CONFIG_LSM` enables `lockdown`",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_value_contains("CONFIG_LSM", &["lockdown"]),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 1, 0)))
    .with_description("Have the lockdown LSM in the boot order so it actually enforces, which `CONFIG_SECURITY_LOCKDOWN_LSM` alone does not guarantee: an LSM missing from `CONFIG_LSM` is never initialized, and neither `lockdown=integrity` nor `CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY` has any effect without it.")
    .with_fix("Recompile the kernel with `lockdown` in the `CONFIG_LSM` list, or pass `lsm=` including it on the kernel command line. Alternatively some distributions have hardened kernels with different compilation options.")
    .register();

    check::Check::new(
        "KNC_235",
        "Ensure kernel build option `CONFIG_LSM` enables `yama`",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_value_contains("CONFIG_LSM", &["yama"]),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 1, 0)))
    .with_description("Have the Yama LSM in the boot order so the `ptrace` restrictions controlled by `/proc/sys/kernel/yama/ptrace_scope` are enforced. `CONFIG_SECURITY_YAMA` only compiles it in: without an entry in `CONFIG_LSM` it is never initialized and every process can attach to any other process of the same user, which is how credential and key material is scraped from a running browser or agent.")
    .with_fix("Recompile the kernel with `yama` in the `CONFIG_LSM` list, or pass `lsm=` including it on the kernel command line. Alternatively some distributions have hardened kernels with different compilation options.")
    .register();

    check::Check::new(
        "KNC_236",
        "Ensure kernel build option `CONFIG_LSM` enables `landlock`",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_value_contains("CONFIG_LSM", &["landlock"]),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 1, 0)))
    .with_description("Have the Landlock LSM in the boot order so unprivileged processes can sandbox themselves with filesystem and network rules. `CONFIG_SECURITY_LANDLOCK` only compiles it in: without an entry in `CONFIG_LSM` the `landlock_create_ruleset` syscall family returns `EOPNOTSUPP` and every sandbox built on it silently degrades to no sandbox at all.")
    .with_fix("Recompile the kernel with `landlock` in the `CONFIG_LSM` list, or pass `lsm=` including it on the kernel command line. Alternatively some distributions have hardened kernels with different compilation options.")
    .register();

    check::Check::new(
        "KNC_237",
        "Ensure kernel build option `CONFIG_IOMMU_DEFAULT_DMA_STRICT` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_IOMMU_DEFAULT_DMA_STRICT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 15, 0)))
    .with_description("Make the IOMMU unmap DMA buffers immediately and flush the IOTLB on every unmap, so a device cannot read a buffer after the driver handed it back, which is what a compromised or malicious peripheral relies on. It is the default KSPP asks for and is mutually exclusive with `CONFIG_IOMMU_DEFAULT_DMA_LAZY` and `CONFIG_IOMMU_DEFAULT_PASSTHROUGH`. Costs measurable DMA throughput on I/O heavy workloads, and `iommu.passthrough=1` or `iommu.strict=0` on the kernel command line weakens it.")
    .with_fix(&fix_is_set("CONFIG_IOMMU_DEFAULT_DMA_STRICT"))
    .register();

    check::Check::new(
        "KNC_238",
        "Ensure kernel build option `CONFIG_IOMMU_DEFAULT_DMA_LAZY` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_IOMMU_DEFAULT_DMA_LAZY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 15, 0)))
    .with_description("Do not make the lazy IOMMU mode the default, which defers unmapping and IOTLB flushing until the IOVA space is exhausted, leaving freed DMA buffers mapped and readable by the device in the meantime. Mutually exclusive with `CONFIG_IOMMU_DEFAULT_DMA_STRICT`; chosen for DMA throughput on some distributions.")
    .with_fix(&fix_disabled("CONFIG_IOMMU_DEFAULT_DMA_LAZY"))
    .register();

    check::Check::new(
        "KNC_239",
        "Ensure kernel build option `CONFIG_IOMMU_DEFAULT_PASSTHROUGH` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_IOMMU_DEFAULT_PASSTHROUGH"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Do not make IOMMU passthrough the default, which disables DMA translation entirely for host drivers and gives every device access to all of memory, removing the protection `CONFIG_IOMMU_SUPPORT` exists for. Chosen by distributions for performance on trusted hardware, and mutually exclusive with `CONFIG_IOMMU_DEFAULT_DMA_STRICT`.")
    .with_fix(&fix_disabled("CONFIG_IOMMU_DEFAULT_PASSTHROUGH"))
    .register();

    check::Check::new(
        "KNC_240",
        "Ensure kernel build option `CONFIG_DEFAULT_MMAP_MIN_ADDR` is set to `65536`",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_value("CONFIG_DEFAULT_MMAP_MIN_ADDR", "65536"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32", "arm64", "riscv64", "riscv32"]))
    .with_description("Keep the minimum address a process may map at 64 KiB, so a NULL pointer dereference in the kernel cannot be turned into control flow by mapping page zero in userspace, which is what the classic NULL dereference exploits do. It is the build-time default of the `vm.mmap_min_addr` sysctl, which can still be lowered at runtime. 32-bit arm kernels legitimately use 32768, and a larger value breaks programs that expect to map very low addresses.")
    .with_fix(&fix_value("CONFIG_DEFAULT_MMAP_MIN_ADDR", "65536"))
    .register();

    check::Check::new(
        "KNC_241",
        "Ensure kernel build option `CONFIG_ARCH_MMAP_RND_BITS` is set to its maximum",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_value("CONFIG_ARCH_MMAP_RND_BITS", "CONFIG_ARCH_MMAP_RND_BITS_MAX"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Use the widest userspace address space randomization the architecture allows, which is what makes brute forcing the location of a stack or heap mapping impractical: the difference between the default and the maximum is several bits of entropy per mapping. `CONFIG_ARCH_MMAP_RND_BITS_MAX` in the same config gives the value to use, and the `vm.mmap_rnd_bits` sysctl can lower it at runtime. Costs nothing but a wider spread of mappings, which slightly worsens cache locality.")
    .with_fix(&fix_value("CONFIG_ARCH_MMAP_RND_BITS", "CONFIG_ARCH_MMAP_RND_BITS_MAX"))
    .register();

    check::Check::new(
        "KNC_242",
        "Ensure kernel build option `CONFIG_ARCH_MMAP_RND_COMPAT_BITS` is set to its maximum",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_value("CONFIG_ARCH_MMAP_RND_COMPAT_BITS", "CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("The architecture independent switch that decides whether the CPU vulnerability mitigations are compiled in at all. With it off no mitigation exists in the image and `mitigations=auto` on the kernel command line has nothing to enable, so the speculative execution and side channel classes of bugs are all reachable. Costs the performance of the individual mitigations, which is why some throughput oriented builds turn it off.")
    .with_fix(&fix_is_set("CONFIG_ARCH_MMAP_RND_COMPAT_BITS"))
    .register();

    check::Check::new(
        "KNC_243",
        "Ensure kernel build option `CONFIG_CPU_MITIGATIONS` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_CPU_MITIGATIONS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("The x86 switch for the speculative execution mitigations. With it off, Spectre, MDS, L1TF and the rest cannot be enabled at boot whatever the kernel command line says.")
    .with_fix(&fix_is_set("CONFIG_CPU_MITIGATIONS"))
    .register();

    check::Check::new(
        "KNC_244",
        "Ensure kernel build option `CONFIG_SPECULATION_MITIGATIONS` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_SPECULATION_MITIGATIONS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 19, 0)))
    .skip_when(|| kernel::skip_kernel_since((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("The x86 switch for the speculative execution mitigations, the older name of what `CONFIG_CPU_MITIGATIONS` covers on other architectures. With it off, Spectre, MDS, L1TF and the rest cannot be enabled at boot whatever the kernel command line says.")
    .with_fix(&fix_is_set("CONFIG_SPECULATION_MITIGATIONS"))
    .register();

    check::Check::new(
        "KNC_245",
        "Ensure kernel build option `CONFIG_MITIGATION_RETPOLINE` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_RETPOLINE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile the kernel with retpolines, replacing indirect branches with a return trampoline that cannot be steered by a poisoned branch predictor, which is the Spectre v2 (CVE-2017-5715) mitigation for the kernel's own indirect calls. Costs a few percent on indirect-call heavy paths; `spectre_v2=off` on the kernel command line disables it at runtime, and `CONFIG_MITIGATION_RETHUNK` replaces it on newer AMD and Intel parts.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_RETPOLINE"))
    .register();

    check::Check::new(
        "KNC_246",
        "Ensure kernel build option `CONFIG_RETPOLINE` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_RETPOLINE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("The name `CONFIG_MITIGATION_RETPOLINE` had before the v6.9 rename, so kernels up to 6.8 carry this symbol instead. Same mitigation: indirect branches become return trampolines that a poisoned branch predictor cannot steer, which is the Spectre v2 defence for kernel code.")
    .with_fix(&fix_is_set("CONFIG_RETPOLINE"))
    .register();

    check::Check::new(
        "KNC_247",
        "Ensure kernel build option `CONFIG_MITIGATION_RETHUNK` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_RETHUNK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Redirect every kernel function return through a single thunk, which is what makes the AMD retbleed (CVE-2022-29900/29901) and the Intel BTC-RET return-instruction predictions safe, and what `CONFIG_ZERO_CALL_USED_REGS` complements. Costs a little on the return path.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_RETHUNK"))
    .register();

    check::Check::new(
        "KNC_248",
        "Ensure kernel build option `CONFIG_MITIGATION_IBPB_ENTRY` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_IBPB_ENTRY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Flush the branch predictor on kernel entry, so predictions trained by one context cannot steer speculation in another, which is the mitigation for retbleed and for cross-context Spectre v2 on the parts that need it. Costs an indirect branch prediction miss on every entry, which is the most expensive of the entry mitigations.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_IBPB_ENTRY"))
    .register();

    check::Check::new(
        "KNC_249",
        "Ensure kernel build option `CONFIG_MITIGATION_IBRS_ENTRY` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_IBRS_ENTRY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Enable Indirect Branch Restricted Speculation on kernel entry, the Intel side of the retbleed and Spectre v2 entry mitigations, which stops userspace-trained predictions from being used while the kernel runs. Costs several percent of syscall and interrupt throughput on the affected parts.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_IBRS_ENTRY"))
    .register();

    check::Check::new(
        "KNC_250",
        "Ensure kernel build option `CONFIG_MITIGATION_UNRET_ENTRY` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_UNRET_ENTRY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Deny the CPU the use of stale return predictions on kernel entry (AMD UNRET), which is the cheaper retbleed mitigation on the parts supporting it, and what `retbleed=unret` selects. Costs less than IBPB where it applies.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_UNRET_ENTRY"))
    .register();

    check::Check::new(
        "KNC_251",
        "Ensure kernel build option `CONFIG_MITIGATION_RETBLEED` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_RETBLEED"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 12, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the retbleed mitigation (CVE-2022-29900 on AMD, CVE-2022-29901 on Intel), which protects kernel returns against a return prediction trained by a lower privilege level. The technique is chosen at boot by `retbleed=` among unret, IBPB and call depth tracking, and `CONFIG_MITIGATION_RETHUNK`, `CONFIG_MITIGATION_UNRET_ENTRY` and `CONFIG_MITIGATION_CALL_DEPTH_TRACKING` decide which ones exist. Costs a few percent on the return path on the affected parts.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_RETBLEED"))
    .register();

    check::Check::new(
        "KNC_252",
        "Ensure kernel build option `CONFIG_MITIGATION_CALL_DEPTH_TRACKING` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_CALL_DEPTH_TRACKING"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Track the call depth in software and emit a stuffing sequence before the CPU's return stack buffer underflows, which is the Intel Skylake-era retbleed/SRSO-class mitigation for the RSB underflow case. Costs a few percent on call heavy code; only offered on the affected Intel parts.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_CALL_DEPTH_TRACKING"))
    .register();

    check::Check::new(
        "KNC_253",
        "Ensure kernel build option `CONFIG_MITIGATION_SPECTRE_V1` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_SPECTRE_V1"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 12, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the bounds-check masking and `nospec` helpers that stop an out-of-bounds index from being used speculatively, the Spectre v1 (CVE-2017-5753) mitigation. Cheap, and without it the syscall and ioctl entry paths leak whatever an attacker trains them to read.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_SPECTRE_V1"))
    .register();

    check::Check::new(
        "KNC_254",
        "Ensure kernel build option `CONFIG_MITIGATION_SPECTRE_V2` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_SPECTRE_V2"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 12, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the Spectre v2 (CVE-2017-5715) mitigations, the retpoline or eIBRS based protection of indirect branches against a poisoned predictor. `spectre_v2=off` on the kernel command line disables it at runtime, and the individual `CONFIG_MITIGATION_RETPOLINE`, `CONFIG_MITIGATION_IBRS_ENTRY` and `CONFIG_MITIGATION_RETHUNK` decide which technique is available.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_SPECTRE_V2"))
    .register();

    check::Check::new(
        "KNC_255",
        "Ensure kernel build option `CONFIG_MITIGATION_SPECTRE_BHI` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_SPECTRE_BHI"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the Branch History Injection mitigation (CVE-2022-0001/0002), which stops an attacker from steering kernel indirect branches through the branch history buffer even when eIBRS is active. `spectre_bhi=off` disables it at runtime; costs a few percent on the entry path.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_SPECTRE_BHI"))
    .register();

    check::Check::new(
        "KNC_256",
        "Ensure kernel build option `CONFIG_MITIGATE_SPECTRE_BRANCH_HISTORY` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATE_SPECTRE_BRANCH_HISTORY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 17, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("The arm64 branch history buffer mitigation for Spectre-BHB, which clears or limits the branch history on exception entry so a userspace-trained history cannot steer kernel indirect branches. Costs a loop of branch instructions on each entry from a lower exception level.")
    .with_fix(&fix_is_set("CONFIG_MITIGATE_SPECTRE_BRANCH_HISTORY"))
    .register();

    check::Check::new(
        "KNC_257",
        "Ensure kernel build option `CONFIG_MITIGATION_SSB` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_SSB"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 12, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the Speculative Store Bypass mitigation (CVE-2018-3639, Spectre v4), which uses the SSBD control to stop a speculative load from bypassing a recent store and reading stale data. `spec_store_bypass_disable=off` disables it at runtime; costs a little on store-to-load forwarding.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_SSB"))
    .register();

    check::Check::new(
        "KNC_258",
        "Ensure kernel build option `CONFIG_MITIGATION_SRBDS` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_SRBDS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 12, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the Special Register Buffer Data Sampling mitigation (CVE-2020-0543), which serializes `RDRAND`/`RDSEED`/`EGETKEY` so a core cannot sample the random number generator results of another. Costs a lot on random-number heavy workloads, which is why `srbds=off` exists.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_SRBDS"))
    .register();

    check::Check::new(
        "KNC_259",
        "Ensure kernel build option `CONFIG_MITIGATION_L1TF` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_L1TF"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 12, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the L1 Terminal Fault mitigation (CVE-2018-3615/3620/3646), which inverts the page frame numbers in unused page table entries so an L1 fault cannot read a page the entry does not really point at. Needed on Intel parts before Cascade Lake; costs a little address translation work and, with SMT and untrusted guests, may need `l1tf=full,force` plus SMT off.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_L1TF"))
    .register();

    check::Check::new(
        "KNC_260",
        "Ensure kernel build option `CONFIG_MITIGATION_MDS` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_MDS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 12, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the Microarchitectural Data Sampling mitigation (CVE-2018-12126/12127/12130, Fallout, RIDL, ZombieLoad), which flushes the affected CPU buffers on kernel entry and before returning to userspace. Costs a few percent and, with SMT and untrusted code, may need SMT disabled to be complete.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_MDS"))
    .register();

    check::Check::new(
        "KNC_261",
        "Ensure kernel build option `CONFIG_MITIGATION_TAA` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_TAA"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 12, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the TSX Asynchronous Abort mitigation (CVE-2019-11135), the MDS-class leak reachable through a transactional abort, which flushes the same buffers as MDS. Also worth pairing with `CONFIG_X86_INTEL_TSX_MODE_OFF` to disable TSX entirely.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_TAA"))
    .register();

    check::Check::new(
        "KNC_262",
        "Ensure kernel build option `CONFIG_MITIGATION_MMIO_STALE_DATA` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_MMIO_STALE_DATA"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 12, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the MMIO Stale Data mitigation (CVE-2022-21123/21125/21127/21166), which flushes the fill buffers before MMIO accesses leak stale data across virtualization boundaries. Mainly matters for hosts running untrusted guests.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_MMIO_STALE_DATA"))
    .register();

    check::Check::new(
        "KNC_263",
        "Ensure kernel build option `CONFIG_MITIGATION_GDS` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_GDS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 12, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the Gather Data Sampling mitigation (CVE-2022-40982, Downfall), which serializes or microcode-patches the AVX gather instructions whose results could leak data from other contexts. Costs a lot on gather-heavy workloads, which is what `gather_data_sampling=force` accepts and `gather_data_sampling=off` refuses.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_GDS"))
    .register();

    check::Check::new(
        "KNC_264",
        "Ensure kernel build option `CONFIG_MITIGATION_RFDS` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_RFDS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the Register File Data Sampling mitigation (CVE-2023-28746), which clears the register file state that an Atom-class core could otherwise leak across privilege boundaries. Only offered on the affected Intel Atom parts.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_RFDS"))
    .register();

    check::Check::new(
        "KNC_265",
        "Ensure kernel build option `CONFIG_MITIGATION_ITS` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_ITS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 15, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Compile in the Indirect Target Selection mitigation (CVE-2024-26598 and the AMD variant), which stops a poisoned predictor from steering the target of an indirect branch in the kernel even with retpolines in place. Costs a little on the affected parts.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_ITS"))
    .register();

    check::Check::new(
        "KNC_266",
        "Ensure kernel build option `CONFIG_MITIGATION_TSA` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_TSA"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 16, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the Transient Scheduler Attacks mitigation (CVE-2024-26950 and related), which flushes the affected CPU buffers on transitions so a transient execution window cannot read data from another context. `tsa=off` disables it at runtime; costs a few percent on the entry path.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_TSA"))
    .register();

    check::Check::new(
        "KNC_267",
        "Ensure kernel build option `CONFIG_MITIGATION_VMSCAPE` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_VMSCAPE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 17, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the VMSCAPE mitigation, which protects the hypervisor and guest boundary against leaking guest state through the predicted control flow of the VMM entry paths. `vmscape=off` disables it at runtime; only offered where the hardware is affected.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_VMSCAPE"))
    .register();

    check::Check::new(
        "KNC_268",
        "Ensure kernel build option `CONFIG_MITIGATION_SRSO` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_SRSO"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Compile in the Speculative Return Stack Overflow mitigation (CVE-2023-20569) for AMD Zen parts, which stops return instructions from speculating onto a stale return stack entry trained by another privilege level. The `retbleed=` and `spec_rstackoverflow=` boot parameters choose between the available techniques; costs a few percent on the return path.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_SRSO"))
    .register();

    check::Check::new(
        "KNC_269",
        "Ensure kernel build option `CONFIG_CPU_SRSO` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_CPU_SRSO"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 5, 0)))
    .skip_when(|| kernel::skip_kernel_since((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("The name `CONFIG_MITIGATION_SRSO` had before the v6.9 rename, so kernels up to 6.8 carry this symbol instead. Same AMD Speculative Return Stack Overflow mitigation (CVE-2023-20569).")
    .with_fix(&fix_is_set("CONFIG_CPU_SRSO"))
    .register();

    check::Check::new(
        "KNC_270",
        "Ensure kernel build option `CONFIG_MITIGATION_PAGE_TABLE_ISOLATION` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MITIGATION_PAGE_TABLE_ISOLATION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in Kernel Page Table Isolation (Meltdown, CVE-2017-5754), which unmaps kernel memory while userspace runs so a speculative read of a kernel address faults instead of leaking data through a cache side channel. `nopti` or `pti=off` on the kernel command line disables it at runtime; costs a few percent on syscall and interrupt heavy workloads.")
    .with_fix(&fix_is_set("CONFIG_MITIGATION_PAGE_TABLE_ISOLATION"))
    .register();

    check::Check::new(
        "KNC_271",
        "Ensure kernel build option `CONFIG_PAGE_TABLE_ISOLATION` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_PAGE_TABLE_ISOLATION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("The name `CONFIG_MITIGATION_PAGE_TABLE_ISOLATION` had before the v6.9 rename, so kernels up to 6.8 carry this symbol instead. Same Meltdown mitigation: kernel memory is unmapped while userspace runs.")
    .with_fix(&fix_is_set("CONFIG_PAGE_TABLE_ISOLATION"))
    .register();

    check::Check::new(
        "KNC_272",
        "Ensure kernel build option `CONFIG_X86_SMAP` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_X86_SMAP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((5, 19, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Use Supervisor Mode Access Prevention, which makes the CPU fault when kernel code dereferences a userspace address unless the access is explicitly allowed, so a missing `access_ok()` or a confused deputy in a syscall handler cannot read or write user memory by accident. Enabled by default since v5.19; `nosmap` on the kernel command line disables it at runtime. Costs a flag flip on each user access.")
    .with_fix(&fix_is_set("CONFIG_X86_SMAP"))
    .register();

    check::Check::new(
        "KNC_273",
        "Ensure kernel build option `CONFIG_X86_UMIP` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_X86_UMIP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 5, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Use User Mode Instruction Prevention, which faults when userspace executes `SGDT`, `SIDT`, `SLDT`, `SMSW` and `STR`, the instructions that leak the addresses of the GDT, IDT and other kernel structures and defeat KASLR. Emulated in software on parts without it, which is what `CONFIG_X86_INTEL_UMIP` was named before the rename.")
    .with_fix(&fix_is_set("CONFIG_X86_UMIP"))
    .register();

    check::Check::new(
        "KNC_274",
        "Ensure kernel build option `CONFIG_X86_INTEL_UMIP` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_X86_INTEL_UMIP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((5, 5, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("The earlier name of `CONFIG_X86_UMIP`, so older kernels carry this symbol instead. Same protection: userspace execution of `SGDT`, `SIDT`, `SLDT`, `SMSW` and `STR` faults instead of leaking kernel structure addresses.")
    .with_fix(&fix_is_set("CONFIG_X86_INTEL_UMIP"))
    .register();

    check::Check::new(
        "KNC_275",
        "Ensure kernel build option `CONFIG_X86_KERNEL_IBT` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_X86_KERNEL_IBT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 18, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Enable Intel's Indirect Branch Tracking for the kernel, the backward-compatible half of CET, which makes every indirect jump and call land on an `ENDBR64` and turns a hijacked function pointer into a fault instead of arbitrary code execution. Requires CET-capable hardware and costs a little code size for the landing pads.")
    .with_fix(&fix_is_set("CONFIG_X86_KERNEL_IBT"))
    .register();

    check::Check::new(
        "KNC_276",
        "Ensure kernel build option `CONFIG_AMD_IOMMU` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_AMD_IOMMU"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64"]))
    .with_description("Compile in the AMD-Vi IOMMU driver, without which `amd_iommu=on` does nothing and no device DMA can be restricted to the memory granted to it. Needs AMD-Vi hardware and firmware enabling; costs DMA throughput in strict mode.")
    .with_fix(&fix_is_set("CONFIG_AMD_IOMMU"))
    .register();

    check::Check::new(
        "KNC_277",
        "Ensure kernel build option `CONFIG_INTEL_IOMMU` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_INTEL_IOMMU"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in the Intel VT-d IOMMU driver, without which `intel_iommu=on` does nothing and device DMA cannot be restricted. Needs VT-d hardware and firmware enabling; pair with `CONFIG_INTEL_IOMMU_DEFAULT_ON` so it is active without a boot parameter.")
    .with_fix(&fix_is_set("CONFIG_INTEL_IOMMU"))
    .register();

    check::Check::new(
        "KNC_278",
        "Ensure kernel build option `CONFIG_MICROCODE` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MICROCODE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Load CPU microcode updates at boot, which is how the hardware side of most speculative execution, MDS and errata mitigations is delivered: without it the kernel reports the vulnerabilities as unmitigable and `MITIGATION_*` options cannot do their job. The updates are built into the kernel image or loaded from the filesystem by the initramfs; `dis_ucode_ldr` on the kernel command line disables the loading.")
    .with_fix(&fix_is_set("CONFIG_MICROCODE"))
    .register();

    check::Check::new(
        "KNC_279",
        "Ensure kernel build option `CONFIG_MICROCODE_INTEL` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MICROCODE_INTEL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 6, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Load Intel CPU microcode updates at boot, the part of `CONFIG_MICROCODE` covering Intel parts. Merged into `CONFIG_MICROCODE` in v6.6, so newer kernels do not have the separate symbol and the check is skipped there.")
    .with_fix(&fix_is_set("CONFIG_MICROCODE_INTEL"))
    .register();

    check::Check::new(
        "KNC_280",
        "Ensure kernel build option `CONFIG_MICROCODE_AMD` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_MICROCODE_AMD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((6, 6, 0)))
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Load AMD CPU microcode updates at boot, the part of `CONFIG_MICROCODE` covering AMD parts and the delivery mechanism for the Zen errata and SRSO mitigations. Merged into `CONFIG_MICROCODE` in v6.6, so newer kernels do not have the separate symbol and the check is skipped there.")
    .with_fix(&fix_is_set("CONFIG_MICROCODE_AMD"))
    .register();

    check::Check::new(
        "KNC_281",
        "Ensure kernel build option `CONFIG_X86_MCE` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_X86_MCE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Compile in Machine Check Exception handling, which is how the CPU reports corrected and uncorrected hardware errors, including the memory corruption that would otherwise be consumed silently by the kernel or by userspace. Without it a hardware fault becomes data corruption; with it the machine can kill the affected process, offline the page or panic deliberately.")
    .with_fix(&fix_is_set("CONFIG_X86_MCE"))
    .register();

    check::Check::new(
        "KNC_282",
        "Ensure kernel build option `CONFIG_X86_MCE_INTEL` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_X86_MCE_INTEL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("The Intel part of Machine Check Exception handling, covering CMCI thresholding, the Intel-specific machine check banks and memory failure recovery on Intel parts. Needs `CONFIG_X86_MCE`.")
    .with_fix(&fix_is_set("CONFIG_X86_MCE_INTEL"))
    .register();

    check::Check::new(
        "KNC_283",
        "Ensure kernel build option `CONFIG_X86_MCE_AMD` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_X86_MCE_AMD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("The AMD part of Machine Check Exception handling, covering the AMD thresholding banks and the SMCA error decoding needed to report which unit failed. Needs `CONFIG_X86_MCE`.")
    .with_fix(&fix_is_set("CONFIG_X86_MCE_AMD"))
    .register();

    check::Check::new(
        "KNC_284",
        "Ensure kernel build option `CONFIG_ARM64_BTI` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM64_BTI"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 8, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Enable the armv8.5 Branch Target Identification hardware support for userspace, which marks valid indirect branch targets so a hijacked pointer cannot jump into the middle of a function (jump-oriented programming). Needs BTI-capable hardware and binaries built with landing pads; `arm64.nobti` on the kernel command line disables it.")
    .with_fix(&fix_is_set("CONFIG_ARM64_BTI"))
    .register();

    check::Check::new(
        "KNC_285",
        "Ensure kernel build option `CONFIG_ARM64_BTI_KERNEL` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM64_BTI_KERNEL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 8, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Apply Branch Target Identification to the kernel itself, not just userspace, so an indirect call inside the kernel that does not land on a `BTI` instruction faults. Requires `CONFIG_ARM64_BTI` and BTI-capable hardware, and costs a little code size for the landing pads.")
    .with_fix(&fix_is_set("CONFIG_ARM64_BTI_KERNEL"))
    .register();

    check::Check::new(
        "KNC_286",
        "Ensure kernel build option `CONFIG_ARM64_PAN` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM64_PAN"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((7, 0, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Use Privileged Access Never, which makes the CPU fault when kernel code touches a userspace address outside an explicit `uaccess` window, so a missing bounds check cannot read or write user memory by accident. Hardware PAN on armv8.1 and later; `CONFIG_ARM64_SW_TTBR0_PAN` is the software fallback for older parts.")
    .with_fix(&fix_is_set("CONFIG_ARM64_PAN"))
    .register();

    check::Check::new(
        "KNC_287",
        "Ensure kernel build option `CONFIG_ARM64_EPAN` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM64_EPAN"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 13, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Use the Enhanced PAN of armv8.7, which extends Privileged Access Never to execution as well as data access, so the kernel cannot be made to execute userspace code even through an explicit access window. Needs EPAN-capable hardware.")
    .with_fix(&fix_is_set("CONFIG_ARM64_EPAN"))
    .register();

    check::Check::new(
        "KNC_288",
        "Ensure kernel build option `CONFIG_ARM64_E0PD` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM64_E0PD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 6, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Enable Enhanced Unprivileged Access Disable, which makes userspace accesses to the kernel half of the address space fault deterministically instead of depending on the translation table state, closing a Meltdown-class timing channel on arm64 and giving userspace a constant fault cost. The arm64 counterpart of `CONFIG_MITIGATION_PAGE_TABLE_ISOLATION`.")
    .with_fix(&fix_is_set("CONFIG_ARM64_E0PD"))
    .register();

    check::Check::new(
        "KNC_289",
        "Ensure kernel build option `CONFIG_ARM64_PTR_AUTH` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM64_PTR_AUTH"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 0, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Enable the armv8.3 pointer authentication hardware support for userspace, which signs return addresses and other pointers with a keyed MAC so a hijacked pointer is detected instead of followed. Needs hardware support and userspace built for it; `arm64.nopauth` on the kernel command line disables it.")
    .with_fix(&fix_is_set("CONFIG_ARM64_PTR_AUTH"))
    .register();

    check::Check::new(
        "KNC_290",
        "Ensure kernel build option `CONFIG_ARM64_PTR_AUTH_KERNEL` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM64_PTR_AUTH_KERNEL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 14, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Sign the kernel's own return addresses and pointers with pointer authentication, so a stack overflow or a corrupted function pointer inside the kernel is detected rather than exploited. Requires `CONFIG_ARM64_PTR_AUTH`, hardware support, and costs a little on function entry and exit. The kernel counterpart of `CONFIG_SHADOW_CALL_STACK`.")
    .with_fix(&fix_is_set("CONFIG_ARM64_PTR_AUTH_KERNEL"))
    .register();

    check::Check::new(
        "KNC_291",
        "Ensure kernel build option `CONFIG_ARM64_MTE` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM64_MTE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 10, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Enable the armv8.5 Memory Tagging Extension, which tags every allocation and pointer so a use-after-free or an out-of-bounds access is caught by the hardware, in the kernel (`CONFIG_KASAN_HW_TAGS`) and in userspace processes that opt in. Needs MTE-capable hardware and costs memory for the tags plus some throughput; `arm64.nomte` disables it.")
    .with_fix(&fix_is_set("CONFIG_ARM64_MTE"))
    .register();

    check::Check::new(
        "KNC_292",
        "Ensure kernel build option `CONFIG_ARM64_GCS` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM64_GCS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 13, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Enable the armv9 Guarded Control Stack, a hardware-protected copy of the return addresses for each thread, so a stack overflow cannot redirect control flow. The arm64 counterpart of `CONFIG_X86_USER_SHADOW_STACK`; needs GCS-capable hardware and libc support, and `arm64.nogcs` disables it.")
    .with_fix(&fix_is_set("CONFIG_ARM64_GCS"))
    .register();

    check::Check::new(
        "KNC_293",
        "Ensure kernel build option `CONFIG_ARM_PAN` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM_PAN"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 10, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm32"]))
    .with_description("The 32-bit arm Privileged Access Never support, which faults when kernel code touches a userspace address outside an explicit access window. On parts without the hardware, `CONFIG_CPU_SW_DOMAIN_PAN` provides the software equivalent.")
    .with_fix(&fix_is_set("CONFIG_ARM_PAN"))
    .register();

    check::Check::new(
        "KNC_294",
        "Ensure kernel build option `CONFIG_CPU_SW_DOMAIN_PAN` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_CPU_SW_DOMAIN_PAN"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["arm32"]))
    .with_description("Emulate Privileged Access Never in software on 32-bit arm by switching the domain permissions around user accesses, so a stray kernel dereference of a userspace address faults. Costs a domain register write per user access; the hardware version is `CONFIG_ARM_PAN`.")
    .with_fix(&fix_is_set("CONFIG_CPU_SW_DOMAIN_PAN"))
    .register();

    check::Check::new(
        "KNC_295",
        "Ensure kernel build option `CONFIG_UNMAP_KERNEL_AT_EL0` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_UNMAP_KERNEL_AT_EL0"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("The arm64 Kernel Page Table Isolation, which unmaps kernel memory while userspace runs so a speculative read cannot leak it through a cache side channel (Meltdown on the Cortex-A parts that are affected). Costs a translation table switch on each exception entry and exit.")
    .with_fix(&fix_is_set("CONFIG_UNMAP_KERNEL_AT_EL0"))
    .register();

    check::Check::new(
        "KNC_296",
        "Ensure kernel build option `CONFIG_HARDEN_BRANCH_PREDICTOR` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_HARDEN_BRANCH_PREDICTOR"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["arm64", "arm32"]))
    .with_description("Invalidate or limit the branch predictor on exceptions taken from userspace, which is the arm Spectre v2 mitigation stopping a userspace-trained predictor from steering kernel indirect branches. Enabled by default since v5.10; costs a little on the entry path.")
    .with_fix(&fix_is_set("CONFIG_HARDEN_BRANCH_PREDICTOR"))
    .register();

    check::Check::new(
        "KNC_297",
        "Ensure kernel build option `CONFIG_HARDEN_BRANCH_HISTORY` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_HARDEN_BRANCH_HISTORY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 17, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm32", "arm64"]))
    .with_description("Clear or limit the branch history on exceptions from userspace, the arm mitigation for Spectre-BHB, which reaches kernel indirect branches through the history buffer even when the predictor itself is hardened. Costs a sequence of instructions on each entry.")
    .with_fix(&fix_is_set("CONFIG_HARDEN_BRANCH_HISTORY"))
    .register();

    check::Check::new(
        "KNC_298",
        "Ensure kernel build option `CONFIG_HARDEN_EL2_VECTORS` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_HARDEN_EL2_VECTORS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_since((5, 9, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Use separate hardened exception vectors at EL2 so a guest cannot exploit the shared vectors to reach the hypervisor, which matters on parts where the EL2 vectors are otherwise mapped into the guest's view. Merged into `CONFIG_RANDOMIZE_BASE` handling in v5.9, so newer kernels do not expose the symbol.")
    .with_fix(&fix_is_set("CONFIG_HARDEN_EL2_VECTORS"))
    .register();

    check::Check::new(
        "KNC_299",
        "Ensure kernel build option `CONFIG_RANDOMIZE_MODULE_REGION_FULL` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_RANDOMIZE_MODULE_REGION_FULL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Randomize the placement of the whole module region instead of keeping modules within a fixed range of the kernel image, so a leaked module address does not give the position of the kernel and module branches have to go through veneers that are harder to steer. Costs a little module load time and indirect branch overhead.")
    .with_fix(&fix_is_set("CONFIG_RANDOMIZE_MODULE_REGION_FULL"))
    .register();

    check::Check::new(
        "KNC_300",
        "Ensure kernel build option `CONFIG_RODATA_FULL_DEFAULT_ENABLED` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_RODATA_FULL_DEFAULT_ENABLED"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 0, 0)))
    .skip_when(|| kernel::skip_kernel_since((6, 18, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Map the kernel read-only data at full granularity by default instead of the larger block mappings, so the text and rodata boundaries are exact and a write gadget cannot cover a neighbouring page. `rodata=off` on the kernel command line can still relax it, which is what `CONFIG_RODATA_FULL_DEFAULT_ENABLED` prevents by default. Costs more page table entries.")
    .with_fix(&fix_is_set("CONFIG_RODATA_FULL_DEFAULT_ENABLED"))
    .register();

    check::Check::new(
        "KNC_301",
        "Ensure kernel build option `CONFIG_ARM_SMMU` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM_SMMU"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["arm64", "arm32"]))
    .with_description("Compile in the ARM System MMU driver, without which no device DMA can be restricted to the memory granted to it on arm and arm64 boards. Needs SMMU hardware and firmware describing it; costs DMA throughput in strict mode.")
    .with_fix(&fix_is_set("CONFIG_ARM_SMMU"))
    .register();

    check::Check::new(
        "KNC_302",
        "Ensure kernel build option `CONFIG_ARM_SMMU_V3` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM_SMMU_V3"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["arm64"]))
    .with_description("Compile in the ARM SMMUv3 driver, the current generation of the System MMU found on arm64 server parts, without which those devices run with unrestricted DMA.")
    .with_fix(&fix_is_set("CONFIG_ARM_SMMU_V3"))
    .register();

    check::Check::new(
        "KNC_303",
        "Ensure kernel build option `CONFIG_ARM_SMMU_DISABLE_BYPASS_BY_DEFAULT` is set",
        Severity::High,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_ARM_SMMU_DISABLE_BYPASS_BY_DEFAULT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 2, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64", "arm32"]))
    .with_description("Refuse DMA from devices the SMMU has no stream mapping for, instead of letting them bypass translation entirely, which is the difference between an IOMMU that is present and one that actually constrains every device. Breaks devices whose firmware does not describe them to the SMMU, so they have to be mapped explicitly or the board support fixed.")
    .with_fix(&fix_is_set("CONFIG_ARM_SMMU_DISABLE_BYPASS_BY_DEFAULT"))
    .register();

    check::Check::new(
        "KNC_304",
        "Ensure kernel build option `CONFIG_DEBUG_ALIGN_RODATA` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_DEBUG_ALIGN_RODATA"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["arm32", "riscv64", "riscv32"]))
    .with_description("Align the kernel read-only data to a strict boundary so the mapping between writable and read-only sections cannot overlap a page, which is what lets `CONFIG_STRICT_KERNEL_RWX` be effective on riscv. Costs a little memory for the padding.")
    .with_fix(&fix_is_set("CONFIG_DEBUG_ALIGN_RODATA"))
    .register();

    check::Check::new(
        "KNC_305",
        "Ensure kernel build option `CONFIG_RISCV_ISA_XTHEADVECTOR` is not set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_not_set("CONFIG_RISCV_ISA_XTHEADVECTOR"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((6, 14, 0)))
    .skip_when(|| arch::skip_not_arch(&["riscv64", "riscv32"]))
    .with_description("Do not enable the T-Head vendor vector extension, which carries the GhostWrite vulnerability (a vector unit that ignores privilege checks and can read or write arbitrary physical memory from userspace). Either keep the extension off, or enable `CONFIG_ERRATA_THEAD_GHOSTWRITE` so the kernel works around it; a riscv kernel without the T-Head vector hardware does not have the option at all.")
    .with_fix(&fix_disabled("CONFIG_RISCV_ISA_XTHEADVECTOR"))
    .register();

    check::Check::new(
        "KNC_306",
        "Ensure kernel build option `CONFIG_STACKPROTECTOR_PER_TASK` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_STACKPROTECTOR_PER_TASK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 0, 0)))
    .skip_when(|| arch::skip_not_arch(&["arm64", "arm32", "riscv64", "riscv32"]))
    .with_description("Use a distinct stack canary per task instead of one per CPU, so leaking the canary of one task does not let an attacker overflow the stack of another. Requires the architecture's TLS register support; costs a canary reload per context switch.")
    .with_fix(&fix_is_set("CONFIG_STACKPROTECTOR_PER_TASK"))
    .register();

    check::Check::new(
        "KNC_307",
        "Ensure kernel build option `CONFIG_SLUB_DEBUG` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_SLUB_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Compile in the SLUB debugging and validation support, which is what makes `slub_debug=FZ` on the kernel command line and the `slabinfo` validation of freed objects possible, and what `CONFIG_SLAB_FREELIST_HARDENED` builds on. Costs nothing while unused, only when the debug flags are switched on at boot.")
    .with_fix(&fix_is_set("CONFIG_SLUB_DEBUG"))
    .register();

    check::Check::new(
        "KNC_308",
        "Ensure kernel build option `CONFIG_WERROR` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_WERROR"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| kernel::skip_kernel_before((5, 15, 0)))
    .with_description("Turn compiler warnings into errors for the kernel build, so a new warning cannot be merged and silently become an uninitialized variable or a truncated length later. A build-time property only: it has no runtime cost, and it is what distributions building their own kernels are expected to keep on.")
    .with_fix(&fix_is_set("CONFIG_WERROR"))
    .register();

    check::Check::new(
        "KNC_309",
        "Ensure kernel build option `CONFIG_SYN_COOKIES` is set",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_SYN_COOKIES"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Compile in SYN cookies, which let the kernel answer a SYN flood without keeping a half-open connection per request, encoding the state in the sequence number instead. Without it `net.ipv4.tcp_syncookies` does nothing and a SYN flood exhausts the backlog queue. Costs nothing until the queue is full.")
    .with_fix(&fix_is_set("CONFIG_SYN_COOKIES"))
    .register();

    check::Check::new(
        "KNC_310",
        "Ensure kernel build option `CONFIG_HW_RANDOM_TPM` is set",
        Severity::Low,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_is_set("CONFIG_HW_RANDOM_TPM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Use the TPM's hardware random number generator as an entropy source for the kernel pool, which adds a physically independent source on systems where the CPU's `RDRAND` is missing, disabled or not trusted. Needs a TPM; costs a little boot time.")
    .with_fix(&fix_is_set("CONFIG_HW_RANDOM_TPM"))
    .register();

    check::Check::new(
        "KNC_311",
        "Ensure kernel build option `CONFIG_DEFAULT_MMAP_MIN_ADDR` is set to `32768`",
        Severity::Medium,
        vec!["kernel", "kconfig", "conditional"],
        || kconfig::check_option_value("CONFIG_DEFAULT_MMAP_MIN_ADDR", "32768"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .skip_when(|| arch::skip_not_arch(&["arm32"]))
    .with_description("Keep the minimum address a process may map at 32 KiB, so a NULL pointer dereference in the kernel cannot be turned into control flow by mapping page zero in userspace. 32-bit arm cannot use the 64 KiB expected on the other architectures, and this is the value the kernel defaults to there through `CONFIG_LSM_MMAP_MIN_ADDR`. It is the build-time default of the `vm.mmap_min_addr` sysctl, which can still be lowered at runtime.")
    .with_fix(&fix_value("CONFIG_DEFAULT_MMAP_MIN_ADDR", "32768"))
    .register();
}
