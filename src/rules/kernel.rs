// - tails: https://tails.net/contribute/design/kernel_hardening/

use crate::check;
use crate::check::Severity;
use crate::modules::kernel;

pub fn add_checks() {
    check::Check::new(
        "KNP_001",
        "Ensure that kernel flag \"slab_nomerge\" is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "tails"],
        || kernel::check_kernel_params("slab_nomerge"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disable slab merging, increasing the difficulty of heap exploit implied by \"slub_debug=FZ\", but having \"slab_nomerge\" explicitly declared can help prevent regressions where disabling of debugging features is desired but re-enabling of merging is not. Increases memory consumption as slabs cannot be merged, and may reduce allocation performance.")
    .with_fix("Add \"slab_nomerge\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_002",
        "Ensure that kernel flag \"slab_debug=FZ\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("slab_debug=FZ"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enables front and end zone poisoning in slab allocator, helping detect memory corruption, buffer overflows, and use-after-free vulnerabilities by inserting canary values around memory allocations. Significant performance overhead due to extra memory usage and checks on every allocation/free.")
    .with_fix("Add \"slab_debug=FZ\" to bootloader kernel params.")
    .register();

    // NOTE: after 5.3 replaced by `init_on_free=1`
    // check::Check::new(
    //     "KNP_003",
    //     "Ensure that kernel flag \"page_poison=1\" is present",
    //     vec!["kernel", "KSPP", "server", "workstation"],
    //     || kernel::check_kernel_params("page_poison=1"),
    //     vec![kernel::init_kernel_params],
    // )
    // .register();

    check::Check::new(
        "KNP_004",
        "Ensure that kernel flag \"page_alloc.shuffle=1\" is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "tails"],
        || kernel::check_kernel_params("page_alloc.shuffle=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable the kernel page allocator to randomize free lists during early boot. Limits some data exfiltration and ROP attacks that rely on inferring sensitive data location, also improves performance by optimizing memory-side cache utilization. Needs CONFIG_SHUFFLE_PAGE_ALLOCATOR=y kernel build config too.")
    .with_fix("Add \"page_alloc.shuffle=1\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_005",
        "Ensure that kernel flag \"init_on_alloc=1\" is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("init_on_alloc=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Zero memory at allocation time. Mitigates use-after-free exploits by erasing sensitive information in memory. Performance overhead from zeroing every allocation; impact varies by workload.")
    .with_fix("Add \"init_on_alloc=1\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_006",
        "Ensure that kernel flag \"init_on_free=1\" is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "tails"],
        || kernel::check_kernel_params("init_on_free=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Zero memory at free time. Mitigates use-after-free exploits by erasing sensitive information in memory. Performance overhead from zeroing every freed page; impact varies by workload.")
    .with_fix("Add \"init_on_free=1\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_007",
        "Ensure that kernel flag \"pti=on\" is present",
        Severity::High,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("pti=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable kernel page table isolation to harden against kernel ASLR (KASLR) bypasses, mitigates the Meltdown (CVE-2017-5754) CPU vulnerability. Performance overhead from additional TLB flushes on every kernel/userspace transition; impact varies by CPU and workload (up to 30% on some server workloads).")
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#kernel-address-space-layout-randomization-kaslr")
    .with_fix("Add \"pti=on\" to bootloader kernel params.")
    .register();

    // TODO: since v5.13
    check::Check::new(
        "KNP_008",
        "Ensure that kernel flag \"randomize_kstack_offset=on\" is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "tails"],
        || kernel::check_kernel_params("randomize_kstack_offset=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable randomization of the kernel stack offset on syscall entries. Hardens against memory corruption attacks due to increased entropy limits attacks relying on deterministic stack addresses or cross-syscall address exposure. Minor performance overhead from extra randomization on every syscall.")
    .with_fix("Add \"randomize_kstack_offset=on\" to bootloader kernel params.")
    .register();

    // TODO: only for x86_64
    check::Check::new(
        "KNP_009",
        "Ensure that kernel flag \"vsyscall=none\" is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "tails"],
        || kernel::check_kernel_params("vsyscall=none"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disable vsyscalls to reduce attack surface as they have been replaced by vDSO vulnerable to ROP attacks as vsyscalls are located at fixed addresses in memory. Specific to x86_64 arch. Breaks very old binaries (pre-glibc 2.22) and some legacy applications that rely on vsyscalls.")
    .with_fix("Add \"vsyscall=none\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_010",
        "Ensure that kernel flag \"debugfs=off\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("debugfs=off"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Restrict access to debugfs that can contain sensitive information. Breaks tools that rely on debugfs (e.g. some GPU drivers, perf tools, power management utilities, debugging tools).")
    .with_fix("Add \"debugfs=off\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_011",
        "Ensure that kernel flag \"oops=panic\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("oops=panic"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Force the kernel to panic on \"oopses\", can sometimes potentially indicate and thwart certain kernel exploitation attempts, also cause panics on machine check exceptions. Some bad drivers can cause harmless oopses which result in system crash.")
    .with_fix("Add \"oops=panic\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_012",
        "Ensure that kernel flag \"module.sig_enforce=1\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("module.sig_enforce=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Require every kernel module to be signed before being loaded. Any module that is unsigned or signed with an invalid key cannot be loaded. Prevents all out-of-tree kernel modules (including DKMS) unless signed, this makes it harder to load a malicious module.")
    .with_fix("Add \"module.sig_enforce=1\" to bootloader kernel params.")
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#restricting-access-to-kernel-modules")
    .with_link("https://docs.kernel.org/admin-guide/module-signing.html")
    .register();

    check::Check::new(
        "KNP_013",
        "Ensure that kernel flag \"lockdown=integrity\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        // TODO: allow for either "integrity" or "confidentiality" flags, from
        // arch wiki: It is recommended to use integrity, unless your specific
        // threat model dictates otherwise.
        || kernel::check_kernel_params("lockdown=integrity"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable kernel lockdown to enforce security boundary between user and kernel space, enforces module signature verification kernel lockdown LSM can eliminate many methods that user space code could abuse for privilege escalation. Some applications may cease to work which rely on low-level access to either hardware or the kernel.")
    .with_fix("Add \"lockdown=integrity\" to bootloader kernel params.")
    .with_link("https://man.archlinux.org/man/kernel_lockdown.7")
    .register();

    check::Check::new(
        "KNP_014",
        "Ensure that kernel flag \"mce=0\" is present",
        Severity::Low,
        vec!["kernel", "server", "workstation", "tails"],
        || kernel::check_kernel_params("mce=0"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keeps the kernel from logging machine check exception (MCE) events that an attacker could correlate with covert side-channel work. Unnecessary for systems without ECC memory.")
    .with_fix("Add \"mce=0\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_015",
        "Ensure that kernel flag \"kfence.sample_interval=100\" is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("kfence.sample_interval=100"),
        vec![kernel::init_kernel_params],
    )
    .with_description("KFENCE detects heap out-of-bounds access, use-after-free, and invalid-free errors. Sampling interval is set to occur every 100 ms as per KSPP recommendation. Small performance and memory overhead from maintaining guard pages for sampled allocations.")
    .with_fix("Add \"kfence.sample_interval=100\" to bootloader kernel params.")
    .with_link("https://docs.kernel.org/dev-tools/kfence.html")
    .register();

    // TODO: only for x86_64
    check::Check::new(
        "KNP_017",
        "Ensure that kernel flag \"vdso32=0\" is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("vdso32=0"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disables the 32-bit vDSO, removing a small fixed-address ROP-friendly mapping from 64-bit processes that don't need it. Reduces predictable kernel-exposed addresses available to exploits. Breaks 32-bit applications that rely on vDSO for fast time-related syscalls (e.g. gettimeofday).")
    .with_fix("Add \"vdso32=0\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_018",
        "Ensure that kernel flag \"amd_iommu=force_isolation\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("amd_iommu=force_isolation"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Forces AMD IOMMU into per-device isolation domains, blocking DMA attacks from peripherals (Thunderbolt, PCIe, FireWire) that would otherwise let a malicious or compromised device read/write arbitrary host memory.")
    .with_fix("Add \"amd_iommu=force_isolation\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_019",
        "Ensure that kernel flag \"intel_iommu=on\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("intel_iommu=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enables Intel VT-d/IOMMU , blocking DMA attacks from peripherals (Thunderbolt, PCIe, FireWire) that would otherwise let a malicious or compromised device read/write arbitrary host memory.")
    .with_fix("Add \"intel_iommu=on\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_020",
        "Ensure that kernel flag \"iommu=force\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("iommu=force"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Force-enable IOMMU , blocking DMA attacks from peripherals (Thunderbolt, PCIe, FireWire) that would otherwise let a malicious or compromised device read/write arbitrary host memory.")
    .with_fix("Add \"iommu=force\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_021",
        "Ensure that kernel flag \"iommu.passthrough=0\" is present",
        Severity::High,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("iommu.passthrough=0"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disable IOMMU passthrough so every DMA request goes through the IOMMU translation tables. Prevents devices from performing direct physical-memory reads and writes. Can reduce I/O performance, but the impact is small on modern hardware.")
    .with_fix("Add \"iommu.passthrough=0\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_022",
        "Ensure that kernel flag \"iommu.strict=1\" is present",
        Severity::High,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("iommu.strict=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Strict IOMMU mode flushes IOTLB entries immediately when DMA mappings are torn down, closing the window where a device could still access stale mappings after the driver believes it has revoked access. Performance overhead from frequent IOTLB flushes; impact varies by I/O workload.")
    .with_fix("Add \"iommu.strict=1\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_023",
        "Ensure that kernel flag \"efi=disable_early_pci_dma\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("efi=disable_early_pci_dma"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Block PCI DMA during early EFI boot before the IOMMU is initialized. Without this, a malicious or compromised peripheral can perform DMA attacks during the boot window before IOMMU protection is active.")
    .with_fix("Add \"efi=disable_early_pci_dma\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_024",
        "Ensure that kernel flag \"random.trust_bootloader=off\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("random.trust_bootloader=off"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not trust entropy provided by the bootloader. A compromised or malicious bootloader could supply predictable seed values, weakening the kernel RNG from the start. May increase boot time.")
    .with_fix("Add \"random.trust_bootloader=off\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_025",
        "Ensure that kernel flag \"random.trust_cpu=off\" is present",
        Severity::Medium,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("random.trust_cpu=off"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not trust CPU-provided entropy (e.g. RDRAND). A backdoored or flawed hardware RNG could produce predictable output, weakening all cryptographic operations that depend on the kernel RNG. May increase boot time.")
    .with_fix("Add \"random.trust_cpu=off\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_026",
        "Ensure that kernel flag \"extra_latent_entropy\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("extra_latent_entropy"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Gather additional entropy from compiler-instrumented latent variables during early boot, seeding the kernel RNG with hard-to-predict state transitions. Strengthens cryptographic randomness on systems with limited hardware entropy sources. May increase boot time.")
    .with_fix("Add \"extra_latent_entropy\" to bootloader kernel params.")
    .register();

    // check::Check::new(
    //     "KNP_028",
    //     "Ensure that kernel flag \"ipv6.disable=1\" is present",
    //     vec!["kernel", "server", "workstation"],
    //     || kernel::check_kernel_params("ipv6.disable=1"),
    //     vec![kernel::init_kernel_params],
    // ).register();

    check::Check::new(
        "KNP_029",
        "Ensure that kernel flag \"ia32_emulation=0\" is present",
        Severity::Medium,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("ia32_emulation=0"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disable 32-bit IA-32 emulation, removing hundreds of legacy 32-bit syscalls from the attack surface. 64-bit systems do not need it unless running legacy 32-bit binaries. Also simplifies security monitoring and application policy. All 32-bit binaries (e.g. Wine, Steam, legacy software) will no longer run.")
    .with_fix("Add \"ia32_emulation=0\" to bootloader kernel params.")
    .register();

    // TODO: only for x86_64
    check::Check::new(
        "KNP_016",
        "Ensure that kernel flag \"cfi=kcfi\" is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("cfi=kcfi"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disable FineIBT since it is weaker than pure KCFI.")
    .with_fix("Add \"cfi=kcfi\" to bootloader kernel params.")
    .register();

    // from: kernel-hardening-checker
    check::Check::new(
        "KNP_063",
        "Ensure that kernel flag \"hardened_usercopy=1\" is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("hardened_usercopy=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Refuse to copy data between kernel and user space if the destination/source is not a valid user buffer. Blocks a class of heap-based information leaks and overflows that rely on usercopy primitives. Performance overhead from additional bounds checking on every usercopy operation.")
    .with_fix("Add \"hardened_usercopy=1\" to bootloader kernel params.")
    .with_link("https://lwn.net/Articles/695991/")
    .register();

    // Remount secure
    // https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/40_remount_secure.cfg
    // remount Secure provides enhanced security via mount options:
    // - 0 (no security): disable remount Secure
    // - 1 (low security): re-mount with nodev and nosuid only
    // - 2 (medium security): re-mount with nodev, nosuid, and noexec for most
    // mount points, excluding /home
    // - 3 (highest security): re-mount with nodev, nosuid, and noexec for all
    // mount points including /home
    check::Check::new(
        "KNP_027",
        "Ensure that kernel flag \"remountsecure=3\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("remountsecure=3"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Re-mount all filesystems at boot with the strictest options: nodev, nosuid, and noexec for every mount point including /home. Prevents executable payloads on writable mounts. May break scripts, JIT-generated code, plugins, interpreters.")
    .with_fix("Add \"remountsecure=3\" to bootloader kernel params.")
    .register();

    // X86 64 and 32 CPU mitigations
    // https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/40_cpu_mitigations.cfg
    check::Check::new(
        "KNP_030",
        "Ensure that kernel flag \"mitigations=auto\" is present",
        Severity::High,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("mitigations=auto"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable all CPU vulnerability mitigations automatically. Protects against Spectre, Meltdown, MDS, TSX Async Abort, and other speculative-execution side-channel attacks. Performance overhead from all active mitigations; impact varies by CPU and workload (typically 5-30%).")
    .with_fix("Add \"mitigations=auto\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_064",
        "Ensure that kernel flag \"mitigations=auto,nosmt\" is present",
        Severity::High,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("mitigations=auto,nosmt"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable all CPU vulnerability mitigations and disable Simultaneous Multithreading. Provides maximum protection against cross-thread side-channel attacks like ForgeCache and ShadowClone. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add \"mitigations=auto,nosmt\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_031",
        "Ensure that kernel flag \"nosmt\" is present",
        Severity::High,
        vec![
            "kernel",
            "KSPP",
            "paranoid",
            "server",
            "workstation",
            "paranoid",
        ],
        || kernel::check_kernel_params("nosmt"),
        vec![kernel::init_kernel_params],
    )
    .with_description(
        "Disable Simultaneous Multithreading. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.",
    )
    .with_fix("Add \"nosmt\" to bootloader kernel params.")
    .with_link("https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/core-scheduling.html")
    .register();

    check::Check::new(
        "KNP_032",
        "Ensure that kernel flag \"spectre_v2=on\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("spectre_v2=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable mitigation for the Spectre variant 2 vulnerability. Affects both Intel and AMD CPUs. Performance overhead from branch target injection mitigations (retpoline/IBRS); impact varies by CPU and workload (typically 5-20%).")
    .with_fix("Add \"spectre_v2=on\" to bootloader kernel params.")
    .with_link("https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/spectre.html")
    .register();

    check::Check::new(
        "KNP_033",
        "Ensure that kernel flag \"spectre_bhi=on\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("spectre_bhi=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable mitigation for the Spectre branch history injection vulnerability. Affects both Intel and AMD CPUs. Performance overhead from branch history clearing on every syscall entry; impact varies by CPU and workload.")
    .with_fix("Add \"spectre_bhi=on\" to bootloader kernel params.")
    .with_link("https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/spectre.html")
    .register();

    check::Check::new(
        "KNP_034",
        "Ensure that kernel flag \"spec_store_bypass_disable=on\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation", "tails"],
        || kernel::check_kernel_params("spec_store_bypass_disable=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description(
        "Unconditionally disable Speculative Store Bypass (SSB) on affected CPUs. Performance overhead from speculative store bypass mitigation; impact varies by CPU and workload.",
    )
    .with_fix("Add \"spec_store_bypass_disable=on\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_035",
        "Ensure that kernel flag \"l1tf=full,force\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("l1tf=full,force"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Unconditionally enable L1 Terminal Fault mitigation and disable SMT. Prevents information leakage from L1 cache via the Foreshadow side-channel attack. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add \"l1tf=full,force\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_036",
        "Ensure that kernel flag \"mds=full\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("mds=full"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable full Microarchitectural Data Sampling mitigation. Clears CPU buffers before returning to user space to prevent side-channel data leakage across hyperthreads. Performance overhead from VERW instruction on every kernel exit; impact varies by CPU and workload.")
    .with_fix("Add \"mds=full\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_065",
        "Ensure that kernel flag \"mds=full,nosm\" is present",
        Severity::High,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("mds=full,nosm"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable full MDS mitigation and disable SMT for maximum protection against microarchitectural data sampling attacks. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add \"mds=full,nosm\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_037",
        "Ensure that kernel flag \"tsx=off\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("tsx=off"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disable Intel TSX (Transactional Synchronization Extensions). TSX-based speculative execution creates side channels exploitable by TAA and other attacks. Breaks applications relying on hardware transactional memory (e.g. some databases, high-performance computing).")
    .with_fix("Add \"tsx=off\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_038",
        "Ensure that kernel flag \"tsx_async_abort=full\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("tsx_async_abort=full"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable full TSX Async Abort mitigation. Clears CPU buffers to prevent data leakage via the TSX side channel (TAA/CVE-2019-11135). Performance overhead from VERW instruction on every kernel exit.")
    .with_fix("Add \"tsx_async_abort=full\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_066",
        "Ensure that kernel flag \"tsx_async_abort=full,nosmt\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation", "paranoid"],
        || kernel::check_kernel_params("tsx_async_abort=full,nosmt"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable full TAA mitigation and disable SMT. Provides maximum protection against TSX Async Abort side-channel attacks. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add \"tsx_async_abort=full,nosmt\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_039",
        "Ensure that kernel flag \"kvm.nx_huge_pages=force\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("kvm.nx_huge_pages=force"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Force NX huge pages for KVM guests, mitigating the iTLB Multihit vulnerability (CVE-2019-19332) where a malicious guest can trigger machine check exceptions on hosts with certain CPU errata. May reduce KVM guest performance by forcing memory to use huge pages only when NX is not required.")
    .with_fix("Add \"kvm.nx_huge_pages=force\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_040",
        "Ensure that kernel flag \"l1d_flush=on\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("l1d_flush=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Flush the L1 data cache on VM entry to prevent cross-guest data leakage via the L1 cache side channel (CVE-2018-3640 / L1TF). Performance overhead from L1 cache flush on every VM entry; impact varies by VM workload frequency.")
    .with_fix("Add \"l1d_flush=on\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_041",
        "Ensure that kernel flag \"mmio_stale_data=full\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("mmio_stale_data=full"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable full MMIO stale data mitigation (CVE-2022-21123/21125/21127/24549). Clears CPU buffers to prevent data leakage from MMIO operations. Performance overhead from VERW instruction on VM entry/exit and kernel exit.")
    .with_fix("Add \"mmio_stale_data=full\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_067",
        "Ensure that kernel flag \"mmio_stale_data=full,nosmt\" is present",
        Severity::High,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("mmio_stale_data=full,nosmt"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable full MMIO stale data mitigation and disable SMT. Maximum protection against Processor MMIO Stale Data vulnerabilities. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add \"mmio_stale_data=full,nosmt\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_042",
        "Ensure that kernel flag \"retbleed=auto\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("retbleed=auto"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Automatically select Retbleed mitigation based on the CPU. Prevents speculative execution of return instructions from leaking data via the RetBleed side channel (CVE-2022-29900/29901). Performance overhead from return instruction mitigation; impact varies by CPU and workload.")
    .with_fix("Add \"retbleed=auto\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_068",
        "Ensure that kernel flag \"retbleed=auto,nosmt\" is present",
        Severity::High,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("retbleed=auto,nosmt"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable automatic Retbleed mitigation and disable SMT. Maximum protection against Retbleed side-channel attacks. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add \"retbleed=auto,nosmt\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_043",
        "Ensure that kernel flag \"spec_rstack_overflow=safe-ret\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("spec_rstack_overflow=safe-ret"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Mitigate Speculative Return Stack Overflow (CVE-2022-28693/29392/29393/29394). Use safe-ret training sequences to prevent guest-to-host and guest-to-guest speculation via the return address predictor. Performance overhead from safe-ret training on every function return.")
    .with_fix("Add \"spec_rstack_overflow=safe-ret\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_044",
        "Ensure that kernel flag \"gather_data_sampling=force\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("gather_data_sampling=force"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Force-enable Gather Data Sampling mitigation (CVE-2022-40982). Prevents data leakage via the AVX2 gather instruction side channel. Performance overhead for AVX2-heavy workloads that use gather instructions.")
    .with_fix("Add \"gather_data_sampling=force\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_045",
        "Ensure that kernel flag \"reg_file_data_sampling=on\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("reg_file_data_sampling=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable Register File Data Sampling mitigation (CVE-2023-28692 / Downfall). Prevents data leakage from architectural register file state via speculative execution side channels. Performance overhead on Intel CPUs from additional mitigation steps on context switches.")
    .with_fix("Add \"reg_file_data_sampling=on\" to bootloader kernel params.")
    .register();

    // from: kernel-hardening-checker
    check::Check::new(
        "KNP_050",
        "Ensure that kernel flag \"spectre_v2_user=on\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("spectre_v2_user=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable Spectre v2 user-space mitigation unconditionally. Protects user-space processes from cross-process Spectre v2 attacks (indirect branch injection). Performance overhead from STIBP/IBPB on context switches; impact varies by CPU and workload (typically 5-15%).")
    .with_fix("Add \"spectre_v2_user=on\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_051",
        "Ensure that kernel flag \"srbds=auto,nosmt\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("srbds=auto,nosmt"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable SRBDS mitigation and disable SMT. Protects against Special Register Buffer Data Sampling (CVE-2020-0548) which leaks data from special registers via a side channel. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add \"srbds=auto,nosmt\" to bootloader kernel params.")
    .register();

    // ARM CPU mitigations
    // "kpti=auto,nosmt"
    // "ssbd=force-on"
    // "rodata=full"

    check::Check::new(
        "KNP_060",
        "Ensure that kernel flag \"loglevel=0\" is present",
        Severity::Low,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("loglevel=0"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Prevent sensitive kernel information leaks in the console during boot.")
    .with_fix("Add \"loglevel=0\" to bootloader kernel params.")
    .with_link("https://wiki.archlinux.org/title/silent_boot")
    .with_link("https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/41_quiet_boot.cfg%23security-misc-shared")
    .register();

    check::Check::new(
        "KNP_061",
        "Ensure that kernel flag \"quiet\" is present",
        Severity::Low,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("quiet"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Prevent sensitive kernel information leaks in the console during boot.")
    .with_fix("Add \"quiet\" to bootloader kernel params.")
    .with_link("https://wiki.archlinux.org/title/silent_boot")
    .with_link("https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/41_quiet_boot.cfg%23security-misc-shared")
    .register();

    // TODO: fron v5.14 to v6.16
    // check::Check::new(
    //     "KNP_062",
    //     "Ensure that kernel flag \"slub_debug=FZ\" is present",
    //     Severity::Medium,
    //     vec!["kernel", "KSPP", "server", "workstation", "tails"],
    //     || kernel::check_kernel_params("slub_debug=FZ"),
    //     vec![kernel::init_kernel_params],
    // )
    // .with_fix("Add \"slub_debug=FZ\" to bootloader kernel params.")
    // .register();

    // TODO: since v6.17
    check::Check::new(
        "KNP_063",
        "Ensure that kernel flag \"hash_pointers=always\" is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "tails"],
        || kernel::check_kernel_params("hash_pointers=always"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Hash all kernel pointers printed via printk and other output paths. Prevents kernel address leaks that aid exploitation via dmesg, /proc/kallsyms, and other interfaces.")
    .with_fix("Add \"hash_pointers=always\" to bootloader kernel params.")
    .register();
}
