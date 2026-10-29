use crate::check;
use crate::check::Severity;
use crate::modules::{base, kernel};

pub fn add_checks() {
    check::Check::new(
        "KNP_001",
        "Ensure that kernel flag `slab_nomerge` is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "tails"],
        || kernel::check_kernel_params("slab_nomerge"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disable slab merging, increasing the difficulty of heap exploit implied by `slub_debug=FZ`, but having `slab_nomerge` explicitly declared can help prevent regressions where disabling of debugging features is desired but re-enabling of merging is not. Increases memory consumption as slabs cannot be merged, and may reduce allocation performance.")
    .with_fix("Add `slab_nomerge` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_002",
        "Ensure that kernel flag `slab_debug=FZ` is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("slab_debug=FZ"),
        vec![kernel::init_kernel_params],
    )
    .skip_when(|| kernel::skip_kernel_before((6, 9, 0)))
    .with_description("Enables front and end zone poisoning in slab allocator, helping detect memory corruption, buffer overflows, and use-after-free vulnerabilities by inserting canary values around memory allocations. Renamed from `slub_debug` in v6.9, the old spelling is still accepted as an alias. Significant performance overhead due to extra memory usage and checks on every allocation/free.")
    .with_fix("Add `slab_debug=FZ` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_004",
        "Ensure that kernel flag `page_alloc.shuffle=1` is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "tails"],
        || kernel::check_kernel_params("page_alloc.shuffle=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable the kernel page allocator to randomize free lists during early boot. Limits some data exfiltration and ROP attacks that rely on inferring sensitive data location, also improves performance by optimizing memory-side cache utilization. Needs `CONFIG_SHUFFLE_PAGE_ALLOCATOR=y` kernel build config too.")
    .with_fix("Add `page_alloc.shuffle=1` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_005",
        "Ensure that kernel flag `init_on_alloc=1` is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "conditional"],
        || kernel::check_kernel_params("init_on_alloc=1"),
        vec![kernel::init_kernel_params],
    )
    .skip_when(|| kernel::skip_kernel_before((5, 3, 0)))
    .with_description("Zero memory at allocation time. Mitigates use-after-free exploits by erasing sensitive information in memory. Performance overhead from zeroing every allocation. Impact varies by workload.")
    .with_fix("Add `init_on_alloc=1` to bootloader kernel params.")
    .register();

    // NOTE: after 5.3 replaced by `init_on_alloc=1 init_on_free=1`
    check::Check::new(
        "KNP_003",
        "Ensure that kernel flag `page_poison=1` is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("page_poison=1"),
        vec![kernel::init_kernel_params],
    )
    .skip_when(|| kernel::skip_kernel_since((5, 3, 0)))
    .with_fix("Add `page_poison=1` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_006",
        "Ensure that kernel flag `init_on_free=1` is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "tails"],
        || kernel::check_kernel_params("init_on_free=1"),
        vec![kernel::init_kernel_params],
    )
    .skip_when(|| kernel::skip_kernel_before((5, 3, 0)))
    .with_description("Zero memory at free time. Mitigates use-after-free exploits by erasing sensitive information in memory. Performance overhead from zeroing every freed page; impact varies by workload.")
    .with_fix("Add `init_on_free=1` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_007",
        "Ensure that kernel flag `pti=on` is present",
        Severity::High,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("pti=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable kernel page table isolation to harden against kernel ASLR (KASLR) bypasses, mitigates the Meltdown (CVE-2017-5754) CPU vulnerability. Performance overhead from additional TLB flushes on every kernel/userspace transition; impact varies by CPU and workload (up to 30% on some server workloads).")
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#kernel-address-space-layout-randomization-kaslr")
    .with_fix("Add `pti=on` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_008",
        "Ensure that kernel flag `randomize_kstack_offset=on` is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "tails"],
        || kernel::check_kernel_params("randomize_kstack_offset=on"),
        vec![kernel::init_kernel_params],
    )
    .skip_when(|| kernel::skip_kernel_before((5, 13, 0)))
    .with_description("Enable randomization of the kernel stack offset on syscall entries. Hardens against memory corruption attacks due to increased entropy limits attacks relying on deterministic stack addresses or cross-syscall address exposure. Minor performance overhead from extra randomization on every syscall.")
    .with_fix("Add `randomize_kstack_offset=on` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_009",
        "Ensure that kernel flag `vsyscall=none` is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "tails"],
        || kernel::check_kernel_params("vsyscall=none"),
        vec![kernel::init_kernel_params],
    )
    .skip_when(|| base::skip_not_arch(&["x86_64"]))
    .with_description("Disable vsyscalls to reduce attack surface as they have been replaced by vDSO vulnerable to ROP attacks as vsyscalls are located at fixed addresses in memory. Specific to x86_64 arch. Breaks very old binaries (pre-glibc 2.22) and some legacy applications that rely on vsyscalls.")
    .with_fix("Add `vsyscall=none` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_010",
        "Ensure that kernel flag `debugfs=off` is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("debugfs=off"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Restrict access to debugfs that can contain sensitive information. Breaks tools that rely on debugfs (e.g. some GPU drivers, perf tools, power management utilities, debugging tools).")
    .with_fix("Add `debugfs=off` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_011",
        "Ensure that kernel flag `oops=panic` is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("oops=panic"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Force the kernel to panic on `oopses`, can sometimes potentially indicate and thwart certain kernel exploitation attempts, also cause panics on machine check exceptions. Some bad drivers can cause harmless oopses which result in system crash.")
    .with_fix("Add `oops=panic` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_012",
        "Ensure that kernel flag `module.sig_enforce=1` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("module.sig_enforce=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Require every kernel module to be signed before being loaded. Any module that is unsigned or signed with an invalid key cannot be loaded. Prevents all out-of-tree kernel modules (including DKMS) unless signed, this makes it harder to load a malicious module.")
    .with_fix("Add `module.sig_enforce=1` to bootloader kernel params.")
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#restricting-access-to-kernel-modules")
    .with_link("https://docs.kernel.org/admin-guide/module-signing.html")
    .register();

    check::Check::new(
        "KNP_013",
        "Ensure that kernel flag `lockdown=integrity` or `lockdown=confidentiality` is present",
        Severity::High,
        vec!["kernel", "KSPP", "server", "workstation"],
        // arch wiki: It is recommended to use integrity, unless your specific
        // threat model dictates otherwise.
        || kernel::check_kernel_params_value_in("lockdown", &["integrity", "confidentiality"]),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable kernel lockdown to enforce security boundary between user and kernel space, enforces module signature verification kernel lockdown LSM can eliminate many methods that user space code could abuse for privilege escalation. `integrity` blocks the interfaces that let userspace modify the running kernel (`/dev/mem`, `kexec` of an unsigned image, some MSR and PCI config space writes), `confidentiality` additionally blocks the ones that let it read kernel memory, so it is the stronger mode and the one KSPP asks for. Use `integrity` unless the threat model dictates otherwise. Some applications may cease to work which rely on low-level access to either hardware or the kernel. A kernel built with `CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY` or `CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY` is locked down whatever the command line says, and this parameter is then only needed to raise the level.")
    .with_fix("Add `lockdown=confidentiality` (or `lockdown=integrity`) to bootloader kernel params.")
    .with_link("https://man.archlinux.org/man/kernel_lockdown.7")
    .register();

    check::Check::new(
        "KNP_014",
        "Ensure that kernel flag `mce=0` is present",
        Severity::Low,
        vec!["kernel", "server", "workstation", "tails"],
        || kernel::check_kernel_params("mce=0"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keeps the kernel from logging machine check exception (MCE) events that an attacker could correlate with covert side-channel work. Unnecessary for systems without ECC memory.")
    .with_fix("Add `mce=0` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_015",
        "Ensure that kernel flag `kfence.sample_interval=100` is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("kfence.sample_interval=100"),
        vec![kernel::init_kernel_params],
    )
    .with_description("KFENCE detects heap out-of-bounds access, use-after-free, and invalid-free errors. Sampling interval is set to occur every 100 ms as per KSPP recommendation. Small performance and memory overhead from maintaining guard pages for sampled allocations.")
    .with_fix("Add `kfence.sample_interval=100` to bootloader kernel params.")
    .with_link("https://docs.kernel.org/dev-tools/kfence.html")
    .register();

    check::Check::new(
        "KNP_017",
        "Ensure that kernel flag `vdso32=0` is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("vdso32=0"),
        vec![kernel::init_kernel_params],
    )
    .skip_when(|| base::skip_not_arch(&["x86_64"]))
    .with_description("Disables the 32-bit vDSO, removing a small fixed-address ROP-friendly mapping from 64-bit processes that don't need it. Reduces predictable kernel-exposed addresses available to exploits. Breaks 32-bit applications that rely on vDSO for fast time-related syscalls (e.g. gettimeofday).")
    .with_fix("Add `vdso32=0` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_018",
        "Ensure that kernel flag `amd_iommu=force_isolation` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("amd_iommu=force_isolation"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Forces AMD IOMMU into per-device isolation domains, blocking DMA attacks from peripherals (Thunderbolt, PCIe, FireWire) that would otherwise let a malicious or compromised device read/write arbitrary host memory.")
    .with_fix("Add `amd_iommu=force_isolation` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_019",
        "Ensure that kernel flag `intel_iommu=on` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("intel_iommu=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enables Intel VT-d/IOMMU , blocking DMA attacks from peripherals (Thunderbolt, PCIe, FireWire) that would otherwise let a malicious or compromised device read/write arbitrary host memory.")
    .with_fix("Add `intel_iommu=on` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_020",
        "Ensure that kernel flag `iommu=force` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("iommu=force"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Force-enable IOMMU , blocking DMA attacks from peripherals (Thunderbolt, PCIe, FireWire) that would otherwise let a malicious or compromised device read/write arbitrary host memory.")
    .with_fix("Add `iommu=force` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_021",
        "Ensure that kernel flag `iommu.passthrough=0` is present",
        Severity::High,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("iommu.passthrough=0"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disable IOMMU passthrough so every DMA request goes through the IOMMU translation tables. Prevents devices from performing direct physical-memory reads and writes. Can reduce I/O performance, but the impact is small on modern hardware.")
    .with_fix("Add `iommu.passthrough=0` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_022",
        "Ensure that kernel flag `iommu.strict=1` is present",
        Severity::High,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("iommu.strict=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Strict IOMMU mode flushes IOTLB entries immediately when DMA mappings are torn down, closing the window where a device could still access stale mappings after the driver believes it has revoked access. Performance overhead from frequent IOTLB flushes; impact varies by I/O workload.")
    .with_fix("Add `iommu.strict=1` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_023",
        "Ensure that kernel flag `efi=disable_early_pci_dma` is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("efi=disable_early_pci_dma"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Block PCI DMA during early EFI boot before the IOMMU is initialized. Without this, a malicious or compromised peripheral can perform DMA attacks during the boot window before IOMMU protection is active.")
    .with_fix("Add `efi=disable_early_pci_dma` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_024",
        "Ensure that kernel flag `random.trust_bootloader=off` is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("random.trust_bootloader=off"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not trust entropy provided by the bootloader. A compromised or malicious bootloader could supply predictable seed values, weakening the kernel RNG from the start. May increase boot time.")
    .with_fix("Add `random.trust_bootloader=off` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_025",
        "Ensure that kernel flag `random.trust_cpu=off` is present",
        Severity::Medium,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("random.trust_cpu=off"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not trust CPU-provided entropy (e.g. RDRAND). A backdoored or flawed hardware RNG could produce predictable output, weakening all cryptographic operations that depend on the kernel RNG. May increase boot time.")
    .with_fix("Add `random.trust_cpu=off` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_026",
        "Ensure that kernel flag `extra_latent_entropy` is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("extra_latent_entropy"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Gather additional entropy from compiler-instrumented latent variables during early boot, seeding the kernel RNG with hard-to-predict state transitions. Strengthens cryptographic randomness on systems with limited hardware entropy sources. May increase boot time.")
    .with_fix("Add `extra_latent_entropy` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_028",
        "Ensure that kernel flag `ipv6.disable=1` is present",
        Severity::Informational,
        vec!["kernel", "server", "workstation", "conditional"],
        || kernel::check_kernel_params("ipv6.disable=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disable IPv6 support. Informational only: CIS recommends it when IPv6 is not required, but turning the protocol off is not a security improvement over a hardened dual-stack host. Keeps the stack out of the kernel entirely.")
    .with_fix("Add `ipv6.disable=1` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_029",
        "Ensure that kernel flag `ia32_emulation=0` is present",
        Severity::Medium,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("ia32_emulation=0"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disable 32-bit IA-32 emulation, removing hundreds of legacy 32-bit syscalls from the attack surface. 64-bit systems do not need it unless running legacy 32-bit binaries. Also simplifies security monitoring and application policy. All 32-bit binaries (e.g. Wine, Steam, legacy software) will no longer run.")
    .with_fix("Add `ia32_emulation=0` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_016",
        "Ensure that kernel flag `cfi=kcfi` is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("cfi=kcfi"),
        vec![kernel::init_kernel_params],
    )
    .skip_when(|| base::skip_not_arch(&["x86_64"]))
    .with_description("Disable FineIBT since it is weaker than pure KCFI.")
    .with_fix("Add `cfi=kcfi` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_064",
        "Ensure that kernel flag `hardened_usercopy=1` is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("hardened_usercopy=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Refuse to copy data between kernel and user space if the destination/source is not a valid user buffer. Blocks a class of heap-based information leaks and overflows that rely on usercopy primitives. Performance overhead from additional bounds checking on every usercopy operation.")
    .with_fix("Add `hardened_usercopy=1` to bootloader kernel params.")
    .with_link("https://lwn.net/Articles/695991/")
    .register();

    check::Check::new(
        "KNP_027",
        "Ensure that kernel flag `remountsecure=3` is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("remountsecure=3"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Re-mount filesystems at boot with restrictive mount options. The level is set by `remountsecure=<0-3>`: `0` (no security) disables the feature, `1` (low security) re-mounts with `nodev` and `nosuid` only, `2` (medium security) adds `noexec` for most mount points excluding `/home`, `3` (highest security) applies `nodev`, `nosuid`, and `noexec` to all mount points including `/home`. Blocks execution of payloads dropped on writable mounts, device node creation, and abuse of setuid binaries. Levels 2 and 3 may break scripts, JIT-generated code, plugins, and interpreters; level 3 can additionally break software installed under `/home`.")
    .with_fix("Add `remountsecure=3` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_030",
        "Ensure that kernel flag `mitigations=auto` is present",
        Severity::High,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params("mitigations=auto"),
        vec![kernel::init_kernel_params],
    )
    .skip_when(|| base::skip_not_arch(&["x86_64", "x86_32"]))
    .with_description("Enable all CPU vulnerability mitigations automatically. Protects against Spectre, Meltdown, MDS, TSX Async Abort, and other speculative-execution side-channel attacks. Performance overhead from all active mitigations; impact varies by CPU and workload (typically 5-30%).")
    .with_fix("Add `mitigations=auto` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_069",
        "Ensure that kernel flag `mitigations=auto,nosmt` is present",
        Severity::High,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("mitigations=auto,nosmt"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable all CPU vulnerability mitigations and disable Simultaneous Multithreading. Provides maximum protection against cross-thread side-channel attacks like ForgeCache and ShadowClone. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add `mitigations=auto,nosmt` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_031",
        "Ensure that kernel flag `nosmt` is present",
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
    .with_fix("Add `nosmt` to bootloader kernel params.")
    .with_link("https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/core-scheduling.html")
    .register();

    check::Check::new(
        "KNP_032",
        "Ensure that kernel flag `spectre_v2=on` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("spectre_v2=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable mitigation for the Spectre variant 2 vulnerability. Affects both Intel and AMD CPUs. Performance overhead from branch target injection mitigations (retpoline/IBRS); impact varies by CPU and workload (typically 5-20%).")
    .with_fix("Add `spectre_v2=on` to bootloader kernel params.")
    .with_link("https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/spectre.html")
    .register();

    check::Check::new(
        "KNP_033",
        "Ensure that kernel flag `spectre_bhi=on` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("spectre_bhi=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable mitigation for the Spectre branch history injection vulnerability. Affects both Intel and AMD CPUs. Performance overhead from branch history clearing on every syscall entry; impact varies by CPU and workload.")
    .with_fix("Add `spectre_bhi=on` to bootloader kernel params.")
    .with_link("https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/spectre.html")
    .register();

    check::Check::new(
        "KNP_034",
        "Ensure that kernel flag `spec_store_bypass_disable=on` is present",
        Severity::High,
        vec!["kernel", "server", "workstation", "tails"],
        || kernel::check_kernel_params("spec_store_bypass_disable=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description(
        "Unconditionally disable Speculative Store Bypass (SSB) on affected CPUs. Performance overhead from speculative store bypass mitigation; impact varies by CPU and workload.",
    )
    .with_fix("Add `spec_store_bypass_disable=on` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_035",
        "Ensure that kernel flag `l1tf=full,force` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("l1tf=full,force"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Unconditionally enable L1 Terminal Fault mitigation and disable SMT. Prevents information leakage from L1 cache via the Foreshadow side-channel attack. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add `l1tf=full,force` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_036",
        "Ensure that kernel flag `mds=full` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("mds=full"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable full Microarchitectural Data Sampling mitigation. Clears CPU buffers before returning to user space to prevent side-channel data leakage across hyperthreads. Performance overhead from VERW instruction on every kernel exit; impact varies by CPU and workload.")
    .with_fix("Add `mds=full` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_065",
        "Ensure that kernel flag `mds=full,nosm` is present",
        Severity::High,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("mds=full,nosm"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable full MDS mitigation and disable SMT for maximum protection against microarchitectural data sampling attacks. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add `mds=full,nosm` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_037",
        "Ensure that kernel flag `tsx=off` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("tsx=off"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disable Intel TSX (Transactional Synchronization Extensions). TSX-based speculative execution creates side channels exploitable by TAA and other attacks. Breaks applications relying on hardware transactional memory (e.g. some databases, high-performance computing).")
    .with_fix("Add `tsx=off` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_038",
        "Ensure that kernel flag `tsx_async_abort=full` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("tsx_async_abort=full"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable full TSX Async Abort mitigation. Clears CPU buffers to prevent data leakage via the TSX side channel (TAA/CVE-2019-11135). Performance overhead from VERW instruction on every kernel exit.")
    .with_fix("Add `tsx_async_abort=full` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_066",
        "Ensure that kernel flag `tsx_async_abort=full,nosmt` is present",
        Severity::High,
        vec!["kernel", "server", "workstation", "paranoid"],
        || kernel::check_kernel_params("tsx_async_abort=full,nosmt"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable full TAA mitigation and disable SMT. Provides maximum protection against TSX Async Abort side-channel attacks. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add `tsx_async_abort=full,nosmt` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_039",
        "Ensure that kernel flag `kvm.nx_huge_pages=force` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("kvm.nx_huge_pages=force"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Force NX huge pages for KVM guests, mitigating the iTLB Multihit vulnerability (CVE-2019-19332) where a malicious guest can trigger machine check exceptions on hosts with certain CPU errata. May reduce KVM guest performance by forcing memory to use huge pages only when NX is not required.")
    .with_fix("Add `kvm.nx_huge_pages=force` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_040",
        "Ensure that kernel flag `l1d_flush=on` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("l1d_flush=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Flush the L1 data cache on VM entry to prevent cross-guest data leakage via the L1 cache side channel (CVE-2018-3640 / L1TF). Performance overhead from L1 cache flush on every VM entry; impact varies by VM workload frequency.")
    .with_fix("Add `l1d_flush=on` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_041",
        "Ensure that kernel flag `mmio_stale_data=full` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("mmio_stale_data=full"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable full MMIO stale data mitigation (CVE-2022-21123/21125/21127/24549). Clears CPU buffers to prevent data leakage from MMIO operations. Performance overhead from VERW instruction on VM entry/exit and kernel exit.")
    .with_fix("Add `mmio_stale_data=full` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_067",
        "Ensure that kernel flag `mmio_stale_data=full,nosmt` is present",
        Severity::High,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("mmio_stale_data=full,nosmt"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable full MMIO stale data mitigation and disable SMT. Maximum protection against Processor MMIO Stale Data vulnerabilities. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add `mmio_stale_data=full,nosmt` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_042",
        "Ensure that kernel flag `retbleed=auto` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("retbleed=auto"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Automatically select Retbleed mitigation based on the CPU. Prevents speculative execution of return instructions from leaking data via the RetBleed side channel (CVE-2022-29900/29901). Performance overhead from return instruction mitigation; impact varies by CPU and workload.")
    .with_fix("Add `retbleed=auto` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_068",
        "Ensure that kernel flag `retbleed=auto,nosmt` is present",
        Severity::High,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("retbleed=auto,nosmt"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable automatic Retbleed mitigation and disable SMT. Maximum protection against Retbleed side-channel attacks. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add `retbleed=auto,nosmt` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_043",
        "Ensure that kernel flag `spec_rstack_overflow=safe-ret` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("spec_rstack_overflow=safe-ret"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Mitigate Speculative Return Stack Overflow (CVE-2022-28693/29392/29393/29394). Use safe-ret training sequences to prevent guest-to-host and guest-to-guest speculation via the return address predictor. Performance overhead from safe-ret training on every function return.")
    .with_fix("Add `spec_rstack_overflow=safe-ret` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_044",
        "Ensure that kernel flag `gather_data_sampling=force` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("gather_data_sampling=force"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Force-enable Gather Data Sampling mitigation (CVE-2022-40982). Prevents data leakage via the AVX2 gather instruction side channel. Performance overhead for AVX2-heavy workloads that use gather instructions.")
    .with_fix("Add `gather_data_sampling=force` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_045",
        "Ensure that kernel flag `reg_file_data_sampling=on` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("reg_file_data_sampling=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable Register File Data Sampling mitigation (CVE-2023-28692 / Downfall). Prevents data leakage from architectural register file state via speculative execution side channels. Performance overhead on Intel CPUs from additional mitigation steps on context switches.")
    .with_fix("Add `reg_file_data_sampling=on` to bootloader kernel params.")
    .register();

    // from: kernel-hardening-checker
    check::Check::new(
        "KNP_050",
        "Ensure that kernel flag `spectre_v2_user=on` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("spectre_v2_user=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable Spectre v2 user-space mitigation unconditionally. Protects user-space processes from cross-process Spectre v2 attacks (indirect branch injection). Performance overhead from STIBP/IBPB on context switches; impact varies by CPU and workload (typically 5-15%).")
    .with_fix("Add `spectre_v2_user=on` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_051",
        "Ensure that kernel flag `srbds=auto,nosmt` is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("srbds=auto,nosmt"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable SRBDS mitigation and disable SMT. Protects against Special Register Buffer Data Sampling (CVE-2020-0548) which leaks data from special registers via a side channel. SMT/Hyper-Threading is disabled, reducing available logical CPUs. May significantly decrease system performance on multi-threaded tasks.")
    .with_fix("Add `srbds=auto,nosmt` to bootloader kernel params.")
    .register();

    // ARM CPU mitigations
    // "kpti=auto,nosmt"
    // "ssbd=force-on"
    // "rodata=full"

    check::Check::new(
        "KNP_060",
        "Ensure that kernel flag `loglevel=0` is present",
        Severity::Low,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("loglevel=0"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Prevent sensitive kernel information leaks in the console during boot.")
    .with_fix("Add `loglevel=0` to bootloader kernel params.")
    .with_link("https://wiki.archlinux.org/title/silent_boot")
    .with_link("https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/41_quiet_boot.cfg%23security-misc-shared")
    .register();

    check::Check::new(
        "KNP_061",
        "Ensure that kernel flag `quiet` is present",
        Severity::Low,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("quiet"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Prevent sensitive kernel information leaks in the console during boot.")
    .with_fix("Add `quiet` to bootloader kernel params.")
    .with_link("https://wiki.archlinux.org/title/silent_boot")
    .with_link("https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/41_quiet_boot.cfg%23security-misc-shared")
    .register();

    check::Check::new(
        "KNP_062",
        "Ensure that kernel flag `slub_debug=FZ` is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "tails"],
        || kernel::check_kernel_params("slub_debug=FZ"),
        vec![kernel::init_kernel_params],
    )
    .skip_when(|| kernel::skip_kernel_since((6, 9, 0)))
    .with_fix("Add `slub_debug=FZ` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_063",
        "Ensure that kernel flag `hash_pointers=always` is present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation", "tails"],
        || kernel::check_kernel_params("hash_pointers=always"),
        vec![kernel::init_kernel_params],
    )
    .skip_when(|| kernel::skip_kernel_before((6, 17, 0)))
    .with_description("Hash all kernel pointers printed via printk and other output paths. Prevents kernel address leaks that aid exploitation via dmesg, `/proc/kallsyms`, and other interfaces.")
    .with_fix("Add `hash_pointers=always` to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_200",
        "Ensure that kernel flag `nokaslr` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("nokaslr"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep Kernel Address Space Layout Randomization (KASLR) active at boot. `nokaslr` disables both the kernel image randomization (`CONFIG_RANDOMIZE_BASE` kconfig) and the kernel memory sections randomization (`CONFIG_RANDOMIZE_MEMORY` kconfig) whatever the kernel build is, so a hardened config becomes fully deterministic and every kernel address can be precomputed by an exploit.")
    .with_fix("Remove `nokaslr` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_201",
        "Ensure that kernel flag `slab_merge` is not present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params_absent("slab_merge"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep slab caches unmerged at boot. `slab_merge` re-enables merging whatever the kernel was built with, undoing both `slab_nomerge` and `CONFIG_SLAB_MERGE_DEFAULT` being disabled: caches of the same size are shared again, so a heap overflow or use-after-free on one object can reach the allocations of unrelated subsystems and the cache layout becomes predictable. The parameter exists to revert a hardened build while debugging.")
    .with_fix("Remove `slab_merge` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_202",
        "Ensure that kernel flag `slub_merge` is not present",
        Severity::Medium,
        vec!["kernel", "KSPP", "server", "workstation"],
        || kernel::check_kernel_params_absent("slub_merge"),
        vec![kernel::init_kernel_params],
    )
    .with_description("The SLUB spelling of `slab_merge`, still accepted by the kernel: it re-enables slab cache merging at boot and undoes `slab_nomerge` and `CONFIG_SLAB_MERGE_DEFAULT` not set. Both spellings have to be absent, since the kernel applies whichever it parses last, so a bootloader entry can carry one and not the other.")
    .with_fix("Remove `slub_merge` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_203",
        "Ensure that kernel flag `nopti` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("nopti"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep Kernel Page Table Isolation active. `nopti` unmaps nothing at the user/kernel boundary whatever the build is, so Meltdown (CVE-2017-5754) becomes exploitable again and a speculative read of a kernel address leaks data through a cache side channel. It is the same switch as `pti=off`, and `CONFIG_MITIGATION_PAGE_TABLE_ISOLATION` only decides whether the code exists.")
    .with_fix("Remove `nopti` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_204",
        "Ensure that kernel flag `kpti` is not one of `kpti=off`, `kpti=0`",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_value_absent("kpti", &["off", "0"]),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep Kernel Page Table Isolation active, the other spelling of the `nopti` switch: `kpti=off` and `kpti=0` disable the user/kernel page table split at boot, making Meltdown (CVE-2017-5754) exploitable again whatever `CONFIG_MITIGATION_PAGE_TABLE_ISOLATION` was built with. `kpti=on` and `kpti=auto` are the safe values.")
    .with_fix("Remove `kpti=off`, `kpti=0` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_205",
        "Ensure that kernel flag `nosmap` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("nosmap"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep Supervisor Mode Access Prevention active. `nosmap` lets kernel code dereference userspace addresses freely again, so a missing bounds check or a confused deputy in a syscall handler becomes a direct read or write of user memory. It defeats `CONFIG_X86_SMAP` and the arm64 PAN equivalents.")
    .with_fix("Remove `nosmap` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_206",
        "Ensure that kernel flag `nosmep` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("nosmep"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep Supervisor Mode Execution Prevention active. `nosmep` lets the kernel execute userspace pages again, which is what turns a write-what-where primitive into control flow by pointing a function pointer at attacker-controlled memory.")
    .with_fix("Remove `nosmep` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_207",
        "Ensure that kernel flag `nospectre_v1` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("nospectre_v1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep the Spectre v1 (CVE-2017-5753) mitigation active. `nospectre_v1` removes the bounds masking and `nospec` helpers, so an out-of-bounds index used speculatively in a syscall or ioctl path leaks whatever the attacker trains it to read.")
    .with_fix("Remove `nospectre_v1` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_208",
        "Ensure that kernel flag `nospectre_v2` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("nospectre_v2"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep the Spectre v2 (CVE-2017-5715) mitigation active. `nospectre_v2` disables the retpoline or eIBRS protection of kernel indirect branches, so a poisoned branch predictor trained from userspace or another guest can steer kernel control flow.")
    .with_fix("Remove `nospectre_v2` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_209",
        "Ensure that kernel flag `nospec_store_bypass_disable` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("nospec_store_bypass_disable"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep the Speculative Store Bypass mitigation (CVE-2018-3639, Spectre v4) active. This parameter is the long spelling of `ssbd=off`: a speculative load can again bypass a recent store and read data from another context.")
    .with_fix("Remove `nospec_store_bypass_disable` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_210",
        "Ensure that kernel flag `ssbd` is not one of `ssbd=off`",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_value_absent("ssbd", &["off", "0"]),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not disable the Speculative Store Bypass mitigation (CVE-2018-3639, Spectre v4) at boot. `ssbd=off` turns it off for every task, which lets a speculative load bypass a recent store and read data another context wrote; `ssbd=kernel` and `ssbd=force-on` are the hardened settings, `ssbd=prctl` and `ssbd=seccomp` leave it to each process.")
    .with_fix("Remove `ssbd=off` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_211",
        "Ensure that kernel flag `nospectre_bhb` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("nospectre_bhb"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep the Spectre-BHB mitigation active on arm64. `nospectre_bhb` stops the kernel from clearing the branch history on exception entry, so a history trained in userspace can steer kernel indirect branches even with eIBRS or retpolines in place (CVE-2022-23960).")
    .with_fix("Remove `nospectre_bhb` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_212",
        "Ensure that kernel flag `clearcpuid` is not present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("clearcpuid"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not clear CPU feature bits at boot. `clearcpuid=` hides a feature from the kernel and from userspace, which is a supported way to turn off the mitigations that depend on it (SME, SMAP, IBT, XSAVE and the rest) without touching the config, and it silently degrades whatever the kernel thought the CPU could do.")
    .with_fix("Remove `clearcpuid` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_213",
        "Ensure that kernel flag `setcpuid` is not present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("setcpuid"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not set CPU feature bits that the hardware does not report. `setcpuid=` makes the kernel believe a feature exists, which either crashes when the instruction is executed or enables a code path that was never validated on this part; it is the counterpart of `clearcpuid`.")
    .with_fix("Remove `setcpuid` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_214",
        "Ensure that kernel flag `dis_ucode_ldr` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("dis_ucode_ldr"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep CPU microcode loading enabled. `dis_ucode_ldr` stops the kernel from applying microcode updates at boot, which is how the hardware side of most speculative execution, MDS and errata mitigations is delivered: the `CONFIG_MICROCODE` build option stays on and the vulnerabilities come back anyway.")
    .with_fix("Remove `dis_ucode_ldr` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_215",
        "Ensure that kernel flag `no_hash_pointers` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("no_hash_pointers"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep kernel pointers hashed in log and `/proc` output. `no_hash_pointers` makes `%p` print the real address, which defeats `kernel.kptr_restrict` and `CONFIG_RANDOMIZE_BASE`/`CONFIG_RANDOMIZE_MEMORY` together: one log line is enough to compute every other kernel address. It is the counterpart of `hash_pointers=always`.")
    .with_fix("Remove `no_hash_pointers` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_216",
        "Ensure that kernel flag `norandmaps` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("norandmaps"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep userspace address space layout randomization active. `norandmaps` places every mapping of every process at a predictable address, so a stack, heap or library overflow no longer needs an information leak to be aimed, and it undoes `CONFIG_ARCH_MMAP_RND_BITS`.")
    .with_fix("Remove `norandmaps` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_217",
        "Ensure that kernel flag `sysrq_always_enabled` is not present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("sysrq_always_enabled"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not force every SysRq function on. The parameter overrides both the `CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE` mask and `/proc/sys/kernel/sysrq` at runtime, so anyone at the console or on the serial line can dump tasks and registers, show memory contents, kill processes and reboot the machine.")
    .with_fix("Remove `sysrq_always_enabled` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_218",
        "Ensure that kernel flag `arm64.nobti` is not present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("arm64.nobti"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep Branch Target Identification active on arm64. `arm64.nobti` disables the hardware marking of valid indirect branch targets, which is what stops a hijacked pointer from jumping into the middle of a function.")
    .with_fix("Remove `arm64.nobti` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_219",
        "Ensure that kernel flag `arm64.nopauth` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("arm64.nopauth"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep pointer authentication active on arm64. `arm64.nopauth` turns off the keyed signing of return addresses and pointers, so an overwritten return address is followed instead of faulting.")
    .with_fix("Remove `arm64.nopauth` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_220",
        "Ensure that kernel flag `arm64.nomte` is not present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("arm64.nomte"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep the Memory Tagging Extension active on arm64. `arm64.nomte` removes the hardware tagging that catches use-after-free and out-of-bounds accesses, both for kernel allocations (`CONFIG_KASAN_HW_TAGS`) and for the processes that opt into MTE.")
    .with_fix("Remove `arm64.nomte` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_221",
        "Ensure that kernel flag `arm64.nogcs` is not present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_absent("arm64.nogcs"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Keep the Guarded Control Stack active on arm64. `arm64.nogcs` disables the hardware-protected copy of the return addresses, so a stack overflow can redirect control flow again.")
    .with_fix("Remove `arm64.nogcs` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_222",
        "Ensure that kernel flag `slab_common.usercopy_fallback` is not present",
        Severity::Medium,
        vec!["kernel", "server", "workstation", "KSPP"],
        || kernel::check_kernel_params_absent("slab_common.usercopy_fallback"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not let an oversized usercopy succeed. The parameter is the runtime counterpart of `CONFIG_HARDENED_USERCOPY_FALLBACK`: with it a `copy_to_user`/`copy_from_user` that should have been rejected is logged and performed anyway, so the checks stop preventing anything.")
    .with_fix("Remove `slab_common.usercopy_fallback` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_223",
        "Ensure that kernel flags `proc_mem.force_override=on` or `proc_mem.force_override=always` are not present",
        Severity::Medium,
        vec!["kernel", "server", "workstation", "KSPP"],
        || kernel::check_kernel_params_value_absent("proc_mem.force_override", &["on", "always"]),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not restore the forced writes to another process's memory through `/proc/pid/mem`. `proc_mem.force_override=on` or `always` overrides `CONFIG_PROC_MEM_NO_FORCE`, which lets root and anything able to ptrace write into a running process even when it is otherwise protected. `never` and an absent parameter are the hardened settings.")
    .with_fix("Remove `proc_mem.force_override=on`, `proc_mem.force_override=always` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_224",
        "Ensure that kernel flags `rodata=off` or `rodata=0` are not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_value_absent("rodata", &["off", "0"]),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not make the kernel's read-only data writable. `rodata=off` leaves the text and rodata sections mapped writable, which turns any write-what-where primitive into a patch of the running kernel and undoes `CONFIG_STRICT_KERNEL_RWX` (`KNC_202`); `rodata=on` and `rodata=full` are the safe values.")
    .with_fix("Remove `rodata=off`, `rodata=0` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_225",
        "Ensure that kernel flag `tsa=off` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_value_absent("tsa", &["off"]),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not disable the Transient Scheduler Attacks mitigation at boot. `tsa=off` stops the CPU buffer flushes on privilege transitions, so data from another context can be read through the transient execution window whatever `CONFIG_MITIGATION_TSA` was built with.")
    .with_fix("Remove `tsa=off` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_226",
        "Ensure that kernel flag `vmscape=off` is not present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_value_absent("vmscape", &["off"]),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not disable the VMSCAPE mitigation at boot. `vmscape=off` removes the protection of the VMM entry paths, so guest state can leak through the predicted control flow of the hypervisor whatever `CONFIG_MITIGATION_VMSCAPE` was built with.")
    .with_fix("Remove `vmscape=off` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_227",
        "Ensure that kernel flag `indirect_target_selection=off` is not present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_value_absent("indirect_target_selection", &["off"]),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not disable the indirect target selection mitigation at boot. `indirect_target_selection=off` lets a poisoned predictor steer the target of an indirect branch again, which is the class of attack the retpoline and IBT mitigations exist for.")
    .with_fix("Remove `indirect_target_selection=off` from bootloader kernel params and reboot.")
    .register();

    check::Check::new(
        "KNP_228",
        "Ensure that kernel flag `bdev_allow_write_mounted=1` is not present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params_value_absent("bdev_allow_write_mounted", &["1"]),
        vec![kernel::init_kernel_params],
    )
    .with_description("Do not allow opening a block device for writing while a filesystem on it is mounted. `bdev_allow_write_mounted=1` restores the old behaviour, which lets root write directly under a mounted filesystem and corrupt or forge its contents past every permission and integrity check; `0` and an absent parameter are the safe settings.")
    .with_fix("Remove `bdev_allow_write_mounted=1` from bootloader kernel params and reboot.")
    .register();
}
