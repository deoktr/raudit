// - tails: https://tails.net/contribute/design/kernel_hardening/

use crate::check;
use crate::check::Severity;
use crate::modules::kernel;

pub fn add_checks() {
    check::Check::new(
        "KNP_001",
        "Ensure that kernel flag \"slab_nomerge\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation", "tails"],
        || kernel::check_kernel_params("slab_nomerge"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disable slab merging, increasing the difficulty of heap exploit implied by \"slub_debug=FZ\", but having \"slab_nomerge\" explicitly declared can help prevent regressions where disabling of debugging features is desired but re-enabling of merging is not.")
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
    .with_description("Enables front and end zone poisoning in slab allocator, helping detect memory corruption, buffer overflows, and use-after-free vulnerabilities by inserting canary values around memory allocations.")
    .with_fix("Add \"slab_debug=FZ\" to bootloader kernel params.")
    .register();

    // NOTE: after 5.3 replaced by `init_on_free=1`
    // check::Check::new(
    //     "KNP_003",
    //     "Ensure that kernel flag \"page_poison=1\" is present",
    //     vec!["kernel", "server", "workstation"],
    //     || kernel::check_kernel_params("page_poison=1"),
    //     vec![kernel::init_kernel_params],
    // )
    // .register();

    check::Check::new(
        "KNP_004",
        "Ensure that kernel flag \"page_alloc.shuffle=1\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation", "tails"],
        || kernel::check_kernel_params("page_alloc.shuffle=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable the kernel page allocator to randomize free lists during early boot. Limits some data exfiltration and ROP attacks that rely on inferring sensitive data location, also improves performance by optimizing memory-side cache utilization.")
    .with_fix("Add \"page_alloc.shuffle=1\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_005",
        "Ensure that kernel flag \"init_on_alloc=1\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("init_on_alloc=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Zero memory at allocation time. Mitigates use-after-free exploits by erasing sensitive information in memory.")
    .with_fix("Add \"init_on_alloc=1\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_006",
        "Ensure that kernel flag \"init_on_free=1\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation", "tails"],
        || kernel::check_kernel_params("init_on_free=1"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Zero memory at free time. Mitigates use-after-free exploits by erasing sensitive information in memory.")
    .with_fix("Add \"init_on_free=1\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_007",
        "Ensure that kernel flag \"pti=on\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("pti=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable kernel page table isolation to harden against kernel ASLR (KASLR) bypasses, mitigates the Meltdown (CVE-2017-5754) CPU vulnerability.")
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#kernel-address-space-layout-randomization-kaslr")
    .with_fix("Add \"pti=on\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_008",
        "Ensure that kernel flag \"randomize_kstack_offset=on\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation", "tails"],
        || kernel::check_kernel_params("randomize_kstack_offset=on"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Enable randomization of the kernel stack offset on syscall entries. Hardens against memory corruption attacks due to increased entropy limits attacks relying on deterministic stack addresses or cross-syscall address exposure.")
    .with_fix("Add \"randomize_kstack_offset=on\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_009",
        "Ensure that kernel flag \"vsyscall=none\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation", "tails"],
        || kernel::check_kernel_params("vsyscall=none"),
        vec![kernel::init_kernel_params],
    )
    .with_description("Disable vsyscalls to reduce attack surface as they have been replaced by vDSO vulnerable to ROP attacks as vsyscalls are located at fixed addresses in memory. Specific to x86_64 arch.")
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
    .with_description("Restrict access to debugfs that can contain sensitive information.")
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
    .with_link("https://man.archlinux.org/man/kernel_lockdown.7")
    .with_fix("Add \"lockdown=integrity\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_014",
        "Ensure that kernel flag \"mce=0\" is present",
        Severity::Low,
        vec!["kernel", "server", "workstation", "tails"],
        || kernel::check_kernel_params("mce=0"),
        vec![kernel::init_kernel_params],
    )
    .with_fix("Add \"mce=0\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_015",
        "Ensure that kernel flag \"kfence.sample_interval=100\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("kfence.sample_interval=100"),
        vec![kernel::init_kernel_params],
    )
    .with_fix("Add \"kfence.sample_interval=100\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_017",
        "Ensure that kernel flag \"vdso32=0\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("vdso32=0"),
        vec![kernel::init_kernel_params],
    )
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
    .with_fix("Add \"iommu=force\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_021",
        "Ensure that kernel flag \"iommu.passthrough=0\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("iommu.passthrough=0"),
        vec![kernel::init_kernel_params],
    )
    .with_fix("Add \"iommu.passthrough=0\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_022",
        "Ensure that kernel flag \"iommu.strict=1\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("iommu.strict=1"),
        vec![kernel::init_kernel_params],
    )
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
    .with_fix("Add \"random.trust_bootloader=off\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_025",
        "Ensure that kernel flag \"random.trust_cpu=off\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("random.trust_cpu=off"),
        vec![kernel::init_kernel_params],
    )
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
    .with_fix("Add \"ia32_emulation=0\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_016",
        "Ensure that kernel flag \"cfi=kcfi\" is present",
        Severity::Medium,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("cfi=kcfi"),
        vec![kernel::init_kernel_params],
    )
    .with_fix("Add \"cfi=kcfi\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_062",
        "Ensure that kernel flag \"random.trust_cpu=off\" is present",
        Severity::Medium,
        vec!["kernel", "paranoid", "server", "workstation"],
        || kernel::check_kernel_params("random.trust_cpu=off"),
        vec![kernel::init_kernel_params],
    )
    .with_fix("Add \"random.trust_cpu=off\" to bootloader kernel params.")
    .register();

    // from: kernel-hardening-checker
    check::Check::new(
        "KNP_063",
        "Ensure that kernel flag \"hardened_usercopy=1\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("hardened_usercopy=1"),
        vec![kernel::init_kernel_params],
    )
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
    .with_fix("Add \"remountsecure=3\" to bootloader kernel params.")
    .register();

    // X86 64 and 32 CPU mitigations
    // https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/40_cpu_mitigations.cfg
    check::Check::new(
        "KNP_030",
        "Ensure that kernel flag \"mitigations=auto\" is present",
        Severity::High,
        vec!["kernel", "server", "workstation"],
        || kernel::check_kernel_params("mitigations=auto"),
        vec![kernel::init_kernel_params],
    )
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
    .with_fix("Add \"mitigations=auto,nosmt\" to bootloader kernel params.")
    .register();

    check::Check::new(
        "KNP_031",
        "Ensure that kernel flag \"nosmt=force\" is present",
        Severity::High,
        vec!["kernel", "paranoid", "server", "workstation", "paranoid"],
        || kernel::check_kernel_params("nosmt=force"),
        vec![kernel::init_kernel_params],
    )
    .with_description(
        "Disabling will significantly decrease system performance on multi-threaded tasks.",
    )
    .with_fix("Add \"nosmt=force\" to bootloader kernel params.")
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
    .with_description("Enable mitigation for the Intel branch history injection vulnerability. Affecting both Intel and AMD CPUs.")
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
    .with_description("Enable mitigation for the Intel branch history injection vulnerability. Affecting both Intel and AMD CPUs.")
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
        "Unconditionally disable the Speculative Store Bypass (SSB) on affected CPUs.",
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

    check::Check::new(
        "KNP_062",
        "Ensure that kernel flag \"slub_debug=FZ\" is present",
        Severity::Medium,
        vec!["kernel", "server", "workstation", "tails"],
        || kernel::check_kernel_params("slub_debug=FZ"),
        vec![kernel::init_kernel_params],
    )
    .with_fix("Add \"slub_debug=FZ\" to bootloader kernel params.")
    .register();
}
