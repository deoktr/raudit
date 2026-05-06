use crate::check;
use crate::check::Severity;
use crate::modules::kconfig;

pub fn add_checks() {
    check::Check::new(
        "KNC_038",
        "Ensure kernel build option \"CONFIG_EFI\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_EFI"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_EFI\" disabled (\"# CONFIG_EFI is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_042",
        "Ensure kernel build option \"CONFIG_CPU_SUP_AMD\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_CPU_SUP_AMD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_CPU_SUP_AMD\" disabled (\"# CONFIG_CPU_SUP_AMD is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_043",
        "Ensure kernel build option \"CONFIG_CPU_SUP_INTEL\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_CPU_SUP_INTEL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_CPU_SUP_INTEL\" disabled (\"# CONFIG_CPU_SUP_INTEL is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_044",
        "Ensure kernel build option \"CONFIG_MODULES\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf", "paranoid"],
        || kconfig::check_option_is_not_set("CONFIG_MODULES"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_MODULES\" disabled (\"# CONFIG_MODULES is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_045",
        "Ensure kernel build option \"CONFIG_DEVMEM\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DEVMEM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_DEVMEM\" disabled (\"# CONFIG_DEVMEM is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_046",
        "Ensure kernel build option \"CONFIG_BPF_SYSCALL\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BPF_SYSCALL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_BPF_SYSCALL\" disabled (\"# CONFIG_BPF_SYSCALL is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_047",
        "Ensure kernel build option \"CONFIG_BUG\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_BUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_BUG=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_049",
        "Ensure kernel build option \"CONFIG_THREAD_INFO_IN_TASK\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_THREAD_INFO_IN_TASK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_THREAD_INFO_IN_TASK=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_050",
        "Ensure kernel build option \"CONFIG_IOMMU_SUPPORT\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_IOMMU_SUPPORT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_IOMMU_SUPPORT=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_051",
        "Ensure kernel build option \"CONFIG_RANDOMIZE_BASE\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_RANDOMIZE_BASE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Enables Kernel Address Space Layout Randomization (KASLR).")
    .with_fix("Recompile the kernel with \"CONFIG_RANDOMIZE_BASE=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#kernel-address-space-layout-randomization-kaslr")
    .register();

    check::Check::new(
        "KNC_052",
        "Ensure kernel build option \"CONFIG_LIST_HARDENED\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_LIST_HARDENED"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_LIST_HARDENED=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_053",
        "Ensure kernel build option \"CONFIG_RANDOM_KMALLOC_CACHES\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_RANDOM_KMALLOC_CACHES"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_RANDOM_KMALLOC_CACHES=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_054",
        "Ensure kernel build option \"CONFIG_SLAB_MERGE_DEFAULT\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SLAB_MERGE_DEFAULT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SLAB_MERGE_DEFAULT=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_055",
        "Ensure kernel build option \"CONFIG_PAGE_TABLE_CHECK\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_PAGE_TABLE_CHECK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .register();

    check::Check::new(
        "KNC_056",
        "Ensure kernel build option \"CONFIG_PAGE_TABLE_CHECK_ENFORCED\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_PAGE_TABLE_CHECK_ENFORCED"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_PAGE_TABLE_CHECK_ENFORCED=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_057",
        "Ensure kernel build option \"CONFIG_BUG_ON_DATA_CORRUPTION\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_BUG_ON_DATA_CORRUPTION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_BUG_ON_DATA_CORRUPTION=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_058",
        "Ensure kernel build option \"CONFIG_SLAB_FREELIST_HARDENED\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SLAB_FREELIST_HARDENED"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SLAB_FREELIST_HARDENED=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_059",
        "Ensure kernel build option \"CONFIG_SLAB_FREELIST_RANDOM\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SLAB_FREELIST_RANDOM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SLAB_FREELIST_RANDOM=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_060",
        "Ensure kernel build option \"CONFIG_SHUFFLE_PAGE_ALLOCATOR\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SHUFFLE_PAGE_ALLOCATOR"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SHUFFLE_PAGE_ALLOCATOR=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_061",
        "Ensure kernel build option \"CONFIG_FORTIFY_SOURCE\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_FORTIFY_SOURCE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_FORTIFY_SOURCE=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_065",
        "Ensure kernel build option \"CONFIG_INIT_ON_ALLOC_DEFAULT_ON\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_INIT_ON_ALLOC_DEFAULT_ON"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_066",
        "Ensure kernel build option \"CONFIG_STATIC_USERMODEHELPER\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_STATIC_USERMODEHELPER"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_STATIC_USERMODEHELPER=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_067",
        "Ensure kernel build option \"CONFIG_SCHED_CORE\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SCHED_CORE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SCHED_CORE=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_068",
        "Ensure kernel build option \"CONFIG_SECURITY_LOCKDOWN_LSM\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_LOCKDOWN_LSM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SECURITY_LOCKDOWN_LSM=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_069",
        "Ensure kernel build option \"CONFIG_SECURITY_LOCKDOWN_LSM_EARLY\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_LOCKDOWN_LSM_EARLY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_070",
        "Ensure kernel build option \"CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    // security policy
    check::Check::new(
        "KNC_073",
        "Ensure kernel build option \"CONFIG_SECURITY\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECURITY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SECURITY=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_074",
        "Ensure kernel build option \"CONFIG_SECURITY_YAMA\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_YAMA"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SECURITY_YAMA=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_075",
        "Ensure kernel build option \"CONFIG_SECURITY_LANDLOCK\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_LANDLOCK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SECURITY_LANDLOCK=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_076",
        "Ensure kernel build option \"CONFIG_SECURITY_SELINUX_DISABLE\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_SELINUX_DISABLE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"# CONFIG_SECURITY_SELINUX_DISABLE is not set\" in .config and reboot.")
    .register();

    check::Check::new(
        "KNC_077",
        "Ensure kernel build option \"CONFIG_SECURITY_SELINUX_BOOTPARAM\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_SELINUX_BOOTPARAM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SECURITY_SELINUX_BOOTPARAM\" disabled (\"# CONFIG_SECURITY_SELINUX_BOOTPARAM is not set\" in .config) and reboot.")
    .register();

    // TODO: set N
    check::Check::new(
        "KNC_078",
        "Ensure kernel build option \"CONFIG_SECURITY_SELINUX_DEVELOP\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_SELINUX_DEVELOP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SECURITY_SELINUX_DEVELOP\" disabled (\"# CONFIG_SECURITY_SELINUX_DEVELOP is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_079",
        "Ensure kernel build option \"CONFIG_SECURITY_WRITABLE_HOOKS\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_WRITABLE_HOOKS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SECURITY_WRITABLE_HOOKS\" disabled (\"# CONFIG_SECURITY_WRITABLE_HOOKS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_080",
        "Ensure kernel build option \"CONFIG_SECURITY_SELINUX_DEBUG\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SECURITY_SELINUX_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SECURITY_SELINUX_DEBUG\" disabled (\"# CONFIG_SECURITY_SELINUX_DEBUG is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_081",
        "Ensure kernel build option \"CONFIG_SECCOMP\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECCOMP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SECCOMP=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_082",
        "Ensure kernel build option \"CONFIG_SECCOMP_FILTER\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECCOMP_FILTER"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SECCOMP_FILTER=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_083",
        "Ensure kernel build option \"CONFIG_BPF_UNPRIV_DEFAULT_OFF\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_BPF_UNPRIV_DEFAULT_OFF"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_BPF_UNPRIV_DEFAULT_OFF=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_084",
        "Ensure kernel build option \"CONFIG_STRICT_DEVMEM\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_STRICT_DEVMEM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_STRICT_DEVMEM=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_085",
        "Ensure kernel build option \"CONFIG_X86_INTEL_TSX_MODE_OFF\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_X86_INTEL_TSX_MODE_OFF"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_X86_INTEL_TSX_MODE_OFF=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_087",
        "Ensure kernel build option \"CONFIG_SECURITY_DMESG_RESTRICT\" is set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_SECURITY_DMESG_RESTRICT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SECURITY_DMESG_RESTRICT=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .register();

    check::Check::new(
        "KNC_088",
        "Ensure kernel build option \"CONFIG_ACPI_CUSTOM_METHOD\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_ACPI_CUSTOM_METHOD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"# CONFIG_ACPI_CUSTOM_METHOD is not set\" in .config and reboot.")
    .register();

    check::Check::new(
        "KNC_089",
        "Ensure kernel build option \"CONFIG_COMPAT_BRK\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_COMPAT_BRK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_COMPAT_BRK\" disabled (\"# CONFIG_COMPAT_BRK is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_090",
        "Ensure kernel build option \"CONFIG_DEVKMEM\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DEVKMEM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_DEVKMEM\" disabled (\"# CONFIG_DEVKMEM is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_091",
        "Ensure kernel build option \"CONFIG_BINFMT_MISC\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BINFMT_MISC"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_BINFMT_MISC\" disabled (\"# CONFIG_BINFMT_MISC is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_092",
        "Ensure kernel build option \"CONFIG_INET_DIAG\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_INET_DIAG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_INET_DIAG\" disabled (\"# CONFIG_INET_DIAG is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_093",
        "Ensure kernel build option \"CONFIG_KEXEC\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KEXEC"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_KEXEC\" disabled (\"# CONFIG_KEXEC is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_094",
        "Ensure kernel build option \"CONFIG_PROC_KCORE\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PROC_KCORE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_PROC_KCORE\" disabled (\"# CONFIG_PROC_KCORE is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_095",
        "Ensure kernel build option \"CONFIG_LEGACY_PTYS\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_LEGACY_PTYS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_LEGACY_PTYS\" disabled (\"# CONFIG_LEGACY_PTYS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_096",
        "Ensure kernel build option \"CONFIG_HIBERNATION\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_HIBERNATION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_HIBERNATION\" disabled (\"# CONFIG_HIBERNATION is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_097",
        "Ensure kernel build option \"CONFIG_COMPAT\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_COMPAT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Eliminate many syscalls for 64-bit systems. Limits the breadth of kernel code that can be reached, possibly reducing the availability of a given bug to an attack.")
    .with_fix("Recompile the kernel with \"CONFIG_COMPAT\" disabled (\"# CONFIG_COMPAT is not set\" in .config) and reboot.")
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#reduced-access-to-syscalls")
    .register();

    check::Check::new(
        "KNC_098",
        "Ensure kernel build option \"CONFIG_IA32_EMULATION\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_IA32_EMULATION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_IA32_EMULATION\" disabled (\"# CONFIG_IA32_EMULATION is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_099",
        "Ensure kernel build option \"CONFIG_X86_X32\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_X32"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_X86_X32\" disabled (\"# CONFIG_X86_X32 is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_100",
        "Ensure kernel build option \"CONFIG_X86_X32_ABI\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_X32_ABI"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_X86_X32_ABI\" disabled (\"# CONFIG_X86_X32_ABI is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_101",
        "Ensure kernel build option \"CONFIG_MODIFY_LDT_SYSCALL\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MODIFY_LDT_SYSCALL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_MODIFY_LDT_SYSCALL\" disabled (\"# CONFIG_MODIFY_LDT_SYSCALL is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_102",
        "Ensure kernel build option \"CONFIG_OABI_COMPAT\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_OABI_COMPAT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_OABI_COMPAT\" disabled (\"# CONFIG_OABI_COMPAT is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_103",
        "Ensure kernel build option \"CONFIG_X86_MSR\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_MSR"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_X86_MSR\" disabled (\"# CONFIG_X86_MSR is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_104",
        "Ensure kernel build option \"CONFIG_LEGACY_TIOCSTI\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_LEGACY_TIOCSTI"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_LEGACY_TIOCSTI\" disabled (\"# CONFIG_LEGACY_TIOCSTI is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_105",
        "Ensure kernel build option \"CONFIG_MODULE_FORCE_LOAD\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MODULE_FORCE_LOAD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_MODULE_FORCE_LOAD\" disabled (\"# CONFIG_MODULE_FORCE_LOAD is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_106",
        "Ensure kernel build option \"CONFIG_DRM_LEGACY\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DRM_LEGACY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_DRM_LEGACY\" disabled (\"# CONFIG_DRM_LEGACY is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_107",
        "Ensure kernel build option \"CONFIG_FB\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_FB"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_FB\" disabled (\"# CONFIG_FB is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_108",
        "Ensure kernel build option \"CONFIG_VT\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_VT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_VT\" disabled (\"# CONFIG_VT is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_109",
        "Ensure kernel build option \"CONFIG_BLK_DEV_FD\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_FD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_BLK_DEV_FD\" disabled (\"# CONFIG_BLK_DEV_FD is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_110",
        "Ensure kernel build option \"CONFIG_BLK_DEV_FD_RAWCMD\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_FD_RAWCMD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_BLK_DEV_FD_RAWCMD\" disabled (\"# CONFIG_BLK_DEV_FD_RAWCMD is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_111",
        "Ensure kernel build option \"CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT\" disabled (\"# CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_112",
        "Ensure kernel build option \"CONFIG_N_GSM\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_N_GSM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_N_GSM\" disabled (\"# CONFIG_N_GSM is not set\" in .config) and reboot.")
    .register();

    // grsec
    check::Check::new(
        "KNC_116",
        "Ensure kernel build option \"CONFIG_ZSMALLOC_STAT\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_ZSMALLOC_STAT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_ZSMALLOC_STAT\" disabled (\"# CONFIG_ZSMALLOC_STAT is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_117",
        "Ensure kernel build option \"CONFIG_DEBUG_KMEMLEAK\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DEBUG_KMEMLEAK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_DEBUG_KMEMLEAK\" disabled (\"# CONFIG_DEBUG_KMEMLEAK is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_118",
        "Ensure kernel build option \"CONFIG_BINFMT_AOUT\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BINFMT_AOUT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .register();

    check::Check::new(
        "KNC_119",
        "Ensure kernel build option \"CONFIG_KPROBE_EVENTS\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KPROBE_EVENTS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_KPROBE_EVENTS\" disabled (\"# CONFIG_KPROBE_EVENTS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_120",
        "Ensure kernel build option \"CONFIG_UPROBE_EVENTS\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_UPROBE_EVENTS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_UPROBE_EVENTS\" disabled (\"# CONFIG_UPROBE_EVENTS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_121",
        "Ensure kernel build option \"CONFIG_GENERIC_TRACER\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_GENERIC_TRACER"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_GENERIC_TRACER\" disabled (\"# CONFIG_GENERIC_TRACER is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_122",
        "Ensure kernel build option \"CONFIG_FUNCTION_TRACER\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_FUNCTION_TRACER"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_FUNCTION_TRACER\" disabled (\"# CONFIG_FUNCTION_TRACER is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_123",
        "Ensure kernel build option \"CONFIG_STACK_TRACER\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_STACK_TRACER"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_STACK_TRACER\" disabled (\"# CONFIG_STACK_TRACER is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_124",
        "Ensure kernel build option \"CONFIG_HIST_TRIGGERS\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_HIST_TRIGGERS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_HIST_TRIGGERS\" disabled (\"# CONFIG_HIST_TRIGGERS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_125",
        "Ensure kernel build option \"CONFIG_BLK_DEV_IO_TRACE\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_IO_TRACE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_BLK_DEV_IO_TRACE\" disabled (\"# CONFIG_BLK_DEV_IO_TRACE is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_126",
        "Ensure kernel build option \"CONFIG_PROC_VMCORE\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PROC_VMCORE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_PROC_VMCORE\" disabled (\"# CONFIG_PROC_VMCORE is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_127",
        "Ensure kernel build option \"CONFIG_PROC_PAGE_MONITOR\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PROC_PAGE_MONITOR"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_PROC_PAGE_MONITOR\" disabled (\"# CONFIG_PROC_PAGE_MONITOR is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_128",
        "Ensure kernel build option \"CONFIG_USELIB\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_USELIB"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_USELIB\" disabled (\"# CONFIG_USELIB is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_129",
        "Ensure kernel build option \"CONFIG_CHECKPOINT_RESTORE\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_CHECKPOINT_RESTORE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_CHECKPOINT_RESTORE\" disabled (\"# CONFIG_CHECKPOINT_RESTORE is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_130",
        "Ensure kernel build option \"CONFIG_USERFAULTFD\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_USERFAULTFD"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_USERFAULTFD\" disabled (\"# CONFIG_USERFAULTFD is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_131",
        "Ensure kernel build option \"CONFIG_HWPOISON_INJECT\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_HWPOISON_INJECT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_HWPOISON_INJECT\" disabled (\"# CONFIG_HWPOISON_INJECT is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_132",
        "Ensure kernel build option \"CONFIG_MEM_SOFT_DIRTY\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MEM_SOFT_DIRTY"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_MEM_SOFT_DIRTY\" disabled (\"# CONFIG_MEM_SOFT_DIRTY is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_133",
        "Ensure kernel build option \"CONFIG_DEVPORT\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DEVPORT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_DEVPORT\" disabled (\"# CONFIG_DEVPORT is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_134",
        "Ensure kernel build option \"CONFIG_DEBUG_FS\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DEBUG_FS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_DEBUG_FS\" disabled (\"# CONFIG_DEBUG_FS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_135",
        "Ensure kernel build option \"CONFIG_NOTIFIER_ERROR_INJECTION\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_NOTIFIER_ERROR_INJECTION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_NOTIFIER_ERROR_INJECTION\" disabled (\"# CONFIG_NOTIFIER_ERROR_INJECTION is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_136",
        "Ensure kernel build option \"CONFIG_FAIL_FUTEX\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_FAIL_FUTEX"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_FAIL_FUTEX\" disabled (\"# CONFIG_FAIL_FUTEX is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_137",
        "Ensure kernel build option \"CONFIG_PUNIT_ATOM_DEBUG\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PUNIT_ATOM_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_PUNIT_ATOM_DEBUG\" disabled (\"# CONFIG_PUNIT_ATOM_DEBUG is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_138",
        "Ensure kernel build option \"CONFIG_ACPI_CONFIGFS\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_ACPI_CONFIGFS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_ACPI_CONFIGFS\" disabled (\"# CONFIG_ACPI_CONFIGFS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_139",
        "Ensure kernel build option \"CONFIG_EDAC_DEBUG\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_EDAC_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_EDAC_DEBUG\" disabled (\"# CONFIG_EDAC_DEBUG is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_140",
        "Ensure kernel build option \"CONFIG_DRM_I915_DEBUG\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DRM_I915_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_DRM_I915_DEBUG\" disabled (\"# CONFIG_DRM_I915_DEBUG is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_141",
        "Ensure kernel build option \"CONFIG_BCACHE_CLOSURES_DEBUG\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BCACHE_CLOSURES_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_BCACHE_CLOSURES_DEBUG\" disabled (\"# CONFIG_BCACHE_CLOSURES_DEBUG is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_142",
        "Ensure kernel build option \"CONFIG_DVB_C8SECTPFE\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_DVB_C8SECTPFE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_DVB_C8SECTPFE\" disabled (\"# CONFIG_DVB_C8SECTPFE is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_143",
        "Ensure kernel build option \"CONFIG_MTD_SLRAM\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MTD_SLRAM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_MTD_SLRAM\" disabled (\"# CONFIG_MTD_SLRAM is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_144",
        "Ensure kernel build option \"CONFIG_MTD_PHRAM\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MTD_PHRAM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_MTD_PHRAM\" disabled (\"# CONFIG_MTD_PHRAM is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_145",
        "Ensure kernel build option \"CONFIG_IO_URING\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_IO_URING"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_IO_URING\" disabled (\"# CONFIG_IO_URING is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_146",
        "Ensure kernel build option \"CONFIG_KCMP\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KCMP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_KCMP\" disabled (\"# CONFIG_KCMP is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_147",
        "Ensure kernel build option \"CONFIG_RSEQ\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_RSEQ"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_RSEQ\" disabled (\"# CONFIG_RSEQ is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_148",
        "Ensure kernel build option \"CONFIG_LATENCYTOP\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_LATENCYTOP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_LATENCYTOP\" disabled (\"# CONFIG_LATENCYTOP is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_149",
        "Ensure kernel build option \"CONFIG_KCOV\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KCOV"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_KCOV\" disabled (\"# CONFIG_KCOV is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_150",
        "Ensure kernel build option \"CONFIG_PROVIDE_OHCI1394_DMA_INIT\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PROVIDE_OHCI1394_DMA_INIT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_PROVIDE_OHCI1394_DMA_INIT\" disabled (\"# CONFIG_PROVIDE_OHCI1394_DMA_INIT is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_151",
        "Ensure kernel build option \"CONFIG_SUNRPC_DEBUG\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SUNRPC_DEBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SUNRPC_DEBUG\" disabled (\"# CONFIG_SUNRPC_DEBUG is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_152",
        "Ensure kernel build option \"CONFIG_X86_16BIT\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_16BIT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_X86_16BIT\" disabled (\"# CONFIG_X86_16BIT is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_153",
        "Ensure kernel build option \"CONFIG_BLK_DEV_UBLK\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_UBLK"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_BLK_DEV_UBLK\" disabled (\"# CONFIG_BLK_DEV_UBLK is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_154",
        "Ensure kernel build option \"CONFIG_SMB_SERVER\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_SMB_SERVER"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_SMB_SERVER\" disabled (\"# CONFIG_SMB_SERVER is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_155",
        "Ensure kernel build option \"CONFIG_XFS_ONLINE_SCRUB_STATS\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_XFS_ONLINE_SCRUB_STATS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_XFS_ONLINE_SCRUB_STATS\" disabled (\"# CONFIG_XFS_ONLINE_SCRUB_STATS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_156",
        "Ensure kernel build option \"CONFIG_CACHESTAT_SYSCALL\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_CACHESTAT_SYSCALL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_CACHESTAT_SYSCALL\" disabled (\"# CONFIG_CACHESTAT_SYSCALL is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_157",
        "Ensure kernel build option \"CONFIG_PREEMPTIRQ_TRACEPOINTS\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PREEMPTIRQ_TRACEPOINTS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_PREEMPTIRQ_TRACEPOINTS\" disabled (\"# CONFIG_PREEMPTIRQ_TRACEPOINTS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_158",
        "Ensure kernel build option \"CONFIG_ENABLE_DEFAULT_TRACERS\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_ENABLE_DEFAULT_TRACERS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_ENABLE_DEFAULT_TRACERS\" disabled (\"# CONFIG_ENABLE_DEFAULT_TRACERS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_159",
        "Ensure kernel build option \"CONFIG_PROVE_LOCKING\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PROVE_LOCKING"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_PROVE_LOCKING\" disabled (\"# CONFIG_PROVE_LOCKING is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_160",
        "Ensure kernel build option \"CONFIG_TEST_DEBUG_VIRTUAL\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_TEST_DEBUG_VIRTUAL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_TEST_DEBUG_VIRTUAL\" disabled (\"# CONFIG_TEST_DEBUG_VIRTUAL is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_161",
        "Ensure kernel build option \"CONFIG_MPTCP\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MPTCP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_MPTCP\" disabled (\"# CONFIG_MPTCP is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_162",
        "Ensure kernel build option \"CONFIG_TLS\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_TLS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_TLS\" disabled (\"# CONFIG_TLS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_163",
        "Ensure kernel build option \"CONFIG_TIPC\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_TIPC"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_TIPC\" disabled (\"# CONFIG_TIPC is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_164",
        "Ensure kernel build option \"CONFIG_IP_SCTP\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_IP_SCTP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_IP_SCTP\" disabled (\"# CONFIG_IP_SCTP is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_165",
        "Ensure kernel build option \"CONFIG_KGDB\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KGDB"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_KGDB\" disabled (\"# CONFIG_KGDB is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_166",
        "Ensure kernel build option \"CONFIG_PTDUMP_DEBUGFS\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_PTDUMP_DEBUGFS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_PTDUMP_DEBUGFS\" disabled (\"# CONFIG_PTDUMP_DEBUGFS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_167",
        "Ensure kernel build option \"CONFIG_X86_PTDUMP\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_PTDUMP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_X86_PTDUMP\" disabled (\"# CONFIG_X86_PTDUMP is not set\" in .config) and reboot.")
    .register();

    // clipos
    check::Check::new(
        "KNC_170",
        "Ensure kernel build option \"CONFIG_STAGING\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_STAGING"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_STAGING\" disabled (\"# CONFIG_STAGING is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_171",
        "Ensure kernel build option \"CONFIG_KSM\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KSM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_KSM\" disabled (\"# CONFIG_KSM is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_172",
        "Ensure kernel build option \"CONFIG_KALLSYMS\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KALLSYMS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_KALLSYMS\" disabled (\"# CONFIG_KALLSYMS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_173",
        "Ensure kernel build option \"CONFIG_KEXEC_FILE\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KEXEC_FILE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_KEXEC_FILE\" disabled (\"# CONFIG_KEXEC_FILE is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_174",
        "Ensure kernel build option \"CONFIG_CRASH_DUMP\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_CRASH_DUMP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_CRASH_DUMP\" disabled (\"# CONFIG_CRASH_DUMP is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_175",
        "Ensure kernel build option \"CONFIG_USER_NS\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_USER_NS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_USER_NS\" disabled (\"# CONFIG_USER_NS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_176",
        "Ensure kernel build option \"CONFIG_X86_CPUID\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_CPUID"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_X86_CPUID\" disabled (\"# CONFIG_X86_CPUID is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_177",
        "Ensure kernel build option \"CONFIG_X86_IOPL_IOPERM\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_X86_IOPL_IOPERM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_X86_IOPL_IOPERM\" disabled (\"# CONFIG_X86_IOPL_IOPERM is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_178",
        "Ensure kernel build option \"CONFIG_ACPI_TABLE_UPGRADE\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_ACPI_TABLE_UPGRADE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_ACPI_TABLE_UPGRADE\" disabled (\"# CONFIG_ACPI_TABLE_UPGRADE is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_179",
        "Ensure kernel build option \"CONFIG_EFI_CUSTOM_SSDT_OVERLAYS\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_EFI_CUSTOM_SSDT_OVERLAYS"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_EFI_CUSTOM_SSDT_OVERLAYS\" disabled (\"# CONFIG_EFI_CUSTOM_SSDT_OVERLAYS is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_180",
        "Ensure kernel build option \"CONFIG_AIO\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_AIO"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_AIO\" disabled (\"# CONFIG_AIO is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_181",
        "Ensure kernel build option \"CONFIG_MAGIC_SYSRQ\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MAGIC_SYSRQ"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_MAGIC_SYSRQ\" disabled (\"# CONFIG_MAGIC_SYSRQ is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_182",
        "Ensure kernel build option \"CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE\" disabled (\"# CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_183",
        "Ensure kernel build option \"CONFIG_MAGIC_SYSRQ_SERIAL\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MAGIC_SYSRQ_SERIAL"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_MAGIC_SYSRQ_SERIAL\" disabled (\"# CONFIG_MAGIC_SYSRQ_SERIAL is not set\" in .config) and reboot.")
    .register();

    // grapheneos
    check::Check::new(
        "KNC_187",
        "Ensure kernel build option \"CONFIG_EFI_TEST\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_EFI_TEST"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_EFI_TEST\" disabled (\"# CONFIG_EFI_TEST is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_188",
        "Ensure kernel build option \"CONFIG_MMIOTRACE_TEST\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MMIOTRACE_TEST"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_MMIOTRACE_TEST\" disabled (\"# CONFIG_MMIOTRACE_TEST is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_189",
        "Ensure kernel build option \"CONFIG_KPROBES\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_KPROBES"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_KPROBES\" disabled (\"# CONFIG_KPROBES is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_191",
        "Ensure kernel build option \"CONFIG_MMIOTRACE\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_MMIOTRACE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_MMIOTRACE\" disabled (\"# CONFIG_MMIOTRACE is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_192",
        "Ensure kernel build option \"CONFIG_LIVEPATCH\" is not set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_LIVEPATCH"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_LIVEPATCH\" disabled (\"# CONFIG_LIVEPATCH is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_193",
        "Ensure kernel build option \"CONFIG_IP_DCCP\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_IP_DCCP"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_IP_DCCP\" disabled (\"# CONFIG_IP_DCCP is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_194",
        "Ensure kernel build option \"CONFIG_FTRACE\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_FTRACE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_FTRACE\" disabled (\"# CONFIG_FTRACE is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_195",
        "Ensure kernel build option \"CONFIG_VIDEO_VIVID\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_VIDEO_VIVID"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_VIDEO_VIVID\" disabled (\"# CONFIG_VIDEO_VIVID is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_196",
        "Ensure kernel build option \"CONFIG_INPUT_EVBUG\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_INPUT_EVBUG"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_INPUT_EVBUG\" disabled (\"# CONFIG_INPUT_EVBUG is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_197",
        "Ensure kernel build option \"CONFIG_CORESIGHT\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_CORESIGHT"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_CORESIGHT\" disabled (\"# CONFIG_CORESIGHT is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_198",
        "Ensure kernel build option \"CONFIG_XFS_SUPPORT_V4\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_XFS_SUPPORT_V4"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_XFS_SUPPORT_V4\" disabled (\"# CONFIG_XFS_SUPPORT_V4 is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_199",
        "Ensure kernel build option \"CONFIG_BLK_DEV_WRITE_MOUNTED\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_BLK_DEV_WRITE_MOUNTED"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_BLK_DEV_WRITE_MOUNTED\" disabled (\"# CONFIG_BLK_DEV_WRITE_MOUNTED is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_200",
        "Ensure kernel build option \"CONFIG_FAULT_INJECTION\" is not set",
        Severity::Medium,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_FAULT_INJECTION"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_FAULT_INJECTION\" disabled (\"# CONFIG_FAULT_INJECTION is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_201",
        "Ensure kernel build option \"CONFIG_LKDTM\" is not set",
        Severity::Low,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_not_set("CONFIG_LKDTM"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_fix("Recompile the kernel with \"CONFIG_LKDTM\" disabled (\"# CONFIG_LKDTM is not set\" in .config) and reboot.")
    .register();

    check::Check::new(
        "KNC_202",
        "Ensure kernel build option \"CONFIG_STRICT_KERNEL_RWX\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_STRICT_KERNEL_RWX"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Executable code and read-only data must not be writable.")
    .with_fix("Recompile the kernel with \"CONFIG_STRICT_KERNEL_RWX=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#executable-code-and-read-only-data-must-not-be-writable")
    .register();

    check::Check::new(
        "KNC_203",
        "Ensure kernel build option \"CONFIG_STRICT_MODULE_RWX\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_STRICT_MODULE_RWX"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Executable code and read-only data must not be writable.")
    .with_fix("Recompile the kernel with \"CONFIG_STRICT_MODULE_RWX=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#executable-code-and-read-only-data-must-not-be-writable")
    .register();

    check::Check::new(
        "KNC_204",
        "Ensure kernel build option \"CONFIG_MODULE_SIG_FORCE\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_MODULE_SIG_FORCE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("Keep from having root load arbitrary kernel code via the module loader interface. Redundant with \"module.sig_enforce=1\" kernel boot params.")
    .with_fix("Recompile the kernel with \"CONFIG_MODULE_SIG_FORCE=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#restricting-access-to-kernel-modules")
    .register();

    check::Check::new(
        "KNC_205",
        "Ensure kernel build option \"CONFIG_KSTACK_ERASE\" is set",
        Severity::High,
        vec!["kernel", "kernel_build_conf"],
        || kconfig::check_option_is_set("CONFIG_KSTACK_ERASE"),
        vec![kconfig::init_kernel_build_config],
    )
    .skip_when(kconfig::skip_no_kbuild_config)
    .with_description("When releasing memory poison the contents to avoid reuse attacks that rely on the old contents of memory.")
    .with_fix("Recompile the kernel with \"CONFIG_KSTACK_ERASE=y\" in the .config (or set in kconfig). Distros: install a kernel package that has it enabled, or follow your distro's kernel-build process.")
    .with_link("https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst#memory-poisoning")
    .register();
}
