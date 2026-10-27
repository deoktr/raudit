use crate::check;
use crate::check::Severity;
use crate::modules::{base, modprobe};

// Most kernel CVEs live in drivers and protocol parsers. The danger is that
// many modules are autoloaded on demand, and some autoload triggers are
// reachable by unprivileged users or by physical attack.
//
// Limitations:
//
// The module could also be directly inside the kernel, compiled-in-modules,
// making it's impossible to disable/blacklist and will always be loaded. In
// that case the solution would be to re-compile the kernel. A message is shown
// to the user in that case.
//
// Those measures only protect from attacks as user, not as root. They protect
// from auto-loading of modules on some triggers from user-space like:
// - Using certain syscalls (netlink, sockets, files operations...)
// - Plugging a USB or other device

/// Build the description for a blacklisted module check.
fn description_blacklist(module: &str, description: &str) -> String {
    format!(
        "Prevents the kernel module `{}` from auto-loading on hardware probe or subsystem request, reducing the attack surface from unused modules that could contain exploitable vulnerabilities. The module remains manually loadable by root if needed. {}",
        module, description
    )
}

/// Build the description for a disabled module check.
fn description_disabled(module: &str, description: &str) -> String {
    format!(
        "Prohibits the kernel module `{}` from loading, reducing the attack surface from unused modules that could contain exploitable vulnerabilities. Note that as root it's still possible to update the configuration and load the module. {}",
        module, description
    )
}

/// Build the remediation text for a blacklisted-module check.
fn fix_blacklist(module: &str) -> String {
    format!(
        "Add entry in `/etc/modprobe.d/blacklist.conf` with: `blacklist {}`",
        module
    )
}

/// Build the remediation text for a disabled-module check.
fn fix_disabled(module: &str) -> String {
    format!(
        "Add entry in `/etc/modprobe.d/disabled.conf` with: `install {} /bin/true`",
        module
    )
}

pub fn add_checks() {
    // modprobe.d configuration directory and files (KMD_)
    check::Check::new(
        "KMD_001",
        "Ensure `/etc/modprobe.d` directory is owned by root",
        Severity::High,
        vec!["module", "server", "workstation"],
        || base::check_dir_owner_id("/etc/modprobe.d", 0, 0),
        vec![],
    )
    .with_description("/etc/modprobe.d holds the module loading policy (blacklist, install, options) that every other module check relies on, non-root ownership lets that user rewrite the policy, re-enable disabled modules or inject module options, allowing for local privilege escalation.")
    .with_fix("chown root:root /etc/modprobe.d")
    .register();

    check::Check::new(
        "KMD_002",
        "Ensure `/etc/modprobe.d` directory permissions is 755 or stricter",
        Severity::High,
        vec!["module", "server", "workstation"],
        || base::check_dir_permission_or_stricter("/etc/modprobe.d", 0o755),
        vec![],
    )
    .with_description("/etc/modprobe.d holds the module loading policy, group or world writable permissions let unprivileged users drop a config file to override blacklists, re-enable disabled modules or inject module options, allowing for local privilege escalation.")
    .with_fix("chmod 755 /etc/modprobe.d")
    .register();

    check::Check::new(
        "KMD_003",
        "Ensure `/etc/modprobe.d` files are owned by root",
        Severity::High,
        vec!["module", "server", "workstation"],
        || base::check_dir_files_owner_id("/etc/modprobe.d/", 0, 0),
        vec![],
    )
    .with_description("Modprobe reads every `.conf` file in /etc/modprobe.d to build the module loading policy, a config file owned by a non-root user lets that user blacklist, re-enable or change options of any module, allowing for local privilege escalation.")
    .with_fix("chown -R root:root /etc/modprobe.d/*")
    .register();

    check::Check::new(
        "KMD_004",
        "Ensure `/etc/modprobe.d` files permissions are 644 or stricter",
        Severity::High,
        vec!["module", "server", "workstation"],
        || base::check_dir_files_permission_or_stricter("/etc/modprobe.d/", 0o644),
        vec![],
    )
    .with_description("Modprobe reads every `.conf` file in /etc/modprobe.d to build the module loading policy, a writable config file lets unprivileged users blacklist, re-enable or change options of any module, allowing for local privilege escalation.")
    .with_fix("chmod -R 644 /etc/modprobe.d/*")
    .register();

    // blacklisted modules
    check::Check::new(
        "KMB_001",
        "Ensure that kernel module `amd76x_edac` is blacklisted",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_blacklist("amd76x_edac"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_blacklist(
        "amd76x_edac",
        "Legacy AMD 76x EDAC memory-error reporting driver.",
    ))
    .with_fix(&fix_blacklist("amd76x_edac"))
    .register();

    check::Check::new(
        "KMB_002",
        "Ensure that kernel module `cdrom` is blacklisted",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_blacklist("cdrom"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_blacklist("cdrom", "CD/DVD drive support."))
    .with_fix(&fix_blacklist("cdrom"))
    .register();

    check::Check::new(
        "KMB_003",
        "Ensure that kernel module `evbug` is blacklisted",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_blacklist("evbug"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_blacklist(
        "evbug",
        "Logs every input event, debug.",
    ))
    .with_fix(&fix_blacklist("evbug"))
    .register();

    check::Check::new(
        "KMB_004",
        "Ensure that kernel module `snd_aw2` is blacklisted",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_blacklist("snd_aw2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_blacklist(
        "snd_aw2",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_blacklist("snd_aw2"))
    .register();

    check::Check::new(
        "KMB_005",
        "Ensure that kernel module `snd_intel8x0` is blacklisted",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_blacklist("snd_intel8x0"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_blacklist(
        "snd_intel8x0",
        "Ancient Intel AC97.",
    ))
    .with_fix(&fix_blacklist("snd_intel8x0"))
    .register();

    check::Check::new(
        "KMB_006",
        "Ensure that kernel module `snd_intel8x0m` is blacklisted",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_blacklist("snd_intel8x0m"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_blacklist(
        "snd_intel8x0m",
        "Ancient Intel AC97.",
    ))
    .with_fix(&fix_blacklist("snd_intel8x0m"))
    .register();

    check::Check::new(
        "KMB_007",
        "Ensure that kernel module `snd_pcsp` is blacklisted",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_blacklist("snd_pcsp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_blacklist("snd_pcsp", "Speaker as sound card."))
    .with_fix(&fix_blacklist("snd_pcsp"))
    .register();

    check::Check::new(
        "KMB_008",
        "Ensure that kernel module `sr_mod` is blacklisted",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_blacklist("sr_mod"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_blacklist("sr_mod", "CD/DVD drive support."))
    .with_fix(&fix_blacklist("sr_mod"))
    .register();

    check::Check::new(
        "KMB_009",
        "Ensure that kernel module `usbkbd` is blacklisted",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_blacklist("usbkbd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_blacklist(
        "usbkbd",
        "Legacy boot-protocol drivers superseded by usbhid. Can hijack input at boot.",
    ))
    .with_fix(&fix_blacklist("usbkbd"))
    .register();

    check::Check::new(
        "KMB_010",
        "Ensure that kernel module `usbmouse` is blacklisted",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_blacklist("usbmouse"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_blacklist(
        "usbmouse",
        "Legacy boot-protocol drivers superseded by usbhid. Can hijack input at boot.",
    ))
    .with_fix(&fix_blacklist("usbmouse"))
    .register();

    // disabled modules, grouped by theme with a dedicated ID prefix per theme

    // testing, debug and development-only modules (KMT_)
    check::Check::new(
        "KMT_001",
        "Ensure that kernel module `adummy` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("adummy"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "adummy",
        "Dummy ATM / ATM-over-TCP test.",
    ))
    .with_fix(&fix_disabled("adummy"))
    .register();

    check::Check::new(
        "KMT_002",
        "Ensure that kernel module `atmtcp` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("atmtcp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "atmtcp",
        "Dummy ATM / ATM-over-TCP test.",
    ))
    .with_fix(&fix_disabled("atmtcp"))
    .register();

    check::Check::new(
        "KMT_003",
        "Ensure that kernel module `comedi_example_test` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("comedi_example_test"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "comedi_example_test",
        "Comedi tests.",
    ))
    .with_fix(&fix_disabled("comedi_example_test"))
    .register();

    check::Check::new(
        "KMT_004",
        "Ensure that kernel module `comedi_test` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("comedi_test"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("comedi_test", "Comedi tests."))
    .with_fix(&fix_disabled("comedi_test"))
    .register();

    check::Check::new(
        "KMT_005",
        "Ensure that kernel module `dummy_can` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dummy_can"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "dummy_can",
        "Virtual CAN interfaces.",
    ))
    .with_fix(&fix_disabled("dummy_can"))
    .register();

    check::Check::new(
        "KMT_006",
        "Ensure that kernel module `dummy_irq` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dummy_irq"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dummy_irq", "Fake IRQ generator."))
    .with_fix(&fix_disabled("dummy_irq"))
    .register();

    check::Check::new(
        "KMT_007",
        "Ensure that kernel module `dvb_dummy_fe` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dvb_dummy_fe"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dvb_dummy_fe", "Dummy DVB frontend."))
    .with_fix(&fix_disabled("dvb_dummy_fe"))
    .register();

    check::Check::new(
        "KMT_008",
        "Ensure that kernel module `dwc3_haps` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dwc3_haps"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "dwc3_haps",
        "USB core on FPGA prototype.",
    ))
    .with_fix(&fix_disabled("dwc3_haps"))
    .register();

    check::Check::new(
        "KMT_009",
        "Ensure that kernel module `ehset` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ehset"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ehset",
        "USB compliance/test drivers.",
    ))
    .with_fix(&fix_disabled("ehset"))
    .register();

    check::Check::new(
        "KMT_010",
        "Ensure that kernel module `g_zero` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_zero"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_zero",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_zero"))
    .register();

    check::Check::new(
        "KMT_011",
        "Ensure that kernel module `gadgetfs` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gadgetfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "gadgetfs",
        "USB gadget test/userspace.",
    ))
    .with_fix(&fix_disabled("gadgetfs"))
    .register();

    check::Check::new(
        "KMT_012",
        "Ensure that kernel module `hangcheck_timer` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hangcheck_timer"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hangcheck_timer",
        "Legacy hang detector.",
    ))
    .with_fix(&fix_disabled("hangcheck_timer"))
    .register();

    check::Check::new(
        "KMT_013",
        "Ensure that kernel module `hci_vhci` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hci_vhci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hci_vhci", "Virtual bluetooth HCI."))
    .with_fix(&fix_disabled("hci_vhci"))
    .register();

    check::Check::new(
        "KMT_014",
        "Ensure that kernel module `lvstest` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("lvstest"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "lvstest",
        "USB compliance/test drivers.",
    ))
    .with_fix(&fix_disabled("lvstest"))
    .register();

    check::Check::new(
        "KMT_015",
        "Ensure that kernel module `mac80211_hwsim` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mac80211_hwsim"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mac80211_hwsim",
        "Software wifi simulator.",
    ))
    .with_fix(&fix_disabled("mac80211_hwsim"))
    .register();

    check::Check::new(
        "KMT_016",
        "Ensure that kernel module `nfcsim` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nfcsim"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nfcsim", "NFC simulators."))
    .with_fix(&fix_disabled("nfcsim"))
    .register();

    check::Check::new(
        "KMT_017",
        "Ensure that kernel module `ni_routes_test` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ni_routes_test"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ni_routes_test", "Comedi tests."))
    .with_fix(&fix_disabled("ni_routes_test"))
    .register();

    check::Check::new(
        "KMT_018",
        "Ensure that kernel module `nosy` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nosy"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nosy", "FireWire traffic sniffer."))
    .with_fix(&fix_disabled("nosy"))
    .register();

    check::Check::new(
        "KMT_019",
        "Ensure that kernel module `null_blk` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("null_blk"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "null_blk",
        "Null/loop block test devices.",
    ))
    .with_fix(&fix_disabled("null_blk"))
    .register();

    check::Check::new(
        "KMT_020",
        "Ensure that kernel module `pkcs7_test_key` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pkcs7_test_key"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pkcs7_test_key",
        "Test key for PKCS#7 parser.",
    ))
    .with_fix(&fix_disabled("pkcs7_test_key"))
    .register();

    check::Check::new(
        "KMT_021",
        "Ensure that kernel module `pktgen` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pktgen"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pktgen",
        "Packet generator, root-only.",
    ))
    .with_fix(&fix_disabled("pktgen"))
    .register();

    check::Check::new(
        "KMT_022",
        "Ensure that kernel module `pretimeout_panic` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pretimeout_panic"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pretimeout_panic",
        "Watchdog pretimeout panic gov.",
    ))
    .with_fix(&fix_disabled("pretimeout_panic"))
    .register();

    check::Check::new(
        "KMT_023",
        "Ensure that kernel module `raw_gadget` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("raw_gadget"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "raw_gadget",
        "USB gadget test/userspace.",
    ))
    .with_fix(&fix_disabled("raw_gadget"))
    .register();

    check::Check::new(
        "KMT_024",
        "Ensure that kernel module `rc_loopback` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rc_loopback"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("rc_loopback", "IR loopback test."))
    .with_fix(&fix_disabled("rc_loopback"))
    .register();

    check::Check::new(
        "KMT_025",
        "Ensure that kernel module `snd_aloop` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_aloop"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_aloop",
        "Audio loopback, virtual MIDI.",
    ))
    .with_fix(&fix_disabled("snd_aloop"))
    .register();

    check::Check::new(
        "KMT_026",
        "Ensure that kernel module `snd_dummy` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_dummy"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_dummy",
        "Dummy/test sound cards.",
    ))
    .with_fix(&fix_disabled("snd_dummy"))
    .register();

    check::Check::new(
        "KMT_027",
        "Ensure that kernel module `snd_pcmtest` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_pcmtest"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_pcmtest",
        "Dummy/test sound cards.",
    ))
    .with_fix(&fix_disabled("snd_pcmtest"))
    .register();

    check::Check::new(
        "KMT_028",
        "Ensure that kernel module `snd_virmidi` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_virmidi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_virmidi",
        "Audio loopback, virtual MIDI.",
    ))
    .with_fix(&fix_disabled("snd_virmidi"))
    .register();

    check::Check::new(
        "KMT_029",
        "Ensure that kernel module `softdog` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("softdog"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("softdog", "Software watchdog, test."))
    .with_fix(&fix_disabled("softdog"))
    .register();

    check::Check::new(
        "KMT_030",
        "Ensure that kernel module `tcrypt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("tcrypt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("tcrypt", "Crypto speed/self test."))
    .with_fix(&fix_disabled("tcrypt"))
    .register();

    check::Check::new(
        "KMT_031",
        "Ensure that kernel module `usb_debug` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_debug"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("usb_debug", "USB debug gadget."))
    .with_fix(&fix_disabled("usb_debug"))
    .register();

    check::Check::new(
        "KMT_032",
        "Ensure that kernel module `usbip_core` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usbip_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usbip_core",
        "USB over IP, a network-exposed USB with repeated CVE history.",
    ))
    .with_fix(&fix_disabled("usbip_core"))
    .register();

    check::Check::new(
        "KMT_033",
        "Ensure that kernel module `usbip_host` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usbip_host"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usbip_host",
        "USB over IP, network-exposed USB with repeated CVE history.",
    ))
    .with_fix(&fix_disabled("usbip_host"))
    .register();

    check::Check::new(
        "KMT_034",
        "Ensure that kernel module `usbip_vudc` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usbip_vudc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usbip_vudc",
        "USB over IP, network-exposed USB with repeated CVE history.",
    ))
    .with_fix(&fix_disabled("usbip_vudc"))
    .register();

    check::Check::new(
        "KMT_035",
        "Ensure that kernel module `usbmon` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usbmon"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("usbmon", "USB traffic capture."))
    .with_fix(&fix_disabled("usbmon"))
    .register();

    check::Check::new(
        "KMT_036",
        "Ensure that kernel module `usbtest` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usbtest"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usbtest",
        "USB compliance/test drivers.",
    ))
    .with_fix(&fix_disabled("usbtest"))
    .register();

    check::Check::new(
        "KMT_037",
        "Ensure that kernel module `vcan` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("vcan"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vcan", "Virtual CAN interfaces."))
    .with_fix(&fix_disabled("vcan"))
    .register();

    check::Check::new(
        "KMT_038",
        "Ensure that kernel module `vhci_hcd` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("vhci_hcd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vhci_hcd",
        "USB over IP, network-exposed USB with repeated CVE history.",
    ))
    .with_fix(&fix_disabled("vhci_hcd"))
    .register();

    check::Check::new(
        "KMT_039",
        "Ensure that kernel module `vicodec` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("vicodec"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vicodec",
        "Virtual codec test driver.",
    ))
    .with_fix(&fix_disabled("vicodec"))
    .register();

    check::Check::new(
        "KMT_040",
        "Ensure that kernel module `vim2m` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("vim2m"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vim2m",
        "Virtual mem2mem test driver.",
    ))
    .with_fix(&fix_disabled("vim2m"))
    .register();

    check::Check::new(
        "KMT_041",
        "Ensure that kernel module `vimc` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("vimc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vimc",
        "Virtual media controller test.",
    ))
    .with_fix(&fix_disabled("vimc"))
    .register();

    check::Check::new(
        "KMT_042",
        "Ensure that kernel module `virtual_ncidev` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("virtual_ncidev"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("virtual_ncidev", "NFC simulators."))
    .with_fix(&fix_disabled("virtual_ncidev"))
    .register();

    check::Check::new(
        "KMT_043",
        "Ensure that kernel module `visl` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("visl"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "visl",
        "Stateless decoder test driver.",
    ))
    .with_fix(&fix_disabled("visl"))
    .register();

    check::Check::new(
        "KMT_044",
        "Ensure that kernel module `vivid` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("vivid"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vivid", "Virtual video test driver."))
    .with_fix(&fix_disabled("vivid"))
    .register();

    check::Check::new(
        "KMT_045",
        "Ensure that kernel module `vxcan` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("vxcan"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vxcan", "Virtual CAN interfaces."))
    .with_fix(&fix_disabled("vxcan"))
    .register();

    check::Check::new(
        "KMT_046",
        "Ensure that kernel module `zloop` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("zloop"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "zloop",
        "Null/loop block test devices.",
    ))
    .with_fix(&fix_disabled("zloop"))
    .register();

    // AF_ALG crypto userspace interface (KMC_)
    check::Check::new(
        "KMC_001",
        "Ensure that kernel module `af_alg` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("af_alg"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("af_alg", "AF_ALG core."))
    .with_fix(&fix_disabled("af_alg"))
    .register();

    check::Check::new(
        "KMC_002",
        "Ensure that kernel module `algif_hash` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("algif_hash"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "algif_hash",
        "AF_ALG hash interface.",
    ))
    .with_fix(&fix_disabled("algif_hash"))
    .register();

    check::Check::new(
        "KMC_003",
        "Ensure that kernel module `algif_rng` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("algif_rng"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("algif_rng", "AF_ALG RNG interface."))
    .with_fix(&fix_disabled("algif_rng"))
    .register();

    check::Check::new(
        "KMC_004",
        "Ensure that kernel module `algif_skcipher` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("algif_skcipher"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "algif_skcipher",
        "AF_ALG symmetric cipher iface.",
    ))
    .with_fix(&fix_disabled("algif_skcipher"))
    .register();

    check::Check::new(
        "KMC_005",
        "Ensure that kernel module `crypto_user` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("crypto_user"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "crypto_user",
        "Crypto config netlink, root-only.",
    ))
    .with_fix(&fix_disabled("crypto_user"))
    .register();

    // niche and legacy network protocols (KMN_)
    check::Check::new(
        "KMN_001",
        "Ensure that kernel module `6lowpan` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("6lowpan"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "6lowpan",
        "6LoWPAN header compression.",
    ))
    .with_fix(&fix_disabled("6lowpan"))
    .register();

    check::Check::new(
        "KMN_002",
        "Ensure that kernel module `6pack` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("6pack"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("6pack", "Ham radio port drivers."))
    .with_fix(&fix_disabled("6pack"))
    .register();

    check::Check::new(
        "KMN_003",
        "Ensure that kernel module `af_802154` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("af_802154"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("af_802154", "802.15.4 sockets."))
    .with_fix(&fix_disabled("af_802154"))
    .register();

    check::Check::new(
        "KMN_004",
        "Ensure that kernel module `af_key` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("af_key"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "af_key",
        "PF_KEY for IPsec keying, needed by strongSwan/IPsec.",
    ))
    .with_fix(&fix_disabled("af_key"))
    .register();

    check::Check::new(
        "KMN_005",
        "Ensure that kernel module `appletalk` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("appletalk"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("appletalk", "AppleTalk."))
    .with_fix(&fix_disabled("appletalk"))
    .register();

    check::Check::new(
        "KMN_006",
        "Ensure that kernel module `arc_rawmode` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("arc_rawmode"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("arc_rawmode", "ARCnet."))
    .with_fix(&fix_disabled("arc_rawmode"))
    .register();

    check::Check::new(
        "KMN_007",
        "Ensure that kernel module `arc_rimi` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("arc_rimi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("arc_rimi", "ARCnet."))
    .with_fix(&fix_disabled("arc_rimi"))
    .register();

    check::Check::new(
        "KMN_008",
        "Ensure that kernel module `arcnet` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("arcnet"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("arcnet", "ARCnet."))
    .with_fix(&fix_disabled("arcnet"))
    .register();

    check::Check::new(
        "KMN_009",
        "Ensure that kernel module `arp_tables` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("arp_tables"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("arp_tables", "Legacy iptables backend. Only safe to disable with nftables-only firewall, breaks Docker with iptables-legacy."))
    .with_fix(&fix_disabled("arp_tables"))
    .register();

    check::Check::new(
        "KMN_010",
        "Ensure that kernel module `arptable_filter` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("arptable_filter"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("arptable_filter", "Legacy iptables backend. Only safe to disable with nftables-only firewall, breaks Docker with iptables-legacy."))
    .with_fix(&fix_disabled("arptable_filter"))
    .register();

    check::Check::new(
        "KMN_011",
        "Ensure that kernel module `atm` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("atm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("atm", "ATM core."))
    .with_fix(&fix_disabled("atm"))
    .register();

    check::Check::new(
        "KMN_012",
        "Ensure that kernel module `avmfritz` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("avmfritz"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "avmfritz",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("avmfritz"))
    .register();

    check::Check::new(
        "KMN_013",
        "Ensure that kernel module `ax25` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ax25"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ax25", "AX.25 link layer."))
    .with_fix(&fix_disabled("ax25"))
    .register();

    check::Check::new(
        "KMN_014",
        "Ensure that kernel module `batman_adv` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("batman_adv"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("batman_adv", "B.A.T.M.A.N. mesh."))
    .with_fix(&fix_disabled("batman_adv"))
    .register();

    check::Check::new(
        "KMN_015",
        "Ensure that kernel module `baycom_par` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("baycom_par"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "baycom_par",
        "Ham radio port drivers.",
    ))
    .with_fix(&fix_disabled("baycom_par"))
    .register();

    check::Check::new(
        "KMN_016",
        "Ensure that kernel module `baycom_ser_fdx` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("baycom_ser_fdx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "baycom_ser_fdx",
        "Ham radio port drivers.",
    ))
    .with_fix(&fix_disabled("baycom_ser_fdx"))
    .register();

    check::Check::new(
        "KMN_017",
        "Ensure that kernel module `baycom_ser_hdx` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("baycom_ser_hdx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "baycom_ser_hdx",
        "Ham radio port drivers.",
    ))
    .with_fix(&fix_disabled("baycom_ser_hdx"))
    .register();

    check::Check::new(
        "KMN_018",
        "Ensure that kernel module `bpqether` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("bpqether"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("bpqether", "Ham radio port drivers."))
    .with_fix(&fix_disabled("bpqether"))
    .register();

    check::Check::new(
        "KMN_019",
        "Ensure that kernel module `br2684` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("br2684"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("br2684", "ATM protocols."))
    .with_fix(&fix_disabled("br2684"))
    .register();

    check::Check::new(
        "KMN_020",
        "Ensure that kernel module `c_can` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("c_can"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "c_can",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("c_can"))
    .register();

    check::Check::new(
        "KMN_021",
        "Ensure that kernel module `c_can_pci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("c_can_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "c_can_pci",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("c_can_pci"))
    .register();

    check::Check::new(
        "KMN_022",
        "Ensure that kernel module `c_can_platform` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("c_can_platform"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "c_can_platform",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("c_can_platform"))
    .register();

    check::Check::new(
        "KMN_023",
        "Ensure that kernel module `caif` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("caif"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "caif",
        "ST-Ericsson modem protocol, autoloadable.",
    ))
    .with_fix(&fix_disabled("caif"))
    .register();

    check::Check::new(
        "KMN_024",
        "Ensure that kernel module `caif_socket` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("caif_socket"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "caif_socket",
        "ST-Ericsson modem protocol, autoloadable.",
    ))
    .with_fix(&fix_disabled("caif_socket"))
    .register();

    check::Check::new(
        "KMN_025",
        "Ensure that kernel module `caif_usb` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("caif_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "caif_usb",
        "ST-Ericsson modem protocol, autoloadable.",
    ))
    .with_fix(&fix_disabled("caif_usb"))
    .register();

    check::Check::new(
        "KMN_026",
        "Ensure that kernel module `can` is disabled",
        Severity::High,
        vec!["module", "STIG", "server", "workstation"],
        || modprobe::check_module_disabled("can"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "can",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("can"))
    .register();

    check::Check::new(
        "KMN_027",
        "Ensure that kernel module `can327` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("can327"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "can327",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("can327"))
    .register();

    check::Check::new(
        "KMN_028",
        "Ensure that kernel module `can_bcm` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("can_bcm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "can_bcm",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("can_bcm"))
    .register();

    check::Check::new(
        "KMN_029",
        "Ensure that kernel module `can_dev` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("can_dev"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "can_dev",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("can_dev"))
    .register();

    check::Check::new(
        "KMN_030",
        "Ensure that kernel module `can_gw` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("can_gw"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "can_gw",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("can_gw"))
    .register();

    check::Check::new(
        "KMN_031",
        "Ensure that kernel module `can_isotp` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("can_isotp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "can_isotp",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("can_isotp"))
    .register();

    check::Check::new(
        "KMN_032",
        "Ensure that kernel module `can_j1939` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("can_j1939"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "can_j1939",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("can_j1939"))
    .register();

    check::Check::new(
        "KMN_033",
        "Ensure that kernel module `can_raw` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("can_raw"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "can_raw",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("can_raw"))
    .register();

    check::Check::new(
        "KMN_034",
        "Ensure that kernel module `capmode` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("capmode"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("capmode", "ARCnet."))
    .with_fix(&fix_disabled("capmode"))
    .register();

    check::Check::new(
        "KMN_035",
        "Ensure that kernel module `cc770` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cc770"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cc770",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("cc770"))
    .register();

    check::Check::new(
        "KMN_036",
        "Ensure that kernel module `cc770_isa` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cc770_isa"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cc770_isa",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("cc770_isa"))
    .register();

    check::Check::new(
        "KMN_037",
        "Ensure that kernel module `cc770_platform` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cc770_platform"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cc770_platform",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("cc770_platform"))
    .register();

    check::Check::new(
        "KMN_038",
        "Ensure that kernel module `chnl_net` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("chnl_net"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "chnl_net",
        "ST-Ericsson modem protocol, autoloadable.",
    ))
    .with_fix(&fix_disabled("chnl_net"))
    .register();

    check::Check::new(
        "KMN_039",
        "Ensure that kernel module `clip` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("clip"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("clip", "ATM protocols."))
    .with_fix(&fix_disabled("clip"))
    .register();

    check::Check::new(
        "KMN_040",
        "Ensure that kernel module `com20020` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("com20020"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("com20020", "ARCnet."))
    .with_fix(&fix_disabled("com20020"))
    .register();

    check::Check::new(
        "KMN_041",
        "Ensure that kernel module `com20020_cs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("com20020_cs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("com20020_cs", "ARCnet."))
    .with_fix(&fix_disabled("com20020_cs"))
    .register();

    check::Check::new(
        "KMN_042",
        "Ensure that kernel module `com20020_pci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("com20020_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("com20020_pci", "ARCnet."))
    .with_fix(&fix_disabled("com20020_pci"))
    .register();

    check::Check::new(
        "KMN_043",
        "Ensure that kernel module `com90io` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("com90io"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("com90io", "ARCnet."))
    .with_fix(&fix_disabled("com90io"))
    .register();

    check::Check::new(
        "KMN_044",
        "Ensure that kernel module `com90xx` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("com90xx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("com90xx", "ARCnet."))
    .with_fix(&fix_disabled("com90xx"))
    .register();

    check::Check::new(
        "KMN_045",
        "Ensure that kernel module `ctucanfd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ctucanfd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ctucanfd",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("ctucanfd"))
    .register();

    check::Check::new(
        "KMN_046",
        "Ensure that kernel module `ctucanfd_pci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ctucanfd_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ctucanfd_pci",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("ctucanfd_pci"))
    .register();

    check::Check::new(
        "KMN_047",
        "Ensure that kernel module `cxacru` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cxacru"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("cxacru", "ADSL modem drivers."))
    .with_fix(&fix_disabled("cxacru"))
    .register();

    check::Check::new(
        "KMN_048",
        "Ensure that kernel module `dccp` is disabled",
        Severity::High,
        vec!["module", "CIS", "STIG", "server", "workstation"],
        || modprobe::check_module_disabled("dccp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "dccp",
        "DCCP transport, autoloadable. Removed from recent kernels.",
    ))
    .with_fix(&fix_disabled("dccp"))
    .register();

    check::Check::new(
        "KMN_049",
        "Ensure that kernel module `decnet` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("decnet"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "decnet",
        "Removed upstream, keep for old kernels.",
    ))
    .with_fix(&fix_disabled("decnet"))
    .register();

    check::Check::new(
        "KMN_050",
        "Ensure that kernel module `defxx` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("defxx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("defxx", "FDDI."))
    .with_fix(&fix_disabled("defxx"))
    .register();

    check::Check::new(
        "KMN_051",
        "Ensure that kernel module `dsa_core` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("dsa_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "dsa_core",
        "Switch chip offload, embedded.",
    ))
    .with_fix(&fix_disabled("dsa_core"))
    .register();

    check::Check::new(
        "KMN_052",
        "Ensure that kernel module `econet` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("econet"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "econet",
        "Removed upstream, keep for old kernels.",
    ))
    .with_fix(&fix_disabled("econet"))
    .register();

    check::Check::new(
        "KMN_053",
        "Ensure that kernel module `ems_pci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ems_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ems_pci",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("ems_pci"))
    .register();

    check::Check::new(
        "KMN_054",
        "Ensure that kernel module `ems_pcmcia` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ems_pcmcia"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ems_pcmcia",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("ems_pcmcia"))
    .register();

    check::Check::new(
        "KMN_055",
        "Ensure that kernel module `ems_usb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ems_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ems_usb",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("ems_usb"))
    .register();

    check::Check::new(
        "KMN_056",
        "Ensure that kernel module `eni` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("eni"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("eni", "ATM NIC drivers."))
    .with_fix(&fix_disabled("eni"))
    .register();

    check::Check::new(
        "KMN_057",
        "Ensure that kernel module `esd_402_pci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("esd_402_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "esd_402_pci",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("esd_402_pci"))
    .register();

    check::Check::new(
        "KMN_058",
        "Ensure that kernel module `esd_usb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("esd_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "esd_usb",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("esd_usb"))
    .register();

    check::Check::new(
        "KMN_059",
        "Ensure that kernel module `etas_es58x` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("etas_es58x"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "etas_es58x",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("etas_es58x"))
    .register();

    check::Check::new(
        "KMN_060",
        "Ensure that kernel module `f81601` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("f81601"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "f81601",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("f81601"))
    .register();

    check::Check::new(
        "KMN_061",
        "Ensure that kernel module `f81604` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("f81604"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "f81604",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("f81604"))
    .register();

    check::Check::new(
        "KMN_062",
        "Ensure that kernel module `farsync` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("farsync"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("farsync", "Synchronous WAN cards."))
    .with_fix(&fix_disabled("farsync"))
    .register();

    check::Check::new(
        "KMN_063",
        "Ensure that kernel module `fdp` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("fdp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("fdp", "NFC reader drivers."))
    .with_fix(&fix_disabled("fdp"))
    .register();

    check::Check::new(
        "KMN_064",
        "Ensure that kernel module `fdp_i2c` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("fdp_i2c"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("fdp_i2c", "NFC reader drivers."))
    .with_fix(&fix_disabled("fdp_i2c"))
    .register();

    check::Check::new(
        "KMN_065",
        "Ensure that kernel module `fore_200e` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("fore_200e"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("fore_200e", "ATM NIC drivers."))
    .with_fix(&fix_disabled("fore_200e"))
    .register();

    check::Check::new(
        "KMN_066",
        "Ensure that kernel module `fou` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("fou"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("fou", "Foo-over-UDP encapsulation."))
    .with_fix(&fix_disabled("fou"))
    .register();

    check::Check::new(
        "KMN_067",
        "Ensure that kernel module `fou6` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("fou6"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("fou6", "Foo-over-UDP encapsulation."))
    .with_fix(&fix_disabled("fou6"))
    .register();

    check::Check::new(
        "KMN_068",
        "Ensure that kernel module `gs_usb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gs_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "gs_usb",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("gs_usb"))
    .register();

    check::Check::new(
        "KMN_069",
        "Ensure that kernel module `hci` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hci",
        "NFC core, autoloadable via socket(AF_NFC).",
    ))
    .with_fix(&fix_disabled("hci"))
    .register();

    check::Check::new(
        "KMN_070",
        "Ensure that kernel module `hdlc` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hdlc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hdlc", "Synchronous WAN cards."))
    .with_fix(&fix_disabled("hdlc"))
    .register();

    check::Check::new(
        "KMN_071",
        "Ensure that kernel module `hdlc_cisco` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hdlc_cisco"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hdlc_cisco",
        "Synchronous WAN cards.",
    ))
    .with_fix(&fix_disabled("hdlc_cisco"))
    .register();

    check::Check::new(
        "KMN_072",
        "Ensure that kernel module `hdlc_fr` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hdlc_fr"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hdlc_fr", "Synchronous WAN cards."))
    .with_fix(&fix_disabled("hdlc_fr"))
    .register();

    check::Check::new(
        "KMN_073",
        "Ensure that kernel module `hdlc_ppp` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hdlc_ppp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hdlc_ppp", "Synchronous WAN cards."))
    .with_fix(&fix_disabled("hdlc_ppp"))
    .register();

    check::Check::new(
        "KMN_074",
        "Ensure that kernel module `hdlc_raw` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hdlc_raw"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hdlc_raw", "Synchronous WAN cards."))
    .with_fix(&fix_disabled("hdlc_raw"))
    .register();

    check::Check::new(
        "KMN_075",
        "Ensure that kernel module `hdlc_raw_eth` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hdlc_raw_eth"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hdlc_raw_eth",
        "Synchronous WAN cards.",
    ))
    .with_fix(&fix_disabled("hdlc_raw_eth"))
    .register();

    check::Check::new(
        "KMN_076",
        "Ensure that kernel module `hdlc_x25` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hdlc_x25"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hdlc_x25", "Synchronous WAN cards."))
    .with_fix(&fix_disabled("hdlc_x25"))
    .register();

    check::Check::new(
        "KMN_077",
        "Ensure that kernel module `hdlcdrv` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hdlcdrv"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hdlcdrv", "Ham radio port drivers."))
    .with_fix(&fix_disabled("hdlcdrv"))
    .register();

    check::Check::new(
        "KMN_078",
        "Ensure that kernel module `he` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("he"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("he", "ATM NIC drivers."))
    .with_fix(&fix_disabled("he"))
    .register();

    check::Check::new(
        "KMN_079",
        "Ensure that kernel module `hfcmulti` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hfcmulti"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hfcmulti",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("hfcmulti"))
    .register();

    check::Check::new(
        "KMN_080",
        "Ensure that kernel module `hfcpci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hfcpci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hfcpci",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("hfcpci"))
    .register();

    check::Check::new(
        "KMN_081",
        "Ensure that kernel module `hfcsusb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hfcsusb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hfcsusb",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("hfcsusb"))
    .register();

    check::Check::new(
        "KMN_082",
        "Ensure that kernel module `hi311x` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hi311x"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hi311x",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("hi311x"))
    .register();

    check::Check::new(
        "KMN_083",
        "Ensure that kernel module `hsr` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("hsr"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hsr",
        "IEC 62439-3 industrial redundancy.",
    ))
    .with_fix(&fix_disabled("hsr"))
    .register();

    check::Check::new(
        "KMN_084",
        "Ensure that kernel module `idt77252` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("idt77252"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("idt77252", "ATM NIC drivers."))
    .with_fix(&fix_disabled("idt77252"))
    .register();

    check::Check::new(
        "KMN_085",
        "Ensure that kernel module `ieee802154` is disabled",
        Severity::High,
        vec!["module", "STIG", "server", "workstation"],
        || modprobe::check_module_disabled("ieee802154"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ieee802154", "802.15.4 stack."))
    .with_fix(&fix_disabled("ieee802154"))
    .register();

    check::Check::new(
        "KMN_086",
        "Ensure that kernel module `ieee802154_6lowpan` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ieee802154_6lowpan"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ieee802154_6lowpan",
        "802.15.4 stack.",
    ))
    .with_fix(&fix_disabled("ieee802154_6lowpan"))
    .register();

    check::Check::new(
        "KMN_087",
        "Ensure that kernel module `ieee802154_socket` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ieee802154_socket"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ieee802154_socket",
        "802.15.4 stack.",
    ))
    .with_fix(&fix_disabled("ieee802154_socket"))
    .register();

    check::Check::new(
        "KMN_088",
        "Ensure that kernel module `ife` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("ife"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ife", "Inter-FE protocol."))
    .with_fix(&fix_disabled("ife"))
    .register();

    check::Check::new(
        "KMN_089",
        "Ensure that kernel module `ifi_canfd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ifi_canfd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ifi_canfd",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("ifi_canfd"))
    .register();

    check::Check::new(
        "KMN_090",
        "Ensure that kernel module `ila` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("ila"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ila",
        "IPv6 identifier-locator addressing.",
    ))
    .with_fix(&fix_disabled("ila"))
    .register();

    check::Check::new(
        "KMN_091",
        "Ensure that kernel module `ip_tables` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("ip_tables"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ip_tables", "Legacy iptables backend. Only safe to disable with nftables-only firewall, breaks Docker with iptables-legacy."))
    .with_fix(&fix_disabled("ip_tables"))
    .register();

    check::Check::new(
        "KMN_092",
        "Ensure that kernel module `iphase` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("iphase"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("iphase", "ATM NIC drivers."))
    .with_fix(&fix_disabled("iphase"))
    .register();

    check::Check::new(
        "KMN_093",
        "Ensure that kernel module `ipx` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ipx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ipx",
        "Removed upstream, keep for old kernels.",
    ))
    .with_fix(&fix_disabled("ipx"))
    .register();

    check::Check::new(
        "KMN_094",
        "Ensure that kernel module `irda` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("irda"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "irda",
        "Removed upstream, keep for old kernels.",
    ))
    .with_fix(&fix_disabled("irda"))
    .register();

    check::Check::new(
        "KMN_095",
        "Ensure that kernel module `isdnhdlc` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("isdnhdlc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "isdnhdlc",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("isdnhdlc"))
    .register();

    check::Check::new(
        "KMN_096",
        "Ensure that kernel module `janz_ican3` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("janz_ican3"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "janz_ican3",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("janz_ican3"))
    .register();

    check::Check::new(
        "KMN_097",
        "Ensure that kernel module `kcm` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("kcm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "kcm",
        "Kernel Connection Multiplexor.",
    ))
    .with_fix(&fix_disabled("kcm"))
    .register();

    check::Check::new(
        "KMN_098",
        "Ensure that kernel module `kvaser_pci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("kvaser_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "kvaser_pci",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("kvaser_pci"))
    .register();

    check::Check::new(
        "KMN_099",
        "Ensure that kernel module `kvaser_pciefd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("kvaser_pciefd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "kvaser_pciefd",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("kvaser_pciefd"))
    .register();

    check::Check::new(
        "KMN_100",
        "Ensure that kernel module `kvaser_usb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("kvaser_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "kvaser_usb",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("kvaser_usb"))
    .register();

    check::Check::new(
        "KMN_101",
        "Ensure that kernel module `l1oip` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("l1oip"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "l1oip",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("l1oip"))
    .register();

    check::Check::new(
        "KMN_102",
        "Ensure that kernel module `l2tp_core` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("l2tp_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "l2tp_core",
        "L2TP VPN, also ISP PPPoE tunnels.",
    ))
    .with_fix(&fix_disabled("l2tp_core"))
    .register();

    check::Check::new(
        "KMN_103",
        "Ensure that kernel module `l2tp_debugfs` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("l2tp_debugfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "l2tp_debugfs",
        "L2TP VPN, also ISP PPPoE tunnels.",
    ))
    .with_fix(&fix_disabled("l2tp_debugfs"))
    .register();

    check::Check::new(
        "KMN_104",
        "Ensure that kernel module `l2tp_eth` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("l2tp_eth"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "l2tp_eth",
        "L2TP VPN, also ISP PPPoE tunnels.",
    ))
    .with_fix(&fix_disabled("l2tp_eth"))
    .register();

    check::Check::new(
        "KMN_105",
        "Ensure that kernel module `l2tp_ip` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("l2tp_ip"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "l2tp_ip",
        "L2TP VPN, also ISP PPPoE tunnels.",
    ))
    .with_fix(&fix_disabled("l2tp_ip"))
    .register();

    check::Check::new(
        "KMN_106",
        "Ensure that kernel module `l2tp_ip6` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("l2tp_ip6"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "l2tp_ip6",
        "L2TP VPN, also ISP PPPoE tunnels.",
    ))
    .with_fix(&fix_disabled("l2tp_ip6"))
    .register();

    check::Check::new(
        "KMN_107",
        "Ensure that kernel module `l2tp_netlink` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("l2tp_netlink"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "l2tp_netlink",
        "L2TP VPN, also ISP PPPoE tunnels.",
    ))
    .with_fix(&fix_disabled("l2tp_netlink"))
    .register();

    check::Check::new(
        "KMN_108",
        "Ensure that kernel module `l2tp_ppp` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("l2tp_ppp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "l2tp_ppp",
        "L2TP VPN, also ISP PPPoE tunnels.",
    ))
    .with_fix(&fix_disabled("l2tp_ppp"))
    .register();

    check::Check::new(
        "KMN_109",
        "Ensure that kernel module `lanai` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("lanai"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("lanai", "ATM NIC drivers."))
    .with_fix(&fix_disabled("lanai"))
    .register();

    check::Check::new(
        "KMN_110",
        "Ensure that kernel module `lapb` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("lapb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("lapb", "LAPB, X.25 layer 2."))
    .with_fix(&fix_disabled("lapb"))
    .register();

    check::Check::new(
        "KMN_111",
        "Ensure that kernel module `lapbether` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("lapbether"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("lapbether", "Synchronous WAN cards."))
    .with_fix(&fix_disabled("lapbether"))
    .register();

    check::Check::new(
        "KMN_112",
        "Ensure that kernel module `lec` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("lec"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("lec", "ATM protocols."))
    .with_fix(&fix_disabled("lec"))
    .register();

    check::Check::new(
        "KMN_113",
        "Ensure that kernel module `mISDN_core` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mISDN_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mISDN_core",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("mISDN_core"))
    .register();

    check::Check::new(
        "KMN_114",
        "Ensure that kernel module `mISDN_dsp` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mISDN_dsp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mISDN_dsp",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("mISDN_dsp"))
    .register();

    check::Check::new(
        "KMN_115",
        "Ensure that kernel module `mISDNinfineon` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mISDNinfineon"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mISDNinfineon",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("mISDNinfineon"))
    .register();

    check::Check::new(
        "KMN_116",
        "Ensure that kernel module `mISDNipac` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mISDNipac"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mISDNipac",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("mISDNipac"))
    .register();

    check::Check::new(
        "KMN_117",
        "Ensure that kernel module `mISDNisar` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mISDNisar"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mISDNisar",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("mISDNisar"))
    .register();

    check::Check::new(
        "KMN_118",
        "Ensure that kernel module `m_can` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("m_can"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "m_can",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("m_can"))
    .register();

    check::Check::new(
        "KMN_119",
        "Ensure that kernel module `m_can_pci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("m_can_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "m_can_pci",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("m_can_pci"))
    .register();

    check::Check::new(
        "KMN_120",
        "Ensure that kernel module `m_can_platform` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("m_can_platform"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "m_can_platform",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("m_can_platform"))
    .register();

    check::Check::new(
        "KMN_121",
        "Ensure that kernel module `mac802154` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mac802154"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mac802154", "802.15.4 stack."))
    .with_fix(&fix_disabled("mac802154"))
    .register();

    check::Check::new(
        "KMN_122",
        "Ensure that kernel module `mcba_usb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mcba_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mcba_usb",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("mcba_usb"))
    .register();

    check::Check::new(
        "KMN_123",
        "Ensure that kernel module `mcp251xfd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mcp251xfd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mcp251xfd",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("mcp251xfd"))
    .register();

    check::Check::new(
        "KMN_124",
        "Ensure that kernel module `mei_phy` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mei_phy"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mei_phy", "NFC reader drivers."))
    .with_fix(&fix_disabled("mei_phy"))
    .register();

    check::Check::new(
        "KMN_125",
        "Ensure that kernel module `microread` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("microread"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("microread", "NFC reader drivers."))
    .with_fix(&fix_disabled("microread"))
    .register();

    check::Check::new(
        "KMN_126",
        "Ensure that kernel module `microread_i2c` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("microread_i2c"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "microread_i2c",
        "NFC reader drivers.",
    ))
    .with_fix(&fix_disabled("microread_i2c"))
    .register();

    check::Check::new(
        "KMN_127",
        "Ensure that kernel module `microread_mei` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("microread_mei"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "microread_mei",
        "NFC reader drivers.",
    ))
    .with_fix(&fix_disabled("microread_mei"))
    .register();

    check::Check::new(
        "KMN_128",
        "Ensure that kernel module `mkiss` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mkiss"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mkiss", "Ham radio port drivers."))
    .with_fix(&fix_disabled("mkiss"))
    .register();

    check::Check::new(
        "KMN_129",
        "Ensure that kernel module `mpls_gso` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("mpls_gso"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mpls_gso", "MPLS."))
    .with_fix(&fix_disabled("mpls_gso"))
    .register();

    check::Check::new(
        "KMN_130",
        "Ensure that kernel module `mpls_iptunnel` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("mpls_iptunnel"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mpls_iptunnel", "MPLS."))
    .with_fix(&fix_disabled("mpls_iptunnel"))
    .register();

    check::Check::new(
        "KMN_131",
        "Ensure that kernel module `mpls_router` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("mpls_router"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mpls_router", "MPLS."))
    .with_fix(&fix_disabled("mpls_router"))
    .register();

    check::Check::new(
        "KMN_132",
        "Ensure that kernel module `mpoa` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mpoa"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mpoa", "ATM protocols."))
    .with_fix(&fix_disabled("mpoa"))
    .register();

    check::Check::new(
        "KMN_133",
        "Ensure that kernel module `n_gsm` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("n_gsm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "n_gsm",
        "GSM 07.10 mux line discipline, cellular modems.",
    ))
    .with_fix(&fix_disabled("n_gsm"))
    .register();

    check::Check::new(
        "KMN_134",
        "Ensure that kernel module `n_hdlc` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("n_hdlc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("n_hdlc", "HDLC line discipline."))
    .with_fix(&fix_disabled("n_hdlc"))
    .register();

    check::Check::new(
        "KMN_135",
        "Ensure that kernel module `nci` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nci",
        "NFC core, autoloadable via socket(AF_NFC).",
    ))
    .with_fix(&fix_disabled("nci"))
    .register();

    check::Check::new(
        "KMN_136",
        "Ensure that kernel module `nci_spi` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nci_spi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nci_spi",
        "NFC core, autoloadable via socket(AF_NFC).",
    ))
    .with_fix(&fix_disabled("nci_spi"))
    .register();

    check::Check::new(
        "KMN_137",
        "Ensure that kernel module `nci_uart` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nci_uart"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nci_uart",
        "NFC core, autoloadable via socket(AF_NFC).",
    ))
    .with_fix(&fix_disabled("nci_uart"))
    .register();

    check::Check::new(
        "KMN_138",
        "Ensure that kernel module `nct6694_canfd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nct6694_canfd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nct6694_canfd",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("nct6694_canfd"))
    .register();

    check::Check::new(
        "KMN_139",
        "Ensure that kernel module `netjet` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("netjet"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "netjet",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("netjet"))
    .register();

    check::Check::new(
        "KMN_140",
        "Ensure that kernel module `netrom` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("netrom"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("netrom", "NET/ROM."))
    .with_fix(&fix_disabled("netrom"))
    .register();

    check::Check::new(
        "KMN_141",
        "Ensure that kernel module `nfc` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nfc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nfc",
        "NFC core, autoloadable via socket(AF_NFC).",
    ))
    .with_fix(&fix_disabled("nfc"))
    .register();

    check::Check::new(
        "KMN_142",
        "Ensure that kernel module `nfc_digital` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nfc_digital"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nfc_digital",
        "NFC core, autoloadable via socket(AF_NFC).",
    ))
    .with_fix(&fix_disabled("nfc_digital"))
    .register();

    check::Check::new(
        "KMN_143",
        "Ensure that kernel module `nfcmrvl` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nfcmrvl"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nfcmrvl", "NFC reader drivers."))
    .with_fix(&fix_disabled("nfcmrvl"))
    .register();

    check::Check::new(
        "KMN_144",
        "Ensure that kernel module `nfcmrvl_i2c` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nfcmrvl_i2c"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nfcmrvl_i2c", "NFC reader drivers."))
    .with_fix(&fix_disabled("nfcmrvl_i2c"))
    .register();

    check::Check::new(
        "KMN_145",
        "Ensure that kernel module `nfcmrvl_spi` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nfcmrvl_spi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nfcmrvl_spi", "NFC reader drivers."))
    .with_fix(&fix_disabled("nfcmrvl_spi"))
    .register();

    check::Check::new(
        "KMN_146",
        "Ensure that kernel module `nfcmrvl_uart` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nfcmrvl_uart"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nfcmrvl_uart", "NFC reader drivers."))
    .with_fix(&fix_disabled("nfcmrvl_uart"))
    .register();

    check::Check::new(
        "KMN_147",
        "Ensure that kernel module `nfcmrvl_usb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nfcmrvl_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nfcmrvl_usb", "NFC reader drivers."))
    .with_fix(&fix_disabled("nfcmrvl_usb"))
    .register();

    check::Check::new(
        "KMN_148",
        "Ensure that kernel module `nhc_dest` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nhc_dest"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nhc_dest",
        "6LoWPAN header compression.",
    ))
    .with_fix(&fix_disabled("nhc_dest"))
    .register();

    check::Check::new(
        "KMN_149",
        "Ensure that kernel module `nhc_fragment` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nhc_fragment"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nhc_fragment",
        "6LoWPAN header compression.",
    ))
    .with_fix(&fix_disabled("nhc_fragment"))
    .register();

    check::Check::new(
        "KMN_150",
        "Ensure that kernel module `nhc_hop` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nhc_hop"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nhc_hop",
        "6LoWPAN header compression.",
    ))
    .with_fix(&fix_disabled("nhc_hop"))
    .register();

    check::Check::new(
        "KMN_151",
        "Ensure that kernel module `nhc_ipv6` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nhc_ipv6"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nhc_ipv6",
        "6LoWPAN header compression.",
    ))
    .with_fix(&fix_disabled("nhc_ipv6"))
    .register();

    check::Check::new(
        "KMN_152",
        "Ensure that kernel module `nhc_mobility` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nhc_mobility"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nhc_mobility",
        "6LoWPAN header compression.",
    ))
    .with_fix(&fix_disabled("nhc_mobility"))
    .register();

    check::Check::new(
        "KMN_153",
        "Ensure that kernel module `nhc_routing` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nhc_routing"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nhc_routing",
        "6LoWPAN header compression.",
    ))
    .with_fix(&fix_disabled("nhc_routing"))
    .register();

    check::Check::new(
        "KMN_154",
        "Ensure that kernel module `nhc_udp` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nhc_udp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nhc_udp",
        "6LoWPAN header compression.",
    ))
    .with_fix(&fix_disabled("nhc_udp"))
    .register();

    check::Check::new(
        "KMN_155",
        "Ensure that kernel module `nicstar` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nicstar"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nicstar", "ATM NIC drivers."))
    .with_fix(&fix_disabled("nicstar"))
    .register();

    check::Check::new(
        "KMN_156",
        "Ensure that kernel module `nsh` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("nsh"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nsh", "Network Service Header, SFC."))
    .with_fix(&fix_disabled("nsh"))
    .register();

    check::Check::new(
        "KMN_157",
        "Ensure that kernel module `nxp_nci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nxp_nci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nxp_nci", "NFC reader drivers."))
    .with_fix(&fix_disabled("nxp_nci"))
    .register();

    check::Check::new(
        "KMN_158",
        "Ensure that kernel module `nxp_nci_i2c` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nxp_nci_i2c"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nxp_nci_i2c", "NFC reader drivers."))
    .with_fix(&fix_disabled("nxp_nci_i2c"))
    .register();

    check::Check::new(
        "KMN_159",
        "Ensure that kernel module `openvswitch` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("openvswitch"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "openvswitch",
        "Open vSwitch, needed by some container/SDN setups.",
    ))
    .with_fix(&fix_disabled("openvswitch"))
    .register();

    check::Check::new(
        "KMN_160",
        "Ensure that kernel module `p8022` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("p8022"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "p8022",
        "Removed upstream, keep for old kernels.",
    ))
    .with_fix(&fix_disabled("p8022"))
    .register();

    check::Check::new(
        "KMN_161",
        "Ensure that kernel module `p8023` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("p8023"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "p8023",
        "Removed upstream, keep for old kernels.",
    ))
    .with_fix(&fix_disabled("p8023"))
    .register();

    check::Check::new(
        "KMN_162",
        "Ensure that kernel module `pc300too` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pc300too"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pc300too", "Synchronous WAN cards."))
    .with_fix(&fix_disabled("pc300too"))
    .register();

    check::Check::new(
        "KMN_163",
        "Ensure that kernel module `pci200syn` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pci200syn"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pci200syn", "Synchronous WAN cards."))
    .with_fix(&fix_disabled("pci200syn"))
    .register();

    check::Check::new(
        "KMN_164",
        "Ensure that kernel module `peak_pci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("peak_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "peak_pci",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("peak_pci"))
    .register();

    check::Check::new(
        "KMN_165",
        "Ensure that kernel module `peak_pciefd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("peak_pciefd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "peak_pciefd",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("peak_pciefd"))
    .register();

    check::Check::new(
        "KMN_166",
        "Ensure that kernel module `peak_usb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("peak_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "peak_usb",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("peak_usb"))
    .register();

    check::Check::new(
        "KMN_167",
        "Ensure that kernel module `phonet` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("phonet"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "phonet",
        "Nokia modem protocol, autoloadable.",
    ))
    .with_fix(&fix_disabled("phonet"))
    .register();

    check::Check::new(
        "KMN_168",
        "Ensure that kernel module `phy_can_transceiver` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("phy_can_transceiver"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "phy_can_transceiver",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("phy_can_transceiver"))
    .register();

    check::Check::new(
        "KMN_169",
        "Ensure that kernel module `plip` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("plip"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("plip", "Parallel-port IP."))
    .with_fix(&fix_disabled("plip"))
    .register();

    check::Check::new(
        "KMN_170",
        "Ensure that kernel module `plx_pci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("plx_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "plx_pci",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("plx_pci"))
    .register();

    check::Check::new(
        "KMN_171",
        "Ensure that kernel module `pn532_uart` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pn532_uart"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pn532_uart", "NFC reader drivers."))
    .with_fix(&fix_disabled("pn532_uart"))
    .register();

    check::Check::new(
        "KMN_172",
        "Ensure that kernel module `pn533` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pn533"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pn533", "NFC reader drivers."))
    .with_fix(&fix_disabled("pn533"))
    .register();

    check::Check::new(
        "KMN_173",
        "Ensure that kernel module `pn533_i2c` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pn533_i2c"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pn533_i2c", "NFC reader drivers."))
    .with_fix(&fix_disabled("pn533_i2c"))
    .register();

    check::Check::new(
        "KMN_174",
        "Ensure that kernel module `pn533_usb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pn533_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pn533_usb", "NFC reader drivers."))
    .with_fix(&fix_disabled("pn533_usb"))
    .register();

    check::Check::new(
        "KMN_175",
        "Ensure that kernel module `pn544` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pn544"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pn544", "NFC reader drivers."))
    .with_fix(&fix_disabled("pn544"))
    .register();

    check::Check::new(
        "KMN_176",
        "Ensure that kernel module `pn544_i2c` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pn544_i2c"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pn544_i2c", "NFC reader drivers."))
    .with_fix(&fix_disabled("pn544_i2c"))
    .register();

    check::Check::new(
        "KMN_177",
        "Ensure that kernel module `pn544_mei` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pn544_mei"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pn544_mei", "NFC reader drivers."))
    .with_fix(&fix_disabled("pn544_mei"))
    .register();

    check::Check::new(
        "KMN_178",
        "Ensure that kernel module `pn_pep` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pn_pep"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pn_pep",
        "Nokia modem protocol, autoloadable.",
    ))
    .with_fix(&fix_disabled("pn_pep"))
    .register();

    check::Check::new(
        "KMN_179",
        "Ensure that kernel module `port100` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("port100"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("port100", "NFC reader drivers."))
    .with_fix(&fix_disabled("port100"))
    .register();

    check::Check::new(
        "KMN_180",
        "Ensure that kernel module `pppoatm` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pppoatm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pppoatm", "ATM protocols."))
    .with_fix(&fix_disabled("pppoatm"))
    .register();

    check::Check::new(
        "KMN_181",
        "Ensure that kernel module `psample` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("psample"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("psample", "Packet sampling."))
    .with_fix(&fix_disabled("psample"))
    .register();

    check::Check::new(
        "KMN_182",
        "Ensure that kernel module `psnap` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("psnap"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "psnap",
        "SNAP, only used by the dead protocols above.",
    ))
    .with_fix(&fix_disabled("psnap"))
    .register();

    check::Check::new(
        "KMN_183",
        "Ensure that kernel module `qrtr` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("qrtr"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "qrtr",
        "Qualcomm IPC router, autoloadable.",
    ))
    .with_fix(&fix_disabled("qrtr"))
    .register();

    check::Check::new(
        "KMN_184",
        "Ensure that kernel module `qrtr_mhi` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("qrtr_mhi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "qrtr_mhi",
        "Qualcomm IPC router, autoloadable.",
    ))
    .with_fix(&fix_disabled("qrtr_mhi"))
    .register();

    check::Check::new(
        "KMN_185",
        "Ensure that kernel module `qrtr_smd` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("qrtr_smd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "qrtr_smd",
        "Qualcomm IPC router, autoloadable.",
    ))
    .with_fix(&fix_disabled("qrtr_smd"))
    .register();

    check::Check::new(
        "KMN_186",
        "Ensure that kernel module `qrtr_tun` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("qrtr_tun"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "qrtr_tun",
        "Qualcomm IPC router, autoloadable.",
    ))
    .with_fix(&fix_disabled("qrtr_tun"))
    .register();

    check::Check::new(
        "KMN_187",
        "Ensure that kernel module `rds` is disabled",
        Severity::High,
        vec!["module", "CIS", "STIG", "server", "workstation"],
        || modprobe::check_module_disabled("rds"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rds",
        "RDS, Oracle RAC uses it, autoloadable, with repeated CVE history.",
    ))
    .with_fix(&fix_disabled("rds"))
    .register();

    check::Check::new(
        "KMN_188",
        "Ensure that kernel module `rds_rdma` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rds_rdma"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rds_rdma",
        "RDS, Oracle RAC uses it, autoloadable, with repeated CVE history.",
    ))
    .with_fix(&fix_disabled("rds_rdma"))
    .register();

    check::Check::new(
        "KMN_189",
        "Ensure that kernel module `rds_tcp` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rds_tcp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rds_tcp",
        "RDS, Oracle RAC uses it, autoloadable, with repeated CVE history.",
    ))
    .with_fix(&fix_disabled("rds_tcp"))
    .register();

    check::Check::new(
        "KMN_190",
        "Ensure that kernel module `rfc1051` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rfc1051"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("rfc1051", "ARCnet."))
    .with_fix(&fix_disabled("rfc1051"))
    .register();

    check::Check::new(
        "KMN_191",
        "Ensure that kernel module `rfc1201` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rfc1201"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("rfc1201", "ARCnet."))
    .with_fix(&fix_disabled("rfc1201"))
    .register();

    check::Check::new(
        "KMN_192",
        "Ensure that kernel module `rose` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rose"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("rose", "ROSE."))
    .with_fix(&fix_disabled("rose"))
    .register();

    check::Check::new(
        "KMN_193",
        "Ensure that kernel module `s3fwrn5` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("s3fwrn5"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("s3fwrn5", "NFC reader drivers."))
    .with_fix(&fix_disabled("s3fwrn5"))
    .register();

    check::Check::new(
        "KMN_194",
        "Ensure that kernel module `s3fwrn5_i2c` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("s3fwrn5_i2c"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("s3fwrn5_i2c", "NFC reader drivers."))
    .with_fix(&fix_disabled("s3fwrn5_i2c"))
    .register();

    check::Check::new(
        "KMN_195",
        "Ensure that kernel module `s3fwrn82_uart` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("s3fwrn82_uart"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "s3fwrn82_uart",
        "NFC reader drivers.",
    ))
    .with_fix(&fix_disabled("s3fwrn82_uart"))
    .register();

    check::Check::new(
        "KMN_196",
        "Ensure that kernel module `sctp` is disabled",
        Severity::High,
        vec!["module", "CIS", "STIG", "server", "workstation"],
        || modprobe::check_module_disabled("sctp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sctp",
        "SCTP, telecom. Autoloadable.",
    ))
    .with_fix(&fix_disabled("sctp"))
    .register();

    check::Check::new(
        "KMN_197",
        "Ensure that kernel module `sctp_diag` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sctp_diag"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sctp_diag",
        "SCTP, telecom. Autoloadable.",
    ))
    .with_fix(&fix_disabled("sctp_diag"))
    .register();

    check::Check::new(
        "KMN_198",
        "Ensure that kernel module `sja1000` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sja1000"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sja1000",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("sja1000"))
    .register();

    check::Check::new(
        "KMN_199",
        "Ensure that kernel module `sja1000_isa` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sja1000_isa"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sja1000_isa",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("sja1000_isa"))
    .register();

    check::Check::new(
        "KMN_200",
        "Ensure that kernel module `sja1000_platform` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sja1000_platform"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sja1000_platform",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("sja1000_platform"))
    .register();

    check::Check::new(
        "KMN_201",
        "Ensure that kernel module `skfp` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("skfp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("skfp", "FDDI."))
    .with_fix(&fix_disabled("skfp"))
    .register();

    check::Check::new(
        "KMN_202",
        "Ensure that kernel module `slcan` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("slcan"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "slcan",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("slcan"))
    .register();

    check::Check::new(
        "KMN_203",
        "Ensure that kernel module `smc` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("smc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "smc",
        "IBM Shared Memory Comm., autoloadable.",
    ))
    .with_fix(&fix_disabled("smc"))
    .register();

    check::Check::new(
        "KMN_204",
        "Ensure that kernel module `smc_diag` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("smc_diag"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "smc_diag",
        "IBM Shared Memory Comm., autoloadable.",
    ))
    .with_fix(&fix_disabled("smc_diag"))
    .register();

    check::Check::new(
        "KMN_205",
        "Ensure that kernel module `softing` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("softing"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "softing",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("softing"))
    .register();

    check::Check::new(
        "KMN_206",
        "Ensure that kernel module `softing_cs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("softing_cs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "softing_cs",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("softing_cs"))
    .register();

    check::Check::new(
        "KMN_207",
        "Ensure that kernel module `solos_pci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("solos_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("solos_pci", "ATM NIC drivers."))
    .with_fix(&fix_disabled("solos_pci"))
    .register();

    check::Check::new(
        "KMN_208",
        "Ensure that kernel module `speedfax` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("speedfax"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "speedfax",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("speedfax"))
    .register();

    check::Check::new(
        "KMN_209",
        "Ensure that kernel module `speedtch` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("speedtch"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("speedtch", "ADSL modem drivers."))
    .with_fix(&fix_disabled("speedtch"))
    .register();

    check::Check::new(
        "KMN_210",
        "Ensure that kernel module `st21nfca_hci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("st21nfca_hci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("st21nfca_hci", "NFC reader drivers."))
    .with_fix(&fix_disabled("st21nfca_hci"))
    .register();

    check::Check::new(
        "KMN_211",
        "Ensure that kernel module `st21nfca_i2c` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("st21nfca_i2c"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("st21nfca_i2c", "NFC reader drivers."))
    .with_fix(&fix_disabled("st21nfca_i2c"))
    .register();

    check::Check::new(
        "KMN_212",
        "Ensure that kernel module `st95hf` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("st95hf"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("st95hf", "NFC reader drivers."))
    .with_fix(&fix_disabled("st95hf"))
    .register();

    check::Check::new(
        "KMN_213",
        "Ensure that kernel module `st_nci` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("st_nci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("st_nci", "NFC reader drivers."))
    .with_fix(&fix_disabled("st_nci"))
    .register();

    check::Check::new(
        "KMN_214",
        "Ensure that kernel module `st_nci_i2c` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("st_nci_i2c"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("st_nci_i2c", "NFC reader drivers."))
    .with_fix(&fix_disabled("st_nci_i2c"))
    .register();

    check::Check::new(
        "KMN_215",
        "Ensure that kernel module `st_nci_spi` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("st_nci_spi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("st_nci_spi", "NFC reader drivers."))
    .with_fix(&fix_disabled("st_nci_spi"))
    .register();

    check::Check::new(
        "KMN_216",
        "Ensure that kernel module `suni` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("suni"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("suni", "ATM NIC drivers."))
    .with_fix(&fix_disabled("suni"))
    .register();

    check::Check::new(
        "KMN_217",
        "Ensure that kernel module `tcan4x5x` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("tcan4x5x"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tcan4x5x",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("tcan4x5x"))
    .register();

    check::Check::new(
        "KMN_218",
        "Ensure that kernel module `tipc` is disabled",
        Severity::High,
        vec!["module", "CIS", "STIG", "server", "workstation"],
        || modprobe::check_module_disabled("tipc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("tipc", "TIPC, autoloadable."))
    .with_fix(&fix_disabled("tipc"))
    .register();

    check::Check::new(
        "KMN_219",
        "Ensure that kernel module `tipc_diag` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("tipc_diag"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("tipc_diag", "TIPC, autoloadable."))
    .with_fix(&fix_disabled("tipc_diag"))
    .register();

    check::Check::new(
        "KMN_220",
        "Ensure that kernel module `tls` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("tls"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tls",
        "KTLS offload. Apps transparently fall back to userspace TLS.",
    ))
    .with_fix(&fix_disabled("tls"))
    .register();

    check::Check::new(
        "KMN_221",
        "Ensure that kernel module `trf7970a` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("trf7970a"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("trf7970a", "NFC reader drivers."))
    .with_fix(&fix_disabled("trf7970a"))
    .register();

    check::Check::new(
        "KMN_222",
        "Ensure that kernel module `ucan` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ucan"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ucan",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("ucan"))
    .register();

    check::Check::new(
        "KMN_223",
        "Ensure that kernel module `ueagle_atm` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ueagle_atm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ueagle_atm", "USB ADSL modems."))
    .with_fix(&fix_disabled("ueagle_atm"))
    .register();

    check::Check::new(
        "KMN_224",
        "Ensure that kernel module `usb_8dev` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_8dev"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_8dev",
        "Controller Area Network CAN bus controller/vendor driver.",
    ))
    .with_fix(&fix_disabled("usb_8dev"))
    .register();

    check::Check::new(
        "KMN_225",
        "Ensure that kernel module `usbatm` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usbatm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("usbatm", "USB ADSL modems."))
    .with_fix(&fix_disabled("usbatm"))
    .register();

    check::Check::new(
        "KMN_226",
        "Ensure that kernel module `vport_geneve` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vport_geneve"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vport_geneve",
        "Open vSwitch, needed by some container/SDN setups.",
    ))
    .with_fix(&fix_disabled("vport_geneve"))
    .register();

    check::Check::new(
        "KMN_227",
        "Ensure that kernel module `vport_gre` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vport_gre"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vport_gre",
        "Open vSwitch, needed by some container/SDN setups.",
    ))
    .with_fix(&fix_disabled("vport_gre"))
    .register();

    check::Check::new(
        "KMN_228",
        "Ensure that kernel module `vport_vxlan` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vport_vxlan"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vport_vxlan",
        "Open vSwitch, needed by some container/SDN setups.",
    ))
    .with_fix(&fix_disabled("vport_vxlan"))
    .register();

    check::Check::new(
        "KMN_229",
        "Ensure that kernel module `w6692` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w6692"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w6692",
        "ISDN driver, legacy telephony.",
    ))
    .with_fix(&fix_disabled("w6692"))
    .register();

    check::Check::new(
        "KMN_230",
        "Ensure that kernel module `wanxl` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("wanxl"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("wanxl", "Synchronous WAN cards."))
    .with_fix(&fix_disabled("wanxl"))
    .register();

    check::Check::new(
        "KMN_231",
        "Ensure that kernel module `x25` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("x25"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("x25", "X.25."))
    .with_fix(&fix_disabled("x25"))
    .register();

    check::Check::new(
        "KMN_232",
        "Ensure that kernel module `xusbatm` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("xusbatm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xusbatm", "USB ADSL modems."))
    .with_fix(&fix_disabled("xusbatm"))
    .register();

    check::Check::new(
        "KMN_233",
        "Ensure that kernel module `yam` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("yam"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("yam", "Ham radio port drivers."))
    .with_fix(&fix_disabled("yam"))
    .register();

    // legacy and uncommon filesystems (KMF_)
    check::Check::new(
        "KMF_001",
        "Ensure that kernel module `adfs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("adfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("adfs", "Historic filesystems."))
    .with_fix(&fix_disabled("adfs"))
    .register();

    check::Check::new(
        "KMF_002",
        "Ensure that kernel module `affs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("affs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("affs", "Historic filesystems."))
    .with_fix(&fix_disabled("affs"))
    .register();

    check::Check::new(
        "KMF_003",
        "Ensure that kernel module `befs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("befs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("befs", "Historic filesystems."))
    .with_fix(&fix_disabled("befs"))
    .register();

    check::Check::new(
        "KMF_004",
        "Ensure that kernel module `bfs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("bfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("bfs", "Historic filesystems."))
    .with_fix(&fix_disabled("bfs"))
    .register();

    check::Check::new(
        "KMF_005",
        "Ensure that kernel module `coda` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("coda"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("coda", "Exotic network fs."))
    .with_fix(&fix_disabled("coda"))
    .register();

    check::Check::new(
        "KMF_006",
        "Ensure that kernel module `cramfs` is disabled",
        Severity::Medium,
        vec!["module", "CIS", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("cramfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cramfs",
        "Rare filesystems, udf/hfs, also optical/Mac media on workstations.",
    ))
    .with_fix(&fix_disabled("cramfs"))
    .register();

    check::Check::new(
        "KMF_007",
        "Ensure that kernel module `efs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("efs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("efs", "Historic filesystems."))
    .with_fix(&fix_disabled("efs"))
    .register();

    check::Check::new(
        "KMF_008",
        "Ensure that kernel module `erofs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("erofs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("erofs", "Maintained but rarely needed on x86 servers, f2fs: some SSDs. Erofs: some container/snap images."))
    .with_fix(&fix_disabled("erofs"))
    .register();

    check::Check::new(
        "KMF_009",
        "Ensure that kernel module `exfat` is disabled",
        Severity::Medium,
        vec!["module", "server"],
        || modprobe::check_module_disabled("exfat"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "exfat",
        "Same pattern as ntfs3, USB sticks.",
    ))
    .with_fix(&fix_disabled("exfat"))
    .register();

    check::Check::new(
        "KMF_010",
        "Ensure that kernel module `exofs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("exofs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("exofs", "Removed upstream."))
    .with_fix(&fix_disabled("exofs"))
    .register();

    check::Check::new(
        "KMF_011",
        "Ensure that kernel module `f2fs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("f2fs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("f2fs", "Maintained but rarely needed on x86 servers, f2fs: some SSDs. Erofs: some container/snap images."))
    .with_fix(&fix_disabled("f2fs"))
    .register();

    check::Check::new(
        "KMF_012",
        "Ensure that kernel module `freevxfs` is disabled",
        Severity::Medium,
        vec!["module", "CIS", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("freevxfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "freevxfs",
        "Rare filesystems, udf/hfs*: also optical/Mac media on workstations.",
    ))
    .with_fix(&fix_disabled("freevxfs"))
    .register();

    check::Check::new(
        "KMF_013",
        "Ensure that kernel module `hfs` is disabled",
        Severity::Medium,
        vec!["module", "CIS", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("hfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hfs",
        "Rare filesystems, udf/hfs*: also optical/Mac media on workstations.",
    ))
    .with_fix(&fix_disabled("hfs"))
    .register();

    check::Check::new(
        "KMF_014",
        "Ensure that kernel module `hfsplus` is disabled",
        Severity::Medium,
        vec!["module", "CIS", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("hfsplus"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hfsplus",
        "Rare filesystems, udf/hfs*: also optical/Mac media on workstations.",
    ))
    .with_fix(&fix_disabled("hfsplus"))
    .register();

    check::Check::new(
        "KMF_015",
        "Ensure that kernel module `hpfs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hpfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hpfs", "Historic filesystems."))
    .with_fix(&fix_disabled("hpfs"))
    .register();

    check::Check::new(
        "KMF_016",
        "Ensure that kernel module `jffs2` is disabled",
        Severity::Medium,
        vec!["module", "CIS", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("jffs2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "jffs2",
        "Rare filesystems, udf/hfs*: also optical/Mac media on workstations.",
    ))
    .with_fix(&fix_disabled("jffs2"))
    .register();

    check::Check::new(
        "KMF_017",
        "Ensure that kernel module `jfs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("jfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("jfs", "Maintained but rarely needed on x86 servers, f2fs: some SSDs. Erofs: some container/snap images."))
    .with_fix(&fix_disabled("jfs"))
    .register();

    check::Check::new(
        "KMF_018",
        "Ensure that kernel module `minix` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("minix"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("minix", "Historic filesystems."))
    .with_fix(&fix_disabled("minix"))
    .register();

    check::Check::new(
        "KMF_019",
        "Ensure that kernel module `mtd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mtd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mtd", "Raw flash, embedded."))
    .with_fix(&fix_disabled("mtd"))
    .register();

    check::Check::new(
        "KMF_020",
        "Ensure that kernel module `nilfs2` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nilfs2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nilfs2", "Historic filesystems."))
    .with_fix(&fix_disabled("nilfs2"))
    .register();

    check::Check::new(
        "KMF_021",
        "Ensure that kernel module `ntfs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ntfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ntfs", "Removed upstream."))
    .with_fix(&fix_disabled("ntfs"))
    .register();

    check::Check::new(
        "KMF_022",
        "Ensure that kernel module `ntfs3` is disabled",
        Severity::Medium,
        vec!["module", "server"],
        || modprobe::check_module_disabled("ntfs3"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ntfs3",
        "Modern NTFS. Workstations mounting NTFS USB drives need it.",
    ))
    .with_fix(&fix_disabled("ntfs3"))
    .register();

    check::Check::new(
        "KMF_023",
        "Ensure that kernel module `ocfs2_dlm` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ocfs2_dlm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ocfs2_dlm",
        "Legacy, uncommon or network filesystem module.",
    ))
    .with_fix(&fix_disabled("ocfs2_dlm"))
    .register();

    check::Check::new(
        "KMF_024",
        "Ensure that kernel module `ocfs2_dlmfs` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ocfs2_dlmfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ocfs2_dlmfs",
        "Legacy, uncommon or network filesystem module.",
    ))
    .with_fix(&fix_disabled("ocfs2_dlmfs"))
    .register();

    check::Check::new(
        "KMF_025",
        "Ensure that kernel module `ocfs2_nodemanager` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ocfs2_nodemanager"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ocfs2_nodemanager",
        "Legacy, uncommon or network filesystem module.",
    ))
    .with_fix(&fix_disabled("ocfs2_nodemanager"))
    .register();

    check::Check::new(
        "KMF_026",
        "Ensure that kernel module `ocfs2_stack_o2cb` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ocfs2_stack_o2cb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ocfs2_stack_o2cb",
        "Legacy, uncommon or network filesystem module.",
    ))
    .with_fix(&fix_disabled("ocfs2_stack_o2cb"))
    .register();

    check::Check::new(
        "KMF_027",
        "Ensure that kernel module `ocfs2_stack_user` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ocfs2_stack_user"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ocfs2_stack_user",
        "Legacy, uncommon or network filesystem module.",
    ))
    .with_fix(&fix_disabled("ocfs2_stack_user"))
    .register();

    check::Check::new(
        "KMF_028",
        "Ensure that kernel module `ocfs2_stackglue` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ocfs2_stackglue"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ocfs2_stackglue",
        "Legacy, uncommon or network filesystem module.",
    ))
    .with_fix(&fix_disabled("ocfs2_stackglue"))
    .register();

    check::Check::new(
        "KMF_029",
        "Ensure that kernel module `omfs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("omfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("omfs", "Historic filesystems."))
    .with_fix(&fix_disabled("omfs"))
    .register();

    check::Check::new(
        "KMF_030",
        "Ensure that kernel module `orangefs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("orangefs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("orangefs", "Exotic network fs."))
    .with_fix(&fix_disabled("orangefs"))
    .register();

    check::Check::new(
        "KMF_031",
        "Ensure that kernel module `pstore_blk` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pstore_blk"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pstore_blk",
        "Pstore on block/EFI vars. Keep ramoops/pstore for crash logs.",
    ))
    .with_fix(&fix_disabled("pstore_blk"))
    .register();

    check::Check::new(
        "KMF_032",
        "Ensure that kernel module `pstore_zone` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pstore_zone"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pstore_zone",
        "Pstore on block/EFI vars. Keep ramoops/pstore for crash logs.",
    ))
    .with_fix(&fix_disabled("pstore_zone"))
    .register();

    check::Check::new(
        "KMF_033",
        "Ensure that kernel module `qnx4` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("qnx4"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("qnx4", "Historic filesystems."))
    .with_fix(&fix_disabled("qnx4"))
    .register();

    check::Check::new(
        "KMF_034",
        "Ensure that kernel module `qnx6` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("qnx6"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("qnx6", "Historic filesystems."))
    .with_fix(&fix_disabled("qnx6"))
    .register();

    check::Check::new(
        "KMF_035",
        "Ensure that kernel module `reiserfs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("reiserfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("reiserfs", "Removed upstream."))
    .with_fix(&fix_disabled("reiserfs"))
    .register();

    check::Check::new(
        "KMF_036",
        "Ensure that kernel module `romfs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("romfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("romfs", "Embedded / zoned-block fs."))
    .with_fix(&fix_disabled("romfs"))
    .register();

    check::Check::new(
        "KMF_037",
        "Ensure that kernel module `squashfs` is disabled",
        Severity::Medium,
        vec!["module", "CIS", "server", "workstation"],
        || modprobe::check_module_disabled("squashfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "squashfs",
        "Needed for snap where built as a module.",
    ))
    .with_fix(&fix_disabled("squashfs"))
    .register();

    check::Check::new(
        "KMF_038",
        "Ensure that kernel module `sysv` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sysv"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("sysv", "Historic filesystems."))
    .with_fix(&fix_disabled("sysv"))
    .register();

    check::Check::new(
        "KMF_039",
        "Ensure that kernel module `ubifs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ubifs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ubifs", "Raw flash, embedded."))
    .with_fix(&fix_disabled("ubifs"))
    .register();

    check::Check::new(
        "KMF_040",
        "Ensure that kernel module `udf` is disabled",
        Severity::Medium,
        vec!["module", "CIS", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("udf"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "udf",
        "Rare filesystems, udf/hfs*: also optical/Mac media on workstations.",
    ))
    .with_fix(&fix_disabled("udf"))
    .register();

    check::Check::new(
        "KMF_041",
        "Ensure that kernel module `ufs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ufs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ufs", "Historic filesystems."))
    .with_fix(&fix_disabled("ufs"))
    .register();

    check::Check::new(
        "KMF_042",
        "Ensure that kernel module `vboxsf` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vboxsf"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vboxsf",
        "VirtualBox shared folders.",
    ))
    .with_fix(&fix_disabled("vboxsf"))
    .register();

    check::Check::new(
        "KMF_043",
        "Ensure that kernel module `zonefs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("zonefs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "zonefs",
        "Embedded / zoned-block fs.",
    ))
    .with_fix(&fix_disabled("zonefs"))
    .register();

    // network filesystems and storage services (KMF_)
    check::Check::new(
        "KMF_060",
        "Ensure that kernel module `9p` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("9p"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("9p", "Plan9 sharing, qemu/VMM host-guest. Dev workstations running VMs may need 9pnet_virtio *in the guest*."))
    .with_fix(&fix_disabled("9p"))
    .register();

    check::Check::new(
        "KMF_061",
        "Ensure that kernel module `9pnet` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("9pnet"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("9pnet", "Plan9 sharing, qemu/VMM host-guest. Dev workstations running VMs may need 9pnet_virtio *in the guest*."))
    .with_fix(&fix_disabled("9pnet"))
    .register();

    check::Check::new(
        "KMF_062",
        "Ensure that kernel module `9pnet_fd` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("9pnet_fd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("9pnet_fd", "Plan9 sharing, qemu/VMM host-guest. Dev workstations running VMs may need 9pnet_virtio *in the guest*."))
    .with_fix(&fix_disabled("9pnet_fd"))
    .register();

    check::Check::new(
        "KMF_063",
        "Ensure that kernel module `9pnet_rdma` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("9pnet_rdma"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("9pnet_rdma", "Plan9 sharing, qemu/VMM host-guest. Dev workstations running VMs may need 9pnet_virtio *in the guest*."))
    .with_fix(&fix_disabled("9pnet_rdma"))
    .register();

    check::Check::new(
        "KMF_064",
        "Ensure that kernel module `9pnet_usbg` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("9pnet_usbg"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("9pnet_usbg", "Plan9 sharing, qemu/VMM host-guest. Dev workstations running VMs may need 9pnet_virtio *in the guest*."))
    .with_fix(&fix_disabled("9pnet_usbg"))
    .register();

    check::Check::new(
        "KMF_065",
        "Ensure that kernel module `9pnet_virtio` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("9pnet_virtio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("9pnet_virtio", "Plan9 sharing, qemu/VMM host-guest. Dev workstations running VMs may need 9pnet_virtio *in the guest*."))
    .with_fix(&fix_disabled("9pnet_virtio"))
    .register();

    check::Check::new(
        "KMF_066",
        "Ensure that kernel module `9pnet_xen` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("9pnet_xen"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("9pnet_xen", "Plan9 sharing, qemu/VMM host-guest. Dev workstations running VMs may need 9pnet_virtio *in the guest*."))
    .with_fix(&fix_disabled("9pnet_xen"))
    .register();

    check::Check::new(
        "KMF_067",
        "Ensure that kernel module `aoe` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("aoe"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "aoe",
        "ATA over Ethernet, dead protocol, with repeated CVE history.",
    ))
    .with_fix(&fix_disabled("aoe"))
    .register();

    check::Check::new(
        "KMF_068",
        "Ensure that kernel module `auth_rpcgss` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("auth_rpcgss"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "auth_rpcgss",
        "NFS/RPC dependencies. Disable together with NFS.",
    ))
    .with_fix(&fix_disabled("auth_rpcgss"))
    .register();

    check::Check::new(
        "KMF_069",
        "Ensure that kernel module `ceph` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ceph"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ceph", "Ceph fs/block client."))
    .with_fix(&fix_disabled("ceph"))
    .register();

    check::Check::new(
        "KMF_070",
        "Ensure that kernel module `cifs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("cifs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("cifs", "SMB client."))
    .with_fix(&fix_disabled("cifs"))
    .register();

    check::Check::new(
        "KMF_071",
        "Ensure that kernel module `cifs_arc4` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("cifs_arc4"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("cifs_arc4", "SMB client."))
    .with_fix(&fix_disabled("cifs_arc4"))
    .register();

    check::Check::new(
        "KMF_072",
        "Ensure that kernel module `cifs_md4` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("cifs_md4"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("cifs_md4", "SMB client."))
    .with_fix(&fix_disabled("cifs_md4"))
    .register();

    check::Check::new(
        "KMF_073",
        "Ensure that kernel module `cxgbit` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("cxgbit"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("cxgbit", "LIO storage target."))
    .with_fix(&fix_disabled("cxgbit"))
    .register();

    check::Check::new(
        "KMF_074",
        "Ensure that kernel module `dlm` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("dlm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dlm", "Cluster filesystems."))
    .with_fix(&fix_disabled("dlm"))
    .register();

    check::Check::new(
        "KMF_075",
        "Ensure that kernel module `drbd` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("drbd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "drbd",
        "Network block devices / replication.",
    ))
    .with_fix(&fix_disabled("drbd"))
    .register();

    check::Check::new(
        "KMF_076",
        "Ensure that kernel module `gfs2` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("gfs2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("gfs2", "Cluster filesystems."))
    .with_fix(&fix_disabled("gfs2"))
    .register();

    check::Check::new(
        "KMF_077",
        "Ensure that kernel module `grace` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("grace"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "grace",
        "NFS/RPC dependencies. Disable together with NFS.",
    ))
    .with_fix(&fix_disabled("grace"))
    .register();

    check::Check::new(
        "KMF_078",
        "Ensure that kernel module `iscsi_target_mod` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("iscsi_target_mod"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "iscsi_target_mod",
        "LIO storage target.",
    ))
    .with_fix(&fix_disabled("iscsi_target_mod"))
    .register();

    check::Check::new(
        "KMF_079",
        "Ensure that kernel module `iscsi_tcp` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("iscsi_tcp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("iscsi_tcp", "ISCSI initiator."))
    .with_fix(&fix_disabled("iscsi_tcp"))
    .register();

    check::Check::new(
        "KMF_080",
        "Ensure that kernel module `kafs` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("kafs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "kafs",
        "AFS filesystem/protocol, autoloadable via rxrpc socket.",
    ))
    .with_fix(&fix_disabled("kafs"))
    .register();

    check::Check::new(
        "KMF_081",
        "Ensure that kernel module `ksmbd` is disabled",
        Severity::Critical,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ksmbd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ksmbd",
        "In-kernel SMB server, has had serious pre-auth RCEs.",
    ))
    .with_fix(&fix_disabled("ksmbd"))
    .register();

    check::Check::new(
        "KMF_082",
        "Ensure that kernel module `libceph` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("libceph"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("libceph", "Ceph fs/block client."))
    .with_fix(&fix_disabled("libceph"))
    .register();

    check::Check::new(
        "KMF_083",
        "Ensure that kernel module `libiscsi` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("libiscsi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("libiscsi", "ISCSI initiator."))
    .with_fix(&fix_disabled("libiscsi"))
    .register();

    check::Check::new(
        "KMF_084",
        "Ensure that kernel module `lockd` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("lockd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "lockd",
        "NFS/RPC dependencies. Disable together with NFS.",
    ))
    .with_fix(&fix_disabled("lockd"))
    .register();

    check::Check::new(
        "KMF_085",
        "Ensure that kernel module `nbd` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("nbd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nbd",
        "Network block devices / replication.",
    ))
    .with_fix(&fix_disabled("nbd"))
    .register();

    check::Check::new(
        "KMF_086",
        "Ensure that kernel module `nfs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("nfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nfs", "NFS client."))
    .with_fix(&fix_disabled("nfs"))
    .register();

    check::Check::new(
        "KMF_087",
        "Ensure that kernel module `nfs_acl` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("nfs_acl"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nfs_acl", "NFS client."))
    .with_fix(&fix_disabled("nfs_acl"))
    .register();

    check::Check::new(
        "KMF_088",
        "Ensure that kernel module `nfs_common` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("nfs_common"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nfs_common",
        "NFS/RPC dependencies. Disable together with NFS.",
    ))
    .with_fix(&fix_disabled("nfs_common"))
    .register();

    check::Check::new(
        "KMF_089",
        "Ensure that kernel module `nfs_layout_flexfiles` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("nfs_layout_flexfiles"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nfs_layout_flexfiles", "NFS client."))
    .with_fix(&fix_disabled("nfs_layout_flexfiles"))
    .register();

    check::Check::new(
        "KMF_090",
        "Ensure that kernel module `nfs_layout_nfsv41_files` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("nfs_layout_nfsv41_files"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nfs_layout_nfsv41_files",
        "NFS client.",
    ))
    .with_fix(&fix_disabled("nfs_layout_nfsv41_files"))
    .register();

    check::Check::new(
        "KMF_091",
        "Ensure that kernel module `nfsd` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("nfsd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nfsd", "NFS server."))
    .with_fix(&fix_disabled("nfsd"))
    .register();

    check::Check::new(
        "KMF_092",
        "Ensure that kernel module `nfsv2` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("nfsv2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nfsv2", "NFS client."))
    .with_fix(&fix_disabled("nfsv2"))
    .register();

    check::Check::new(
        "KMF_093",
        "Ensure that kernel module `nfsv3` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("nfsv3"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nfsv3", "NFS client."))
    .with_fix(&fix_disabled("nfsv3"))
    .register();

    check::Check::new(
        "KMF_094",
        "Ensure that kernel module `nfsv4` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("nfsv4"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nfsv4", "NFS client."))
    .with_fix(&fix_disabled("nfsv4"))
    .register();

    check::Check::new(
        "KMF_095",
        "Ensure that kernel module `ocfs2` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ocfs2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ocfs2", "Cluster filesystems."))
    .with_fix(&fix_disabled("ocfs2"))
    .register();

    check::Check::new(
        "KMF_096",
        "Ensure that kernel module `rbd` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("rbd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("rbd", "Ceph fs/block client."))
    .with_fix(&fix_disabled("rbd"))
    .register();

    check::Check::new(
        "KMF_097",
        "Ensure that kernel module `rnbd_client` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("rnbd_client"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rnbd_client",
        "Network block devices / replication.",
    ))
    .with_fix(&fix_disabled("rnbd_client"))
    .register();

    check::Check::new(
        "KMF_098",
        "Ensure that kernel module `rnbd_server` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("rnbd_server"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rnbd_server",
        "Network block devices / replication.",
    ))
    .with_fix(&fix_disabled("rnbd_server"))
    .register();

    check::Check::new(
        "KMF_099",
        "Ensure that kernel module `rpcrdma` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("rpcrdma"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rpcrdma",
        "NFS/RPC dependencies. Disable together with NFS.",
    ))
    .with_fix(&fix_disabled("rpcrdma"))
    .register();

    check::Check::new(
        "KMF_100",
        "Ensure that kernel module `rpcsec_gss_krb5` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("rpcsec_gss_krb5"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rpcsec_gss_krb5",
        "NFS/RPC dependencies. Disable together with NFS.",
    ))
    .with_fix(&fix_disabled("rpcsec_gss_krb5"))
    .register();

    check::Check::new(
        "KMF_101",
        "Ensure that kernel module `rxrpc` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rxrpc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rxrpc",
        "AFS filesystem/protocol, autoloadable via rxrpc socket.",
    ))
    .with_fix(&fix_disabled("rxrpc"))
    .register();

    check::Check::new(
        "KMF_102",
        "Ensure that kernel module `sbp_target` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("sbp_target"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("sbp_target", "LIO storage target."))
    .with_fix(&fix_disabled("sbp_target"))
    .register();

    check::Check::new(
        "KMF_103",
        "Ensure that kernel module `scsi_transport_iscsi` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("scsi_transport_iscsi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "scsi_transport_iscsi",
        "ISCSI initiator.",
    ))
    .with_fix(&fix_disabled("scsi_transport_iscsi"))
    .register();

    check::Check::new(
        "KMF_104",
        "Ensure that kernel module `sunrpc` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("sunrpc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sunrpc",
        "NFS/RPC dependencies. Disable together with NFS.",
    ))
    .with_fix(&fix_disabled("sunrpc"))
    .register();

    check::Check::new(
        "KMF_105",
        "Ensure that kernel module `target_core_file` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("target_core_file"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "target_core_file",
        "LIO storage target file backend.",
    ))
    .with_fix(&fix_disabled("target_core_file"))
    .register();

    check::Check::new(
        "KMF_106",
        "Ensure that kernel module `target_core_iblock` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("target_core_iblock"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "target_core_iblock",
        "LIO storage target block backend.",
    ))
    .with_fix(&fix_disabled("target_core_iblock"))
    .register();

    check::Check::new(
        "KMF_107",
        "Ensure that kernel module `target_core_mod` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("target_core_mod"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "target_core_mod",
        "LIO storage target.",
    ))
    .with_fix(&fix_disabled("target_core_mod"))
    .register();

    check::Check::new(
        "KMF_108",
        "Ensure that kernel module `target_core_pscsi` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("target_core_pscsi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "target_core_pscsi",
        "LIO storage target SCSI backend.",
    ))
    .with_fix(&fix_disabled("target_core_pscsi"))
    .register();

    check::Check::new(
        "KMF_109",
        "Ensure that kernel module `target_core_user` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("target_core_user"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "target_core_user",
        "LIO storage target userspace backend.",
    ))
    .with_fix(&fix_disabled("target_core_user"))
    .register();

    check::Check::new(
        "KMF_110",
        "Ensure that kernel module `tcm_fc` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("tcm_fc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tcm_fc",
        "LIO Fibre-Channel target fabric.",
    ))
    .with_fix(&fix_disabled("tcm_fc"))
    .register();

    check::Check::new(
        "KMF_111",
        "Ensure that kernel module `tcm_loop` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("tcm_loop"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tcm_loop",
        "LIO loopback SCSI target fabric.",
    ))
    .with_fix(&fix_disabled("tcm_loop"))
    .register();

    check::Check::new(
        "KMF_112",
        "Ensure that kernel module `virtiofs` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("virtiofs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "virtiofs",
        "Virtio shared fs, VM guests.",
    ))
    .with_fix(&fix_disabled("virtiofs"))
    .register();

    // bluetooth (KMO_)
    check::Check::new(
        "KMO_001",
        "Ensure that kernel module `ath3k` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ath3k"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ath3k", "Additional vendor drivers."))
    .with_fix(&fix_disabled("ath3k"))
    .register();

    check::Check::new(
        "KMO_002",
        "Ensure that kernel module `bcm203x` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("bcm203x"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "bcm203x",
        "Additional vendor drivers.",
    ))
    .with_fix(&fix_disabled("bcm203x"))
    .register();

    check::Check::new(
        "KMO_003",
        "Ensure that kernel module `bfusb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("bfusb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("bfusb", "Additional vendor drivers."))
    .with_fix(&fix_disabled("bfusb"))
    .register();

    check::Check::new(
        "KMO_004",
        "Ensure that kernel module `bluecard_cs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("bluecard_cs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "bluecard_cs",
        "Additional vendor drivers.",
    ))
    .with_fix(&fix_disabled("bluecard_cs"))
    .register();

    check::Check::new(
        "KMO_005",
        "Ensure that kernel module `bluetooth` is disabled",
        Severity::High,
        vec!["module", "STIG", "server", "workstation"],
        || modprobe::check_module_disabled("bluetooth"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("bluetooth", "Core stack."))
    .with_fix(&fix_disabled("bluetooth"))
    .register();

    check::Check::new(
        "KMO_006",
        "Ensure that kernel module `bluetooth_6lowpan` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("bluetooth_6lowpan"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("bluetooth_6lowpan", "BLE 6LoWPAN."))
    .with_fix(&fix_disabled("bluetooth_6lowpan"))
    .register();

    check::Check::new(
        "KMO_007",
        "Ensure that kernel module `bnep` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("bnep"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "bnep",
        "BT network/serial/HID profiles, autoloadable via socket(AF_BLUETOOTH).",
    ))
    .with_fix(&fix_disabled("bnep"))
    .register();

    check::Check::new(
        "KMO_008",
        "Ensure that kernel module `bpa10x` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("bpa10x"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "bpa10x",
        "Additional vendor drivers.",
    ))
    .with_fix(&fix_disabled("bpa10x"))
    .register();

    check::Check::new(
        "KMO_009",
        "Ensure that kernel module `bt3c_cs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("bt3c_cs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("bt3c_cs", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("bt3c_cs"))
    .register();

    check::Check::new(
        "KMO_010",
        "Ensure that kernel module `btbcm` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btbcm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("btbcm", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("btbcm"))
    .register();

    check::Check::new(
        "KMO_011",
        "Ensure that kernel module `btintel` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btintel"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("btintel", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("btintel"))
    .register();

    check::Check::new(
        "KMO_012",
        "Ensure that kernel module `btintel_pcie` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btintel_pcie"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "btintel_pcie",
        "Additional vendor drivers.",
    ))
    .with_fix(&fix_disabled("btintel_pcie"))
    .register();

    check::Check::new(
        "KMO_013",
        "Ensure that kernel module `btmrvl` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btmrvl"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("btmrvl", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("btmrvl"))
    .register();

    check::Check::new(
        "KMO_014",
        "Ensure that kernel module `btmrvl_sdio` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btmrvl_sdio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("btmrvl_sdio", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("btmrvl_sdio"))
    .register();

    check::Check::new(
        "KMO_015",
        "Ensure that kernel module `btmtk` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btmtk"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("btmtk", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("btmtk"))
    .register();

    check::Check::new(
        "KMO_016",
        "Ensure that kernel module `btmtksdio` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btmtksdio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("btmtksdio", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("btmtksdio"))
    .register();

    check::Check::new(
        "KMO_017",
        "Ensure that kernel module `btmtkuart` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btmtkuart"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("btmtkuart", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("btmtkuart"))
    .register();

    check::Check::new(
        "KMO_018",
        "Ensure that kernel module `btnxpuart` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btnxpuart"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("btnxpuart", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("btnxpuart"))
    .register();

    check::Check::new(
        "KMO_019",
        "Ensure that kernel module `btqca` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btqca"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("btqca", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("btqca"))
    .register();

    check::Check::new(
        "KMO_020",
        "Ensure that kernel module `btrsi` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btrsi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("btrsi", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("btrsi"))
    .register();

    check::Check::new(
        "KMO_021",
        "Ensure that kernel module `btrtl` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btrtl"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("btrtl", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("btrtl"))
    .register();

    check::Check::new(
        "KMO_022",
        "Ensure that kernel module `btsdio` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btsdio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("btsdio", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("btsdio"))
    .register();

    check::Check::new(
        "KMO_023",
        "Ensure that kernel module `btusb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btusb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("btusb", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("btusb"))
    .register();

    check::Check::new(
        "KMO_024",
        "Ensure that kernel module `dtl1_cs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dtl1_cs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "dtl1_cs",
        "Additional vendor drivers.",
    ))
    .with_fix(&fix_disabled("dtl1_cs"))
    .register();

    check::Check::new(
        "KMO_025",
        "Ensure that kernel module `hci_bcm4377` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hci_bcm4377"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hci_bcm4377",
        "Additional vendor drivers.",
    ))
    .with_fix(&fix_disabled("hci_bcm4377"))
    .register();

    check::Check::new(
        "KMO_026",
        "Ensure that kernel module `hci_nokia` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hci_nokia"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hci_nokia",
        "Additional vendor drivers.",
    ))
    .with_fix(&fix_disabled("hci_nokia"))
    .register();

    check::Check::new(
        "KMO_027",
        "Ensure that kernel module `hci_uart` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hci_uart"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hci_uart",
        "Additional vendor drivers.",
    ))
    .with_fix(&fix_disabled("hci_uart"))
    .register();

    check::Check::new(
        "KMO_028",
        "Ensure that kernel module `hidp` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hidp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hidp",
        "BT network/serial/HID profiles, autoloadable via socket(AF_BLUETOOTH).",
    ))
    .with_fix(&fix_disabled("hidp"))
    .register();

    check::Check::new(
        "KMO_029",
        "Ensure that kernel module `rfcomm` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rfcomm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rfcomm",
        "BT network/serial/HID profiles, autoloadable via socket(AF_BLUETOOTH).",
    ))
    .with_fix(&fix_disabled("rfcomm"))
    .register();

    check::Check::new(
        "KMO_030",
        "Ensure that kernel module `virtio_bt` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("virtio_bt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("virtio_bt", "Vendor HCI drivers."))
    .with_fix(&fix_disabled("virtio_bt"))
    .register();

    // wireless LAN (Wi-Fi) (KMO_)
    check::Check::new(
        "KMO_040",
        "Ensure that kernel module `cfg80211` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("cfg80211"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("cfg80211", "Wireless core."))
    .with_fix(&fix_disabled("cfg80211"))
    .register();

    check::Check::new(
        "KMO_041",
        "Ensure that kernel module `mac80211` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("mac80211"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mac80211", "Soft-MAC layer."))
    .with_fix(&fix_disabled("mac80211"))
    .register();

    // USB (KMU_)
    check::Check::new(
        "KMU_001",
        "Ensure that kernel module `adutux` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("adutux"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "adutux",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("adutux"))
    .register();

    check::Check::new(
        "KMU_002",
        "Ensure that kernel module `apple_mfi_fastcharge` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("apple_mfi_fastcharge"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "apple_mfi_fastcharge",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("apple_mfi_fastcharge"))
    .register();

    check::Check::new(
        "KMU_003",
        "Ensure that kernel module `appledisplay` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("appledisplay"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "appledisplay",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("appledisplay"))
    .register();

    check::Check::new(
        "KMU_004",
        "Ensure that kernel module `aqc111` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("aqc111"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "aqc111",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("aqc111"))
    .register();

    check::Check::new(
        "KMU_005",
        "Ensure that kernel module `ark3116` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ark3116"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ark3116",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("ark3116"))
    .register();

    check::Check::new(
        "KMU_006",
        "Ensure that kernel module `asix` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("asix"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "asix",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("asix"))
    .register();

    check::Check::new(
        "KMU_007",
        "Ensure that kernel module `ax88179_178a` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("ax88179_178a"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ax88179_178a",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("ax88179_178a"))
    .register();

    check::Check::new(
        "KMU_008",
        "Ensure that kernel module `bcma_hcd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("bcma_hcd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "bcma_hcd",
        "Obsolete host controllers.",
    ))
    .with_fix(&fix_disabled("bcma_hcd"))
    .register();

    check::Check::new(
        "KMU_009",
        "Ensure that kernel module `belkin_sa` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("belkin_sa"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "belkin_sa",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("belkin_sa"))
    .register();

    check::Check::new(
        "KMU_010",
        "Ensure that kernel module `catc` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("catc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "catc",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("catc"))
    .register();

    check::Check::new(
        "KMU_011",
        "Ensure that kernel module `cdc_eem` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("cdc_eem"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cdc_eem",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("cdc_eem"))
    .register();

    check::Check::new(
        "KMU_012",
        "Ensure that kernel module `cdc_ether` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("cdc_ether"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cdc_ether",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("cdc_ether"))
    .register();

    check::Check::new(
        "KMU_013",
        "Ensure that kernel module `cdc_mbim` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("cdc_mbim"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cdc_mbim",
        "Laptops with LTE modems.",
    ))
    .with_fix(&fix_disabled("cdc_mbim"))
    .register();

    check::Check::new(
        "KMU_014",
        "Ensure that kernel module `cdc_ncm` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("cdc_ncm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cdc_ncm",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("cdc_ncm"))
    .register();

    check::Check::new(
        "KMU_015",
        "Ensure that kernel module `cdc_wdm` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("cdc_wdm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("cdc_wdm", "Laptops with LTE modems."))
    .with_fix(&fix_disabled("cdc_wdm"))
    .register();

    check::Check::new(
        "KMU_016",
        "Ensure that kernel module `ch341` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ch341"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ch341",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("ch341"))
    .register();

    check::Check::new(
        "KMU_017",
        "Ensure that kernel module `ch9200` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("ch9200"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ch9200",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("ch9200"))
    .register();

    check::Check::new(
        "KMU_018",
        "Ensure that kernel module `chaoskey` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("chaoskey"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "chaoskey",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("chaoskey"))
    .register();

    check::Check::new(
        "KMU_019",
        "Ensure that kernel module `cp210x` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("cp210x"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cp210x",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("cp210x"))
    .register();

    check::Check::new(
        "KMU_020",
        "Ensure that kernel module `cx82310_eth` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("cx82310_eth"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cx82310_eth",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("cx82310_eth"))
    .register();

    check::Check::new(
        "KMU_021",
        "Ensure that kernel module `cypress_cy7c63` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cypress_cy7c63"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cypress_cy7c63",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("cypress_cy7c63"))
    .register();

    check::Check::new(
        "KMU_022",
        "Ensure that kernel module `cypress_m8` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("cypress_m8"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cypress_m8",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("cypress_m8"))
    .register();

    check::Check::new(
        "KMU_023",
        "Ensure that kernel module `cytherm` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cytherm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cytherm",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("cytherm"))
    .register();

    check::Check::new(
        "KMU_024",
        "Ensure that kernel module `digi_acceleport` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("digi_acceleport"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "digi_acceleport",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("digi_acceleport"))
    .register();

    check::Check::new(
        "KMU_025",
        "Ensure that kernel module `dm9601` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("dm9601"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "dm9601",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("dm9601"))
    .register();

    check::Check::new(
        "KMU_026",
        "Ensure that kernel module `ehci_fsl` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ehci_fsl"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ehci_fsl",
        "Obsolete host controllers.",
    ))
    .with_fix(&fix_disabled("ehci_fsl"))
    .register();

    check::Check::new(
        "KMU_027",
        "Ensure that kernel module `emi26` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("emi26"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "emi26",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("emi26"))
    .register();

    check::Check::new(
        "KMU_028",
        "Ensure that kernel module `emi62` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("emi62"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "emi62",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("emi62"))
    .register();

    check::Check::new(
        "KMU_029",
        "Ensure that kernel module `ezusb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ezusb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ezusb",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("ezusb"))
    .register();

    check::Check::new(
        "KMU_030",
        "Ensure that kernel module `f81232` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("f81232"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "f81232",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("f81232"))
    .register();

    check::Check::new(
        "KMU_031",
        "Ensure that kernel module `f81534` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("f81534"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "f81534",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("f81534"))
    .register();

    check::Check::new(
        "KMU_032",
        "Ensure that kernel module `fsl_mph_dr_of` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("fsl_mph_dr_of"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "fsl_mph_dr_of",
        "Obsolete host controllers.",
    ))
    .with_fix(&fix_disabled("fsl_mph_dr_of"))
    .register();

    check::Check::new(
        "KMU_033",
        "Ensure that kernel module `ftdi_sio` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ftdi_sio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ftdi_sio",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("ftdi_sio"))
    .register();

    check::Check::new(
        "KMU_034",
        "Ensure that kernel module `g_acm_ms` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_acm_ms"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_acm_ms",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_acm_ms"))
    .register();

    check::Check::new(
        "KMU_035",
        "Ensure that kernel module `g_audio` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_audio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_audio",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_audio"))
    .register();

    check::Check::new(
        "KMU_036",
        "Ensure that kernel module `g_cdc` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_cdc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_cdc",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_cdc"))
    .register();

    check::Check::new(
        "KMU_037",
        "Ensure that kernel module `g_dbgp` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_dbgp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_dbgp",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_dbgp"))
    .register();

    check::Check::new(
        "KMU_038",
        "Ensure that kernel module `g_ether` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_ether"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_ether",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_ether"))
    .register();

    check::Check::new(
        "KMU_039",
        "Ensure that kernel module `g_ffs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_ffs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_ffs",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_ffs"))
    .register();

    check::Check::new(
        "KMU_040",
        "Ensure that kernel module `g_hid` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_hid"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_hid",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_hid"))
    .register();

    check::Check::new(
        "KMU_041",
        "Ensure that kernel module `g_mass_storage` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_mass_storage"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_mass_storage",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_mass_storage"))
    .register();

    check::Check::new(
        "KMU_042",
        "Ensure that kernel module `g_midi` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_midi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_midi",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_midi"))
    .register();

    check::Check::new(
        "KMU_043",
        "Ensure that kernel module `g_ncm` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_ncm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_ncm",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_ncm"))
    .register();

    check::Check::new(
        "KMU_044",
        "Ensure that kernel module `g_nokia` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_nokia"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_nokia",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_nokia"))
    .register();

    check::Check::new(
        "KMU_045",
        "Ensure that kernel module `g_printer` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_printer"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_printer",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_printer"))
    .register();

    check::Check::new(
        "KMU_046",
        "Ensure that kernel module `g_serial` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_serial"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_serial",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_serial"))
    .register();

    check::Check::new(
        "KMU_047",
        "Ensure that kernel module `g_webcam` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g_webcam"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g_webcam",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("g_webcam"))
    .register();

    check::Check::new(
        "KMU_048",
        "Ensure that kernel module `gl620a` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("gl620a"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "gl620a",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("gl620a"))
    .register();

    check::Check::new(
        "KMU_049",
        "Ensure that kernel module `hso` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("hso"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hso", "Laptops with LTE modems."))
    .with_fix(&fix_disabled("hso"))
    .register();

    check::Check::new(
        "KMU_050",
        "Ensure that kernel module `huawei_cdc_ncm` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("huawei_cdc_ncm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "huawei_cdc_ncm",
        "Laptops with LTE modems.",
    ))
    .with_fix(&fix_disabled("huawei_cdc_ncm"))
    .register();

    check::Check::new(
        "KMU_051",
        "Ensure that kernel module `idmouse` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("idmouse"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "idmouse",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("idmouse"))
    .register();

    check::Check::new(
        "KMU_052",
        "Ensure that kernel module `int51x1` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("int51x1"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "int51x1",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("int51x1"))
    .register();

    check::Check::new(
        "KMU_053",
        "Ensure that kernel module `io_edgeport` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("io_edgeport"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "io_edgeport",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("io_edgeport"))
    .register();

    check::Check::new(
        "KMU_054",
        "Ensure that kernel module `io_ti` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("io_ti"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "io_ti",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("io_ti"))
    .register();

    check::Check::new(
        "KMU_055",
        "Ensure that kernel module `iowarrior` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("iowarrior"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "iowarrior",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("iowarrior"))
    .register();

    check::Check::new(
        "KMU_056",
        "Ensure that kernel module `ipaq` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ipaq"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ipaq",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("ipaq"))
    .register();

    check::Check::new(
        "KMU_057",
        "Ensure that kernel module `ipheth` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("ipheth"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ipheth",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("ipheth"))
    .register();

    check::Check::new(
        "KMU_058",
        "Ensure that kernel module `isight_firmware` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("isight_firmware"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "isight_firmware",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("isight_firmware"))
    .register();

    check::Check::new(
        "KMU_059",
        "Ensure that kernel module `isp116x_hcd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("isp116x_hcd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "isp116x_hcd",
        "Obsolete host controllers.",
    ))
    .with_fix(&fix_disabled("isp116x_hcd"))
    .register();

    check::Check::new(
        "KMU_060",
        "Ensure that kernel module `isp1760` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("isp1760"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "isp1760",
        "Obsolete host controllers.",
    ))
    .with_fix(&fix_disabled("isp1760"))
    .register();

    check::Check::new(
        "KMU_061",
        "Ensure that kernel module `kalmia` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("kalmia"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("kalmia", "Laptops with LTE modems."))
    .with_fix(&fix_disabled("kalmia"))
    .register();

    check::Check::new(
        "KMU_062",
        "Ensure that kernel module `kaweth` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("kaweth"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "kaweth",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("kaweth"))
    .register();

    check::Check::new(
        "KMU_063",
        "Ensure that kernel module `keyspan` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("keyspan"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "keyspan",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("keyspan"))
    .register();

    check::Check::new(
        "KMU_064",
        "Ensure that kernel module `kl5kusb105` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("kl5kusb105"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "kl5kusb105",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("kl5kusb105"))
    .register();

    check::Check::new(
        "KMU_065",
        "Ensure that kernel module `lan78xx` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("lan78xx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "lan78xx",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("lan78xx"))
    .register();

    check::Check::new(
        "KMU_066",
        "Ensure that kernel module `ldusb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ldusb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ldusb",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("ldusb"))
    .register();

    check::Check::new(
        "KMU_067",
        "Ensure that kernel module `legousbtower` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("legousbtower"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "legousbtower",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("legousbtower"))
    .register();

    check::Check::new(
        "KMU_068",
        "Ensure that kernel module `lg_vl6000` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("lg_vl6000"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "lg_vl6000",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("lg_vl6000"))
    .register();

    check::Check::new(
        "KMU_069",
        "Ensure that kernel module `libcomposite` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("libcomposite"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "libcomposite",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("libcomposite"))
    .register();

    check::Check::new(
        "KMU_070",
        "Ensure that kernel module `mcs7830` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("mcs7830"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mcs7830",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("mcs7830"))
    .register();

    check::Check::new(
        "KMU_071",
        "Ensure that kernel module `mct_u232` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("mct_u232"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mct_u232",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("mct_u232"))
    .register();

    check::Check::new(
        "KMU_072",
        "Ensure that kernel module `mdc800` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mdc800"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mdc800",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("mdc800"))
    .register();

    check::Check::new(
        "KMU_073",
        "Ensure that kernel module `metro_usb` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("metro_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "metro_usb",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("metro_usb"))
    .register();

    check::Check::new(
        "KMU_074",
        "Ensure that kernel module `mos7720` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("mos7720"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mos7720",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("mos7720"))
    .register();

    check::Check::new(
        "KMU_075",
        "Ensure that kernel module `mos7840` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("mos7840"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mos7840",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("mos7840"))
    .register();

    check::Check::new(
        "KMU_076",
        "Ensure that kernel module `mxuport` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("mxuport"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mxuport",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("mxuport"))
    .register();

    check::Check::new(
        "KMU_077",
        "Ensure that kernel module `navman` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("navman"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "navman",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("navman"))
    .register();

    check::Check::new(
        "KMU_078",
        "Ensure that kernel module `net1080` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("net1080"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "net1080",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("net1080"))
    .register();

    check::Check::new(
        "KMU_079",
        "Ensure that kernel module `omninet` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("omninet"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "omninet",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("omninet"))
    .register();

    check::Check::new(
        "KMU_080",
        "Ensure that kernel module `opticon` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("opticon"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "opticon",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("opticon"))
    .register();

    check::Check::new(
        "KMU_081",
        "Ensure that kernel module `option` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("option"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("option", "Laptops with LTE modems."))
    .with_fix(&fix_disabled("option"))
    .register();

    check::Check::new(
        "KMU_082",
        "Ensure that kernel module `oti6858` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("oti6858"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "oti6858",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("oti6858"))
    .register();

    check::Check::new(
        "KMU_083",
        "Ensure that kernel module `oxu210hp_hcd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("oxu210hp_hcd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "oxu210hp_hcd",
        "Obsolete host controllers.",
    ))
    .with_fix(&fix_disabled("oxu210hp_hcd"))
    .register();

    check::Check::new(
        "KMU_084",
        "Ensure that kernel module `pegasus` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("pegasus"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pegasus",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("pegasus"))
    .register();

    check::Check::new(
        "KMU_085",
        "Ensure that kernel module `pl2303` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("pl2303"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pl2303",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("pl2303"))
    .register();

    check::Check::new(
        "KMU_086",
        "Ensure that kernel module `plusb` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("plusb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "plusb",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("plusb"))
    .register();

    check::Check::new(
        "KMU_087",
        "Ensure that kernel module `qmi_wwan` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("qmi_wwan"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "qmi_wwan",
        "Laptops with LTE modems.",
    ))
    .with_fix(&fix_disabled("qmi_wwan"))
    .register();

    check::Check::new(
        "KMU_088",
        "Ensure that kernel module `quatech2` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("quatech2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "quatech2",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("quatech2"))
    .register();

    check::Check::new(
        "KMU_089",
        "Ensure that kernel module `r8152` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("r8152"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "r8152",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("r8152"))
    .register();

    check::Check::new(
        "KMU_090",
        "Ensure that kernel module `r8153_ecm` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("r8153_ecm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "r8153_ecm",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("r8153_ecm"))
    .register();

    check::Check::new(
        "KMU_091",
        "Ensure that kernel module `r8a66597_hcd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("r8a66597_hcd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "r8a66597_hcd",
        "Obsolete host controllers.",
    ))
    .with_fix(&fix_disabled("r8a66597_hcd"))
    .register();

    check::Check::new(
        "KMU_092",
        "Ensure that kernel module `rndis_host` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("rndis_host"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rndis_host",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("rndis_host"))
    .register();

    check::Check::new(
        "KMU_093",
        "Ensure that kernel module `rtl8150` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("rtl8150"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rtl8150",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("rtl8150"))
    .register();

    check::Check::new(
        "KMU_094",
        "Ensure that kernel module `safe_serial` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("safe_serial"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "safe_serial",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("safe_serial"))
    .register();

    check::Check::new(
        "KMU_095",
        "Ensure that kernel module `sierra` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("sierra"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("sierra", "Laptops with LTE modems."))
    .with_fix(&fix_disabled("sierra"))
    .register();

    check::Check::new(
        "KMU_096",
        "Ensure that kernel module `sierra_net` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("sierra_net"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sierra_net",
        "Laptops with LTE modems.",
    ))
    .with_fix(&fix_disabled("sierra_net"))
    .register();

    check::Check::new(
        "KMU_097",
        "Ensure that kernel module `sisusbvga` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sisusbvga"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sisusbvga",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("sisusbvga"))
    .register();

    check::Check::new(
        "KMU_098",
        "Ensure that kernel module `sl811_cs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sl811_cs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sl811_cs",
        "Obsolete host controllers.",
    ))
    .with_fix(&fix_disabled("sl811_cs"))
    .register();

    check::Check::new(
        "KMU_099",
        "Ensure that kernel module `sl811_hcd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sl811_hcd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sl811_hcd",
        "Obsolete host controllers.",
    ))
    .with_fix(&fix_disabled("sl811_hcd"))
    .register();

    check::Check::new(
        "KMU_100",
        "Ensure that kernel module `smsc75xx` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("smsc75xx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "smsc75xx",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("smsc75xx"))
    .register();

    check::Check::new(
        "KMU_101",
        "Ensure that kernel module `smsc95xx` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("smsc95xx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "smsc95xx",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("smsc95xx"))
    .register();

    check::Check::new(
        "KMU_102",
        "Ensure that kernel module `spcp8x5` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("spcp8x5"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "spcp8x5",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("spcp8x5"))
    .register();

    check::Check::new(
        "KMU_103",
        "Ensure that kernel module `sr9700` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("sr9700"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sr9700",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("sr9700"))
    .register();

    check::Check::new(
        "KMU_104",
        "Ensure that kernel module `sr9800` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("sr9800"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sr9800",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("sr9800"))
    .register();

    check::Check::new(
        "KMU_105",
        "Ensure that kernel module `ssb_hcd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ssb_hcd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ssb_hcd",
        "Obsolete host controllers.",
    ))
    .with_fix(&fix_disabled("ssb_hcd"))
    .register();

    check::Check::new(
        "KMU_106",
        "Ensure that kernel module `ssu100` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ssu100"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ssu100",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("ssu100"))
    .register();

    check::Check::new(
        "KMU_107",
        "Ensure that kernel module `symbolserial` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("symbolserial"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "symbolserial",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("symbolserial"))
    .register();

    check::Check::new(
        "KMU_108",
        "Ensure that kernel module `tcm_usb_gadget` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("tcm_usb_gadget"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tcm_usb_gadget",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("tcm_usb_gadget"))
    .register();

    check::Check::new(
        "KMU_109",
        "Ensure that kernel module `ti_usb_3410_5052` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ti_usb_3410_5052"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ti_usb_3410_5052",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("ti_usb_3410_5052"))
    .register();

    check::Check::new(
        "KMU_110",
        "Ensure that kernel module `trancevibrator` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("trancevibrator"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "trancevibrator",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("trancevibrator"))
    .register();

    check::Check::new(
        "KMU_111",
        "Ensure that kernel module `uas` is disabled",
        Severity::High,
        vec!["module", "server"],
        || modprobe::check_module_disabled("uas"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("uas", "USB attached SCSI, modern USB disks use this instead of usb_storage. Disabling only usb_storage leaves the door open."))
    .with_fix(&fix_disabled("uas"))
    .register();

    check::Check::new(
        "KMU_112",
        "Ensure that kernel module `udc_core` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("udc_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "udc_core",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("udc_core"))
    .register();

    check::Check::new(
        "KMU_113",
        "Ensure that kernel module `ums_alauda` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ums_alauda"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ums_alauda",
        "Exotic card-reader sub-drivers of usb-storage.",
    ))
    .with_fix(&fix_disabled("ums_alauda"))
    .register();

    check::Check::new(
        "KMU_114",
        "Ensure that kernel module `ums_cypress` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ums_cypress"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ums_cypress",
        "Exotic card-reader sub-drivers of usb-storage.",
    ))
    .with_fix(&fix_disabled("ums_cypress"))
    .register();

    check::Check::new(
        "KMU_115",
        "Ensure that kernel module `ums_datafab` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ums_datafab"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ums_datafab",
        "Exotic card-reader sub-drivers of usb-storage.",
    ))
    .with_fix(&fix_disabled("ums_datafab"))
    .register();

    check::Check::new(
        "KMU_116",
        "Ensure that kernel module `ums_eneub6250` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ums_eneub6250"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ums_eneub6250",
        "Exotic card-reader sub-drivers of usb-storage.",
    ))
    .with_fix(&fix_disabled("ums_eneub6250"))
    .register();

    check::Check::new(
        "KMU_117",
        "Ensure that kernel module `ums_freecom` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ums_freecom"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ums_freecom",
        "Exotic card-reader sub-drivers of usb-storage.",
    ))
    .with_fix(&fix_disabled("ums_freecom"))
    .register();

    check::Check::new(
        "KMU_118",
        "Ensure that kernel module `ums_isd200` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ums_isd200"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ums_isd200",
        "Exotic card-reader sub-drivers of usb-storage.",
    ))
    .with_fix(&fix_disabled("ums_isd200"))
    .register();

    check::Check::new(
        "KMU_119",
        "Ensure that kernel module `ums_jumpshot` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ums_jumpshot"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ums_jumpshot",
        "Exotic card-reader sub-drivers of usb-storage.",
    ))
    .with_fix(&fix_disabled("ums_jumpshot"))
    .register();

    check::Check::new(
        "KMU_120",
        "Ensure that kernel module `ums_karma` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ums_karma"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ums_karma",
        "Exotic card-reader sub-drivers of usb-storage.",
    ))
    .with_fix(&fix_disabled("ums_karma"))
    .register();

    check::Check::new(
        "KMU_121",
        "Ensure that kernel module `ums_onetouch` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ums_onetouch"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ums_onetouch",
        "Exotic card-reader sub-drivers of usb-storage.",
    ))
    .with_fix(&fix_disabled("ums_onetouch"))
    .register();

    check::Check::new(
        "KMU_122",
        "Ensure that kernel module `ums_realtek` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ums_realtek"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ums_realtek",
        "Exotic card-reader sub-drivers of usb-storage.",
    ))
    .with_fix(&fix_disabled("ums_realtek"))
    .register();

    check::Check::new(
        "KMU_123",
        "Ensure that kernel module `ums_sddr09` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ums_sddr09"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ums_sddr09",
        "Exotic card-reader sub-drivers of usb-storage.",
    ))
    .with_fix(&fix_disabled("ums_sddr09"))
    .register();

    check::Check::new(
        "KMU_124",
        "Ensure that kernel module `ums_sddr55` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ums_sddr55"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ums_sddr55",
        "Exotic card-reader sub-drivers of usb-storage.",
    ))
    .with_fix(&fix_disabled("ums_sddr55"))
    .register();

    check::Check::new(
        "KMU_125",
        "Ensure that kernel module `usb_f_acm` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_acm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_acm",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_acm"))
    .register();

    check::Check::new(
        "KMU_126",
        "Ensure that kernel module `usb_f_ecm` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_ecm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_ecm",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_ecm"))
    .register();

    check::Check::new(
        "KMU_127",
        "Ensure that kernel module `usb_f_ecm_subset` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_ecm_subset"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_ecm_subset",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_ecm_subset"))
    .register();

    check::Check::new(
        "KMU_128",
        "Ensure that kernel module `usb_f_eem` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_eem"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_eem",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_eem"))
    .register();

    check::Check::new(
        "KMU_129",
        "Ensure that kernel module `usb_f_ffs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_ffs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_ffs",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_ffs"))
    .register();

    check::Check::new(
        "KMU_130",
        "Ensure that kernel module `usb_f_fs` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_fs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_fs",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_fs"))
    .register();

    check::Check::new(
        "KMU_131",
        "Ensure that kernel module `usb_f_hid` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_hid"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_hid",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_hid"))
    .register();

    check::Check::new(
        "KMU_132",
        "Ensure that kernel module `usb_f_mass_storage` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_mass_storage"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_mass_storage",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_mass_storage"))
    .register();

    check::Check::new(
        "KMU_133",
        "Ensure that kernel module `usb_f_midi` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_midi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_midi",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_midi"))
    .register();

    check::Check::new(
        "KMU_134",
        "Ensure that kernel module `usb_f_midi2` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_midi2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_midi2",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_midi2"))
    .register();

    check::Check::new(
        "KMU_135",
        "Ensure that kernel module `usb_f_ncm` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_ncm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_ncm",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_ncm"))
    .register();

    check::Check::new(
        "KMU_136",
        "Ensure that kernel module `usb_f_obex` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_obex"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_obex",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_obex"))
    .register();

    check::Check::new(
        "KMU_137",
        "Ensure that kernel module `usb_f_phonet` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_phonet"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_phonet",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_phonet"))
    .register();

    check::Check::new(
        "KMU_138",
        "Ensure that kernel module `usb_f_printer` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_printer"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_printer",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_printer"))
    .register();

    check::Check::new(
        "KMU_139",
        "Ensure that kernel module `usb_f_rndis` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_rndis"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_rndis",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_rndis"))
    .register();

    check::Check::new(
        "KMU_140",
        "Ensure that kernel module `usb_f_serial` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_serial"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_serial",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_serial"))
    .register();

    check::Check::new(
        "KMU_141",
        "Ensure that kernel module `usb_f_ss_lb` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_ss_lb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_ss_lb",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_ss_lb"))
    .register();

    check::Check::new(
        "KMU_142",
        "Ensure that kernel module `usb_f_tcm` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_tcm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_tcm",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_tcm"))
    .register();

    check::Check::new(
        "KMU_143",
        "Ensure that kernel module `usb_f_uac1` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_uac1"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_uac1",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_uac1"))
    .register();

    check::Check::new(
        "KMU_144",
        "Ensure that kernel module `usb_f_uac1_legacy` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_uac1_legacy"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_uac1_legacy",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_uac1_legacy"))
    .register();

    check::Check::new(
        "KMU_145",
        "Ensure that kernel module `usb_f_uac2` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_uac2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_uac2",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_uac2"))
    .register();

    check::Check::new(
        "KMU_146",
        "Ensure that kernel module `usb_f_uvc` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_f_uvc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_f_uvc",
        "USB gadget function driver, makes the host present itself as a USB device.",
    ))
    .with_fix(&fix_disabled("usb_f_uvc"))
    .register();

    check::Check::new(
        "KMU_147",
        "Ensure that kernel module `usb_storage` is disabled",
        Severity::High,
        vec!["module", "CIS", "STIG", "server"],
        || modprobe::check_module_disabled("usb_storage"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("usb_storage", "USB mass storage."))
    .with_fix(&fix_disabled("usb_storage"))
    .register();

    check::Check::new(
        "KMU_148",
        "Ensure that kernel module `usb_wwan` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("usb_wwan"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_wwan",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("usb_wwan"))
    .register();

    check::Check::new(
        "KMU_149",
        "Ensure that kernel module `usbio` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usbio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usbio",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("usbio"))
    .register();

    check::Check::new(
        "KMU_150",
        "Ensure that kernel module `usblcd` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usblcd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usblcd",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("usblcd"))
    .register();

    check::Check::new(
        "KMU_151",
        "Ensure that kernel module `usblp` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("usblp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("usblp", "USB printers."))
    .with_fix(&fix_disabled("usblp"))
    .register();

    check::Check::new(
        "KMU_152",
        "Ensure that kernel module `usbnet` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("usbnet"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usbnet",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("usbnet"))
    .register();

    check::Check::new(
        "KMU_153",
        "Ensure that kernel module `usbserial` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("usbserial"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usbserial",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("usbserial"))
    .register();

    check::Check::new(
        "KMU_154",
        "Ensure that kernel module `usbsevseg` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usbsevseg"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usbsevseg",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("usbsevseg"))
    .register();

    check::Check::new(
        "KMU_155",
        "Ensure that kernel module `usbtmc` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usbtmc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("usbtmc", "USB test & measurement."))
    .with_fix(&fix_disabled("usbtmc"))
    .register();

    check::Check::new(
        "KMU_156",
        "Ensure that kernel module `uss720` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("uss720"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uss720",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("uss720"))
    .register();

    check::Check::new(
        "KMU_157",
        "Ensure that kernel module `visor` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("visor"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "visor",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("visor"))
    .register();

    check::Check::new(
        "KMU_158",
        "Ensure that kernel module `whiteheat` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("whiteheat"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "whiteheat",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("whiteheat"))
    .register();

    check::Check::new(
        "KMU_159",
        "Ensure that kernel module `xr_serial` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("xr_serial"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "xr_serial",
        "Dev boards, UPS, ham radio, serial consoles, common on workstations/dev servers.",
    ))
    .with_fix(&fix_disabled("xr_serial"))
    .register();

    check::Check::new(
        "KMU_160",
        "Ensure that kernel module `yurex` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("yurex"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "yurex",
        "Gadgets, LED signs, firmware loaders...",
    ))
    .with_fix(&fix_disabled("yurex"))
    .register();

    check::Check::new(
        "KMU_161",
        "Ensure that kernel module `zaurus` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("zaurus"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "zaurus",
        "USB NIC dongles are common even on servers, verify before disabling.",
    ))
    .with_fix(&fix_disabled("zaurus"))
    .register();

    // fireWire (IEEE 1394) (KMK_)
    check::Check::new(
        "KMK_001",
        "Ensure that kernel module `dv1394` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dv1394"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "dv1394",
        "Removed upstream, old stack.",
    ))
    .with_fix(&fix_disabled("dv1394"))
    .register();

    check::Check::new(
        "KMK_002",
        "Ensure that kernel module `firewire_core` is disabled",
        Severity::High,
        vec!["module", "STIG", "server", "workstation"],
        || modprobe::check_module_disabled("firewire_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("firewire_core", "Core stack."))
    .with_fix(&fix_disabled("firewire_core"))
    .register();

    check::Check::new(
        "KMK_003",
        "Ensure that kernel module `firewire_net` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("firewire_net"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("firewire_net", "Core stack."))
    .with_fix(&fix_disabled("firewire_net"))
    .register();

    check::Check::new(
        "KMK_004",
        "Ensure that kernel module `firewire_ohci` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("firewire_ohci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("firewire_ohci", "Core stack."))
    .with_fix(&fix_disabled("firewire_ohci"))
    .register();

    check::Check::new(
        "KMK_005",
        "Ensure that kernel module `firewire_sbp2` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("firewire_sbp2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("firewire_sbp2", "Core stack."))
    .with_fix(&fix_disabled("firewire_sbp2"))
    .register();

    check::Check::new(
        "KMK_006",
        "Ensure that kernel module `ohci1394` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ohci1394"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ohci1394",
        "Removed upstream, old stack.",
    ))
    .with_fix(&fix_disabled("ohci1394"))
    .register();

    check::Check::new(
        "KMK_007",
        "Ensure that kernel module `raw1394` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("raw1394"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "raw1394",
        "Removed upstream, old stack.",
    ))
    .with_fix(&fix_disabled("raw1394"))
    .register();

    check::Check::new(
        "KMK_008",
        "Ensure that kernel module `sbp2` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sbp2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sbp2",
        "Removed upstream, old stack.",
    ))
    .with_fix(&fix_disabled("sbp2"))
    .register();

    check::Check::new(
        "KMK_009",
        "Ensure that kernel module `video1394` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("video1394"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "video1394",
        "Removed upstream, old stack.",
    ))
    .with_fix(&fix_disabled("video1394"))
    .register();

    // thunderbolt (KMJ_)
    check::Check::new(
        "KMJ_001",
        "Ensure that kernel module `intel_wmi_thunderbolt` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("intel_wmi_thunderbolt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "intel_wmi_thunderbolt",
        "WMI force-power interface.",
    ))
    .with_fix(&fix_disabled("intel_wmi_thunderbolt"))
    .register();

    check::Check::new(
        "KMJ_002",
        "Ensure that kernel module `thunderbolt` is disabled",
        Severity::High,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("thunderbolt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("thunderbolt", "Core driver."))
    .with_fix(&fix_disabled("thunderbolt"))
    .register();

    check::Check::new(
        "KMJ_003",
        "Ensure that kernel module `thunderbolt_net` is disabled",
        Severity::High,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("thunderbolt_net"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("thunderbolt_net", "TB networking."))
    .with_fix(&fix_disabled("thunderbolt_net"))
    .register();

    check::Check::new(
        "KMJ_004",
        "Ensure that kernel module `typec_thunderbolt` is disabled",
        Severity::High,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("typec_thunderbolt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "typec_thunderbolt",
        "USB-C alt-mode entry for TB.",
    ))
    .with_fix(&fix_disabled("typec_thunderbolt"))
    .register();

    // GPS / GNSS (KMH_)
    check::Check::new(
        "KMH_001",
        "Ensure that kernel module `garmin_gps` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("garmin_gps"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "garmin_gps",
        "GPS/GNSS receiver driver, autoloaded when a USB GPS is plugged.",
    ))
    .with_fix(&fix_disabled("garmin_gps"))
    .register();

    check::Check::new(
        "KMH_002",
        "Ensure that kernel module `gnss` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gnss"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "gnss",
        "GPS/GNSS receiver driver, autoloaded when a USB GPS is plugged.",
    ))
    .with_fix(&fix_disabled("gnss"))
    .register();

    check::Check::new(
        "KMH_003",
        "Ensure that kernel module `gnss_mtk` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gnss_mtk"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "gnss_mtk",
        "GPS/GNSS receiver driver, autoloaded when a USB GPS is plugged.",
    ))
    .with_fix(&fix_disabled("gnss_mtk"))
    .register();

    check::Check::new(
        "KMH_004",
        "Ensure that kernel module `gnss_serial` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gnss_serial"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "gnss_serial",
        "GPS/GNSS receiver driver, autoloaded when a USB GPS is plugged.",
    ))
    .with_fix(&fix_disabled("gnss_serial"))
    .register();

    check::Check::new(
        "KMH_005",
        "Ensure that kernel module `gnss_sirf` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gnss_sirf"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "gnss_sirf",
        "GPS/GNSS receiver driver, autoloaded when a USB GPS is plugged.",
    ))
    .with_fix(&fix_disabled("gnss_sirf"))
    .register();

    check::Check::new(
        "KMH_006",
        "Ensure that kernel module `gnss_ubx` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gnss_ubx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "gnss_ubx",
        "GPS/GNSS receiver driver, autoloaded when a USB GPS is plugged.",
    ))
    .with_fix(&fix_disabled("gnss_ubx"))
    .register();

    check::Check::new(
        "KMH_007",
        "Ensure that kernel module `gnss_usb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gnss_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "gnss_usb",
        "GPS/GNSS receiver driver, autoloaded when a USB GPS is plugged.",
    ))
    .with_fix(&fix_disabled("gnss_usb"))
    .register();

    // optical, floppy and legacy removable media (KMP_)
    check::Check::new(
        "KMP_001",
        "Ensure that kernel module `alcor_pci` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("alcor_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "alcor_pci",
        "SD/MMC card readers, workstation laptops often need these. Servers don't.",
    ))
    .with_fix(&fix_disabled("alcor_pci"))
    .register();

    check::Check::new(
        "KMP_002",
        "Ensure that kernel module `cb710` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("cb710"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cb710",
        "SD/MMC card readers, workstation laptops often need these. Servers don't.",
    ))
    .with_fix(&fix_disabled("cb710"))
    .register();

    check::Check::new(
        "KMP_003",
        "Ensure that kernel module `floppy` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("floppy"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("floppy", "FDD."))
    .with_fix(&fix_disabled("floppy"))
    .register();

    check::Check::new(
        "KMP_004",
        "Ensure that kernel module `jmb38x_ms` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("jmb38x_ms"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "jmb38x_ms",
        "Sony MemoryStick readers, old laptops.",
    ))
    .with_fix(&fix_disabled("jmb38x_ms"))
    .register();

    check::Check::new(
        "KMP_005",
        "Ensure that kernel module `memstick` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("memstick"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "memstick",
        "Sony MemoryStick readers, old laptops.",
    ))
    .with_fix(&fix_disabled("memstick"))
    .register();

    check::Check::new(
        "KMP_006",
        "Ensure that kernel module `ms_block` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("ms_block"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ms_block",
        "Sony MemoryStick readers, old laptops.",
    ))
    .with_fix(&fix_disabled("ms_block"))
    .register();

    check::Check::new(
        "KMP_007",
        "Ensure that kernel module `mspro_block` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("mspro_block"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mspro_block",
        "Sony MemoryStick readers, old laptops.",
    ))
    .with_fix(&fix_disabled("mspro_block"))
    .register();

    check::Check::new(
        "KMP_008",
        "Ensure that kernel module `r592` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("r592"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "r592",
        "Sony MemoryStick readers, old laptops.",
    ))
    .with_fix(&fix_disabled("r592"))
    .register();

    check::Check::new(
        "KMP_009",
        "Ensure that kernel module `rtsx_pci` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("rtsx_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rtsx_pci",
        "SD/MMC card readers, workstation laptops often need these. Servers don't.",
    ))
    .with_fix(&fix_disabled("rtsx_pci"))
    .register();

    check::Check::new(
        "KMP_010",
        "Ensure that kernel module `rtsx_usb` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("rtsx_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rtsx_usb",
        "SD/MMC card readers, workstation laptops often need these. Servers don't.",
    ))
    .with_fix(&fix_disabled("rtsx_usb"))
    .register();

    check::Check::new(
        "KMP_011",
        "Ensure that kernel module `rtsx_usb_ms` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("rtsx_usb_ms"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rtsx_usb_ms",
        "Sony MemoryStick readers, old laptops.",
    ))
    .with_fix(&fix_disabled("rtsx_usb_ms"))
    .register();

    check::Check::new(
        "KMP_012",
        "Ensure that kernel module `tifm_7xx1` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("tifm_7xx1"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tifm_7xx1",
        "SD/MMC card readers, workstation laptops often need these. Servers don't.",
    ))
    .with_fix(&fix_disabled("tifm_7xx1"))
    .register();

    check::Check::new(
        "KMP_013",
        "Ensure that kernel module `tifm_core` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("tifm_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tifm_core",
        "SD/MMC card readers, workstation laptops often need these. Servers don't.",
    ))
    .with_fix(&fix_disabled("tifm_core"))
    .register();

    check::Check::new(
        "KMP_014",
        "Ensure that kernel module `tifm_ms` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("tifm_ms"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tifm_ms",
        "Sony MemoryStick readers, old laptops.",
    ))
    .with_fix(&fix_disabled("tifm_ms"))
    .register();

    // audio and PC speaker (KMA_)
    check::Check::new(
        "KMA_001",
        "Ensure that kernel module `ac97` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ac97"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ac97",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("ac97"))
    .register();

    check::Check::new(
        "KMA_002",
        "Ensure that kernel module `ac97_codec` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ac97_codec"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ac97_codec",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("ac97_codec"))
    .register();

    check::Check::new(
        "KMA_003",
        "Ensure that kernel module `ac97_plugin_ad1980` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ac97_plugin_ad1980"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ac97_plugin_ad1980",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("ac97_plugin_ad1980"))
    .register();

    check::Check::new(
        "KMA_004",
        "Ensure that kernel module `ac97_plugin_wm97xx` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ac97_plugin_wm97xx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ac97_plugin_wm97xx",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("ac97_plugin_wm97xx"))
    .register();

    check::Check::new(
        "KMA_005",
        "Ensure that kernel module `ad1816` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ad1816"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ad1816",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("ad1816"))
    .register();

    check::Check::new(
        "KMA_006",
        "Ensure that kernel module `ad1848` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ad1848"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ad1848",
        "Removed from upstream long ago.",
    ))
    .with_fix(&fix_disabled("ad1848"))
    .register();

    check::Check::new(
        "KMA_007",
        "Ensure that kernel module `ad1889` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ad1889"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ad1889",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("ad1889"))
    .register();

    check::Check::new(
        "KMA_008",
        "Ensure that kernel module `adlib_card` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("adlib_card"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "adlib_card",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("adlib_card"))
    .register();

    check::Check::new(
        "KMA_009",
        "Ensure that kernel module `aedsp16` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("aedsp16"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "aedsp16",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("aedsp16"))
    .register();

    check::Check::new(
        "KMA_010",
        "Ensure that kernel module `ali5455` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ali5455"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ali5455",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("ali5455"))
    .register();

    check::Check::new(
        "KMA_011",
        "Ensure that kernel module `audio` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("audio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "audio",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("audio"))
    .register();

    check::Check::new(
        "KMA_012",
        "Ensure that kernel module `awe_wave` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("awe_wave"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "awe_wave",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("awe_wave"))
    .register();

    check::Check::new(
        "KMA_013",
        "Ensure that kernel module `btaudio` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("btaudio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "btaudio",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("btaudio"))
    .register();

    check::Check::new(
        "KMA_014",
        "Ensure that kernel module `cmpci` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cmpci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cmpci",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("cmpci"))
    .register();

    check::Check::new(
        "KMA_015",
        "Ensure that kernel module `cs4232` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cs4232"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cs4232",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("cs4232"))
    .register();

    check::Check::new(
        "KMA_016",
        "Ensure that kernel module `cs4281` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cs4281"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cs4281",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("cs4281"))
    .register();

    check::Check::new(
        "KMA_017",
        "Ensure that kernel module `cs461x` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cs461x"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cs461x",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("cs461x"))
    .register();

    check::Check::new(
        "KMA_018",
        "Ensure that kernel module `cs46xx` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cs46xx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cs46xx",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("cs46xx"))
    .register();

    check::Check::new(
        "KMA_019",
        "Ensure that kernel module `dmasound_core` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dmasound_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "dmasound_core",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("dmasound_core"))
    .register();

    check::Check::new(
        "KMA_020",
        "Ensure that kernel module `dmasound_pmac` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dmasound_pmac"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "dmasound_pmac",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("dmasound_pmac"))
    .register();

    check::Check::new(
        "KMA_021",
        "Ensure that kernel module `emu10k1` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("emu10k1"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "emu10k1",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("emu10k1"))
    .register();

    check::Check::new(
        "KMA_022",
        "Ensure that kernel module `es1370` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("es1370"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "es1370",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("es1370"))
    .register();

    check::Check::new(
        "KMA_023",
        "Ensure that kernel module `es1371` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("es1371"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "es1371",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("es1371"))
    .register();

    check::Check::new(
        "KMA_024",
        "Ensure that kernel module `esssolo1` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("esssolo1"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "esssolo1",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("esssolo1"))
    .register();

    check::Check::new(
        "KMA_025",
        "Ensure that kernel module `forte` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("forte"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "forte",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("forte"))
    .register();

    check::Check::new(
        "KMA_026",
        "Ensure that kernel module `gus` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gus"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "gus",
        "Removed from upstream long ago.",
    ))
    .with_fix(&fix_disabled("gus"))
    .register();

    check::Check::new(
        "KMA_027",
        "Ensure that kernel module `harmony` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("harmony"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "harmony",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("harmony"))
    .register();

    check::Check::new(
        "KMA_028",
        "Ensure that kernel module `i810_audio` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("i810_audio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "i810_audio",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("i810_audio"))
    .register();

    check::Check::new(
        "KMA_029",
        "Ensure that kernel module `kahlua` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("kahlua"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "kahlua",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("kahlua"))
    .register();

    check::Check::new(
        "KMA_030",
        "Ensure that kernel module `mad16` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mad16"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mad16",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("mad16"))
    .register();

    check::Check::new(
        "KMA_031",
        "Ensure that kernel module `maestro` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("maestro"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "maestro",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("maestro"))
    .register();

    check::Check::new(
        "KMA_032",
        "Ensure that kernel module `maestro3` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("maestro3"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "maestro3",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("maestro3"))
    .register();

    check::Check::new(
        "KMA_033",
        "Ensure that kernel module `maui` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("maui"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "maui",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("maui"))
    .register();

    check::Check::new(
        "KMA_034",
        "Ensure that kernel module `mpu401` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mpu401"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mpu401",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("mpu401"))
    .register();

    check::Check::new(
        "KMA_035",
        "Ensure that kernel module `nm256_audio` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nm256_audio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nm256_audio",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("nm256_audio"))
    .register();

    check::Check::new(
        "KMA_036",
        "Ensure that kernel module `opl3` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("opl3"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "opl3",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("opl3"))
    .register();

    check::Check::new(
        "KMA_037",
        "Ensure that kernel module `opl3sa` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("opl3sa"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "opl3sa",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("opl3sa"))
    .register();

    check::Check::new(
        "KMA_038",
        "Ensure that kernel module `opl3sa2` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("opl3sa2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "opl3sa2",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("opl3sa2"))
    .register();

    check::Check::new(
        "KMA_039",
        "Ensure that kernel module `pas2` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pas2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pas2",
        "Removed from upstream long ago.",
    ))
    .with_fix(&fix_disabled("pas2"))
    .register();

    check::Check::new(
        "KMA_040",
        "Ensure that kernel module `pcspkr` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pcspkr"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pcspkr", "PC speaker beep."))
    .with_fix(&fix_disabled("pcspkr"))
    .register();

    check::Check::new(
        "KMA_041",
        "Ensure that kernel module `pss` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pss"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pss",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("pss"))
    .register();

    check::Check::new(
        "KMA_042",
        "Ensure that kernel module `rme96xx` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rme96xx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rme96xx",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("rme96xx"))
    .register();

    check::Check::new(
        "KMA_043",
        "Ensure that kernel module `sb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sb",
        "Removed from upstream long ago.",
    ))
    .with_fix(&fix_disabled("sb"))
    .register();

    check::Check::new(
        "KMA_044",
        "Ensure that kernel module `sb_lib` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sb_lib"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sb_lib",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("sb_lib"))
    .register();

    check::Check::new(
        "KMA_045",
        "Ensure that kernel module `sequencer` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sequencer"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sequencer",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("sequencer"))
    .register();

    check::Check::new(
        "KMA_046",
        "Ensure that kernel module `sgalaxy` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sgalaxy"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sgalaxy",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("sgalaxy"))
    .register();

    check::Check::new(
        "KMA_047",
        "Ensure that kernel module `snd` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("snd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd",
        "ALSA cores, disabling blocks all audio.",
    ))
    .with_fix(&fix_disabled("snd"))
    .register();

    check::Check::new(
        "KMA_048",
        "Ensure that kernel module `snd_hda_core` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("snd_hda_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_hda_core",
        "ALSA cores, disabling blocks all audio.",
    ))
    .with_fix(&fix_disabled("snd_hda_core"))
    .register();

    check::Check::new(
        "KMA_049",
        "Ensure that kernel module `snd_mixer_oss` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_mixer_oss"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("snd_mixer_oss", "OSS emulation."))
    .with_fix(&fix_disabled("snd_mixer_oss"))
    .register();

    check::Check::new(
        "KMA_050",
        "Ensure that kernel module `snd_mpu401` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_mpu401"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_mpu401",
        "Legacy MIDI/synth ports.",
    ))
    .with_fix(&fix_disabled("snd_mpu401"))
    .register();

    check::Check::new(
        "KMA_051",
        "Ensure that kernel module `snd_mpu401_uart` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_mpu401_uart"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_mpu401_uart",
        "Legacy MIDI/synth ports.",
    ))
    .with_fix(&fix_disabled("snd_mpu401_uart"))
    .register();

    check::Check::new(
        "KMA_052",
        "Ensure that kernel module `snd_mts64` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_mts64"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_mts64",
        "Legacy MIDI/synth ports.",
    ))
    .with_fix(&fix_disabled("snd_mts64"))
    .register();

    check::Check::new(
        "KMA_053",
        "Ensure that kernel module `snd_opl3_lib` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_opl3_lib"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_opl3_lib",
        "Legacy MIDI/synth ports.",
    ))
    .with_fix(&fix_disabled("snd_opl3_lib"))
    .register();

    check::Check::new(
        "KMA_054",
        "Ensure that kernel module `snd_opl3_synth` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_opl3_synth"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_opl3_synth",
        "Legacy MIDI/synth ports.",
    ))
    .with_fix(&fix_disabled("snd_opl3_synth"))
    .register();

    check::Check::new(
        "KMA_055",
        "Ensure that kernel module `snd_pcm` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("snd_pcm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_pcm",
        "ALSA cores, disabling blocks all audio.",
    ))
    .with_fix(&fix_disabled("snd_pcm"))
    .register();

    check::Check::new(
        "KMA_056",
        "Ensure that kernel module `snd_pcm_oss` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_pcm_oss"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_pcm_oss",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("snd_pcm_oss"))
    .register();

    check::Check::new(
        "KMA_057",
        "Ensure that kernel module `snd_portman2x4` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_portman2x4"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_portman2x4",
        "Legacy MIDI/synth ports.",
    ))
    .with_fix(&fix_disabled("snd_portman2x4"))
    .register();

    check::Check::new(
        "KMA_058",
        "Ensure that kernel module `snd_seq` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("snd_seq"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_seq",
        "ALSA cores, disabling blocks all audio.",
    ))
    .with_fix(&fix_disabled("snd_seq"))
    .register();

    check::Check::new(
        "KMA_059",
        "Ensure that kernel module `snd_seq_device` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("snd_seq_device"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_seq_device",
        "ALSA sequencer device layer.",
    ))
    .with_fix(&fix_disabled("snd_seq_device"))
    .register();

    check::Check::new(
        "KMA_060",
        "Ensure that kernel module `snd_serial_u16550` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_serial_u16550"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_serial_u16550",
        "Legacy MIDI/synth ports.",
    ))
    .with_fix(&fix_disabled("snd_serial_u16550"))
    .register();

    check::Check::new(
        "KMA_061",
        "Ensure that kernel module `snd_timer` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("snd_timer"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_timer",
        "ALSA cores, disabling blocks all audio.",
    ))
    .with_fix(&fix_disabled("snd_timer"))
    .register();

    check::Check::new(
        "KMA_062",
        "Ensure that kernel module `snd_vx_lib` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("snd_vx_lib"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "snd_vx_lib",
        "Legacy MIDI/synth ports.",
    ))
    .with_fix(&fix_disabled("snd_vx_lib"))
    .register();

    check::Check::new(
        "KMA_063",
        "Ensure that kernel module `sonicvibes` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sonicvibes"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sonicvibes",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("sonicvibes"))
    .register();

    check::Check::new(
        "KMA_064",
        "Ensure that kernel module `sound` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sound"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sound",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("sound"))
    .register();

    check::Check::new(
        "KMA_065",
        "Ensure that kernel module `soundcard` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("soundcard"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "soundcard",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("soundcard"))
    .register();

    check::Check::new(
        "KMA_066",
        "Ensure that kernel module `soundcore` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("soundcore"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "soundcore",
        "ALSA cores, disabling blocks all audio.",
    ))
    .with_fix(&fix_disabled("soundcore"))
    .register();

    check::Check::new(
        "KMA_067",
        "Ensure that kernel module `sscape` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sscape"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sscape",
        "Removed from upstream long ago.",
    ))
    .with_fix(&fix_disabled("sscape"))
    .register();

    check::Check::new(
        "KMA_068",
        "Ensure that kernel module `trident` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("trident"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "trident",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("trident"))
    .register();

    check::Check::new(
        "KMA_069",
        "Ensure that kernel module `trix` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("trix"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "trix",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("trix"))
    .register();

    check::Check::new(
        "KMA_070",
        "Ensure that kernel module `uart401` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("uart401"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uart401",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("uart401"))
    .register();

    check::Check::new(
        "KMA_071",
        "Ensure that kernel module `uart6850` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("uart6850"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uart6850",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("uart6850"))
    .register();

    check::Check::new(
        "KMA_072",
        "Ensure that kernel module `usb_midi` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("usb_midi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "usb_midi",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("usb_midi"))
    .register();

    check::Check::new(
        "KMA_073",
        "Ensure that kernel module `v_midi` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("v_midi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "v_midi",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("v_midi"))
    .register();

    check::Check::new(
        "KMA_074",
        "Ensure that kernel module `via82cxxx_audio` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("via82cxxx_audio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "via82cxxx_audio",
        "Legacy OSS/ISA audio driver, removed upstream. Kept for old-kernel coverage.",
    ))
    .with_fix(&fix_disabled("via82cxxx_audio"))
    .register();

    check::Check::new(
        "KMA_075",
        "Ensure that kernel module `wavefront` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("wavefront"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "wavefront",
        "Removed from upstream long ago.",
    ))
    .with_fix(&fix_disabled("wavefront"))
    .register();

    check::Check::new(
        "KMA_076",
        "Ensure that kernel module `ymfpci` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ymfpci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ymfpci",
        "Removed from upstream long ago.",
    ))
    .with_fix(&fix_disabled("ymfpci"))
    .register();

    // legacy framebuffers (fbdev) (KMR_)
    check::Check::new(
        "KMR_001",
        "Ensure that kernel module `arcfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("arcfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "arcfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("arcfb"))
    .register();

    check::Check::new(
        "KMR_002",
        "Ensure that kernel module `arkfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("arkfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "arkfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("arkfb"))
    .register();

    check::Check::new(
        "KMR_003",
        "Ensure that kernel module `aty128fb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("aty128fb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "aty128fb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("aty128fb"))
    .register();

    check::Check::new(
        "KMR_004",
        "Ensure that kernel module `atyfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("atyfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "atyfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("atyfb"))
    .register();

    check::Check::new(
        "KMR_005",
        "Ensure that kernel module `carminefb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("carminefb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "carminefb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("carminefb"))
    .register();

    check::Check::new(
        "KMR_006",
        "Ensure that kernel module `cirrusfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cirrusfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cirrusfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("cirrusfb"))
    .register();

    check::Check::new(
        "KMR_007",
        "Ensure that kernel module `cyber2000fb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cyber2000fb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cyber2000fb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("cyber2000fb"))
    .register();

    check::Check::new(
        "KMR_008",
        "Ensure that kernel module `cyblafb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cyblafb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cyblafb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("cyblafb"))
    .register();

    check::Check::new(
        "KMR_009",
        "Ensure that kernel module `fb_ddc` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("fb_ddc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "fb_ddc",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("fb_ddc"))
    .register();

    check::Check::new(
        "KMR_010",
        "Ensure that kernel module `g450_pll` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("g450_pll"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "g450_pll",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("g450_pll"))
    .register();

    check::Check::new(
        "KMR_011",
        "Ensure that kernel module `gx1fb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gx1fb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "gx1fb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("gx1fb"))
    .register();

    check::Check::new(
        "KMR_012",
        "Ensure that kernel module `hecubafb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hecubafb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hecubafb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("hecubafb"))
    .register();

    check::Check::new(
        "KMR_013",
        "Ensure that kernel module `hgafb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hgafb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hgafb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("hgafb"))
    .register();

    check::Check::new(
        "KMR_014",
        "Ensure that kernel module `i2c_matroxfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("i2c_matroxfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "i2c_matroxfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("i2c_matroxfb"))
    .register();

    check::Check::new(
        "KMR_015",
        "Ensure that kernel module `i740fb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("i740fb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "i740fb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("i740fb"))
    .register();

    check::Check::new(
        "KMR_016",
        "Ensure that kernel module `i810fb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("i810fb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "i810fb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("i810fb"))
    .register();

    check::Check::new(
        "KMR_017",
        "Ensure that kernel module `intel_agp` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("intel_agp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "intel_agp",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("intel_agp"))
    .register();

    check::Check::new(
        "KMR_018",
        "Ensure that kernel module `intelfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("intelfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "intelfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("intelfb"))
    .register();

    check::Check::new(
        "KMR_019",
        "Ensure that kernel module `kyrofb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("kyrofb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "kyrofb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("kyrofb"))
    .register();

    check::Check::new(
        "KMR_020",
        "Ensure that kernel module `lxfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("lxfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "lxfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("lxfb"))
    .register();

    check::Check::new(
        "KMR_021",
        "Ensure that kernel module `macmodes` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("macmodes"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "macmodes",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("macmodes"))
    .register();

    check::Check::new(
        "KMR_022",
        "Ensure that kernel module `matroxfb_DAC1064` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("matroxfb_DAC1064"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "matroxfb_DAC1064",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("matroxfb_DAC1064"))
    .register();

    check::Check::new(
        "KMR_023",
        "Ensure that kernel module `matroxfb_Ti3026` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("matroxfb_Ti3026"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "matroxfb_Ti3026",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("matroxfb_Ti3026"))
    .register();

    check::Check::new(
        "KMR_024",
        "Ensure that kernel module `matroxfb_accel` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("matroxfb_accel"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "matroxfb_accel",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("matroxfb_accel"))
    .register();

    check::Check::new(
        "KMR_025",
        "Ensure that kernel module `matroxfb_base` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("matroxfb_base"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "matroxfb_base",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("matroxfb_base"))
    .register();

    check::Check::new(
        "KMR_026",
        "Ensure that kernel module `matroxfb_bases` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("matroxfb_bases"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "matroxfb_bases",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("matroxfb_bases"))
    .register();

    check::Check::new(
        "KMR_027",
        "Ensure that kernel module `matroxfb_crtc2` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("matroxfb_crtc2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "matroxfb_crtc2",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("matroxfb_crtc2"))
    .register();

    check::Check::new(
        "KMR_028",
        "Ensure that kernel module `matroxfb_g450` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("matroxfb_g450"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "matroxfb_g450",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("matroxfb_g450"))
    .register();

    check::Check::new(
        "KMR_029",
        "Ensure that kernel module `matroxfb_maven` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("matroxfb_maven"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "matroxfb_maven",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("matroxfb_maven"))
    .register();

    check::Check::new(
        "KMR_030",
        "Ensure that kernel module `matroxfb_misc` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("matroxfb_misc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "matroxfb_misc",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("matroxfb_misc"))
    .register();

    check::Check::new(
        "KMR_031",
        "Ensure that kernel module `mb862xxfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mb862xxfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mb862xxfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("mb862xxfb"))
    .register();

    check::Check::new(
        "KMR_032",
        "Ensure that kernel module `metronomefb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("metronomefb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "metronomefb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("metronomefb"))
    .register();

    check::Check::new(
        "KMR_033",
        "Ensure that kernel module `n411` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("n411"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "n411",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("n411"))
    .register();

    check::Check::new(
        "KMR_034",
        "Ensure that kernel module `neofb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("neofb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "neofb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("neofb"))
    .register();

    check::Check::new(
        "KMR_035",
        "Ensure that kernel module `nvidiafb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nvidiafb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nvidiafb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("nvidiafb"))
    .register();

    check::Check::new(
        "KMR_036",
        "Ensure that kernel module `ocfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ocfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ocfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("ocfb"))
    .register();

    check::Check::new(
        "KMR_037",
        "Ensure that kernel module `pm2fb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pm2fb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pm2fb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("pm2fb"))
    .register();

    check::Check::new(
        "KMR_038",
        "Ensure that kernel module `pm3fb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pm3fb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pm3fb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("pm3fb"))
    .register();

    check::Check::new(
        "KMR_039",
        "Ensure that kernel module `radeonfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("radeonfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "radeonfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("radeonfb"))
    .register();

    check::Check::new(
        "KMR_040",
        "Ensure that kernel module `rivafb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rivafb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rivafb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("rivafb"))
    .register();

    check::Check::new(
        "KMR_041",
        "Ensure that kernel module `s1d13xxxfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("s1d13xxxfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "s1d13xxxfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("s1d13xxxfb"))
    .register();

    check::Check::new(
        "KMR_042",
        "Ensure that kernel module `s3fb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("s3fb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "s3fb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("s3fb"))
    .register();

    check::Check::new(
        "KMR_043",
        "Ensure that kernel module `savagefb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("savagefb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "savagefb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("savagefb"))
    .register();

    check::Check::new(
        "KMR_044",
        "Ensure that kernel module `sis_agp` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sis_agp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sis_agp",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("sis_agp"))
    .register();

    check::Check::new(
        "KMR_045",
        "Ensure that kernel module `sisfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sisfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sisfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("sisfb"))
    .register();

    check::Check::new(
        "KMR_046",
        "Ensure that kernel module `sm501fb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sm501fb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sm501fb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("sm501fb"))
    .register();

    check::Check::new(
        "KMR_047",
        "Ensure that kernel module `sm712fb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sm712fb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sm712fb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("sm712fb"))
    .register();

    check::Check::new(
        "KMR_048",
        "Ensure that kernel module `smscufx` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("smscufx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "smscufx",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("smscufx"))
    .register();

    check::Check::new(
        "KMR_049",
        "Ensure that kernel module `ssd1307fb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ssd1307fb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ssd1307fb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("ssd1307fb"))
    .register();

    check::Check::new(
        "KMR_050",
        "Ensure that kernel module `sstfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sstfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sstfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("sstfb"))
    .register();

    check::Check::new(
        "KMR_051",
        "Ensure that kernel module `svgalib` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("svgalib"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "svgalib",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("svgalib"))
    .register();

    check::Check::new(
        "KMR_052",
        "Ensure that kernel module `tdfxfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("tdfxfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tdfxfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("tdfxfb"))
    .register();

    check::Check::new(
        "KMR_053",
        "Ensure that kernel module `tridentfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("tridentfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tridentfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("tridentfb"))
    .register();

    check::Check::new(
        "KMR_054",
        "Ensure that kernel module `udlfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("udlfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "udlfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("udlfb"))
    .register();

    check::Check::new(
        "KMR_055",
        "Ensure that kernel module `uvesafb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("uvesafb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uvesafb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("uvesafb"))
    .register();

    check::Check::new(
        "KMR_056",
        "Ensure that kernel module `vesafb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("vesafb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vesafb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("vesafb"))
    .register();

    check::Check::new(
        "KMR_057",
        "Ensure that kernel module `vfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("vfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vfb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("vfb"))
    .register();

    check::Check::new(
        "KMR_058",
        "Ensure that kernel module `vga16fb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("vga16fb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vga16fb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("vga16fb"))
    .register();

    check::Check::new(
        "KMR_059",
        "Ensure that kernel module `viafb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("viafb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "viafb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("viafb"))
    .register();

    check::Check::new(
        "KMR_060",
        "Ensure that kernel module `vt8623fb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("vt8623fb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vt8623fb",
        "Legacy PCI framebuffer fbdev driver, superseded by DRM/KMS.",
    ))
    .with_fix(&fix_disabled("vt8623fb"))
    .register();

    // media capture, DVB, infrared (KME_)
    check::Check::new(
        "KME_001",
        "Ensure that kernel module `ati_remote` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ati_remote"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ati_remote", "Infrared/remotes."))
    .with_fix(&fix_disabled("ati_remote"))
    .register();

    check::Check::new(
        "KME_002",
        "Ensure that kernel module `cx2341x` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cx2341x"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cx2341x",
        "Legacy TV capture support.",
    ))
    .with_fix(&fix_disabled("cx2341x"))
    .register();

    check::Check::new(
        "KME_003",
        "Ensure that kernel module `cypress_firmware` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cypress_firmware"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cypress_firmware",
        "Legacy TV capture support.",
    ))
    .with_fix(&fix_disabled("cypress_firmware"))
    .register();

    check::Check::new(
        "KME_004",
        "Ensure that kernel module `dsbr100` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dsbr100"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dsbr100", "FM radio USB sticks."))
    .with_fix(&fix_disabled("dsbr100"))
    .register();

    check::Check::new(
        "KME_005",
        "Ensure that kernel module `dvb_core` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("dvb_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dvb_core", "Digital TV."))
    .with_fix(&fix_disabled("dvb_core"))
    .register();

    check::Check::new(
        "KME_006",
        "Ensure that kernel module `dvb_pll` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("dvb_pll"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dvb_pll", "Digital TV."))
    .with_fix(&fix_disabled("dvb_pll"))
    .register();

    check::Check::new(
        "KME_007",
        "Ensure that kernel module `ene_ir` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ene_ir"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ene_ir", "Infrared/remotes."))
    .with_fix(&fix_disabled("ene_ir"))
    .register();

    check::Check::new(
        "KME_008",
        "Ensure that kernel module `fintek_cir` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("fintek_cir"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("fintek_cir", "Infrared/remotes."))
    .with_fix(&fix_disabled("fintek_cir"))
    .register();

    check::Check::new(
        "KME_009",
        "Ensure that kernel module `firedtv` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("firedtv"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "firedtv",
        "Legacy TV capture support.",
    ))
    .with_fix(&fix_disabled("firedtv"))
    .register();

    check::Check::new(
        "KME_010",
        "Ensure that kernel module `igorplugusb` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("igorplugusb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("igorplugusb", "Infrared/remotes."))
    .with_fix(&fix_disabled("igorplugusb"))
    .register();

    check::Check::new(
        "KME_011",
        "Ensure that kernel module `iguanair` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("iguanair"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("iguanair", "Infrared/remotes."))
    .with_fix(&fix_disabled("iguanair"))
    .register();

    check::Check::new(
        "KME_012",
        "Ensure that kernel module `imon` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("imon"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("imon", "Infrared/remotes."))
    .with_fix(&fix_disabled("imon"))
    .register();

    check::Check::new(
        "KME_013",
        "Ensure that kernel module `ir_toy` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ir_toy"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ir_toy", "Infrared/remotes."))
    .with_fix(&fix_disabled("ir_toy"))
    .register();

    check::Check::new(
        "KME_014",
        "Ensure that kernel module `ite_cir` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ite_cir"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ite_cir", "Infrared/remotes."))
    .with_fix(&fix_disabled("ite_cir"))
    .register();

    check::Check::new(
        "KME_015",
        "Ensure that kernel module `m2m_deinterlace` is disabled",
        Severity::Medium,
        vec!["module", "server"],
        || modprobe::check_module_disabled("m2m_deinterlace"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "m2m_deinterlace",
        "V4L2 cores, blocks all 700+ media drivers.",
    ))
    .with_fix(&fix_disabled("m2m_deinterlace"))
    .register();

    check::Check::new(
        "KME_016",
        "Ensure that kernel module `mc` is disabled",
        Severity::Medium,
        vec!["module", "server"],
        || modprobe::check_module_disabled("mc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mc",
        "V4L2 cores, blocks all 700+ media drivers.",
    ))
    .with_fix(&fix_disabled("mc"))
    .register();

    check::Check::new(
        "KME_017",
        "Ensure that kernel module `mceusb` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("mceusb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mceusb", "Infrared/remotes."))
    .with_fix(&fix_disabled("mceusb"))
    .register();

    check::Check::new(
        "KME_018",
        "Ensure that kernel module `nuvoton_cir` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("nuvoton_cir"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nuvoton_cir", "Infrared/remotes."))
    .with_fix(&fix_disabled("nuvoton_cir"))
    .register();

    check::Check::new(
        "KME_019",
        "Ensure that kernel module `radio_shark` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("radio_shark"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("radio_shark", "FM radio USB sticks."))
    .with_fix(&fix_disabled("radio_shark"))
    .register();

    check::Check::new(
        "KME_020",
        "Ensure that kernel module `rc_core` is disabled",
        Severity::Medium,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("rc_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("rc_core", "Infrared/remotes."))
    .with_fix(&fix_disabled("rc_core"))
    .register();

    check::Check::new(
        "KME_021",
        "Ensure that kernel module `redrat3` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("redrat3"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("redrat3", "Infrared/remotes."))
    .with_fix(&fix_disabled("redrat3"))
    .register();

    check::Check::new(
        "KME_022",
        "Ensure that kernel module `serial_ir` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("serial_ir"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("serial_ir", "Infrared/remotes."))
    .with_fix(&fix_disabled("serial_ir"))
    .register();

    check::Check::new(
        "KME_023",
        "Ensure that kernel module `shark2` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("shark2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("shark2", "FM radio USB sticks."))
    .with_fix(&fix_disabled("shark2"))
    .register();

    check::Check::new(
        "KME_024",
        "Ensure that kernel module `streamzap` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("streamzap"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("streamzap", "Infrared/remotes."))
    .with_fix(&fix_disabled("streamzap"))
    .register();

    check::Check::new(
        "KME_025",
        "Ensure that kernel module `tea575x` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("tea575x"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("tea575x", "FM radio USB sticks."))
    .with_fix(&fix_disabled("tea575x"))
    .register();

    check::Check::new(
        "KME_026",
        "Ensure that kernel module `ttpci_eeprom` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ttpci_eeprom"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ttpci_eeprom",
        "Legacy TV capture support.",
    ))
    .with_fix(&fix_disabled("ttpci_eeprom"))
    .register();

    check::Check::new(
        "KME_027",
        "Ensure that kernel module `ttusbir` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("ttusbir"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ttusbir", "Infrared/remotes."))
    .with_fix(&fix_disabled("ttusbir"))
    .register();

    check::Check::new(
        "KME_028",
        "Ensure that kernel module `tuner` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("tuner"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("tuner", "Legacy TV capture support."))
    .with_fix(&fix_disabled("tuner"))
    .register();

    check::Check::new(
        "KME_029",
        "Ensure that kernel module `tveeprom` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("tveeprom"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tveeprom",
        "Legacy TV capture support.",
    ))
    .with_fix(&fix_disabled("tveeprom"))
    .register();

    check::Check::new(
        "KME_030",
        "Ensure that kernel module `uvcvideo` is disabled",
        Severity::Medium,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("uvcvideo"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("uvcvideo", "USB webcams."))
    .with_fix(&fix_disabled("uvcvideo"))
    .register();

    check::Check::new(
        "KME_031",
        "Ensure that kernel module `v4l2_async` is disabled",
        Severity::Medium,
        vec!["module", "server"],
        || modprobe::check_module_disabled("v4l2_async"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "v4l2_async",
        "V4L2 cores, blocks all 700+ media drivers.",
    ))
    .with_fix(&fix_disabled("v4l2_async"))
    .register();

    check::Check::new(
        "KME_032",
        "Ensure that kernel module `v4l2_cci` is disabled",
        Severity::Medium,
        vec!["module", "server"],
        || modprobe::check_module_disabled("v4l2_cci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "v4l2_cci",
        "V4L2 cores, blocks all 700+ media drivers.",
    ))
    .with_fix(&fix_disabled("v4l2_cci"))
    .register();

    check::Check::new(
        "KME_033",
        "Ensure that kernel module `v4l2_common` is disabled",
        Severity::Medium,
        vec!["module", "server"],
        || modprobe::check_module_disabled("v4l2_common"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "v4l2_common",
        "V4L2 cores, blocks all 700+ media drivers.",
    ))
    .with_fix(&fix_disabled("v4l2_common"))
    .register();

    check::Check::new(
        "KME_034",
        "Ensure that kernel module `v4l2_dv_timings` is disabled",
        Severity::Medium,
        vec!["module", "server"],
        || modprobe::check_module_disabled("v4l2_dv_timings"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "v4l2_dv_timings",
        "V4L2 cores, blocks all 700+ media drivers.",
    ))
    .with_fix(&fix_disabled("v4l2_dv_timings"))
    .register();

    check::Check::new(
        "KME_035",
        "Ensure that kernel module `v4l2_flash_led_class` is disabled",
        Severity::Medium,
        vec!["module", "server"],
        || modprobe::check_module_disabled("v4l2_flash_led_class"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "v4l2_flash_led_class",
        "V4L2 cores, blocks all 700+ media drivers.",
    ))
    .with_fix(&fix_disabled("v4l2_flash_led_class"))
    .register();

    check::Check::new(
        "KME_036",
        "Ensure that kernel module `v4l2_fwnode` is disabled",
        Severity::Medium,
        vec!["module", "server"],
        || modprobe::check_module_disabled("v4l2_fwnode"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "v4l2_fwnode",
        "V4L2 cores, blocks all 700+ media drivers.",
    ))
    .with_fix(&fix_disabled("v4l2_fwnode"))
    .register();

    check::Check::new(
        "KME_037",
        "Ensure that kernel module `v4l2_mem2mem` is disabled",
        Severity::Medium,
        vec!["module", "server"],
        || modprobe::check_module_disabled("v4l2_mem2mem"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "v4l2_mem2mem",
        "V4L2 cores, blocks all 700+ media drivers.",
    ))
    .with_fix(&fix_disabled("v4l2_mem2mem"))
    .register();

    check::Check::new(
        "KME_038",
        "Ensure that kernel module `videodev` is disabled",
        Severity::Medium,
        vec!["module", "server"],
        || modprobe::check_module_disabled("videodev"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "videodev",
        "V4L2 cores, blocks all 700+ media drivers.",
    ))
    .with_fix(&fix_disabled("videodev"))
    .register();

    check::Check::new(
        "KME_039",
        "Ensure that kernel module `winbond_cir` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("winbond_cir"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("winbond_cir", "Infrared/remotes."))
    .with_fix(&fix_disabled("winbond_cir"))
    .register();

    check::Check::new(
        "KME_040",
        "Ensure that kernel module `xbox_remote` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("xbox_remote"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xbox_remote", "Infrared/remotes."))
    .with_fix(&fix_disabled("xbox_remote"))
    .register();

    // input and gaming (KMG_)
    check::Check::new(
        "KMG_001",
        "Ensure that kernel module `emu10k1_gp` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("emu10k1_gp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("emu10k1_gp", "Game ports."))
    .with_fix(&fix_disabled("emu10k1_gp"))
    .register();

    check::Check::new(
        "KMG_002",
        "Ensure that kernel module `fm801_gp` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("fm801_gp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("fm801_gp", "Game ports."))
    .with_fix(&fix_disabled("fm801_gp"))
    .register();

    check::Check::new(
        "KMG_003",
        "Ensure that kernel module `gameport` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gameport"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("gameport", "Game ports."))
    .with_fix(&fix_disabled("gameport"))
    .register();

    check::Check::new(
        "KMG_004",
        "Ensure that kernel module `joydev` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("joydev"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "joydev",
        "Joystick/gamepad input layer.",
    ))
    .with_fix(&fix_disabled("joydev"))
    .register();

    check::Check::new(
        "KMG_005",
        "Ensure that kernel module `mousedev` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("mousedev"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mousedev",
        "PS/2 mouse. Workstations with PS/2 touchpads, older ThinkPads, need psmouse.",
    ))
    .with_fix(&fix_disabled("mousedev"))
    .register();

    check::Check::new(
        "KMG_006",
        "Ensure that kernel module `psmouse` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("psmouse"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "psmouse",
        "PS/2 mouse. Workstations with PS/2 touchpads, older ThinkPads, need psmouse.",
    ))
    .with_fix(&fix_disabled("psmouse"))
    .register();

    check::Check::new(
        "KMG_007",
        "Ensure that kernel module `xpad` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("xpad"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xpad", "Xbox controllers."))
    .with_fix(&fix_disabled("xpad"))
    .register();

    // watchdogs (KMW_)
    check::Check::new(
        "KMW_001",
        "Ensure that kernel module `acquirewdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("acquirewdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "acquirewdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("acquirewdt"))
    .register();

    check::Check::new(
        "KMW_002",
        "Ensure that kernel module `advantech_ec_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("advantech_ec_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "advantech_ec_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("advantech_ec_wdt"))
    .register();

    check::Check::new(
        "KMW_003",
        "Ensure that kernel module `advantechwdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("advantechwdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "advantechwdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("advantechwdt"))
    .register();

    check::Check::new(
        "KMW_004",
        "Ensure that kernel module `alim1535_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("alim1535_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "alim1535_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("alim1535_wdt"))
    .register();

    check::Check::new(
        "KMW_005",
        "Ensure that kernel module `alim7101_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("alim7101_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "alim7101_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("alim7101_wdt"))
    .register();

    check::Check::new(
        "KMW_006",
        "Ensure that kernel module `cadence_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cadence_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cadence_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("cadence_wdt"))
    .register();

    check::Check::new(
        "KMW_007",
        "Ensure that kernel module `cgbc_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cgbc_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cgbc_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("cgbc_wdt"))
    .register();

    check::Check::new(
        "KMW_008",
        "Ensure that kernel module `cpu5wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cpu5wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cpu5wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("cpu5wdt"))
    .register();

    check::Check::new(
        "KMW_009",
        "Ensure that kernel module `cros_ec_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cros_ec_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "cros_ec_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("cros_ec_wdt"))
    .register();

    check::Check::new(
        "KMW_010",
        "Ensure that kernel module `da9052_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("da9052_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "da9052_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("da9052_wdt"))
    .register();

    check::Check::new(
        "KMW_011",
        "Ensure that kernel module `da9055_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("da9055_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "da9055_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("da9055_wdt"))
    .register();

    check::Check::new(
        "KMW_012",
        "Ensure that kernel module `da9062_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("da9062_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "da9062_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("da9062_wdt"))
    .register();

    check::Check::new(
        "KMW_013",
        "Ensure that kernel module `da9063_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("da9063_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "da9063_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("da9063_wdt"))
    .register();

    check::Check::new(
        "KMW_014",
        "Ensure that kernel module `dw_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dw_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "dw_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("dw_wdt"))
    .register();

    check::Check::new(
        "KMW_015",
        "Ensure that kernel module `ebc_c384_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ebc_c384_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ebc_c384_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("ebc_c384_wdt"))
    .register();

    check::Check::new(
        "KMW_016",
        "Ensure that kernel module `eurotechwdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("eurotechwdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "eurotechwdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("eurotechwdt"))
    .register();

    check::Check::new(
        "KMW_017",
        "Ensure that kernel module `exar_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("exar_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "exar_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("exar_wdt"))
    .register();

    check::Check::new(
        "KMW_018",
        "Ensure that kernel module `f71808e_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("f71808e_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "f71808e_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("f71808e_wdt"))
    .register();

    check::Check::new(
        "KMW_019",
        "Ensure that kernel module `hpwdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hpwdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hpwdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("hpwdt"))
    .register();

    check::Check::new(
        "KMW_020",
        "Ensure that kernel module `i6300esb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("i6300esb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "i6300esb",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("i6300esb"))
    .register();

    check::Check::new(
        "KMW_021",
        "Ensure that kernel module `iTCO_vendor_support` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("iTCO_vendor_support"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "iTCO_vendor_support",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("iTCO_vendor_support"))
    .register();

    check::Check::new(
        "KMW_022",
        "Ensure that kernel module `iTCO_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("iTCO_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "iTCO_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("iTCO_wdt"))
    .register();

    check::Check::new(
        "KMW_023",
        "Ensure that kernel module `ib700wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ib700wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ib700wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("ib700wdt"))
    .register();

    check::Check::new(
        "KMW_024",
        "Ensure that kernel module `ibmasr` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ibmasr"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ibmasr",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("ibmasr"))
    .register();

    check::Check::new(
        "KMW_025",
        "Ensure that kernel module `ie6xx_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ie6xx_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ie6xx_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("ie6xx_wdt"))
    .register();

    check::Check::new(
        "KMW_026",
        "Ensure that kernel module `intel_oc_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("intel_oc_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "intel_oc_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("intel_oc_wdt"))
    .register();

    check::Check::new(
        "KMW_027",
        "Ensure that kernel module `it8712f_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("it8712f_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "it8712f_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("it8712f_wdt"))
    .register();

    check::Check::new(
        "KMW_028",
        "Ensure that kernel module `it87_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("it87_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "it87_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("it87_wdt"))
    .register();

    check::Check::new(
        "KMW_029",
        "Ensure that kernel module `kempld_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("kempld_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "kempld_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("kempld_wdt"))
    .register();

    check::Check::new(
        "KMW_030",
        "Ensure that kernel module `lenovo_se10_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("lenovo_se10_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "lenovo_se10_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("lenovo_se10_wdt"))
    .register();

    check::Check::new(
        "KMW_031",
        "Ensure that kernel module `lenovo_se30_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("lenovo_se30_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "lenovo_se30_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("lenovo_se30_wdt"))
    .register();

    check::Check::new(
        "KMW_032",
        "Ensure that kernel module `machzwd` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("machzwd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "machzwd",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("machzwd"))
    .register();

    check::Check::new(
        "KMW_033",
        "Ensure that kernel module `max63xx_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("max63xx_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "max63xx_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("max63xx_wdt"))
    .register();

    check::Check::new(
        "KMW_034",
        "Ensure that kernel module `mei_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mei_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mei_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("mei_wdt"))
    .register();

    check::Check::new(
        "KMW_035",
        "Ensure that kernel module `mena21_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mena21_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mena21_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("mena21_wdt"))
    .register();

    check::Check::new(
        "KMW_036",
        "Ensure that kernel module `menf21bmc_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("menf21bmc_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "menf21bmc_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("menf21bmc_wdt"))
    .register();

    check::Check::new(
        "KMW_037",
        "Ensure that kernel module `menz69_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("menz69_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "menz69_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("menz69_wdt"))
    .register();

    check::Check::new(
        "KMW_038",
        "Ensure that kernel module `mlx_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mlx_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mlx_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("mlx_wdt"))
    .register();

    check::Check::new(
        "KMW_039",
        "Ensure that kernel module `nct6694_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nct6694_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nct6694_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("nct6694_wdt"))
    .register();

    check::Check::new(
        "KMW_040",
        "Ensure that kernel module `ni903x_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ni903x_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ni903x_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("ni903x_wdt"))
    .register();

    check::Check::new(
        "KMW_041",
        "Ensure that kernel module `nic7018_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nic7018_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nic7018_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("nic7018_wdt"))
    .register();

    check::Check::new(
        "KMW_042",
        "Ensure that kernel module `nv_tco` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("nv_tco"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nv_tco",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("nv_tco"))
    .register();

    check::Check::new(
        "KMW_043",
        "Ensure that kernel module `of_xilinx_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("of_xilinx_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "of_xilinx_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("of_xilinx_wdt"))
    .register();

    check::Check::new(
        "KMW_044",
        "Ensure that kernel module `pc87413_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pc87413_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pc87413_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("pc87413_wdt"))
    .register();

    check::Check::new(
        "KMW_045",
        "Ensure that kernel module `pcwd_pci` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pcwd_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pcwd_pci",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("pcwd_pci"))
    .register();

    check::Check::new(
        "KMW_046",
        "Ensure that kernel module `pcwd_usb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pcwd_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pcwd_usb",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("pcwd_usb"))
    .register();

    check::Check::new(
        "KMW_047",
        "Ensure that kernel module `rave_sp_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rave_sp_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "rave_sp_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("rave_sp_wdt"))
    .register();

    check::Check::new(
        "KMW_048",
        "Ensure that kernel module `retu_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("retu_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "retu_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("retu_wdt"))
    .register();

    check::Check::new(
        "KMW_049",
        "Ensure that kernel module `sbc60xxwdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sbc60xxwdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sbc60xxwdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("sbc60xxwdt"))
    .register();

    check::Check::new(
        "KMW_050",
        "Ensure that kernel module `sbc_epx_c3` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sbc_epx_c3"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sbc_epx_c3",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("sbc_epx_c3"))
    .register();

    check::Check::new(
        "KMW_051",
        "Ensure that kernel module `sbc_fitpc2_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sbc_fitpc2_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sbc_fitpc2_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("sbc_fitpc2_wdt"))
    .register();

    check::Check::new(
        "KMW_052",
        "Ensure that kernel module `sc1200wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sc1200wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sc1200wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("sc1200wdt"))
    .register();

    check::Check::new(
        "KMW_053",
        "Ensure that kernel module `sch311x_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sch311x_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sch311x_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("sch311x_wdt"))
    .register();

    check::Check::new(
        "KMW_054",
        "Ensure that kernel module `simatic_ipc_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("simatic_ipc_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "simatic_ipc_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("simatic_ipc_wdt"))
    .register();

    check::Check::new(
        "KMW_055",
        "Ensure that kernel module `smsc37b787_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("smsc37b787_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "smsc37b787_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("smsc37b787_wdt"))
    .register();

    check::Check::new(
        "KMW_056",
        "Ensure that kernel module `sp5100_tco` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sp5100_tco"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sp5100_tco",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("sp5100_tco"))
    .register();

    check::Check::new(
        "KMW_057",
        "Ensure that kernel module `tqmx86_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("tqmx86_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tqmx86_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("tqmx86_wdt"))
    .register();

    check::Check::new(
        "KMW_058",
        "Ensure that kernel module `twl4030_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("twl4030_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "twl4030_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("twl4030_wdt"))
    .register();

    check::Check::new(
        "KMW_059",
        "Ensure that kernel module `via_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("via_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "via_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("via_wdt"))
    .register();

    check::Check::new(
        "KMW_060",
        "Ensure that kernel module `w83627hf_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w83627hf_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w83627hf_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("w83627hf_wdt"))
    .register();

    check::Check::new(
        "KMW_061",
        "Ensure that kernel module `w83877f_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w83877f_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w83877f_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("w83877f_wdt"))
    .register();

    check::Check::new(
        "KMW_062",
        "Ensure that kernel module `w83977f_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w83977f_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w83977f_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("w83977f_wdt"))
    .register();

    check::Check::new(
        "KMW_063",
        "Ensure that kernel module `wafer5823wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("wafer5823wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "wafer5823wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("wafer5823wdt"))
    .register();

    check::Check::new(
        "KMW_064",
        "Ensure that kernel module `wdat_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("wdat_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "wdat_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("wdat_wdt"))
    .register();

    check::Check::new(
        "KMW_065",
        "Ensure that kernel module `wdt_pci` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("wdt_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "wdt_pci",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("wdt_pci"))
    .register();

    check::Check::new(
        "KMW_066",
        "Ensure that kernel module `wm831x_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("wm831x_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "wm831x_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("wm831x_wdt"))
    .register();

    check::Check::new(
        "KMW_067",
        "Ensure that kernel module `wm8350_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("wm8350_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "wm8350_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("wm8350_wdt"))
    .register();

    check::Check::new(
        "KMW_068",
        "Ensure that kernel module `ziirave_wdt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ziirave_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ziirave_wdt",
        "Hardware watchdog timer driver.",
    ))
    .with_fix(&fix_disabled("ziirave_wdt"))
    .register();

    // platform management (Intel ME, PMT, MSR) (KMM_)
    check::Check::new(
        "KMM_001",
        "Ensure that kernel module `applicom` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("applicom"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "applicom",
        "HPC/vendor server-management legacy, SGI, IBM ASM, HP iLO passthrough, Siemens PLC cards.",
    ))
    .with_fix(&fix_disabled("applicom"))
    .register();

    check::Check::new(
        "KMM_002",
        "Ensure that kernel module `cpuid` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("cpuid"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("cpuid", "Raw MSR/CPUID access. Root-only, but MSRs can undo mitigations; tools like thermald, intel-microcode, cpuid may need them."))
    .with_fix(&fix_disabled("cpuid"))
    .register();

    check::Check::new(
        "KMM_003",
        "Ensure that kernel module `dca` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dca"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "dca",
        "HPC/vendor server-management legacy, SGI, IBM ASM, HP iLO passthrough, Siemens PLC cards.",
    ))
    .with_fix(&fix_disabled("dca"))
    .register();

    check::Check::new(
        "KMM_004",
        "Ensure that kernel module `genwqe_card` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("genwqe_card"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "genwqe_card",
        "HPC/vendor server-management legacy, SGI, IBM ASM, HP iLO passthrough, Siemens PLC cards.",
    ))
    .with_fix(&fix_disabled("genwqe_card"))
    .register();

    check::Check::new(
        "KMM_005",
        "Ensure that kernel module `gru` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gru"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "gru",
        "HPC/vendor server-management legacy, SGI, IBM ASM, HP iLO passthrough, Siemens PLC cards.",
    ))
    .with_fix(&fix_disabled("gru"))
    .register();

    check::Check::new(
        "KMM_006",
        "Ensure that kernel module `hpilo` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hpilo"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hpilo",
        "HPC/vendor server-management legacy, SGI, IBM ASM, HP iLO passthrough, Siemens PLC cards.",
    ))
    .with_fix(&fix_disabled("hpilo"))
    .register();

    check::Check::new(
        "KMM_007",
        "Ensure that kernel module `ibmasm` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ibmasm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ibmasm",
        "HPC/vendor server-management legacy, SGI, IBM ASM, HP iLO passthrough, Siemens PLC cards.",
    ))
    .with_fix(&fix_disabled("ibmasm"))
    .register();

    check::Check::new(
        "KMM_008",
        "Ensure that kernel module `pmt_class` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pmt_class"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pmt_class", "Intel PMT telemetry."))
    .with_fix(&fix_disabled("pmt_class"))
    .register();

    check::Check::new(
        "KMM_009",
        "Ensure that kernel module `pmt_crashlog` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pmt_crashlog"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pmt_crashlog",
        "Intel PMT telemetry.",
    ))
    .with_fix(&fix_disabled("pmt_crashlog"))
    .register();

    check::Check::new(
        "KMM_010",
        "Ensure that kernel module `pmt_discovery` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pmt_discovery"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pmt_discovery",
        "Intel PMT discovery.",
    ))
    .with_fix(&fix_disabled("pmt_discovery"))
    .register();

    check::Check::new(
        "KMM_011",
        "Ensure that kernel module `pmt_telemetry` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pmt_telemetry"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pmt_telemetry",
        "Intel PMT telemetry.",
    ))
    .with_fix(&fix_disabled("pmt_telemetry"))
    .register();

    check::Check::new(
        "KMM_012",
        "Ensure that kernel module `uv_mmtimer` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("uv_mmtimer"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uv_mmtimer",
        "HPC/vendor server-management legacy, SGI, IBM ASM, HP iLO passthrough, Siemens PLC cards.",
    ))
    .with_fix(&fix_disabled("uv_mmtimer"))
    .register();

    check::Check::new(
        "KMM_013",
        "Ensure that kernel module `xp` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("xp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "xp",
        "HPC/vendor server-management legacy, SGI, IBM ASM, HP iLO passthrough, Siemens PLC cards.",
    ))
    .with_fix(&fix_disabled("xp"))
    .register();

    check::Check::new(
        "KMM_014",
        "Ensure that kernel module `xpc` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("xpc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "xpc",
        "HPC/vendor server-management legacy, SGI, IBM ASM, HP iLO passthrough, Siemens PLC cards.",
    ))
    .with_fix(&fix_disabled("xpc"))
    .register();

    check::Check::new(
        "KMM_015",
        "Ensure that kernel module `xpnet` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("xpnet"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "xpnet",
        "HPC/vendor server-management legacy, SGI, IBM ASM, HP iLO passthrough, Siemens PLC cards.",
    ))
    .with_fix(&fix_disabled("xpnet"))
    .register();

    // industrial, embedded and exotic buses (KMI_)
    check::Check::new(
        "KMI_001",
        "Ensure that kernel module `104_quad_8` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("104_quad_8"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("104_quad_8", "Counter subsystem."))
    .with_fix(&fix_disabled("104_quad_8"))
    .register();

    check::Check::new(
        "KMI_002",
        "Ensure that kernel module `altera_cvp` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("altera_cvp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("altera_cvp", "FPGA."))
    .with_fix(&fix_disabled("altera_cvp"))
    .register();

    check::Check::new(
        "KMI_003",
        "Ensure that kernel module `altera_freeze_bridge` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("altera_freeze_bridge"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("altera_freeze_bridge", "FPGA."))
    .with_fix(&fix_disabled("altera_freeze_bridge"))
    .register();

    check::Check::new(
        "KMI_004",
        "Ensure that kernel module `altera_pr_ip_core` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("altera_pr_ip_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("altera_pr_ip_core", "FPGA."))
    .with_fix(&fix_disabled("altera_pr_ip_core"))
    .register();

    check::Check::new(
        "KMI_005",
        "Ensure that kernel module `altera_ps_spi` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("altera_ps_spi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("altera_ps_spi", "FPGA."))
    .with_fix(&fix_disabled("altera_ps_spi"))
    .register();

    check::Check::new(
        "KMI_006",
        "Ensure that kernel module `altera_stapl` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("altera_stapl"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "altera_stapl",
        "Misc PCIe appliances.",
    ))
    .with_fix(&fix_disabled("altera_stapl"))
    .register();

    check::Check::new(
        "KMI_007",
        "Ensure that kernel module `amd_axi_w1` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("amd_axi_w1"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "amd_axi_w1",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("amd_axi_w1"))
    .register();

    check::Check::new(
        "KMI_008",
        "Ensure that kernel module `bcm_vk` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("bcm_vk"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("bcm_vk", "Misc PCIe appliances."))
    .with_fix(&fix_disabled("bcm_vk"))
    .register();

    check::Check::new(
        "KMI_009",
        "Ensure that kernel module `cfag12864b` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cfag12864b"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("cfag12864b", "Auxiliary displays."))
    .with_fix(&fix_disabled("cfag12864b"))
    .register();

    check::Check::new(
        "KMI_010",
        "Ensure that kernel module `cfag12864bfb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("cfag12864bfb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("cfag12864bfb", "Auxiliary displays."))
    .with_fix(&fix_disabled("cfag12864bfb"))
    .register();

    check::Check::new(
        "KMI_011",
        "Ensure that kernel module `charlcd` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("charlcd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("charlcd", "Auxiliary displays."))
    .with_fix(&fix_disabled("charlcd"))
    .register();

    check::Check::new(
        "KMI_012",
        "Ensure that kernel module `comedi` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("comedi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("comedi", "Data acquisition, comedi."))
    .with_fix(&fix_disabled("comedi"))
    .register();

    check::Check::new(
        "KMI_013",
        "Ensure that kernel module `comedi_8254` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("comedi_8254"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "comedi_8254",
        "Data acquisition, comedi.",
    ))
    .with_fix(&fix_disabled("comedi_8254"))
    .register();

    check::Check::new(
        "KMI_014",
        "Ensure that kernel module `comedi_8255` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("comedi_8255"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "comedi_8255",
        "Data acquisition, comedi.",
    ))
    .with_fix(&fix_disabled("comedi_8255"))
    .register();

    check::Check::new(
        "KMI_015",
        "Ensure that kernel module `comedi_bond` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("comedi_bond"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "comedi_bond",
        "Data acquisition, comedi.",
    ))
    .with_fix(&fix_disabled("comedi_bond"))
    .register();

    check::Check::new(
        "KMI_016",
        "Ensure that kernel module `comedi_isadma` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("comedi_isadma"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "comedi_isadma",
        "Data acquisition, comedi.",
    ))
    .with_fix(&fix_disabled("comedi_isadma"))
    .register();

    check::Check::new(
        "KMI_017",
        "Ensure that kernel module `comedi_parport` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("comedi_parport"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "comedi_parport",
        "Data acquisition, comedi.",
    ))
    .with_fix(&fix_disabled("comedi_parport"))
    .register();

    check::Check::new(
        "KMI_018",
        "Ensure that kernel module `comedi_pci` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("comedi_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "comedi_pci",
        "Data acquisition, comedi.",
    ))
    .with_fix(&fix_disabled("comedi_pci"))
    .register();

    check::Check::new(
        "KMI_019",
        "Ensure that kernel module `comedi_pcmcia` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("comedi_pcmcia"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "comedi_pcmcia",
        "Data acquisition, comedi.",
    ))
    .with_fix(&fix_disabled("comedi_pcmcia"))
    .register();

    check::Check::new(
        "KMI_020",
        "Ensure that kernel module `comedi_usb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("comedi_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "comedi_usb",
        "Data acquisition, comedi.",
    ))
    .with_fix(&fix_disabled("comedi_usb"))
    .register();

    check::Check::new(
        "KMI_021",
        "Ensure that kernel module `counter` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("counter"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("counter", "Counter subsystem."))
    .with_fix(&fix_disabled("counter"))
    .register();

    check::Check::new(
        "KMI_022",
        "Ensure that kernel module `dfl` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dfl"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dfl", "FPGA."))
    .with_fix(&fix_disabled("dfl"))
    .register();

    check::Check::new(
        "KMI_023",
        "Ensure that kernel module `dfl_afu` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dfl_afu"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dfl_afu", "FPGA."))
    .with_fix(&fix_disabled("dfl_afu"))
    .register();

    check::Check::new(
        "KMI_024",
        "Ensure that kernel module `dfl_fme` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dfl_fme"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dfl_fme", "FPGA."))
    .with_fix(&fix_disabled("dfl_fme"))
    .register();

    check::Check::new(
        "KMI_025",
        "Ensure that kernel module `dfl_fme_br` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dfl_fme_br"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dfl_fme_br", "FPGA."))
    .with_fix(&fix_disabled("dfl_fme_br"))
    .register();

    check::Check::new(
        "KMI_026",
        "Ensure that kernel module `dfl_fme_mgr` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dfl_fme_mgr"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dfl_fme_mgr", "FPGA."))
    .with_fix(&fix_disabled("dfl_fme_mgr"))
    .register();

    check::Check::new(
        "KMI_027",
        "Ensure that kernel module `dfl_fme_region` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dfl_fme_region"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dfl_fme_region", "FPGA."))
    .with_fix(&fix_disabled("dfl_fme_region"))
    .register();

    check::Check::new(
        "KMI_028",
        "Ensure that kernel module `dfl_n3000_nios` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dfl_n3000_nios"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dfl_n3000_nios", "FPGA."))
    .with_fix(&fix_disabled("dfl_n3000_nios"))
    .register();

    check::Check::new(
        "KMI_029",
        "Ensure that kernel module `dfl_pci` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dfl_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("dfl_pci", "FPGA."))
    .with_fix(&fix_disabled("dfl_pci"))
    .register();

    check::Check::new(
        "KMI_030",
        "Ensure that kernel module `ds2482` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ds2482"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ds2482",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("ds2482"))
    .register();

    check::Check::new(
        "KMI_031",
        "Ensure that kernel module `ds2490` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ds2490"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ds2490",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("ds2490"))
    .register();

    check::Check::new(
        "KMI_032",
        "Ensure that kernel module `dummy_stm` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("dummy_stm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "dummy_stm",
        "Intel TH / STM tracing.",
    ))
    .with_fix(&fix_disabled("dummy_stm"))
    .register();

    check::Check::new(
        "KMI_033",
        "Ensure that kernel module `dw_xdata_pcie` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("dw_xdata_pcie"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "dw_xdata_pcie",
        "Misc PCIe appliances.",
    ))
    .with_fix(&fix_disabled("dw_xdata_pcie"))
    .register();

    check::Check::new(
        "KMI_034",
        "Ensure that kernel module `enclosure` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("enclosure"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("enclosure", "Misc PCIe appliances."))
    .with_fix(&fix_disabled("enclosure"))
    .register();

    check::Check::new(
        "KMI_035",
        "Ensure that kernel module `fpga_bridge` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("fpga_bridge"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("fpga_bridge", "FPGA."))
    .with_fix(&fix_disabled("fpga_bridge"))
    .register();

    check::Check::new(
        "KMI_036",
        "Ensure that kernel module `fpga_mgr` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("fpga_mgr"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("fpga_mgr", "FPGA."))
    .with_fix(&fix_disabled("fpga_mgr"))
    .register();

    check::Check::new(
        "KMI_037",
        "Ensure that kernel module `fpga_region` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("fpga_region"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("fpga_region", "FPGA."))
    .with_fix(&fix_disabled("fpga_region"))
    .register();

    check::Check::new(
        "KMI_038",
        "Ensure that kernel module `gb_beagleplay` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gb_beagleplay"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("gb_beagleplay", "Greybus."))
    .with_fix(&fix_disabled("gb_beagleplay"))
    .register();

    check::Check::new(
        "KMI_039",
        "Ensure that kernel module `gb_es2` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("gb_es2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("gb_es2", "Greybus."))
    .with_fix(&fix_disabled("gb_es2"))
    .register();

    check::Check::new(
        "KMI_040",
        "Ensure that kernel module `greybus` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("greybus"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("greybus", "Greybus."))
    .with_fix(&fix_disabled("greybus"))
    .register();

    check::Check::new(
        "KMI_041",
        "Ensure that kernel module `hd44780` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hd44780"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hd44780", "Auxiliary displays."))
    .with_fix(&fix_disabled("hd44780"))
    .register();

    check::Check::new(
        "KMI_042",
        "Ensure that kernel module `hd44780_common` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("hd44780_common"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hd44780_common",
        "Auxiliary displays.",
    ))
    .with_fix(&fix_disabled("hd44780_common"))
    .register();

    check::Check::new(
        "KMI_043",
        "Ensure that kernel module `ht16k33` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ht16k33"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ht16k33", "Auxiliary displays."))
    .with_fix(&fix_disabled("ht16k33"))
    .register();

    check::Check::new(
        "KMI_044",
        "Ensure that kernel module `i82092` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("i82092"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("i82092", "PCMCIA."))
    .with_fix(&fix_disabled("i82092"))
    .register();

    check::Check::new(
        "KMI_045",
        "Ensure that kernel module `i8254` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("i8254"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("i8254", "Counter subsystem."))
    .with_fix(&fix_disabled("i8254"))
    .register();

    check::Check::new(
        "KMI_046",
        "Ensure that kernel module `idt_89hpesx` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("idt_89hpesx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "idt_89hpesx",
        "Misc PCIe appliances.",
    ))
    .with_fix(&fix_disabled("idt_89hpesx"))
    .register();

    check::Check::new(
        "KMI_047",
        "Ensure that kernel module `idt_gen2` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("idt_gen2"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("idt_gen2", "RapidIO."))
    .with_fix(&fix_disabled("idt_gen2"))
    .register();

    check::Check::new(
        "KMI_048",
        "Ensure that kernel module `idt_gen3` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("idt_gen3"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("idt_gen3", "RapidIO."))
    .with_fix(&fix_disabled("idt_gen3"))
    .register();

    check::Check::new(
        "KMI_049",
        "Ensure that kernel module `idtcps` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("idtcps"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("idtcps", "RapidIO."))
    .with_fix(&fix_disabled("idtcps"))
    .register();

    check::Check::new(
        "KMI_050",
        "Ensure that kernel module `img_ascii_lcd` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("img_ascii_lcd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "img_ascii_lcd",
        "Auxiliary displays.",
    ))
    .with_fix(&fix_disabled("img_ascii_lcd"))
    .register();

    check::Check::new(
        "KMI_051",
        "Ensure that kernel module `industrialio` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("industrialio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("industrialio", "IIO sensors."))
    .with_fix(&fix_disabled("industrialio"))
    .register();

    check::Check::new(
        "KMI_052",
        "Ensure that kernel module `intel_qep` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("intel_qep"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("intel_qep", "Counter subsystem."))
    .with_fix(&fix_disabled("intel_qep"))
    .register();

    check::Check::new(
        "KMI_053",
        "Ensure that kernel module `intel_th` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("intel_th"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("intel_th", "Intel TH / STM tracing."))
    .with_fix(&fix_disabled("intel_th"))
    .register();

    check::Check::new(
        "KMI_054",
        "Ensure that kernel module `intel_th_acpi` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("intel_th_acpi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "intel_th_acpi",
        "Intel TH / STM tracing.",
    ))
    .with_fix(&fix_disabled("intel_th_acpi"))
    .register();

    check::Check::new(
        "KMI_055",
        "Ensure that kernel module `intel_th_gth` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("intel_th_gth"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "intel_th_gth",
        "Intel TH / STM tracing.",
    ))
    .with_fix(&fix_disabled("intel_th_gth"))
    .register();

    check::Check::new(
        "KMI_056",
        "Ensure that kernel module `intel_th_msu` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("intel_th_msu"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "intel_th_msu",
        "Intel TH / STM tracing.",
    ))
    .with_fix(&fix_disabled("intel_th_msu"))
    .register();

    check::Check::new(
        "KMI_057",
        "Ensure that kernel module `intel_th_msu_sink` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("intel_th_msu_sink"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "intel_th_msu_sink",
        "Intel TH / STM tracing.",
    ))
    .with_fix(&fix_disabled("intel_th_msu_sink"))
    .register();

    check::Check::new(
        "KMI_058",
        "Ensure that kernel module `intel_th_pci` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("intel_th_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "intel_th_pci",
        "Intel TH / STM tracing.",
    ))
    .with_fix(&fix_disabled("intel_th_pci"))
    .register();

    check::Check::new(
        "KMI_059",
        "Ensure that kernel module `intel_th_pti` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("intel_th_pti"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "intel_th_pti",
        "Intel TH / STM tracing.",
    ))
    .with_fix(&fix_disabled("intel_th_pti"))
    .register();

    check::Check::new(
        "KMI_060",
        "Ensure that kernel module `intel_th_sth` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("intel_th_sth"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "intel_th_sth",
        "Intel TH / STM tracing.",
    ))
    .with_fix(&fix_disabled("intel_th_sth"))
    .register();

    check::Check::new(
        "KMI_061",
        "Ensure that kernel module `interrupt_cnt` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("interrupt_cnt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("interrupt_cnt", "Counter subsystem."))
    .with_fix(&fix_disabled("interrupt_cnt"))
    .register();

    check::Check::new(
        "KMI_062",
        "Ensure that kernel module `ipack` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ipack"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ipack", "IPACK."))
    .with_fix(&fix_disabled("ipack"))
    .register();

    check::Check::new(
        "KMI_063",
        "Ensure that kernel module `ipoctal` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ipoctal"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ipoctal", "IPACK."))
    .with_fix(&fix_disabled("ipoctal"))
    .register();

    check::Check::new(
        "KMI_064",
        "Ensure that kernel module `kcomedilib` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("kcomedilib"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "kcomedilib",
        "Data acquisition, comedi.",
    ))
    .with_fix(&fix_disabled("kcomedilib"))
    .register();

    check::Check::new(
        "KMI_065",
        "Ensure that kernel module `ks0108` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ks0108"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ks0108", "Auxiliary displays."))
    .with_fix(&fix_disabled("ks0108"))
    .register();

    check::Check::new(
        "KMI_066",
        "Ensure that kernel module `lattice_ecp3_config` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("lattice_ecp3_config"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "lattice_ecp3_config",
        "Misc PCIe appliances.",
    ))
    .with_fix(&fix_disabled("lattice_ecp3_config"))
    .register();

    check::Check::new(
        "KMI_067",
        "Ensure that kernel module `lattice_sysconfig` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("lattice_sysconfig"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("lattice_sysconfig", "FPGA."))
    .with_fix(&fix_disabled("lattice_sysconfig"))
    .register();

    check::Check::new(
        "KMI_068",
        "Ensure that kernel module `lattice_sysconfig_spi` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("lattice_sysconfig_spi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("lattice_sysconfig_spi", "FPGA."))
    .with_fix(&fix_disabled("lattice_sysconfig_spi"))
    .register();

    check::Check::new(
        "KMI_069",
        "Ensure that kernel module `lcd2s` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("lcd2s"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("lcd2s", "Auxiliary displays."))
    .with_fix(&fix_disabled("lcd2s"))
    .register();

    check::Check::new(
        "KMI_070",
        "Ensure that kernel module `line_display` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("line_display"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("line_display", "Auxiliary displays."))
    .with_fix(&fix_disabled("line_display"))
    .register();

    check::Check::new(
        "KMI_071",
        "Ensure that kernel module `lp` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("lp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("lp", "Parallel port."))
    .with_fix(&fix_disabled("lp"))
    .register();

    check::Check::new(
        "KMI_072",
        "Ensure that kernel module `machxo2_spi` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("machxo2_spi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("machxo2_spi", "FPGA."))
    .with_fix(&fix_disabled("machxo2_spi"))
    .register();

    check::Check::new(
        "KMI_073",
        "Ensure that kernel module `matrox_w1` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("matrox_w1"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "matrox_w1",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("matrox_w1"))
    .register();

    check::Check::new(
        "KMI_074",
        "Ensure that kernel module `max6959` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("max6959"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("max6959", "Auxiliary displays."))
    .with_fix(&fix_disabled("max6959"))
    .register();

    check::Check::new(
        "KMI_075",
        "Ensure that kernel module `mcb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mcb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mcb", "MEN Chameleon."))
    .with_fix(&fix_disabled("mcb"))
    .register();

    check::Check::new(
        "KMI_076",
        "Ensure that kernel module `mcb_lpc` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mcb_lpc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mcb_lpc", "MEN Chameleon."))
    .with_fix(&fix_disabled("mcb_lpc"))
    .register();

    check::Check::new(
        "KMI_077",
        "Ensure that kernel module `mcb_pci` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mcb_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mcb_pci", "MEN Chameleon."))
    .with_fix(&fix_disabled("mcb_pci"))
    .register();

    check::Check::new(
        "KMI_078",
        "Ensure that kernel module `mchp_pci1xxxx_gp` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("mchp_pci1xxxx_gp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mchp_pci1xxxx_gp",
        "Misc PCIe appliances.",
    ))
    .with_fix(&fix_disabled("mchp_pci1xxxx_gp"))
    .register();

    check::Check::new(
        "KMI_079",
        "Ensure that kernel module `mchp_pci1xxxx_gpio` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("mchp_pci1xxxx_gpio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mchp_pci1xxxx_gpio",
        "Misc PCIe appliances.",
    ))
    .with_fix(&fix_disabled("mchp_pci1xxxx_gpio"))
    .register();

    check::Check::new(
        "KMI_080",
        "Ensure that kernel module `mchp_pci1xxxx_otpe2p` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("mchp_pci1xxxx_otpe2p"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mchp_pci1xxxx_otpe2p",
        "Misc PCIe appliances.",
    ))
    .with_fix(&fix_disabled("mchp_pci1xxxx_otpe2p"))
    .register();

    check::Check::new(
        "KMI_081",
        "Ensure that kernel module `microchip_spi` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("microchip_spi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("microchip_spi", "FPGA."))
    .with_fix(&fix_disabled("microchip_spi"))
    .register();

    check::Check::new(
        "KMI_082",
        "Ensure that kernel module `most_cdev` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("most_cdev"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("most_cdev", "MOST, automotive."))
    .with_fix(&fix_disabled("most_cdev"))
    .register();

    check::Check::new(
        "KMI_083",
        "Ensure that kernel module `most_core` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("most_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("most_core", "MOST, automotive."))
    .with_fix(&fix_disabled("most_core"))
    .register();

    check::Check::new(
        "KMI_084",
        "Ensure that kernel module `most_snd` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("most_snd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("most_snd", "MOST, automotive."))
    .with_fix(&fix_disabled("most_snd"))
    .register();

    check::Check::new(
        "KMI_085",
        "Ensure that kernel module `most_usb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("most_usb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("most_usb", "MOST, automotive."))
    .with_fix(&fix_disabled("most_usb"))
    .register();

    check::Check::new(
        "KMI_086",
        "Ensure that kernel module `nsm` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("nsm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("nsm", "Misc PCIe appliances."))
    .with_fix(&fix_disabled("nsm"))
    .register();

    check::Check::new(
        "KMI_087",
        "Ensure that kernel module `ntb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ntb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ntb", "Non-transparent bridge."))
    .with_fix(&fix_disabled("ntb"))
    .register();

    check::Check::new(
        "KMI_088",
        "Ensure that kernel module `ntb_msi_test` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ntb_msi_test"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ntb_msi_test",
        "Non-transparent bridge.",
    ))
    .with_fix(&fix_disabled("ntb_msi_test"))
    .register();

    check::Check::new(
        "KMI_089",
        "Ensure that kernel module `ntb_netdev` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ntb_netdev"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ntb_netdev",
        "Non-transparent bridge.",
    ))
    .with_fix(&fix_disabled("ntb_netdev"))
    .register();

    check::Check::new(
        "KMI_090",
        "Ensure that kernel module `ntb_perf` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ntb_perf"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ntb_perf", "Non-transparent bridge."))
    .with_fix(&fix_disabled("ntb_perf"))
    .register();

    check::Check::new(
        "KMI_091",
        "Ensure that kernel module `ntb_pingpong` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ntb_pingpong"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ntb_pingpong",
        "Non-transparent bridge.",
    ))
    .with_fix(&fix_disabled("ntb_pingpong"))
    .register();

    check::Check::new(
        "KMI_092",
        "Ensure that kernel module `ntb_tool` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ntb_tool"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ntb_tool", "Non-transparent bridge."))
    .with_fix(&fix_disabled("ntb_tool"))
    .register();

    check::Check::new(
        "KMI_093",
        "Ensure that kernel module `ntb_transport` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ntb_transport"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ntb_transport",
        "Non-transparent bridge.",
    ))
    .with_fix(&fix_disabled("ntb_transport"))
    .register();

    check::Check::new(
        "KMI_094",
        "Ensure that kernel module `panel` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("panel"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("panel", "Auxiliary displays."))
    .with_fix(&fix_disabled("panel"))
    .register();

    check::Check::new(
        "KMI_095",
        "Ensure that kernel module `parport` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("parport"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("parport", "Parallel port."))
    .with_fix(&fix_disabled("parport"))
    .register();

    check::Check::new(
        "KMI_096",
        "Ensure that kernel module `parport_cs` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("parport_cs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("parport_cs", "Parallel port."))
    .with_fix(&fix_disabled("parport_cs"))
    .register();

    check::Check::new(
        "KMI_097",
        "Ensure that kernel module `parport_pc` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("parport_pc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("parport_pc", "Parallel port."))
    .with_fix(&fix_disabled("parport_pc"))
    .register();

    check::Check::new(
        "KMI_098",
        "Ensure that kernel module `parport_serial` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("parport_serial"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("parport_serial", "Parallel port."))
    .with_fix(&fix_disabled("parport_serial"))
    .register();

    check::Check::new(
        "KMI_099",
        "Ensure that kernel module `pcmcia` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pcmcia"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pcmcia", "PCMCIA."))
    .with_fix(&fix_disabled("pcmcia"))
    .register();

    check::Check::new(
        "KMI_100",
        "Ensure that kernel module `pcmcia_core` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pcmcia_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pcmcia_core", "PCMCIA."))
    .with_fix(&fix_disabled("pcmcia_core"))
    .register();

    check::Check::new(
        "KMI_101",
        "Ensure that kernel module `pcmcia_rsrc` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pcmcia_rsrc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pcmcia_rsrc", "PCMCIA."))
    .with_fix(&fix_disabled("pcmcia_rsrc"))
    .register();

    check::Check::new(
        "KMI_102",
        "Ensure that kernel module `pd6729` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pd6729"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pd6729", "PCMCIA."))
    .with_fix(&fix_disabled("pd6729"))
    .register();

    check::Check::new(
        "KMI_103",
        "Ensure that kernel module `phantom` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("phantom"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("phantom", "Misc PCIe appliances."))
    .with_fix(&fix_disabled("phantom"))
    .register();

    check::Check::new(
        "KMI_104",
        "Ensure that kernel module `ppdev` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("ppdev"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ppdev", "Parallel port."))
    .with_fix(&fix_disabled("ppdev"))
    .register();

    check::Check::new(
        "KMI_105",
        "Ensure that kernel module `rio_cm` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rio_cm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("rio_cm", "RapidIO."))
    .with_fix(&fix_disabled("rio_cm"))
    .register();

    check::Check::new(
        "KMI_106",
        "Ensure that kernel module `rio_mport_cdev` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rio_mport_cdev"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("rio_mport_cdev", "RapidIO."))
    .with_fix(&fix_disabled("rio_mport_cdev"))
    .register();

    check::Check::new(
        "KMI_107",
        "Ensure that kernel module `rio_scan` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("rio_scan"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("rio_scan", "RapidIO."))
    .with_fix(&fix_disabled("rio_scan"))
    .register();

    check::Check::new(
        "KMI_108",
        "Ensure that kernel module `seg_led_gpio` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("seg_led_gpio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("seg_led_gpio", "Auxiliary displays."))
    .with_fix(&fix_disabled("seg_led_gpio"))
    .register();

    check::Check::new(
        "KMI_109",
        "Ensure that kernel module `sgi_w1` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("sgi_w1"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sgi_w1",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("sgi_w1"))
    .register();

    check::Check::new(
        "KMI_110",
        "Ensure that kernel module `siox_bus_gpio` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("siox_bus_gpio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("siox_bus_gpio", "SIOX."))
    .with_fix(&fix_disabled("siox_bus_gpio"))
    .register();

    check::Check::new(
        "KMI_111",
        "Ensure that kernel module `siox_core` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("siox_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("siox_core", "SIOX."))
    .with_fix(&fix_disabled("siox_core"))
    .register();

    check::Check::new(
        "KMI_112",
        "Ensure that kernel module `slimbus` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("slimbus"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("slimbus", "SLIMbus."))
    .with_fix(&fix_disabled("slimbus"))
    .register();

    check::Check::new(
        "KMI_113",
        "Ensure that kernel module `smpro_errmon` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("smpro_errmon"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "smpro_errmon",
        "Misc PCIe appliances.",
    ))
    .with_fix(&fix_disabled("smpro_errmon"))
    .register();

    check::Check::new(
        "KMI_114",
        "Ensure that kernel module `smpro_misc` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("smpro_misc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("smpro_misc", "Misc PCIe appliances."))
    .with_fix(&fix_disabled("smpro_misc"))
    .register();

    check::Check::new(
        "KMI_115",
        "Ensure that kernel module `stm_console` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("stm_console"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "stm_console",
        "Intel TH / STM tracing.",
    ))
    .with_fix(&fix_disabled("stm_console"))
    .register();

    check::Check::new(
        "KMI_116",
        "Ensure that kernel module `stm_core` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("stm_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("stm_core", "Intel TH / STM tracing."))
    .with_fix(&fix_disabled("stm_core"))
    .register();

    check::Check::new(
        "KMI_117",
        "Ensure that kernel module `stm_ftrace` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("stm_ftrace"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "stm_ftrace",
        "Intel TH / STM tracing.",
    ))
    .with_fix(&fix_disabled("stm_ftrace"))
    .register();

    check::Check::new(
        "KMI_118",
        "Ensure that kernel module `stm_heartbeat` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("stm_heartbeat"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "stm_heartbeat",
        "Intel TH / STM tracing.",
    ))
    .with_fix(&fix_disabled("stm_heartbeat"))
    .register();

    check::Check::new(
        "KMI_119",
        "Ensure that kernel module `stm_p_basic` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("stm_p_basic"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "stm_p_basic",
        "Intel TH / STM tracing.",
    ))
    .with_fix(&fix_disabled("stm_p_basic"))
    .register();

    check::Check::new(
        "KMI_120",
        "Ensure that kernel module `stm_p_sys_t` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("stm_p_sys_t"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "stm_p_sys_t",
        "Intel TH / STM tracing.",
    ))
    .with_fix(&fix_disabled("stm_p_sys_t"))
    .register();

    check::Check::new(
        "KMI_121",
        "Ensure that kernel module `tpci200` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("tpci200"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("tpci200", "IPACK."))
    .with_fix(&fix_disabled("tpci200"))
    .register();

    check::Check::new(
        "KMI_122",
        "Ensure that kernel module `tps6594_esm` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("tps6594_esm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tps6594_esm",
        "Misc PCIe appliances.",
    ))
    .with_fix(&fix_disabled("tps6594_esm"))
    .register();

    check::Check::new(
        "KMI_123",
        "Ensure that kernel module `tps6594_pfsm` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation", "conditional"],
        || modprobe::check_module_disabled("tps6594_pfsm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tps6594_pfsm",
        "Misc PCIe appliances.",
    ))
    .with_fix(&fix_disabled("tps6594_pfsm"))
    .register();

    check::Check::new(
        "KMI_124",
        "Ensure that kernel module `tsi721_mport` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("tsi721_mport"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("tsi721_mport", "RapidIO."))
    .with_fix(&fix_disabled("tsi721_mport"))
    .register();

    check::Check::new(
        "KMI_125",
        "Ensure that kernel module `uio` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("uio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uio",
        "UIO, DPDK/SPDK userspace drivers.",
    ))
    .with_fix(&fix_disabled("uio"))
    .register();

    check::Check::new(
        "KMI_126",
        "Ensure that kernel module `uio_aec` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("uio_aec"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uio_aec",
        "UIO, DPDK/SPDK userspace drivers.",
    ))
    .with_fix(&fix_disabled("uio_aec"))
    .register();

    check::Check::new(
        "KMI_127",
        "Ensure that kernel module `uio_cif` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("uio_cif"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uio_cif",
        "UIO, DPDK/SPDK userspace drivers.",
    ))
    .with_fix(&fix_disabled("uio_cif"))
    .register();

    check::Check::new(
        "KMI_128",
        "Ensure that kernel module `uio_dfl` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("uio_dfl"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uio_dfl",
        "UIO, DPDK/SPDK userspace drivers.",
    ))
    .with_fix(&fix_disabled("uio_dfl"))
    .register();

    check::Check::new(
        "KMI_129",
        "Ensure that kernel module `uio_dmem_genirq` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("uio_dmem_genirq"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uio_dmem_genirq",
        "UIO, DPDK/SPDK userspace drivers.",
    ))
    .with_fix(&fix_disabled("uio_dmem_genirq"))
    .register();

    check::Check::new(
        "KMI_130",
        "Ensure that kernel module `uio_hv_generic` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("uio_hv_generic"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uio_hv_generic",
        "UIO, DPDK/SPDK userspace drivers.",
    ))
    .with_fix(&fix_disabled("uio_hv_generic"))
    .register();

    check::Check::new(
        "KMI_131",
        "Ensure that kernel module `uio_mf624` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("uio_mf624"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uio_mf624",
        "UIO, DPDK/SPDK userspace drivers.",
    ))
    .with_fix(&fix_disabled("uio_mf624"))
    .register();

    check::Check::new(
        "KMI_132",
        "Ensure that kernel module `uio_netx` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("uio_netx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uio_netx",
        "UIO, DPDK/SPDK userspace drivers.",
    ))
    .with_fix(&fix_disabled("uio_netx"))
    .register();

    check::Check::new(
        "KMI_133",
        "Ensure that kernel module `uio_pci_generic` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("uio_pci_generic"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uio_pci_generic",
        "UIO, DPDK/SPDK userspace drivers.",
    ))
    .with_fix(&fix_disabled("uio_pci_generic"))
    .register();

    check::Check::new(
        "KMI_134",
        "Ensure that kernel module `uio_pci_generic_sva` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("uio_pci_generic_sva"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uio_pci_generic_sva",
        "UIO, DPDK/SPDK userspace drivers.",
    ))
    .with_fix(&fix_disabled("uio_pci_generic_sva"))
    .register();

    check::Check::new(
        "KMI_135",
        "Ensure that kernel module `uio_pdrv_genirq` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("uio_pdrv_genirq"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uio_pdrv_genirq",
        "UIO, DPDK/SPDK userspace drivers.",
    ))
    .with_fix(&fix_disabled("uio_pdrv_genirq"))
    .register();

    check::Check::new(
        "KMI_136",
        "Ensure that kernel module `uio_sercos3` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("uio_sercos3"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "uio_sercos3",
        "UIO, DPDK/SPDK userspace drivers.",
    ))
    .with_fix(&fix_disabled("uio_sercos3"))
    .register();

    check::Check::new(
        "KMI_137",
        "Ensure that kernel module `vfio` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vfio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vfio", "VFIO."))
    .with_fix(&fix_disabled("vfio"))
    .register();

    check::Check::new(
        "KMI_138",
        "Ensure that kernel module `vfio_iommu_type1` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vfio_iommu_type1"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vfio_iommu_type1", "VFIO."))
    .with_fix(&fix_disabled("vfio_iommu_type1"))
    .register();

    check::Check::new(
        "KMI_139",
        "Ensure that kernel module `vfio_pci` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vfio_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vfio_pci", "VFIO."))
    .with_fix(&fix_disabled("vfio_pci"))
    .register();

    check::Check::new(
        "KMI_140",
        "Ensure that kernel module `vmk80xx` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("vmk80xx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vmk80xx",
        "Data acquisition, comedi.",
    ))
    .with_fix(&fix_disabled("vmk80xx"))
    .register();

    check::Check::new(
        "KMI_141",
        "Ensure that kernel module `w1_ds2405` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds2405"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds2405",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds2405"))
    .register();

    check::Check::new(
        "KMI_142",
        "Ensure that kernel module `w1_ds2406` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds2406"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds2406",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds2406"))
    .register();

    check::Check::new(
        "KMI_143",
        "Ensure that kernel module `w1_ds2408` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds2408"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds2408",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds2408"))
    .register();

    check::Check::new(
        "KMI_144",
        "Ensure that kernel module `w1_ds2413` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds2413"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds2413",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds2413"))
    .register();

    check::Check::new(
        "KMI_145",
        "Ensure that kernel module `w1_ds2423` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds2423"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds2423",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds2423"))
    .register();

    check::Check::new(
        "KMI_146",
        "Ensure that kernel module `w1_ds2430` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds2430"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds2430",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds2430"))
    .register();

    check::Check::new(
        "KMI_147",
        "Ensure that kernel module `w1_ds2431` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds2431"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds2431",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds2431"))
    .register();

    check::Check::new(
        "KMI_148",
        "Ensure that kernel module `w1_ds2433` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds2433"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds2433",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds2433"))
    .register();

    check::Check::new(
        "KMI_149",
        "Ensure that kernel module `w1_ds2438` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds2438"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds2438",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds2438"))
    .register();

    check::Check::new(
        "KMI_150",
        "Ensure that kernel module `w1_ds250x` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds250x"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds250x",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds250x"))
    .register();

    check::Check::new(
        "KMI_151",
        "Ensure that kernel module `w1_ds2780` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds2780"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds2780",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds2780"))
    .register();

    check::Check::new(
        "KMI_152",
        "Ensure that kernel module `w1_ds2781` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds2781"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds2781",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds2781"))
    .register();

    check::Check::new(
        "KMI_153",
        "Ensure that kernel module `w1_ds2805` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds2805"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds2805",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds2805"))
    .register();

    check::Check::new(
        "KMI_154",
        "Ensure that kernel module `w1_ds28e04` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds28e04"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds28e04",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds28e04"))
    .register();

    check::Check::new(
        "KMI_155",
        "Ensure that kernel module `w1_ds28e17` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_ds28e17"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_ds28e17",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_ds28e17"))
    .register();

    check::Check::new(
        "KMI_156",
        "Ensure that kernel module `w1_gpio` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_gpio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_gpio",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_gpio"))
    .register();

    check::Check::new(
        "KMI_157",
        "Ensure that kernel module `w1_smem` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_smem"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_smem",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_smem"))
    .register();

    check::Check::new(
        "KMI_158",
        "Ensure that kernel module `w1_therm` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_therm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_therm",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_therm"))
    .register();

    check::Check::new(
        "KMI_159",
        "Ensure that kernel module `w1_uart` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("w1_uart"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "w1_uart",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("w1_uart"))
    .register();

    check::Check::new(
        "KMI_160",
        "Ensure that kernel module `wire` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("wire"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "wire",
        "1-Wire bus / slave-device driver.",
    ))
    .with_fix(&fix_disabled("wire"))
    .register();

    check::Check::new(
        "KMI_161",
        "Ensure that kernel module `xilinx_core` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("xilinx_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xilinx_core", "FPGA."))
    .with_fix(&fix_disabled("xilinx_core"))
    .register();

    check::Check::new(
        "KMI_162",
        "Ensure that kernel module `xilinx_pr_decoupler` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("xilinx_pr_decoupler"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xilinx_pr_decoupler", "FPGA."))
    .with_fix(&fix_disabled("xilinx_pr_decoupler"))
    .register();

    check::Check::new(
        "KMI_163",
        "Ensure that kernel module `xilinx_selectmap` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("xilinx_selectmap"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xilinx_selectmap", "FPGA."))
    .with_fix(&fix_disabled("xilinx_selectmap"))
    .register();

    check::Check::new(
        "KMI_164",
        "Ensure that kernel module `xilinx_spi` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("xilinx_spi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xilinx_spi", "FPGA."))
    .with_fix(&fix_disabled("xilinx_spi"))
    .register();

    check::Check::new(
        "KMI_165",
        "Ensure that kernel module `xillybus_class` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("xillybus_class"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xillybus_class", "Xillybus."))
    .with_fix(&fix_disabled("xillybus_class"))
    .register();

    check::Check::new(
        "KMI_166",
        "Ensure that kernel module `xillybus_core` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("xillybus_core"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xillybus_core", "Xillybus."))
    .with_fix(&fix_disabled("xillybus_core"))
    .register();

    check::Check::new(
        "KMI_167",
        "Ensure that kernel module `xillybus_pcie` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("xillybus_pcie"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xillybus_pcie", "Xillybus."))
    .with_fix(&fix_disabled("xillybus_pcie"))
    .register();

    check::Check::new(
        "KMI_168",
        "Ensure that kernel module `xillyusb` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("xillyusb"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xillyusb", "Xillybus."))
    .with_fix(&fix_disabled("xillyusb"))
    .register();

    check::Check::new(
        "KMI_169",
        "Ensure that kernel module `yenta_socket` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("yenta_socket"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("yenta_socket", "PCMCIA."))
    .with_fix(&fix_disabled("yenta_socket"))
    .register();

    // virtualization-platform-specific modules (KMV_)
    check::Check::new(
        "KMV_001",
        "Ensure that kernel module `acrn` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("acrn"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("acrn", "Guest helpers."))
    .with_fix(&fix_disabled("acrn"))
    .register();

    check::Check::new(
        "KMV_002",
        "Ensure that kernel module `efi_secret` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("efi_secret"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "efi_secret",
        "Confidential computing guests.",
    ))
    .with_fix(&fix_disabled("efi_secret"))
    .register();

    check::Check::new(
        "KMV_003",
        "Ensure that kernel module `hv_balloon` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("hv_balloon"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hv_balloon", "Hyper-V."))
    .with_fix(&fix_disabled("hv_balloon"))
    .register();

    check::Check::new(
        "KMV_004",
        "Ensure that kernel module `hv_netvsc` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("hv_netvsc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hv_netvsc", "Hyper-V."))
    .with_fix(&fix_disabled("hv_netvsc"))
    .register();

    check::Check::new(
        "KMV_005",
        "Ensure that kernel module `hv_sock` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("hv_sock"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hv_sock", "Hyper-V."))
    .with_fix(&fix_disabled("hv_sock"))
    .register();

    check::Check::new(
        "KMV_006",
        "Ensure that kernel module `hv_storvsc` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("hv_storvsc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hv_storvsc", "Hyper-V."))
    .with_fix(&fix_disabled("hv_storvsc"))
    .register();

    check::Check::new(
        "KMV_007",
        "Ensure that kernel module `hv_utils` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("hv_utils"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hv_utils", "Hyper-V."))
    .with_fix(&fix_disabled("hv_utils"))
    .register();

    check::Check::new(
        "KMV_008",
        "Ensure that kernel module `hv_vmbus` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("hv_vmbus"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("hv_vmbus", "Hyper-V."))
    .with_fix(&fix_disabled("hv_vmbus"))
    .register();

    check::Check::new(
        "KMV_009",
        "Ensure that kernel module `kvm` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("kvm"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("kvm", "Host-side."))
    .with_fix(&fix_disabled("kvm"))
    .register();

    check::Check::new(
        "KMV_010",
        "Ensure that kernel module `kvm_amd` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("kvm_amd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("kvm_amd", "Host-side."))
    .with_fix(&fix_disabled("kvm_amd"))
    .register();

    check::Check::new(
        "KMV_011",
        "Ensure that kernel module `kvm_intel` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("kvm_intel"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("kvm_intel", "Host-side."))
    .with_fix(&fix_disabled("kvm_intel"))
    .register();

    check::Check::new(
        "KMV_012",
        "Ensure that kernel module `mshv_root` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("mshv_root"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("mshv_root", "Hyper-V."))
    .with_fix(&fix_disabled("mshv_root"))
    .register();

    check::Check::new(
        "KMV_013",
        "Ensure that kernel module `nitro_enclaves` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("nitro_enclaves"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "nitro_enclaves",
        "Confidential computing guests.",
    ))
    .with_fix(&fix_disabled("nitro_enclaves"))
    .register();

    check::Check::new(
        "KMV_014",
        "Ensure that kernel module `pvcalls_front` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("pvcalls_front"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pvcalls_front", "Xen."))
    .with_fix(&fix_disabled("pvcalls_front"))
    .register();

    check::Check::new(
        "KMV_015",
        "Ensure that kernel module `pvpanic` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("pvpanic"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pvpanic", "Guest helpers."))
    .with_fix(&fix_disabled("pvpanic"))
    .register();

    check::Check::new(
        "KMV_016",
        "Ensure that kernel module `pvpanic_mmio` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("pvpanic_mmio"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("pvpanic_mmio", "Guest helpers."))
    .with_fix(&fix_disabled("pvpanic_mmio"))
    .register();

    check::Check::new(
        "KMV_017",
        "Ensure that kernel module `sev_guest` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("sev_guest"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "sev_guest",
        "Confidential computing guests.",
    ))
    .with_fix(&fix_disabled("sev_guest"))
    .register();

    check::Check::new(
        "KMV_018",
        "Ensure that kernel module `snd_xen_front` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("snd_xen_front"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("snd_xen_front", "Xen."))
    .with_fix(&fix_disabled("snd_xen_front"))
    .register();

    check::Check::new(
        "KMV_019",
        "Ensure that kernel module `tdx_guest` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("tdx_guest"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tdx_guest",
        "Confidential computing guests.",
    ))
    .with_fix(&fix_disabled("tdx_guest"))
    .register();

    check::Check::new(
        "KMV_020",
        "Ensure that kernel module `tsm_report` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("tsm_report"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tsm_report",
        "Confidential computing guests.",
    ))
    .with_fix(&fix_disabled("tsm_report"))
    .register();

    check::Check::new(
        "KMV_021",
        "Ensure that kernel module `vboxguest` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vboxguest"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vboxguest", "VirtualBox."))
    .with_fix(&fix_disabled("vboxguest"))
    .register();

    check::Check::new(
        "KMV_022",
        "Ensure that kernel module `vboxvideo` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vboxvideo"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vboxvideo", "VirtualBox."))
    .with_fix(&fix_disabled("vboxvideo"))
    .register();

    check::Check::new(
        "KMV_023",
        "Ensure that kernel module `vhost` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vhost"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vhost", "Host-side."))
    .with_fix(&fix_disabled("vhost"))
    .register();

    check::Check::new(
        "KMV_024",
        "Ensure that kernel module `vhost_net` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vhost_net"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vhost_net", "Host-side."))
    .with_fix(&fix_disabled("vhost_net"))
    .register();

    check::Check::new(
        "KMV_025",
        "Ensure that kernel module `vhost_scsi` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vhost_scsi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vhost_scsi", "Host-side."))
    .with_fix(&fix_disabled("vhost_scsi"))
    .register();

    check::Check::new(
        "KMV_026",
        "Ensure that kernel module `vhost_vsock` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vhost_vsock"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vhost_vsock", "Vsock."))
    .with_fix(&fix_disabled("vhost_vsock"))
    .register();

    check::Check::new(
        "KMV_027",
        "Ensure that kernel module `vmgenid` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vmgenid"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vmgenid", "Guest helpers."))
    .with_fix(&fix_disabled("vmgenid"))
    .register();

    check::Check::new(
        "KMV_028",
        "Ensure that kernel module `vmw_balloon` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vmw_balloon"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vmw_balloon", "VMware."))
    .with_fix(&fix_disabled("vmw_balloon"))
    .register();

    check::Check::new(
        "KMV_029",
        "Ensure that kernel module `vmw_vmci` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vmw_vmci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vmw_vmci", "VMware."))
    .with_fix(&fix_disabled("vmw_vmci"))
    .register();

    check::Check::new(
        "KMV_030",
        "Ensure that kernel module `vmw_vsock_virtio_transport` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vmw_vsock_virtio_transport"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vmw_vsock_virtio_transport",
        "Vsock.",
    ))
    .with_fix(&fix_disabled("vmw_vsock_virtio_transport"))
    .register();

    check::Check::new(
        "KMV_031",
        "Ensure that kernel module `vmw_vsock_virtio_transport_common` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vmw_vsock_virtio_transport_common"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "vmw_vsock_virtio_transport_common",
        "Vsock.",
    ))
    .with_fix(&fix_disabled("vmw_vsock_virtio_transport_common"))
    .register();

    check::Check::new(
        "KMV_032",
        "Ensure that kernel module `vmw_vsock_vmci_transport` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vmw_vsock_vmci_transport"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vmw_vsock_vmci_transport", "VMware."))
    .with_fix(&fix_disabled("vmw_vsock_vmci_transport"))
    .register();

    check::Check::new(
        "KMV_033",
        "Ensure that kernel module `vmwgfx` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vmwgfx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vmwgfx", "VMware."))
    .with_fix(&fix_disabled("vmwgfx"))
    .register();

    check::Check::new(
        "KMV_034",
        "Ensure that kernel module `vsock` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("vsock"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("vsock", "Vsock."))
    .with_fix(&fix_disabled("vsock"))
    .register();

    check::Check::new(
        "KMV_035",
        "Ensure that kernel module `xen_blkback` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xen_blkback"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xen_blkback", "Xen."))
    .with_fix(&fix_disabled("xen_blkback"))
    .register();

    check::Check::new(
        "KMV_036",
        "Ensure that kernel module `xen_evtchn` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xen_evtchn"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xen_evtchn", "Xen."))
    .with_fix(&fix_disabled("xen_evtchn"))
    .register();

    check::Check::new(
        "KMV_037",
        "Ensure that kernel module `xen_fbfront` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xen_fbfront"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xen_fbfront", "Xen."))
    .with_fix(&fix_disabled("xen_fbfront"))
    .register();

    check::Check::new(
        "KMV_038",
        "Ensure that kernel module `xen_front_pgdir_shbuf` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xen_front_pgdir_shbuf"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xen_front_pgdir_shbuf", "Xen."))
    .with_fix(&fix_disabled("xen_front_pgdir_shbuf"))
    .register();

    check::Check::new(
        "KMV_039",
        "Ensure that kernel module `xen_gntalloc` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xen_gntalloc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xen_gntalloc", "Xen."))
    .with_fix(&fix_disabled("xen_gntalloc"))
    .register();

    check::Check::new(
        "KMV_040",
        "Ensure that kernel module `xen_gntdev` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xen_gntdev"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xen_gntdev", "Xen."))
    .with_fix(&fix_disabled("xen_gntdev"))
    .register();

    check::Check::new(
        "KMV_041",
        "Ensure that kernel module `xen_hcd` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xen_hcd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xen_hcd", "Xen."))
    .with_fix(&fix_disabled("xen_hcd"))
    .register();

    check::Check::new(
        "KMV_042",
        "Ensure that kernel module `xen_netback` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xen_netback"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xen_netback", "Xen."))
    .with_fix(&fix_disabled("xen_netback"))
    .register();

    check::Check::new(
        "KMV_043",
        "Ensure that kernel module `xen_pciback` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xen_pciback"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xen_pciback", "Xen."))
    .with_fix(&fix_disabled("xen_pciback"))
    .register();

    check::Check::new(
        "KMV_044",
        "Ensure that kernel module `xen_privcmd` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xen_privcmd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xen_privcmd", "Xen."))
    .with_fix(&fix_disabled("xen_privcmd"))
    .register();

    check::Check::new(
        "KMV_045",
        "Ensure that kernel module `xen_scsiback` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xen_scsiback"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xen_scsiback", "Xen."))
    .with_fix(&fix_disabled("xen_scsiback"))
    .register();

    check::Check::new(
        "KMV_046",
        "Ensure that kernel module `xen_tpmfront` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xen_tpmfront"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xen_tpmfront", "Xen."))
    .with_fix(&fix_disabled("xen_tpmfront"))
    .register();

    check::Check::new(
        "KMV_047",
        "Ensure that kernel module `xen_wdt` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xen_wdt"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xen_wdt", "Xen."))
    .with_fix(&fix_disabled("xen_wdt"))
    .register();

    check::Check::new(
        "KMV_048",
        "Ensure that kernel module `xenfs` is disabled",
        Severity::Medium,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("xenfs"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("xenfs", "Xen."))
    .with_fix(&fix_disabled("xenfs"))
    .register();

    // legacy NICs and replaced drivers (KML_)
    check::Check::new(
        "KML_001",
        "Ensure that kernel module `asus_acpi` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("asus_acpi"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "asus_acpi",
        "Asus_wmi, removed upstream.",
    ))
    .with_fix(&fix_disabled("asus_acpi"))
    .register();

    check::Check::new(
        "KML_002",
        "Ensure that kernel module `ath_pci` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ath_pci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ath_pci", "Ath5k/ath9k."))
    .with_fix(&fix_disabled("ath_pci"))
    .register();

    check::Check::new(
        "KML_003",
        "Ensure that kernel module `bcm43xx` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("bcm43xx"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "bcm43xx",
        "B43/brcm*, removed upstream.",
    ))
    .with_fix(&fix_disabled("bcm43xx"))
    .register();

    check::Check::new(
        "KML_004",
        "Ensure that kernel module `de4x5` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("de4x5"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("de4x5", "Tulip, removed upstream."))
    .with_fix(&fix_disabled("de4x5"))
    .register();

    check::Check::new(
        "KML_005",
        "Ensure that kernel module `eepro100` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("eepro100"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("eepro100", "E100, removed upstream."))
    .with_fix(&fix_disabled("eepro100"))
    .register();

    check::Check::new(
        "KML_006",
        "Ensure that kernel module `eth1394` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("eth1394"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "eth1394",
        "Firewire_net, removed upstream.",
    ))
    .with_fix(&fix_disabled("eth1394"))
    .register();

    check::Check::new(
        "KML_007",
        "Ensure that kernel module `prism54` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("prism54"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("prism54", "P54, removed upstream."))
    .with_fix(&fix_disabled("prism54"))
    .register();

    // miscellaneous (KMS_)
    check::Check::new(
        "KMS_001",
        "Ensure that kernel module `apds9802als` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("apds9802als"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "apds9802als",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("apds9802als"))
    .register();

    check::Check::new(
        "KMS_002",
        "Ensure that kernel module `apds990x` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("apds990x"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "apds990x",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("apds990x"))
    .register();

    check::Check::new(
        "KMS_003",
        "Ensure that kernel module `at24` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("at24"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "at24",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("at24"))
    .register();

    check::Check::new(
        "KMS_004",
        "Ensure that kernel module `at25` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("at25"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "at25",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("at25"))
    .register();

    check::Check::new(
        "KMS_005",
        "Ensure that kernel module `bh1770glc` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("bh1770glc"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "bh1770glc",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("bh1770glc"))
    .register();

    check::Check::new(
        "KMS_006",
        "Ensure that kernel module `brd` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("brd"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("brd", "RAM block device."))
    .with_fix(&fix_disabled("brd"))
    .register();

    check::Check::new(
        "KMS_007",
        "Ensure that kernel module `ds1682` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("ds1682"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ds1682",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("ds1682"))
    .register();

    check::Check::new(
        "KMS_008",
        "Ensure that kernel module `ee1004` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("ee1004"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ee1004",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("ee1004"))
    .register();

    check::Check::new(
        "KMS_009",
        "Ensure that kernel module `fwctl` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("fwctl"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "fwctl",
        "Device firmware control interface, new subsystem.",
    ))
    .with_fix(&fix_disabled("fwctl"))
    .register();

    check::Check::new(
        "KMS_010",
        "Ensure that kernel module `hmc6352` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("hmc6352"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "hmc6352",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("hmc6352"))
    .register();

    check::Check::new(
        "KMS_011",
        "Ensure that kernel module `ics932s401` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("ics932s401"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ics932s401",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("ics932s401"))
    .register();

    check::Check::new(
        "KMS_012",
        "Ensure that kernel module `isl29003` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("isl29003"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "isl29003",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("isl29003"))
    .register();

    check::Check::new(
        "KMS_013",
        "Ensure that kernel module `isl29020` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("isl29020"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "isl29020",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("isl29020"))
    .register();

    check::Check::new(
        "KMS_014",
        "Ensure that kernel module `ks8995` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("ks8995"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ks8995",
        "SPI ethernet/switch chips, embedded.",
    ))
    .with_fix(&fix_disabled("ks8995"))
    .register();

    check::Check::new(
        "KMS_015",
        "Ensure that kernel module `lan9252` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("lan9252"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "lan9252",
        "SPI ethernet/switch chips, embedded.",
    ))
    .with_fix(&fix_disabled("lan9252"))
    .register();

    check::Check::new(
        "KMS_016",
        "Ensure that kernel module `lis3lv02d` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("lis3lv02d"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "lis3lv02d",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("lis3lv02d"))
    .register();

    check::Check::new(
        "KMS_017",
        "Ensure that kernel module `m24lr` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("m24lr"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "m24lr",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("m24lr"))
    .register();

    check::Check::new(
        "KMS_018",
        "Ensure that kernel module `max6875` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("max6875"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "max6875",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("max6875"))
    .register();

    check::Check::new(
        "KMS_019",
        "Ensure that kernel module `mcp251x` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mcp251x"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mcp251x",
        "SPI ethernet/switch chips, embedded.",
    ))
    .with_fix(&fix_disabled("mcp251x"))
    .register();

    check::Check::new(
        "KMS_020",
        "Ensure that kernel module `mctp` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("mctp"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mctp",
        "Management Component Transport, BMC traffic.",
    ))
    .with_fix(&fix_disabled("mctp"))
    .register();

    check::Check::new(
        "KMS_021",
        "Ensure that kernel module `microcode` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("microcode"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "microcode",
        "Late CPU microcode loader. Deprecated, modern systems load microcode early from initrd.",
    ))
    .with_fix(&fix_disabled("microcode"))
    .register();

    check::Check::new(
        "KMS_022",
        "Ensure that kernel module `mlx5_fwctl` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("mlx5_fwctl"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "mlx5_fwctl",
        "Device firmware control interface, new subsystem.",
    ))
    .with_fix(&fix_disabled("mlx5_fwctl"))
    .register();

    check::Check::new(
        "KMS_023",
        "Ensure that kernel module `ntsync` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("ntsync"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "ntsync",
        "Wine NT-sync primitive. Gaming workstations may want it, servers never.",
    ))
    .with_fix(&fix_disabled("ntsync"))
    .register();

    check::Check::new(
        "KMS_024",
        "Ensure that kernel module `pds_fwctl` is disabled",
        Severity::Low,
        vec!["module", "server", "workstation"],
        || modprobe::check_module_disabled("pds_fwctl"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "pds_fwctl",
        "Device firmware control interface, new subsystem.",
    ))
    .with_fix(&fix_disabled("pds_fwctl"))
    .register();

    check::Check::new(
        "KMS_025",
        "Ensure that kernel module `peci` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("peci"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("peci", "Intel PECI monitoring."))
    .with_fix(&fix_disabled("peci"))
    .register();

    check::Check::new(
        "KMS_026",
        "Ensure that kernel module `peci_cpu` is disabled",
        Severity::Low,
        vec!["module", "server", "conditional"],
        || modprobe::check_module_disabled("peci_cpu"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("peci_cpu", "Intel PECI monitoring."))
    .with_fix(&fix_disabled("peci_cpu"))
    .register();

    check::Check::new(
        "KMS_027",
        "Ensure that kernel module `tsl2550` is disabled",
        Severity::Low,
        vec!["module", "server"],
        || modprobe::check_module_disabled("tsl2550"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled(
        "tsl2550",
        "Misc i2c sensors/EEPROMs, low risk, disable on servers as a batch.",
    ))
    .with_fix(&fix_disabled("tsl2550"))
    .register();

    check::Check::new(
        "KMS_028",
        "Ensure that kernel module `ublk_drv` is disabled",
        Severity::Low,
        vec!["module", "conditional"],
        || modprobe::check_module_disabled("ublk_drv"),
        vec![modprobe::init_modprobe],
    )
    .with_description(&description_disabled("ublk_drv", "Userspace block driver."))
    .with_fix(&fix_disabled("ublk_drv"))
    .register();
}
