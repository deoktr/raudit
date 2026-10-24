#!/bin/bash
# Phase 1 of the rAudit "hardened" e2e profile.
#
# Only persistent configuration is applied here (files, fstab, bootloader).
# The VM is rebooted afterwards so the kernel command line takes effect, then
# hardened-post-setup.sh applies the runtime-only hardening (module unloading,
# audit rule loading, sudo lockdown).
#
# NOTE: sudo must keep working until the post-setup phase, so the sudoers
# lockdown and the removal of the cloud-init NOPASSWD rule happen over there.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
    openssh-server \
    sudo \
    iptables \
    apparmor \
    apparmor-utils \
    grub2-common \
    procps \
    auditd \
    chrony \
    acl \
    apt-utils \
    kmod \
    libpam-pwquality \
    nginx

# modules that are already loaded are removed in the post-setup phase
MODULES_BLACKLIST="
    snd_intel8x0 sr_mod snd_intel8x0m cdrom amd76x_edac ath_pci evbug
    snd_aw2 snd_pcsp usbkbd usbmouse
"

MODULES_DISABLED="
    cfg80211 intel_agp ip_tables mousedev psmouse tls virtio_balloon
    virtio_console af_802154 appletalk dccp netrom rose n_hdlc ax25 x25
    decnet econet ipx psnap p8023 p8022 eepro100 eth1394 atm ueagle_atm
    usbatm xusbatm c_can c_can_pci c_can_platform can can_bcm can_dev
    can_gw can_isotp can_raw can_j1939 can327 ifi_canfd janz_ican3 m_can
    m_can_pci m_can_platform phy_can_transceiver slcan ucan vxcan vcan
    tipc tipc_diag rds rds_rdma rds_tcp sctp sctp_diag adfs affs bfs
    befs cramfs efs erofs exofs freevxfs f2fs hfs hfsplus squashfs hpfs
    jfs jffs2 minix nilfs2 ntfs omfs qnx4 qnx6 sysv ufs udf reiserfs
    ksmbd gfs2 cifs cifs_arc4 cifs_md4 nfs nfs_acl
    nfs_layout_nfsv41_files nfs_layout_flexfiles nfsd nfsv2 nfsv3 nfsv4
    usb_storage vivid floppy joydev bluetooth bluetooth_6lowpan bt3c_cs
    btbcm btintel btmrvl btmrvl_sdio btmtk btmtksdio btmtkuart btnxpuart
    btqca btrsi btrtl btsdio btusb virtio_bt dv1394 firewire_core
    firewire_ohci firewire_net firewire_sbp2 ohci1394 raw1394 sbp2
    video1394 garmin_gps gnss gnss_mtk gnss_serial gnss_sirf gnss_ubx
    gnss_usb pmt_class pmt_crashlog pmt_telemetry intel_wmi_thunderbolt
    thunderbolt thunderbolt_net hamradio aty128fb atyfb cirrusfb
    cyber2000fb cyblafb gx1fb hgafb i810fb intelfb kyrofb lxfb
    matroxfb_bases neofb nvidiafb pm2fb radeonfb rivafb s1d13xxxfb
    savagefb sisfb sstfb tdfxfb tridentfb vesafb vfb viafb vt8623fb
    udlfb asus_acpi bcm43xx de4x5 prism54 uvcvideo arkfb matroxfb_base
    mb862xxfb pm3fb s3fb snd_mixer_oss acquirewdt advantech_ec_wdt
    advantechwdt alim1535_wdt cadence_wdt cpu5wdt da9055_wdt da9063_wdt
    dw_wdt eurotechwdt f71808e_wdt i6300esb iTCO_wdt ibmasr it8712f_wdt
    kempld_wdt max63xx_wdt mena21_wdt menz69_wdt ni903x_wdt nv_tco
    pc87413_wdt pcwd_usb rave_sp_wdt sbc60xxwdt sbc_fitpc2_wdt
    sch311x_wdt smsc37b787_wdt sp5100_tco twl4030_wdt w83627hf_wdt
    w83977f_wdt wdat_wdt wm831x_wdt xen_wdt snd_pcm_oss alim7101_wdt
    da9052_wdt da9062_wdt ebc_c384_wdt exar_wdt hpwdt
    iTCO_vendor_support ib700wdt ie6xx_wdt it87_wdt machzwd mei_wdt
    menf21bmc_wdt mlx_wdt nic7018_wdt of_xilinx_wdt pcwd_pci
    pretimeout_panic retu_wdt sbc_epx_c3 sc1200wdt simatic_ipc_wdt
    softdog tqmx86_wdt via_wdt w83877f_wdt wafer5823wdt wdt_pci
    wm8350_wdt ziirave_wdt pcspkr ac97 ac97_codec ac97_plugin_ad1980
    ad1848 ad1889 adlib_card aedsp16 ali5455 btaudio cmpci cs4232 cs4281
    cs461x cs46xx emu10k1 es1370 es1371 esssolo1 forte gus i810_audio
    kahlua mad16 maestro maestro3 maui mpu401 nm256_audio opl3 opl3sa
    opl3sa2 pas2 pss rme96xx sb sb_lib sgalaxy sonicvibes sound sscape
    trident trix uart401 uart6850 via82cxxx_audio v_midi wavefront
    ymfpci ac97_plugin_wm97xx ad1816 audio awe_wave dmasound_core
    dmasound_pmac harmony sequencer soundcard usb_midi microcode
"

{
    for m in ${MODULES_BLACKLIST}; do
        echo "blacklist ${m}"
    done
} >/etc/modprobe.d/99-hardened-blacklist.conf

{
    for m in ${MODULES_DISABLED}; do
        echo "install ${m} /bin/true"
    done
} >/etc/modprobe.d/99-hardened-disabled.conf

chmod 0644 /etc/modprobe.d/99-hardened-blacklist.conf /etc/modprobe.d/99-hardened-disabled.conf

cat >/etc/sysctl.d/zz-hardened-kernel.conf <<'SYSCTL_EOF'
kernel.pid_max = 65536
kernel.kptr_restrict = 2
kernel.ftrace_enabled = 0
kernel.print-fatal-signals = 0
kernel.printk_devkmsg = off
kernel.stack_tracer_enabled = 0
kernel.ftrace_dump_on_oops = 0
kernel.tracepoint_printk = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.printk = 3	3	3	3
kernel.perf_cpu_time_max_percent = 1
kernel.perf_event_max_sample_rate = 1
kernel.perf_event_paranoid = 3
kernel.sysrq = 0
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
kernel.unprivileged_userns_clone = 0
kernel.apparmor_restrict_unprivileged_userns = 1
kernel.apparmor_restrict_unprivileged_unconfined = 1
net.core.bpf_jit_harden = 2
net.core.bpf_jit_enable = 0
net.core.bpf_jit_kallsyms = 0
kernel.panic_on_oops = 1
kernel.panic = -1
kernel.panic_on_warn = 1
kernel.unknown_nmi_panic = 1
kernel.panic_on_unrecovered_nmi = 1
kernel.panic_on_io_nmi = 1
kernel.hardlockup_panic = 1
kernel.panic_on_rcu_stall = 1
kernel.nmi_watchdog = 1
kernel.watchdog = 1
kernel.yama.ptrace_scope = 3
kernel.io_uring_disabled = 2
kernel.core_pattern = |/bin/false
kernel.core_uses_pid = 1
kernel.ctrl-alt-del = 0
kernel.shm_rmid_forced = 1
vm.unprivileged_userfaultfd = 0
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
vm.mmap_min_addr = 65536
vm.memfd_noexec = 2
vm.legacy_va_layout = 0
vm.oom_dump_tasks = 0
dev.tty.ldisc_autoload = 0
dev.tty.legacy_tiocsti = 0
dev.hpet.max-user-freq = 64
vm.max_map_count = 1048576
vm.swappiness = 1
kernel.oops_limit = 100
kernel.warn_limit = 100
user.max_user_namespaces = 31231
abi.vsyscall32 = 0
SYSCTL_EOF

cat >/etc/sysctl.d/zz-hardened-fs.conf <<'SYSCTL_EOF'
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.binfmt_misc.status = 0
fs.verity.require_signatures = 1
SYSCTL_EOF

cat >/etc/sysctl.d/zz-hardened-ipv4.conf <<'SYSCTL_EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089
net.ipv4.icmp_msgs_per_sec = 1000
net.ipv4.icmp_msgs_burst = 50
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_local = 0
net.ipv4.conf.default.accept_local = 0
net.ipv4.conf.all.shared_media = 0
net.ipv4.conf.default.shared_media = 0
net.ipv4.conf.all.arp_filter = 1
net.ipv4.conf.default.arp_filter = 1
net.ipv4.conf.all.arp_ignore = 2
net.ipv4.conf.default.arp_ignore = 2
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.arp_accept = 0
net.ipv4.conf.default.arp_accept = 0
net.ipv4.conf.all.drop_gratuitous_arp = 1
net.ipv4.conf.default.drop_gratuitous_arp = 1
net.ipv4.conf.all.route_localnet = 0
net.ipv4.conf.default.route_localnet = 0
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.conf.default.proxy_arp = 0
net.ipv4.conf.all.proxy_arp_pvlan = 0
net.ipv4.conf.default.proxy_arp_pvlan = 0
net.ipv4.conf.all.bc_forwarding = 0
net.ipv4.conf.default.bc_forwarding = 0
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.default.bootp_relay = 0
net.ipv4.conf.all.disable_policy = 0
net.ipv4.conf.default.disable_policy = 0
net.ipv4.conf.all.disable_xfrm = 0
net.ipv4.conf.default.disable_xfrm = 0
net.ipv4.conf.all.drop_unicast_in_l2_multicast = 1
net.ipv4.conf.default.drop_unicast_in_l2_multicast = 1
net.ipv4.ip_local_port_range = 32768	65535
net.ipv4.ping_group_range = 1	0
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_fastopen = 0
net.ipv4.ipfrag_time = 15
SYSCTL_EOF

cat >/etc/sysctl.d/zz-hardened-ipv6.conf <<'SYSCTL_EOF'
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.router_solicitations = 0
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.all.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.all.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.all.accept_ra_from_local = 0
net.ipv6.conf.default.accept_ra_from_local = 0
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.all.max_addresses = 1
net.ipv6.conf.default.max_addresses = 1
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.all.addr_gen_mode = 2
net.ipv6.conf.default.addr_gen_mode = 2
net.ipv6.conf.all.accept_dad = 1
net.ipv6.conf.default.accept_dad = 1
net.ipv6.conf.all.enhanced_dad = 1
net.ipv6.conf.default.enhanced_dad = 1
net.ipv6.conf.all.accept_untracked_na = 0
net.ipv6.conf.default.accept_untracked_na = 0
net.ipv6.conf.all.drop_unsolicited_na = 1
net.ipv6.conf.default.drop_unsolicited_na = 1
net.ipv6.conf.all.proxy_ndp = 0
net.ipv6.conf.default.proxy_ndp = 0
net.ipv6.conf.all.suppress_frag_ndisc = 1
net.ipv6.conf.default.suppress_frag_ndisc = 1
net.ipv6.conf.all.disable_policy = 0
net.ipv6.conf.default.disable_policy = 0
net.ipv6.conf.all.drop_unicast_in_l2_multicast = 1
net.ipv6.conf.default.drop_unicast_in_l2_multicast = 1
net.ipv6.conf.all.seg6_enabled = 0
net.ipv6.conf.default.seg6_enabled = 0
net.ipv6.conf.all.rpl_seg_enabled = 0
net.ipv6.conf.default.rpl_seg_enabled = 0
net.ipv6.conf.all.ioam6_enabled = 0
net.ipv6.conf.default.ioam6_enabled = 0
net.ipv6.icmp.echo_ignore_all = 1
net.ipv6.icmp.echo_ignore_anycast = 1
net.ipv6.icmp.echo_ignore_multicast = 1
net.ipv6.icmp.ratelimit = 100
net.ipv6.max_dst_opts_number = 8
net.ipv6.max_hbh_opts_number = 8
net.ipv6.max_dst_opts_length = 65536
net.ipv6.max_hbh_length = 65536
net.ipv6.ip6frag_time = 15
SYSCTL_EOF

cat >/etc/sysctl.d/zz-hardened-net.conf <<'SYSCTL_EOF'
net.core.devconf_inherit_init_net = 1
net.core.fb_tunnels_only_for_init_net = 1
net.core.xfrm_larval_drop = 1
net.mptcp.enabled = 0
net.netfilter.nf_conntrack_tcp_be_liberal = 0
net.netfilter.nf_conntrack_tcp_ignore_invalid_rst = 0
net.netfilter.nf_conntrack_tcp_loose = 0
net.netfilter.nf_conntrack_checksum = 1
SYSCTL_EOF

rm -f /etc/sysctl.d/99-hardened-kernel.conf \
    /etc/sysctl.d/99-hardened-fs.conf \
    /etc/sysctl.d/99-hardened-ipv4.conf \
    /etc/sysctl.d/99-hardened-ipv6.conf

# the net.netfilter.* keys only exist while the conntrack module is loaded
modprobe nf_conntrack 2>/dev/null || true

sysctl --system >/dev/null || true

cat >/etc/login.defs <<'LOGIN_EOF'
MAIL_DIR /var/mail
ENV_SUPATH PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
FAIL_DELAY 3
FAILLOG_ENAB yes
LOG_UNKFAIL_ENAB no
LOG_OK_LOGINS yes
SYSLOG_SU_ENAB yes
SYSLOG_SG_ENAB yes
TTYGROUP tty
TTYPERM 0600
UMASK 077
PASS_MAX_DAYS 128
PASS_MIN_DAYS 1
PASS_WARN_AGE 7
SYS_UID_MIN 101
SYS_UID_MAX 999
SYS_GID_MIN 101
SYS_GID_MAX 999
UID_MIN 1000
UID_MAX 60000
GID_MIN 1000
GID_MAX 60000
SUB_UID_MIN 100000
SUB_UID_MAX 600100000
SUB_UID_COUNT 65536
SUB_GID_MIN 100000
SUB_GID_MAX 600100000
SUB_GID_COUNT 65536
LOGIN_RETRIES 3
LOGIN_TIMEOUT 60
CHFN_RESTRICT rwh
DEFAULT_HOME yes
HOME_MODE 0700
NONEXISTENT /nonexistent
HUSHLOGIN_FILE .hushlogin
ENCRYPT_METHOD YESCRYPT
YESCRYPT_COST_FACTOR 8
LOGIN_EOF

cat >/etc/apt/apt.conf.d/90-hardening <<'APT_EOF'
Acquire::http::AllowRedirect "0";
Acquire::AllowDowngradeToInsecureRepositories "0";
Acquire::AllowInsecureRepositories "0";
APT::Get::AllowUnauthenticated "0";
APT::Install-Recommends "0";
APT::Install-Suggests "0";
APT::Sandbox::Seccomp "1";
APT_EOF

cat >/etc/apt/apt.conf.d/90-autoclean <<'APT_EOF'
APT::Periodic::AutocleanInterval "7";
APT::Get::AutomaticRemove "1";
APT_EOF

cat >/etc/apt/apt.conf.d/90-unattended-upgrade <<'APT_EOF'
Unattended-Upgrade::Remove-Unused-Dependencies "1";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "1";
APT_EOF

# apport overrides kernel.core_pattern and forces fs.suid_dumpable=2 when it
# starts, undoing the sysctl hardening below
apt-get purge -y apport apport-symptoms >/dev/null 2>&1 || true
systemctl mask apport.service apport-autoreport.path apport-autoreport.timer \
    >/dev/null 2>&1 || true
rm -f /etc/sysctl.d/*apport* /usr/lib/sysctl.d/*apport*

groupadd sshusers 2>/dev/null || true
for u in ubuntu test root; do
    if id "${u}" >/dev/null 2>&1; then
        usermod -aG sshusers "${u}"
    fi
done

mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/00-hardening.conf <<'SSH_EOF'
FingerprintHash SHA256
SyslogFacility AUTH
LogLevel VERBOSE
LoginGraceTime 30
PermitRootLogin no
StrictModes yes
MaxAuthTries 4
MaxSessions 4
HostbasedAuthentication no
IgnoreUserKnownHosts yes
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
KerberosAuthentication no
KerberosOrLocalPasswd no
KerberosTicketCleanup yes
GSSAPIAuthentication no
GSSAPICleanupCredentials yes
UsePAM yes
AuthenticationMethods publickey
DisableForwarding yes
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
X11Forwarding no
X11UseLocalhost yes
PrintMotd no
PrintLastLog yes
PermitUserEnvironment no
UseDNS no
TCPKeepAlive no
ClientAliveInterval 15
ClientAliveCountMax 3
MaxStartups 10:30:60
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO
AllowGroups sshusers
SSH_EOF
rm -f /etc/ssh/sshd_config.d/99-hardening.conf
chmod 0644 /etc/ssh/sshd_config.d/*.conf

sshd -t -f /etc/ssh/sshd_config
# the account used to drive the test must be allowed
# NOTE: no `cmd | grep -q` pipelines, `grep -q` exits as soon as it matches and
# the SIGPIPE it sends to `cmd` fails the script through `pipefail`
sshd_effective_config=$(sshd -T)
grep -qi '^allowgroups sshusers$' <<<"${sshd_effective_config}"
ubuntu_groups=$(id -nG ubuntu)
grep -qw sshusers <<<"${ubuntu_groups}"

systemctl enable ssh >/dev/null 2>&1 || systemctl enable sshd >/dev/null 2>&1 || true
systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true

# --------------------------------------------------------------------------- pam
# The stock Debian/Ubuntu layout is kept on purpose: the service files are left
# alone and `@include` the common-* stacks, the hardening goes in those stacks.
# rAudit resolves the includes per service, so hardening `common-auth` covers
# every service asking for a password (`login`, `sshd`, `su`, `su-l`, `sudo` and
# `sudo-i`) and hardening `common-password` covers every password tool
# (`passwd`, `chpasswd` and `newusers`).

# account lockout wrapped around the unix authentication, `pam_unix` is
# `sufficient` so a success skips the `authfail` record below it
cat >/etc/pam.d/common-auth <<'PAM_AUTH_EOF'
auth	required	pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth	sufficient	pam_unix.so try_first_pass
auth	[default=die]	pam_faillock.so authfail audit deny=5 unlock_time=900
auth	requisite	pam_deny.so
auth	required	pam_permit.so
PAM_AUTH_EOF

# a locked account must also be refused once the password is not asked anymore
cat >/etc/pam.d/common-account <<'PAM_ACCOUNT_EOF'
account	[success=1 new_authtok_reqd=done default=ignore]	pam_unix.so
account	requisite	pam_deny.so
account	required	pam_permit.so
account	required	pam_faillock.so
PAM_ACCOUNT_EOF

# quality and reuse checks must run before pam_unix writes the new hash
cat >/etc/pam.d/common-password <<'PAM_PASSWORD_EOF'
password	requisite	pam_pwquality.so retry=3 minlen=14 difok=4 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 enforce_for_root
password	required	pam_pwhistory.so remember=5 enforce_for_root use_authtok
password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass yescrypt
password	requisite	pam_deny.so
password	required	pam_permit.so
PAM_PASSWORD_EOF

cat >/etc/pam.d/common-session <<'PAM_SESSION_EOF'
session	[default=1]	pam_permit.so
session	requisite	pam_deny.so
session	required	pam_permit.so
session	required	pam_umask.so
session	required	pam_unix.so
session	required	pam_loginuid.so
session	required	pam_limits.so
session	required	pam_env.so readenv=1
session	optional	pam_systemd.so
PAM_SESSION_EOF

chmod 0644 /etc/pam.d/common-auth /etc/pam.d/common-account \
    /etc/pam.d/common-password /etc/pam.d/common-session

# `su` restricted to the wheel group, the stock file ships that rule commented out
# (`gpasswd` instead of `usermod`, the harness user is logged in while this runs)
groupadd -f wheel
gpasswd -a ubuntu wheel
sed -i '/^auth[[:space:]]\+sufficient[[:space:]]\+pam_rootok\.so/a auth       required   pam_wheel.so use_uid' /etc/pam.d/su
grep -q '^auth[[:space:]]\+required[[:space:]]\+pam_wheel\.so use_uid$' /etc/pam.d/su

# longer pause before the next authentication attempt, the stock `login` already
# has the rule so only its value is hardened
sed -i -E 's/^(auth[[:space:]]+optional[[:space:]]+pam_faildelay\.so[[:space:]]+)delay=[0-9]+/\1delay=4000000/' /etc/pam.d/login
grep -qE '^auth[[:space:]]+optional[[:space:]]+pam_faildelay\.so[[:space:]]+delay=4000000' /etc/pam.d/login

# the services must still be readable by the PAM library
chmod 0644 /etc/pam.d/login /etc/pam.d/su /etc/pam.d/passwd

cat >/etc/security/pwquality.conf <<'PWQUALITY_EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
retry = 3
difok = 4
enforce_for_root
PWQUALITY_EOF

cat >/etc/security/limits.conf <<'LIMITS_EOF'
*    hard    core    0
*    soft    core    0
*    hard    maxlogins    10
*    soft    maxlogins    10
*    hard    maxsyslogins    10
*    soft    maxsyslogins    10
LIMITS_EOF

cat >/etc/profile.d/umask.sh <<'UMASK_EOF'
umask 027
UMASK_EOF
chmod 0644 /etc/profile.d/umask.sh

cat >/etc/profile.d/shell-timeout.sh <<'SHELL_EOF'
TMOUT="$(( 60*10 ))";
[ -z "$DISPLAY" ] && export TMOUT;
case $( /usr/bin/tty ) in
    /dev/tty[0-9]*) export TMOUT;;
esac
SHELL_EOF
chmod 0644 /etc/profile.d/shell-timeout.sh
rm -f /etc/profile.d/99-timeout.sh

cat >/etc/audit/auditd.conf <<'AUDIT_EOF'
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = root
log_format = RAW
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 8
num_logs = 5
priority_boost = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = HALT
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
distribute_network = no
AUDIT_EOF
chmod 0640 /etc/audit/auditd.conf
chown root:root /etc/audit/auditd.conf

cat >/etc/audit/rules.d/hardened.rules <<'AUDIT_RULES_EOF'
-D
-b 8192
-f 1
-w /etc/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audit/rules.d/ -p wa -k auditrules
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /etc/sudoers -p wa -k privileged
-w /etc/sudoers.d/ -p wa -k privileged
-w /var/log/sudo.log -p wa -k log_file
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-e 2
AUDIT_RULES_EOF
chmod 0640 /etc/audit/rules.d/hardened.rules
chown root:root /etc/audit/rules.d/hardened.rules

install -d -m 0700 -o root -g root /var/log/audit
touch /var/log/sudo.log
chmod 0600 /var/log/sudo.log
chown root:root /var/log/sudo.log

systemctl enable auditd >/dev/null 2>&1 || true

cat >/etc/hosts <<'HOSTS_EOF'
127.0.0.1	localhost
127.0.0.1	localhost.localdomain
127.0.0.1	local
127.0.1.1	raudit-test
::1	localhost
::1	ip6-localhost
::1	ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
0.0.0.0	0.0.0.0
HOSTS_EOF

if [ -f /etc/gshadow ]; then
    : >/etc/gshadow
    chown root:shadow /etc/gshadow
    chmod 0640 /etc/gshadow
fi
if [ -f /etc/gshadow- ]; then
    chown root:shadow /etc/gshadow-
    chmod 0640 /etc/gshadow-
fi

if ! grep -q '^CtrlAltDelBurstAction=' /etc/systemd/system.conf; then
    sed -i 's/^#\?CtrlAltDelBurstAction=.*/CtrlAltDelBurstAction=none/' /etc/systemd/system.conf
fi
grep -q '^CtrlAltDelBurstAction=none$' /etc/systemd/system.conf ||
    echo 'CtrlAltDelBurstAction=none' >>/etc/systemd/system.conf

# must leave NOPASSWD for cloud-init
cat >/etc/sudoers.d/99-hardening <<'SUDO_EOF'
Defaults env_reset
Defaults mail_badpass
Defaults use_pty
Defaults umask=0027
Defaults ignore_dot
Defaults passwd_timeout=1
Defaults logfile="/var/log/sudo.log"
Defaults lecture="always"
Defaults lecture_file="/usr/share/doc/sudo_lecture.txt"
SUDO_EOF
chmod 0440 /etc/sudoers.d/99-hardening
chown root:root /etc/sudoers.d/99-hardening

cat >/usr/share/doc/sudo_lecture.txt <<'LECTURE_EOF'
This host is audited. Every privileged command is logged and attributable.
Use the least privilege required, and never share credentials.
LECTURE_EOF
chmod 0644 /usr/share/doc/sudo_lecture.txt

visudo -cf /etc/sudoers.d/99-hardening >/dev/null

# single image so bind remount
cat >/etc/fstab <<'FSTAB_EOF'
LABEL=cloudimg-rootfs	/	  ext4	discard,commit=30,errors=remount-ro	0 1
LABEL=BOOT	/boot	  ext4	defaults,nodev,nosuid,noexec	0 2
LABEL=UEFI	/boot/efi vfat	umask=0077	0 1
/var		/var	  none	bind,nodev,nosuid,noexec	0 0
/var/log	/var/log	  none	bind,nodev,nosuid,noexec	0 0
/var/log/audit	/var/log/audit none	bind,nodev,nosuid,noexec	0 0
/home		/home	  none	bind,nodev,nosuid,noexec	0 0
tmpfs		/tmp	  tmpfs	defaults,nodev,nosuid,noexec,mode=1777,size=512M	0 0
tmpfs		/var/tmp  tmpfs	defaults,nodev,nosuid,noexec,mode=1777,size=512M	0 0
tmpfs		/dev/shm  tmpfs	defaults,nodev,nosuid,noexec,mode=1777	0 0
FSTAB_EOF

install -d -m 1777 /var/tmp
install -d -m 0700 -o root -g root /var/log/audit
findmnt --verify --tab-file /etc/fstab >/dev/null || true

rm -f /etc/nginx/sites-enabled/default
cat >/etc/nginx/conf.d/99-hardening.conf <<'NGINX_EOF'
server_tokens off;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header Referrer-Policy "no-referrer" always;

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}
NGINX_EOF
nginx -t
systemctl enable nginx >/dev/null 2>&1 || true
systemctl restart nginx >/dev/null 2>&1 || true

cat >/etc/default/grub.d/99-hardened.cfg <<'GRUB_CFG_EOF'
GRUB_TIMEOUT=0
GRUB_TIMEOUT_STYLE=hidden
GRUB_RECORDFAIL_TIMEOUT=0
GRUB_TERMINAL=console
GRUB_CMDLINE_LINUX_DEFAULT="console=tty1 console=ttyS0 quiet loglevel=0 slab_nomerge slab_debug=FZ page_alloc.shuffle=1 init_on_alloc=1 init_on_free=1 pti=on randomize_kstack_offset=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=integrity mce=0 kfence.sample_interval=100 vdso32=0 amd_iommu=force_isolation intel_iommu=on iommu=force iommu.passthrough=0 iommu.strict=1 efi=disable_early_pci_dma random.trust_bootloader=off random.trust_cpu=off extra_latent_entropy ia32_emulation=0 cfi=kcfi hardened_usercopy=1 remountsecure=3 mitigations=auto,nosmt nosmt spectre_v2=on spectre_bhi=on spec_store_bypass_disable=on l1tf=full,force mds=full tsx=off tsx_async_abort=full,nosmt kvm.nx_huge_pages=force l1d_flush=on mmio_stale_data=full,nosmt retbleed=auto,nosmt spec_rstack_overflow=safe-ret gather_data_sampling=force reg_file_data_sampling=on spectre_v2_user=on srbds=auto,nosmt hash_pointers=always apparmor=1 security=apparmor"
GRUB_CFG_EOF
chmod 0644 /etc/default/grub.d/99-hardened.cfg

update-grub

find /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ \
    -type f -exec chmod 0644 {} \; 2>/dev/null || true
chmod 0600 /etc/crontab 2>/dev/null || true

systemctl enable apparmor >/dev/null 2>&1 || true
systemctl start apparmor >/dev/null 2>&1 || true
# aa-enforce is not applied: it blocks raudit from running its probe commands

# runtime-only freeze, everything needed by the test is loaded at this point.
# it must not go in a sysctl.d file: applied at boot it would block the module
# loading the boot itself needs
sysctl -w kernel.modules_disabled=1

echo "HARDENED SETUP COMPLETE"
