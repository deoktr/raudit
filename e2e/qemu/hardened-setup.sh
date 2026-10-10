#!/bin/bash
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
    apt-utils

cat >/etc/sysctl.d/99-hardened-kernel.conf <<'SYSCTL_EOF'
kernel.pid_max = 65536
kernel.kptr_restrict = 2
kernel.ftrace_enabled = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.printk = 3	3	3	3
kernel.perf_cpu_time_max_percent = 1
kernel.perf_event_max_sample_rate = 1
kernel.perf_event_paranoid = 3
kernel.sysrq = 0
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.panic_on_oops = 1
kernel.panic = -1
kernel.yama.ptrace_scope = 3
kernel.io_uring_disabled = 2
kernel.core_pattern = |/bin/false
kernel.core_uses_pid = 1
vm.unprivileged_userfaultfd = 0
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
vm.mmap_min_addr = 65536
dev.tty.ldisc_autoload = 0
dev.tty.legacy_tiocsti = 0
vm.max_map_count = 1048576
vm.swappiness = 1
kernel.oops_limit = 100
kernel.warn_limit = 100
user.max_user_namespaces = 31231
SYSCTL_EOF

cat >/etc/sysctl.d/99-hardened-fs.conf <<'SYSCTL_EOF'
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.binfmt_misc.status = 0
SYSCTL_EOF

cat >/etc/sysctl.d/99-hardened-ipv4.conf <<'SYSCTL_EOF'
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
net.ipv6.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_local = 0
net.ipv4.conf.all.shared_media = 0
net.ipv4.conf.default.shared_media = 0
net.ipv4.conf.all.arp_filter = 1
net.ipv4.conf.all.arp_ignore = 2
net.ipv4.conf.default.arp_ignore = 2
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.drop_gratuitous_arp = 1
net.ipv4.conf.all.route_localnet = 0
net.ipv4.ip_local_port_range = 32768	65535
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0
SYSCTL_EOF

cat >/etc/sysctl.d/99-hardened-ipv6.conf <<'SYSCTL_EOF'
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
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.all.max_addresses = 1
net.ipv6.conf.default.max_addresses = 1
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.icmp.echo_ignore_anycast = 1
net.ipv6.icmp.echo_ignore_multicast = 1
SYSCTL_EOF

sysctl --system

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

mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-hardening.conf <<'SSH_EOF'
FingerprintHash SHA256
SyslogFacility AUTH
LogLevel VERBOSE
LoginGraceTime 60
PermitRootLogin no
StrictModes yes
MaxAuthTries 4
MaxSessions 4
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
ClientAliveInterval 300
ClientAliveCountMax 2
SSH_EOF

cat >/etc/sudoers.d/99-hardening <<'SUDO_EOF'
Defaults use_pty
Defaults umask=0027
Defaults ignore_dot
Defaults passwd_timeout=1
Defaults timestamp_timeout=1
Defaults log_output
SUDO_EOF
chmod 0440 /etc/sudoers.d/99-hardening

cat >/etc/profile.d/99-timeout.sh <<'SHELL_EOF'
export TMOUT=600
readonly TMOUT
SHELL_EOF
chmod 0644 /etc/profile.d/99-timeout.sh

cat >/etc/grub.d/40_custom <<'GRUB_EOF'
#!/bin/sh
exec tail -n +3 $0
set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.AB42TEST00000000000000000000000000000000000000000000000000000000000000000000000.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000TESTGRUB
GRUB_EOF

if [ -f /etc/default/grub ]; then
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 apparmor=1 security=apparmor"/' /etc/default/grub || true
fi

systemctl enable apparmor 2>/dev/null || true
systemctl start apparmor 2>/dev/null || true
# aa-enforce is disabled because it blocks raudit from running commands
# aa-enforce /etc/apparmor.d/* 2>/dev/null || true

find /etc/cron.d/ -type f -exec chmod 0644 {} \; 2>/dev/null || true
find /etc/cron.daily/ -type f -exec chmod 0644 {} \; 2>/dev/null || true
find /etc/cron.hourly/ -type f -exec chmod 0644 {} \; 2>/dev/null || true
find /etc/cron.weekly/ -type f -exec chmod 0644 {} \; 2>/dev/null || true
find /etc/cron.monthly/ -type f -exec chmod 0644 {} \; 2>/dev/null || true
chmod 0600 /etc/crontab 2>/dev/null || true

cat >/etc/hosts <<'HOSTS_EOF'
127.0.0.1	localhost
127.0.1.1	raudit-test
127.0.0.1	localhost.localdomain
127.0.0.1	local
::1		ip6-localhost ip6-loopback localhost
fe00::0		ip6-localnet
ff00::0		ip6-mcastprefix
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters
0.0.0.0		0.0.0.0
HOSTS_EOF

if [ -f /etc/gshadow ]; then
    chmod 0640 /etc/gshadow
    chgrp root /etc/gshadow 2>/dev/null || true
fi
if [ -f /etc/gshadow- ]; then
    chmod 0640 /etc/gshadow-
fi

cat >/etc/audit/auditd.conf <<'AUDIT_EOF'
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
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
disk_full_action = SUSPEND
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
-w /var/log/sudo.log -p wa -k privileged
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-e 2
AUDIT_RULES_EOF
chmod 0640 /etc/audit/rules.d/hardened.rules
chown root:root /etc/audit/rules.d/hardened.rules

systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true

cat >/etc/pam.d/common-password <<'PAM_PASSWORD_EOF'
password    requisite     pam_pwquality.so retry=3 minlen=14 difok=4 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 enforce_for_root
password    [success=1 default=ignore]    pam_unix.so obscure use_authtok try_first_pass yescrypt
password    requisite     pam_deny.so
password    required      pam_permit.so
password    required      pam_pwhistory.so remember=5 enforce_for_root
PAM_PASSWORD_EOF

cat >/etc/pam.d/common-auth <<'PAM_AUTH_EOF'
auth    [success=1 default=ignore]    pam_unix.so
auth    requisite     pam_deny.so
auth    required      pam_permit.so
auth    required      pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth    [default=ignore]    pam_faillock.so authfail audit deny=5 unlock_time=900
PAM_AUTH_EOF

cat >/etc/pam.d/common-account <<'PAM_ACCOUNT_EOF'
account    [success=1 new_authtok_reqd=done default=ignore]    pam_unix.so
account    requisite     pam_deny.so
account    required      pam_permit.so
account    required      pam_time.so
account    required      pam_faillock.so
PAM_ACCOUNT_EOF

cat >/etc/pam.d/common-session <<'PAM_SESSION_EOF'
session    [success=1 default=ignore]    pam_unix.so
session    requisite     pam_deny.so
session    required      pam_permit.so
session    required      pam_umask.so
session    required      pam_loginuid.so
session    required      pam_limits.so
session    required      pam_env.so
PAM_SESSION_EOF

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

systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

chmod 644 /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true

echo "HARDENED SETUP COMPLETE"
