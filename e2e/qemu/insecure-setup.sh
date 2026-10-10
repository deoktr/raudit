#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
    openssh-server \
    sudo

cat >/etc/sysctl.d/99-insecure.conf <<'SYSCTL_EOF'
kernel.randomize_va_space = 0
kernel.dmesg_restrict = 0
kernel.yama.ptrace_scope = 0
kernel.warn_limit = 10000
vm.unprivileged_userfaultfd = 1
vm.mmap_rnd_bits = 28
vm.mmap_rnd_compat_bits = 8
vm.mmap_min_addr = 0
vm.max_map_count = 65530
dev.tty.legacy_tiocsti = 1
fs.suid_dumpable = 2
user.max_user_namespaces = 2147483647
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.default.accept_source_route = 1
net.ipv4.conf.all.accept_local = 1
net.ipv4.conf.all.route_localnet = 1
net.ipv4.icmp_echo_ignore_broadcasts = 0
net.ipv4.icmp_ignore_bogus_error_responses = 0
net.ipv4.tcp_syncookies = 0
net.ipv4.tcp_synack_retries = 10
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.accept_source_route = 1
net.ipv6.conf.default.accept_source_route = 1
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.default.accept_redirects = 1
net.ipv4.conf.all.secure_redirects = 1
net.ipv4.conf.default.secure_redirects = 1
net.ipv4.conf.all.send_redirects = 1
net.ipv4.conf.default.send_redirects = 1
SYSCTL_EOF

cat >/etc/sysctl.d/99-protect-links.conf <<'SYSCTL_EOF'
fs.protected_hardlinks = 0
fs.protected_regular = 0
fs.protected_symlinks = 0
fs.protected_fifos = 0
SYSCTL_EOF
sysctl --system >/dev/null

sed -i 's/^UMASK.*/UMASK\t\t\t000/' /etc/login.defs
sed -i 's/^HOME_MODE.*/HOME_MODE\t0777/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t0/' /etc/login.defs
sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES\t\t99/' /etc/login.defs
sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT\t\t999/' /etc/login.defs
sed -i 's/^SYSLOG_SU_ENAB.*/SYSLOG_SU_ENAB\tno/' /etc/login.defs
sed -i 's/^SYSLOG_SG_ENAB.*/SYSLOG_SG_ENAB\tno/' /etc/login.defs
sed -i 's/^FAILLOG_ENAB.*/FAILLOG_ENAB\tno/' /etc/login.defs
sed -i 's/^LOG_OK_LOGINS.*/LOG_OK_LOGINS\tno/' /etc/login.defs
cat >/etc/profile.d/umask.sh <<'UMASK_EOF'
umask 000
UMASK_EOF

cat >/etc/apt/apt.conf.d/00-insecure <<'APT_EOF'
Acquire::http::AllowRedirect "1";
Acquire::AllowInsecureRepositories "1";
Acquire::AllowDowngradeToInsecureRepositories "1";
APT::Get::AllowUnauthenticated "1";
APT::Install-Recommends "1";
APT::Install-Suggests "1";
APT::Sandbox::Seccomp "0";
APT::Sandbox::User "root";
APT::Periodic::AutocleanInterval "0";
APT::Get::AutomaticRemove "0";
APT_EOF
cat >/etc/apt/apt.conf <<'APT_EOF'
Dir "/etc/apt/";
APT_EOF

mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/00-insecure.conf <<'SSH_EOF'
FingerprintHash md5
SyslogFacility LOCAL0
LogLevel QUIET
LoginGraceTime 600
PermitRootLogin yes
StrictModes no
MaxAuthTries 20
MaxSessions 50
MaxStartups 100:30:200
HostbasedAuthentication yes
IgnoreRhosts no
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords yes
KbdInteractiveAuthentication yes
KerberosAuthentication yes
KerberosTicketCleanup no
GSSAPIAuthentication yes
GSSAPICleanupCredentials no
UsePAM no
AllowAgentForwarding yes
AllowTcpForwarding yes
GatewayPorts yes
PermitTunnel yes
X11Forwarding yes
X11UseLocalhost no
PrintMotd yes
PrintLastLog no
PermitUserEnvironment yes
Compression yes
UseDNS yes
ClientAliveInterval 30
ClientAliveCountMax 9
SSH_EOF
sshd -t
systemctl enable --now ssh
systemctl restart ssh
systemctl is-active --quiet ssh

sed -i -E 's/^Defaults[[:space:]]+(use_pty|env_reset|mail_badpass)[[:space:]]*$/#insecure &/' /etc/sudoers
cat >/etc/sudoers.d/99-insecure <<'SUDO_EOF'
Defaults !authenticate
Defaults umask_override
Defaults umask=0000
Defaults timestamp_timeout=60
Defaults passwd_timeout=60
SUDO_EOF
chown root:nogroup /etc/sudoers.d/99-insecure
chmod 0400 /etc/sudoers.d/99-insecure
visudo -cf /etc/sudoers >/dev/null

rm -f /etc/modprobe.d/disable-algif_aead.conf /etc/modprobe.d/blacklist-ath_pci.conf
sed -i -E '/^blacklist[[:space:]]+(snd_intel8x0m|amd76x_edac|evbug|snd_aw2|snd_pcsp|usbkbd|usbmouse)([[:space:]]|$)/d' /etc/modprobe.d/blacklist.conf

sed -i -E '\#[[:space:]]/boot(/efi)?[[:space:]]#d' /etc/fstab
umount /boot/efi
umount /boot
mount -o remount,dev,suid,exec /proc
mount -o remount,dev,suid,exec /dev
mount -o remount,dev,suid,exec /dev/shm

useradd --non-unique --uid 0 --gid 0 --no-create-home --shell /usr/sbin/nologin root2
useradd --no-create-home --shell /usr/sbin/nologin nopass
useradd --no-create-home --uid 1500 --shell /bin/bash ghost
useradd --create-home --uid 1501 --shell /bin/bash expired
useradd --create-home --uid 1502 --shell /bin/bash weakhash
passwd --delete nopass
usermod --expiredate 2020-01-01 expired
usermod --password '$6$insecuretest$HFEDZNjcAXdDA2Q2YQFWyY5Ol0fCb4q9otDVXCHLyWUyyoqLbTWb1BGUjLuE0MFkfcNGRLuxy1yWMFxlq5PFr1' weakhash
usermod --password '$6$7c789be6c382bc33$.K0YIkbMy56EsNFDRhC0USQsQqsNIu0GD64o21aYOfyiQMk5LEi/.OUNDc0p0IJYeocus3NhpdaKxkANbnzj81' root
usermod --shell /bin/bash games
groupadd --non-unique --gid 0 root2
gpasswd -a test shadow

chown root:root /home/test
chmod 0777 /home/test
printf '+ +\n' >/home/test/.rhosts
printf '+ +\n' >/home/test/.shosts
install -m 0666 -o test -g test /dev/null /home/test/world-writable

cat >/etc/systemd/system/insecure.service <<'SYSD_EOF'
[Unit]
Description=World writable unit file

[Service]
Type=oneshot
ExecStart=/bin/true
SYSD_EOF
chown nobody:nogroup /etc/systemd/system/insecure.service
chmod 0666 /etc/systemd/system/insecure.service

printf 'linux-image-generic\n' >/var/run/reboot-required.pkgs
printf '*** System restart required ***\n' >/var/run/reboot-required

sed -i '/^127\.0\.0\.1[[:space:]]\+localhost$/d' /etc/hosts
sed -i 's/^ghost:x:/ghost::/' /etc/passwd
printf 'test:x:1000:1000::/home/test:/bin/bash\n' >>/etc/passwd
sed -i 's#^games:x:#games:$6$insecuretest$HFEDZNjcAXdDA2Q2YQFWyY5Ol0fCb4q9otDVXCHLyWUyyoqLbTWb1BGUjLuE0MFkfcNGRLuxy1yWMFxlq5PFr1:#' /etc/group
printf 'games:x:60001:\n' >>/etc/group
printf 'tty1\nttyS0\nconsole\n' >/etc/securetty
install -m 0666 -o nobody -g nogroup /dev/null /etc/shadow-
install -m 0666 -o nobody -g nogroup /dev/null /etc/gshadow-
install -m 0666 -o nobody -g nogroup /dev/null /etc/security/opasswd

chmod 0777 /etc/cron.d /etc/cron.hourly /etc/cron.daily
chmod 0777 /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly
find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
    /etc/cron.monthly /etc/cron.yearly -type f -exec chmod 0666 {} +
chgrp -R nogroup /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
    /etc/cron.monthly /etc/cron.yearly
chmod 0666 /lib/systemd/system/cron.service /usr/lib/systemd/system/ssh.service
chgrp nogroup /lib/systemd/system/cron.service /usr/lib/systemd/system/ssh.service
chmod 0777 /etc/ssh
chmod 0666 /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf /etc/ssh/ssh_host_*_key.pub
chgrp -R nogroup /etc/ssh
chmod 0666 /etc/apt/apt.conf /etc/apt/apt.conf.d/*
chgrp -R nogroup /etc/apt/apt.conf /etc/apt/apt.conf.d
chmod 0644 /etc/shadow /etc/gshadow
chown root:root /etc/shadow /etc/gshadow
chmod 0666 /etc/passwd /etc/group /etc/securetty
chown nobody:nogroup /etc/passwd /etc/group /etc/securetty
chmod 0666 /etc/hostname /etc/machine-id /etc/hosts /etc/resolv.conf
chown nobody:nogroup /etc/hostname /etc/machine-id /etc/hosts /etc/resolv.conf
chmod 0666 /etc/apt/sources.list
chown nobody:nogroup /etc/apt/sources.list
chmod -R 0666 /etc/apt/sources.list.d
chown -R nobody:nogroup /etc/apt/sources.list.d

echo "INSECURE SETUP COMPLETE"
