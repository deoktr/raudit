#!/bin/sh
set -eu

profile="${1:-hardened}"
src="/etc/ssh/profiles/${profile}"

if [ ! -d "${src}" ]; then
    echo "unknown profile: ${profile}" >&2
    exit 1
fi

groupadd -f --system sshusers

# the privilege separation directory is created by tmpfiles.d on a real boot,
# there is no init system here
mkdir -p /run/sshd
chmod 755 /run/sshd

cp "${src}/sshd_config" /etc/ssh/sshd_config
rm -rf /etc/ssh/sshd_config.d
mkdir -p /etc/ssh/sshd_config.d
cp "${src}"/sshd_config.d/*.conf /etc/ssh/sshd_config.d/
chmod 644 /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf

if [ "${profile}" = "hardened" ]; then
    chown -R root:root /etc/ssh
    chmod 755 /etc/ssh /etc/ssh/sshd_config.d
    chmod 644 /etc/ssh/ssh_host_*.pub
    chmod 600 /etc/ssh/ssh_host_*_key
else
    # same sabotage as the qemu insecure setup: open permissions and
    # non-root group ownership on ssh configuration and public keys
    chgrp -R nogroup /etc/ssh
    chmod 777 /etc/ssh /etc/ssh/sshd_config.d
    chmod 666 /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
    chmod 666 /etc/ssh/ssh_host_*.pub
    chmod 600 /etc/ssh/ssh_host_*_key
fi

sshd -t -f /etc/ssh/sshd_config

exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
