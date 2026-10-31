#!/bin/sh
set -eu

profile="${1:-hardened}"
src="/profiles/${profile}"

if [ ! -f "${src}/etc/passwd" ]; then
    echo "unknown profile: ${profile}" >&2
    exit 1
fi

cp "${src}/etc/passwd" /etc/passwd
cp "${src}/etc/shadow" /etc/shadow
mkdir -p /etc/default
cp "${src}/etc/default/useradd" /etc/default/useradd

if [ "${profile}" = "hardened" ]; then
    rm -f /etc/securetty /etc/shadow- /etc/security/opasswd
    chown root:root /etc/passwd /etc/shadow /etc/default/useradd
    chmod 644 /etc/passwd /etc/default/useradd
    chmod 600 /etc/shadow
    install -d -m 750 -o 1000 -g 1000 /home/audit
    install -m 644 -o 1000 -g 1000 "${src}/home/audit/.profile" /home/audit/.profile
else
    # sabotage classes of the qemu insecure setup: unlocked root with an MD5
    # hash, a second UID 0 account, duplicate passwd lines, empty password
    # fields, legacy trust files, an open mis-owned home directory, and loose
    # permissions/ownership on the identity files (USR_100..USR_107).
    # /home/ghost is deliberately not created (USR_008), the nopass/expired
    # accounts have nologin shells so their homes are not audited.
    cp "${src}/etc/securetty" /etc/securetty
    chown root:root /etc/securetty
    chmod 666 /etc/securetty

    mkdir -p /etc/security
    cp "${src}/etc/shadow-" /etc/shadow-
    cp "${src}/etc/security/opasswd" /etc/security/opasswd

    chown nobody:nogroup /etc/passwd
    chmod 666 /etc/passwd
    chown root:nogroup /etc/shadow
    chmod 644 /etc/shadow
    chown nobody:nogroup /etc/shadow-
    chmod 666 /etc/shadow-
    chown nobody:nogroup /etc/security/opasswd
    chmod 666 /etc/security/opasswd

    mkdir -p /home/audit
    chown root:root /home/audit
    chmod 777 /home/audit
    cp "${src}/home/audit/.rhosts" /home/audit/.rhosts
    chown root:root /home/audit/.rhosts
    chmod 644 /home/audit/.rhosts
    cp "${src}/home/audit/notes.txt" /home/audit/notes.txt
    chown 1000:1000 /home/audit/notes.txt
    chmod 666 /home/audit/notes.txt
fi

touch /run/app-ready
exec sleep infinity
