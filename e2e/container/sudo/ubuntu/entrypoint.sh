#!/bin/sh
set -eu

profile="${1:-hardened}"
src="/profiles/${profile}"

if [ ! -f "${src}/sudoers" ]; then
    echo "unknown profile: ${profile}" >&2
    exit 1
fi

if [ -f "${src}/sudo_lecture.txt" ]; then
    mkdir -p /usr/share/doc
    install -m 0644 "${src}/sudo_lecture.txt" /usr/share/doc/sudo_lecture.txt
fi

cp "${src}/sudoers" /etc/sudoers
rm -rf /etc/sudoers.d
mkdir -p /etc/sudoers.d
cp "${src}"/sudoers.d/* /etc/sudoers.d/

# visudo -c is strict about permissions, validate the syntax while everything
# is at the canonical root:root 0440 (dir 0750), then apply the profile modes
chown root:root /etc/sudoers /etc/sudoers.d /etc/sudoers.d/*
chmod 440 /etc/sudoers /etc/sudoers.d/*
chmod 750 /etc/sudoers.d
visudo -c

if [ "${profile}" = "hardened" ]; then
    # the README ships 0644 on the distros providing it, sudo parses it fine
    # but SUD_202 audits the permissions of every file and fails, see
    # e2e/findings.md
    chmod 644 /etc/sudoers.d/README
else
    # same sabotage as the qemu insecure setup: non-root ownership and open
    # permissions on the sudoers configuration
    chown nobody:nogroup /etc/sudoers /etc/sudoers.d /etc/sudoers.d/*
    chmod 644 /etc/sudoers
    chmod 777 /etc/sudoers.d
    chmod 666 /etc/sudoers.d/*
fi

touch /run/app-ready
exec sleep infinity
