#!/bin/sh
set -eu

profile="${1:-hardened}"
src="/profiles/${profile}"

if [ ! -f "${src}/etc/group" ]; then
    echo "unknown profile: ${profile}" >&2
    exit 1
fi

cp "${src}/etc/group" /etc/group

if [ "${profile}" = "hardened" ]; then
    rm -f /etc/gshadow /etc/gshadow-
    chown root:root /etc/group
    chmod 644 /etc/group
else
    # same sabotage classes as the qemu insecure setup: a group password,
    # duplicate GIDs and names, a populated gshadow and non-root ownership
    # with open permissions on the group databases
    cp "${src}/etc/gshadow" /etc/gshadow
    cp "${src}/etc/gshadow-" /etc/gshadow-
    chown root:nogroup /etc/group
    chmod 664 /etc/group
    chown root:root /etc/gshadow
    chmod 644 /etc/gshadow
    chown nobody:nogroup /etc/gshadow-
    chmod 666 /etc/gshadow-
fi

touch /run/app-ready
exec sleep infinity
