#!/bin/sh
set -eu

profile="${1:-hardened}"
src="/profiles/${profile}"

if [ ! -f "${src}/etc/group" ]; then
    echo "unknown profile: ${profile}" >&2
    exit 1
fi

cp "${src}/etc/group" /etc/group
rm -f /etc/gshadow /etc/gshadow-

if [ "${profile}" = "hardened" ]; then
    # stock Ubuntu: a populated gshadow with locked passwords, owned by
    # root:shadow at 0640 (GRP_001, GRP_102, GRP_103)
    cp "${src}/etc/gshadow" /etc/gshadow
    chown root:root /etc/group
    chmod 644 /etc/group
    chown root:shadow /etc/gshadow
    chmod 640 /etc/gshadow
else
    # same sabotage classes as the qemu insecure setup: a group password,
    # duplicate GIDs and names, a member of the `shadow` group, a populated
    # gshadow and non-root ownership with open permissions on the group
    # databases
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
