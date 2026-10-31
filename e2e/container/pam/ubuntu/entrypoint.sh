#!/bin/sh
set -eu

profile="${1:-hardened}"
src="/profiles/${profile}"

if [ ! -d "${src}/pam.d" ]; then
    echo "unknown profile: ${profile}" >&2
    exit 1
fi

rm -rf /etc/pam.d
mkdir -p /etc/pam.d
cp "${src}"/pam.d/* /etc/pam.d/
chmod 644 /etc/pam.d/*

# LDF_002 is tagged `pam` and reads /etc/login.defs
cp "${src}/etc/login.defs" /etc/login.defs
chmod 644 /etc/login.defs

touch /run/app-ready
exec sleep infinity
