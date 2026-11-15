#!/bin/sh
set -eu

profile="${1:-hardened}"
src="/profiles/${profile}"

if [ ! -d "${src}/profile.d" ]; then
    echo "unknown profile: ${profile}" >&2
    exit 1
fi

mkdir -p /etc/profile.d
cp "${src}"/profile.d/* /etc/profile.d/
chmod 644 /etc/profile.d/*

touch /run/app-ready
exec sleep infinity
