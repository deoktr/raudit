#!/bin/sh
set -eu

profile="${1:-hardened}"

case "${profile}" in
hardened)
    # minimal offline signature database (md5:size:name of a 1-byte file),
    # clamd refuses to start with an empty database directory and freshclam
    # would have to download the real one
    mkdir -p /var/lib/clamav /run/clamav /var/log/clamav
    printf '9dd4e461268c8034f5c8564e155c67a6:1:RAUDIT.E2E.TEST\n' \
        > /var/lib/clamav/e2e.hdb
    chown -R clamav:clamav /var/lib/clamav /run/clamav /var/log/clamav

    clamscan --version

    # Ubuntu's clamd.conf points LocalSocket at /run/clamav/clamd.ctl
    clamd --foreground=yes &
    clamd_pid=$!

    i=0
    while [ ! -S /run/clamav/clamd.ctl ] && [ "${i}" -lt 60 ]; do
        sleep 1
        i=$((i + 1))
    done
    if [ ! -S /run/clamav/clamd.ctl ]; then
        echo "clamd did not create its socket" >&2
        exit 1
    fi

    touch /run/app-ready
    wait "${clamd_pid}"
    ;;
weak)
    # the weak profile is a host where ClamAV is not installed at all
    apt-get -y purge clamav clamav-daemon clamav-base >/dev/null

    touch /run/app-ready
    exec sleep infinity
    ;;
*)
    echo "unknown profile: ${profile}" >&2
    exit 1
    ;;
esac
