#!/bin/sh
set -eu

profile="${1:-hardened}"
src="/profiles/${profile}"

if [ ! -d "${src}" ]; then
    echo "unknown profile: ${profile}" >&2
    exit 1
fi

CRON_DIRS="/etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly"
PERIODIC="hourly daily weekly monthly yearly"
# APT_103/APT_107 are tagged `cron` and only run on the Debian family, they
# audit the ownership of the apt configuration directories
APT_DIRS="/etc/apt/sources.list.d /etc/apt/apt.conf.d"

# shellcheck disable=SC2086
mkdir -p ${CRON_DIRS}

cp "${src}/crontab" /etc/crontab
cp "${src}/cron.d/"* /etc/cron.d/
for d in ${PERIODIC}; do
    cp "${src}/cron.${d}/"* "/etc/cron.${d}/"
done
install -m 0755 "${src}/job/raudit-e2e-job" /usr/local/bin/raudit-e2e-job

if [ "${profile}" = "hardened" ]; then
    # shellcheck disable=SC2086
    chown -R root:root ${CRON_DIRS} /etc/crontab
    # shellcheck disable=SC2086
    chmod 755 ${CRON_DIRS}
    chmod 644 /etc/crontab /etc/cron.d/*
    # the periodic scripts stay executable: run-parts skips non-executable
    # files and the stock Ubuntu scripts ship 0755, CRN_009/013/017/021/025
    # only require them not to be group or world writable, see e2e/findings.md
    for d in ${PERIODIC}; do
        chmod 755 "/etc/cron.${d}/"*
    done
    # shellcheck disable=SC2086
    find ${APT_DIRS} -type f -exec chown root:root {} +
else
    # same sabotage as the qemu insecure setup: open permissions and
    # non-root group ownership on cron directories and files
    # shellcheck disable=SC2086
    chgrp -R nogroup ${CRON_DIRS}
    chown nobody:nogroup /etc/crontab
    # shellcheck disable=SC2086
    chmod 777 ${CRON_DIRS}
    for d in ${PERIODIC}; do
        chmod 666 "/etc/cron.${d}/"*
    done
    chmod 666 /etc/crontab /etc/cron.d/*
    # shellcheck disable=SC2086
    find ${APT_DIRS} -type f -exec chown nobody:nogroup {} +
fi

# run cron in the foreground as a child and wait on it, the same shape as the
# Alpine entrypoint (where it is required: dcron cannot be PID 1, see
# e2e/findings.md), so the container lifetime follows the daemon
/usr/sbin/cron -f &
cron_pid=$!

i=0
while ! pidof cron >/dev/null 2>&1 && [ "${i}" -lt 30 ]; do
    sleep 1
    i=$((i + 1))
done
if ! pidof cron >/dev/null 2>&1; then
    echo "cron failed to start" >&2
    exit 1
fi

wait "${cron_pid}"
