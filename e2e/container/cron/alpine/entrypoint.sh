#!/bin/sh
set -eu

profile="${1:-hardened}"
src="/profiles/${profile}"

if [ ! -d "${src}" ]; then
    echo "unknown profile: ${profile}" >&2
    exit 1
fi

CRON_DIRS="/etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly"

# shellcheck disable=SC2086
mkdir -p ${CRON_DIRS}

cp "${src}/crontab" /etc/crontab
cp "${src}/cron.d/"* /etc/cron.d/
for d in hourly daily weekly monthly yearly; do
    cp "${src}/cron.${d}/"* "/etc/cron.${d}/"
done
install -m 0755 "${src}/job/raudit-e2e-job" /usr/local/bin/raudit-e2e-job

if [ "${profile}" = "hardened" ]; then
    # shellcheck disable=SC2086
    chown -R root:root ${CRON_DIRS} /etc/crontab
    # shellcheck disable=SC2086
    chmod 755 ${CRON_DIRS}
    chmod 644 /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* \
        /etc/cron.weekly/* /etc/cron.monthly/* /etc/cron.yearly/*
else
    # same sabotage as the qemu insecure setup: open permissions and
    # non-root group ownership on cron directories and files
    # shellcheck disable=SC2086
    chgrp -R nogroup ${CRON_DIRS}
    chown nobody:nogroup /etc/crontab
    # shellcheck disable=SC2086
    chmod 777 ${CRON_DIRS}
    chmod 666 /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* \
        /etc/cron.weekly/* /etc/cron.monthly/* /etc/cron.yearly/*
fi

# dcron calls setpgid() at startup, which fails with EPERM when crond is the
# container PID 1 (session leader), run it as a child and wait on it instead
/usr/sbin/crond -f -L /dev/stdout &
crond_pid=$!

i=0
while ! pidof crond >/dev/null 2>&1 && [ "${i}" -lt 30 ]; do
    sleep 1
    i=$((i + 1))
done
if ! pidof crond >/dev/null 2>&1; then
    echo "crond failed to start" >&2
    exit 1
fi

wait "${crond_pid}"
