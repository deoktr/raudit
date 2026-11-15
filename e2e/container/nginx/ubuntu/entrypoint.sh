#!/bin/sh
set -eu

profile="${1:-hardened}"
src="/profiles/${profile}"

if [ ! -f "${src}/nginx.conf" ]; then
    echo "unknown profile: ${profile}" >&2
    exit 1
fi

mkdir -p /var/log/nginx /var/www/html
cp "${src}/nginx.conf" /etc/nginx/nginx.conf
echo "rAudit e2e nginx ${profile} profile" > /var/www/html/index.html

nginx -t -c /etc/nginx/nginx.conf

exec /usr/sbin/nginx -c /etc/nginx/nginx.conf -g "daemon off;"
