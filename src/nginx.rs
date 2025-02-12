/*
 * rAudit, a Linux security auditing toolkit
 * Copyright (C) 2024 - 2025  deoktr
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// NOTE: this is a WIP!
// TODO: make a better parser to understand the complexity of nginx config

use std::process;
use std::process::Stdio;

const NGINX_CONF_PATH: &str = "/etc/nginx/nginx.conf";

/// Nginx configuration.
pub type NginxConfig = Vec<String>;

/// Parse Nginx configuration from `nginx -T` command stdout.
fn parse_nginx_config(content: String) -> NginxConfig {
    content
        .lines()
        // remove indentation
        .map(|line| line.trim_start())
        .filter(|line| !line.starts_with("#"))
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect()
}

/// Get the Nginx configuration by running `nginx -T`.
pub fn init_nginx_config() -> Result<NginxConfig, std::io::Error> {
    let mut cmd = process::Command::new("nginx");
    cmd.stdin(Stdio::null());
    cmd.args(vec!["-c", NGINX_CONF_PATH, "-T"]);

    let output = cmd.output()?;

    // TODO: error if not 0
    // match output.status.code() {
    //     Some(c) => c,
    //     None => 0,
    // }

    Ok(parse_nginx_config(
        String::from_utf8_lossy(&output.stdout).to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nginx_config() {
        let lines = parse_nginx_config(
            r##"nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
# configuration file /etc/nginx/nginx.conf:
pid /run/nginx/nginx.pid;
error_log stderr;
daemon off;
events {
}
http {
        # Load mime types and configure maximum size of the types hash tables.
        include /etc/nginx/mailcap-2.1.54/etc/nginx/mime.types;
        types_hash_max_size 2688;
        include /etc/nginx/nginx-1.26.2/conf/fastcgi.conf;
        include /etc/nginx/nginx-1.26.2/conf/uwsgi_params;
        default_type application/octet-stream;
        # optimisation
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
        ssl_dhparam /etc/nginx/ffdhe2048.txt;
        # Keep in sync with https://ssl-config.mozilla.org/#server=nginx&config=intermediate
        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:10m;
        # Breaks forward secrecy: https://github.com/mozilla/server-side-tls/issues/135
        ssl_session_tickets off;
        # We don't enable insecure ciphers by default, so this allows
        # clients to pick the most performant, per https://github.com/mozilla/server-side-tls/issues/260
        ssl_prefer_server_ciphers off;
        # OCSP stapling
        ssl_stapling on;
        ssl_stapling_verify on;
        gzip on;
        gzip_static on;
        gzip_vary on;
        gzip_comp_level 5;
        gzip_min_length 256;
        gzip_proxied expired no-cache no-store private auth;
        gzip_types application/atom+xml application/geo+json application/javascript application/json application/ld+json application/manifest+json application/rdf+xml application/vnd.ms-fontobject application/wasm application/x-rss+xml application/x-web-app-manifest+json application/xhtml+xml application/xliff+xml application/xml font/collection font/otf font/ttf image/bmp image/svg+xml image/vnd.microsoft.icon text/cache-manifest text/calendar text/css text/csv text/javascript text/markdown text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/xml;
        proxy_redirect          off;
        proxy_connect_timeout   60s;
        proxy_send_timeout      60s;
        proxy_read_timeout      60s;
        proxy_http_version      1.1;
        # don't let clients close the keep-alive connection to upstream. See the nginx blog for details:
        # https://www.nginx.com/blog/avoiding-top-10-nginx-configuration-mistakes/#no-keepalives
        proxy_set_header        "Connection" "";
        include /etc/nginx/nginx-recommended-proxy-headers.conf;
        # $connection_upgrade is used for websocket proxying
        map $http_upgrade $connection_upgrade {
                default upgrade;
                ''      close;
        }
        client_max_body_size 10m;
        server_tokens off;
        server {
                listen 0.0.0.0:80 default_server ;
                listen [::0]:80 default_server ;
                server_name example.com ;
                location / {
                        return 301 https://$host$request_uri;
                }
                location ^~ /.well-known/acme-challenge/ {
                        root /var/lib/acme/acme-challenge;
                        auth_basic off;
                        auth_request off;
                }
        }
        server {
                listen 0.0.0.0:443 ssl default_server ;
                listen [::0]:443 ssl default_server ;
                server_name example.com ;
                http2 on;
                ssl_certificate /var/lib/acme/example.com/fullchain.pem;
                ssl_certificate_key /var/lib/acme/example.com/key.pem;
                ssl_trusted_certificate /var/lib/acme/example.com/chain.pem;
                location ^~ /.well-known/acme-challenge/ {
                        root /var/lib/acme/acme-challenge;
                        auth_basic off;
                        auth_request off;
                }
                location / {
                        proxy_pass http://127.0.0.1:8080;
                        proxy_http_version 1.1;
                        proxy_set_header Upgrade $http_upgrade;
                        proxy_set_header Connection $connection_upgrade;
                        include /etc/nginx/nginx-recommended-proxy-headers.conf;
                }
                # disable access logging
                #access_log off;
        }
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Cross-Origin-Embedder-Policy "require-corp" always;
        add_header Cross-Origin-Resource-Policy "same-site" always;
        add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), interest-cohort=()" always;
        add_header X-DNS-Prefetch-Control "on" always;
        ssl_ecdh_curve X25519:prime256v1:secp384r1;
}

# configuration file /etc/nginx/recommended-proxy-headers.conf:
proxy_set_header        Host $host;
proxy_set_header        X-Real-IP $remote_addr;
proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header        X-Forwarded-Proto $scheme;
proxy_set_header        X-Forwarded-Host $host;
proxy_set_header        X-Forwarded-Server $host;
"##
            .to_string(),
        );
        assert_eq!(lines.len(), 95);
        assert!(lines.get(0).is_some());
    }
}
