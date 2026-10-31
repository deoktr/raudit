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

use std::process;
use std::process::Stdio;

use crate::check::State;
use crate::{check, utils};

const NGINX_CONF_PATH: &str = "/etc/nginx/nginx.conf";

static NGINX_CONFIG: State<NginxConfig> = State::new("nginx configuration");

/// A single nginx configuration directive (key = value).
#[derive(Debug, Clone)]
struct NginxDirective {
    name: String,
    value: String,
}

/// A named block context (http, server, location, events, etc.).
#[derive(Debug, Clone)]
struct NginxBlock {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    args: String,
    directives: Vec<NginxDirective>,
    blocks: Vec<NginxBlock>,
}

/// Top-level nginx configuration.
#[derive(Debug, Clone)]
struct NginxConfig {
    directives: Vec<NginxDirective>,
    blocks: Vec<NginxBlock>,
}

/// Skip if nginx is not installed
pub fn skip_no_nginx() -> bool {
    utils::which("nginx").is_none()
}

/// Parse nginx -T output into a structured config.
fn parse_nginx_config(content: &str) -> NginxConfig {
    let lines: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .filter(|l| !l.starts_with('#'))
        // Skip nginx -T header lines
        .filter(|l| !l.starts_with("nginx:"))
        .collect();
    let mut pos = 0;
    let (directives, blocks) = parse_block_contents(&lines, &mut pos);
    NginxConfig { directives, blocks }
}

/// Parse the contents of a block (or root level) until end or closing brace.
fn parse_block_contents(lines: &[&str], pos: &mut usize) -> (Vec<NginxDirective>, Vec<NginxBlock>) {
    let mut directives = Vec::new();
    let mut blocks = Vec::new();

    while *pos < lines.len() {
        let line = lines[*pos];

        // end of current block
        if line == "}" {
            *pos += 1;
            break;
        }

        // start of a new block
        if line.ends_with('{') || line.contains('{') {
            let block_header = line.trim_end_matches('{').trim();
            let (name, args) = match block_header.split_once(' ') {
                Some((n, a)) => (n.to_string(), a.trim().to_string()),
                None => (block_header.to_string(), String::new()),
            };
            *pos += 1;
            let (child_directives, child_blocks) = parse_block_contents(lines, pos);
            blocks.push(NginxBlock {
                name,
                args,
                directives: child_directives,
                blocks: child_blocks,
            });
            continue;
        }

        // regular directive
        if line.ends_with(';') {
            let content = line.trim_end_matches(';').trim();
            if let Some((name, value)) = content.split_once(' ') {
                directives.push(NginxDirective {
                    name: name.to_string(),
                    value: value.trim().to_string(),
                });
            } else {
                directives.push(NginxDirective {
                    name: content.to_string(),
                    value: String::new(),
                });
            }
        }
        *pos += 1;
    }
    (directives, blocks)
}

/// Get the first directive with the given name, searching recursively.
#[allow(dead_code)]
pub fn get_directive(name: &str) -> Option<String> {
    let config = NGINX_CONFIG.try_get().ok()?;
    find_directive_in_config(config, name)
}

/// Find a directive in the config tree.
fn find_directive_in_config(config: &NginxConfig, name: &str) -> Option<String> {
    for d in &config.directives {
        if d.name == name {
            return Some(d.value.clone());
        }
    }
    for block in &config.blocks {
        if let Some(v) = find_directive_in_block(block, name) {
            return Some(v);
        }
    }
    None
}

/// Find a directive recursively in a block.
fn find_directive_in_block(block: &NginxBlock, name: &str) -> Option<String> {
    for d in &block.directives {
        if d.name == name {
            return Some(d.value.clone());
        }
    }
    for child in &block.blocks {
        if let Some(v) = find_directive_in_block(child, name) {
            return Some(v);
        }
    }
    None
}

/// Get all directives with the given name, searching recursively.
#[allow(dead_code)]
pub fn get_directives(name: &str) -> Vec<String> {
    let config = match NGINX_CONFIG.try_get() {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let mut results = Vec::new();
    collect_directives_from_config(config, name, &mut results);
    results
}

/// Collect all matching directives from config.
fn collect_directives_from_config(config: &NginxConfig, name: &str, results: &mut Vec<String>) {
    for d in &config.directives {
        if d.name == name {
            results.push(d.value.clone());
        }
    }
    for block in &config.blocks {
        collect_directives_from_block(block, name, results);
    }
}

/// Collect all matching directives from a block recursively.
fn collect_directives_from_block(block: &NginxBlock, name: &str, results: &mut Vec<String>) {
    for d in &block.directives {
        if d.name == name {
            results.push(d.value.clone());
        }
    }
    for child in &block.blocks {
        collect_directives_from_block(child, name, results);
    }
}

/// Check if an add_header directive exists with the given header name.
#[allow(dead_code)]
pub fn has_header(header_name: &str) -> bool {
    let headers = get_directives("add_header");
    headers.iter().any(|v| v.starts_with(header_name))
}

/// Check a directive value against an expected value.
#[allow(dead_code)]
pub fn check_directive(name: &str, expected: &str) -> check::CheckReturn {
    NGINX_CONFIG.with(|config| match find_directive_in_config(config, name) {
        Some(value) => {
            if value == expected {
                (check::CheckState::Pass, None)
            } else {
                (
                    check::CheckState::Fail,
                    Some(format!("`{}` != `{}`", value, expected)),
                )
            }
        }
        None => (
            check::CheckState::Fail,
            Some(format!("directive `{}` not found", name)),
        ),
    })
}

/// Check that a directive does NOT contain a forbidden substring.
#[allow(dead_code)]
pub fn check_directive_not_contains(name: &str, forbidden: &str) -> check::CheckReturn {
    NGINX_CONFIG.with(|config| match find_directive_in_config(config, name) {
        Some(value) => {
            if value.contains(forbidden) {
                (
                    check::CheckState::Fail,
                    Some(format!("`{}` contains `{}`", value, forbidden)),
                )
            } else {
                (check::CheckState::Pass, Some(value))
            }
        }
        None => (
            check::CheckState::Fail,
            Some(format!("directive `{}` not found", name)),
        ),
    })
}

/// Check that every instance of a directive has the expected value.
///
/// Unlike [`check_directive`] which returns the first match, a per-server
/// override is reported, for example `server_tokens off` in http and
/// `server_tokens on` in one server leaks the version for that vhost.
pub fn check_all_directives(name: &str, expected: &str) -> check::CheckReturn {
    NGINX_CONFIG.with(|config| {
        let mut values = Vec::new();
        collect_directives_from_config(config, name, &mut values);

        if values.is_empty() {
            return (
                check::CheckState::Fail,
                Some(format!("directive `{}` not found", name)),
            );
        }

        let unexpected: Vec<&str> = values
            .iter()
            .map(|value| value.as_str())
            .filter(|value| *value != expected)
            .collect();

        if unexpected.is_empty() {
            (check::CheckState::Pass, None)
        } else {
            (
                check::CheckState::Fail,
                Some(format!(
                    "`{}` found with value `{}`",
                    name,
                    unexpected.join("`, `")
                )),
            )
        }
    })
}

/// Whether an `add_header` value carries the `always` flag, without it the
/// header is not sent on error responses.
fn header_value_has_always(value: &str) -> bool {
    value.split_whitespace().any(|token| token == "always")
}

/// Check that a header is effectively applied by every server and location.
///
/// nginx only inherits the parent `add_header` directives into a block that
/// defines none of its own, a location with a single unrelated `add_header`
/// silently drops the http-level security headers. Walking the tree with the
/// inheritance rules catches it, and the `always` flag is required so the
/// header is also sent on 4xx/5xx responses.
pub fn check_header_present(header_name: &str) -> check::CheckReturn {
    NGINX_CONFIG.with(|config| match config_missing_header(config, header_name) {
        Some(message) => (check::CheckState::Fail, Some(message)),
        None => (check::CheckState::Pass, None),
    })
}

/// First context missing `header_name`, `None` when the header is effective
/// everywhere.
///
/// `nginx -T` dumps the included files flattened: the http-level `add_header`
/// of a conf.d drop-in lands at the root of the output, out of the `http`
/// block. Root-level `add_header` directives are not valid nginx outside of a
/// dump, they are the http-level ones, seed the inheritance with them.
fn config_missing_header(config: &NginxConfig, header_name: &str) -> Option<String> {
    let root_headers: Vec<String> = config
        .directives
        .iter()
        .filter(|directive| directive.name == "add_header")
        .map(|directive| directive.value.clone())
        .collect();

    for block in &config.blocks {
        if let Some(message) = check_block_headers(block, &root_headers, header_name) {
            return Some(message);
        }
    }
    None
}

/// Walk `block` and its children, `inherited` holds the `add_header` values
/// in effect from the parents, returns the first context missing the
/// `header_name` header.
fn check_block_headers(
    block: &NginxBlock,
    inherited: &[String],
    header_name: &str,
) -> Option<String> {
    let own: Vec<String> = block
        .directives
        .iter()
        .filter(|directive| directive.name == "add_header")
        .map(|directive| directive.value.clone())
        .collect();
    // a block defining any add_header of its own drops the inherited ones
    let effective: &[String] = if own.is_empty() { inherited } else { &own };

    let context = if block.args.is_empty() {
        block.name.clone()
    } else {
        format!("{} {}", block.name, block.args)
    };

    if matches!(block.name.as_str(), "server" | "location") {
        let matching: Vec<&String> = effective
            .iter()
            .filter(|value| value.starts_with(header_name))
            .collect();

        if matching.is_empty() {
            return Some(format!(
                "header `{}` not applied in `{}`",
                header_name, context
            ));
        }
        if !matching.iter().any(|value| header_value_has_always(value)) {
            return Some(format!(
                "header `{}` without the `always` flag in `{}`",
                header_name, context
            ));
        }
    }

    for child in &block.blocks {
        if let Some(message) = check_block_headers(child, effective, header_name) {
            return Some(message);
        }
    }

    None
}

/// Whether a `listen` directive value listens on the port 80.
fn listen_is_http(value: &str) -> bool {
    let Some(address) = value.split_whitespace().next() else {
        return false;
    };
    let port = match address.rsplit_once(':') {
        Some((_, port)) => port,
        None => address,
    };
    port == "80"
}

/// Collect every `server` block of the tree.
fn collect_server_blocks<'a>(block: &'a NginxBlock, servers: &mut Vec<&'a NginxBlock>) {
    if block.name == "server" {
        servers.push(block);
    }
    for child in &block.blocks {
        collect_server_blocks(child, servers);
    }
}

/// Whether a server listens on the port 80, a server without any `listen`
/// directive listens on the port 80 by default.
fn server_listens_on_http(server: &NginxBlock) -> bool {
    let listens: Vec<&str> = server
        .directives
        .iter()
        .filter(|directive| directive.name == "listen")
        .map(|directive| directive.value.as_str())
        .collect();

    listens.is_empty() || listens.iter().any(|value| listen_is_http(value))
}

/// Whether a block or one of its children redirects to HTTPS.
fn block_redirects_to_https(block: &NginxBlock) -> bool {
    block
        .directives
        .iter()
        .any(|directive| match directive.name.as_str() {
            "return" => {
                let code = directive
                    .value
                    .split_whitespace()
                    .next()
                    .unwrap_or_default();
                matches!(code, "301" | "302" | "307" | "308") && directive.value.contains("https")
            }
            "rewrite" => directive.value.contains("https"),
            _ => false,
        })
        || block.blocks.iter().any(block_redirects_to_https)
}

/// The `server_name` of a server block, for messages.
fn server_name(server: &NginxBlock) -> String {
    server
        .directives
        .iter()
        .find(|directive| directive.name == "server_name")
        .map(|directive| directive.value.clone())
        .unwrap_or_else(|| "default".to_string())
}

/// Check that the HTTP traffic is redirected to HTTPS.
///
/// Every server listening on the port 80 must hold the redirect, a `return`
/// in an unrelated vhost does not protect the others. A configuration
/// without any port 80 listener serves no plaintext HTTP and passes.
pub fn check_https_redirect() -> check::CheckReturn {
    NGINX_CONFIG.with(|config| {
        let mut servers: Vec<&NginxBlock> = Vec::new();
        for block in &config.blocks {
            collect_server_blocks(block, &mut servers);
        }

        let offenders: Vec<String> = servers
            .iter()
            .filter(|server| server_listens_on_http(server))
            .filter(|server| !block_redirects_to_https(server))
            .map(|server| server_name(server))
            .collect();

        if offenders.is_empty() {
            (check::CheckState::Pass, None)
        } else {
            (
                check::CheckState::Fail,
                Some(format!(
                    "server{} listening on port 80 without an HTTPS redirect: `{}`",
                    if offenders.len() > 1 { "s" } else { "" },
                    offenders.join("`, `")
                )),
            )
        }
    })
}

/// Get nginx config by running `nginx -T`.
fn get_nginx_config() -> Result<NginxConfig, String> {
    let mut cmd = process::Command::new("nginx");
    cmd.stdin(Stdio::null());
    cmd.args(["-c", NGINX_CONF_PATH, "-T"]);

    let output = cmd
        .output()
        .map_err(|err| format!("failed to run `nginx -c {} -T`: {}", NGINX_CONF_PATH, err))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();

        return Err(if stderr.is_empty() {
            format!("`nginx -c {} -T` {}", NGINX_CONF_PATH, output.status)
        } else {
            format!(
                "`nginx -c {} -T` {}: {}",
                NGINX_CONF_PATH, output.status, stderr
            )
        });
    }

    Ok(parse_nginx_config(&String::from_utf8_lossy(&output.stdout)))
}

/// Init nginx configuration by running `nginx -T`.
pub fn init_nginx_config() {
    NGINX_CONFIG.init(get_nginx_config);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = r##"nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
# configuration file /etc/nginx/nginx.conf:
pid /run/nginx/nginx.pid;
error_log stderr;
daemon off;
events {
}
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    server_tokens off;
    server {
        listen 0.0.0.0:80 default_server;
        server_name example.com;
        location / {
            return 301 https://$host$request_uri;
        }
    }
    server {
        listen 0.0.0.0:443 ssl default_server;
        server_name example.com;
        http2 on;
        ssl_certificate /var/lib/acme/example.com/fullchain.pem;
        ssl_certificate_key /var/lib/acme/example.com/key.pem;
        location / {
            proxy_pass http://127.0.0.1:8080;
        }
    }
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}
"##;

    #[test]
    fn test_parse_top_level_directives() {
        let config = parse_nginx_config(SAMPLE_CONFIG);
        assert!(config.directives.len() >= 3);
        assert!(
            config
                .directives
                .iter()
                .any(|d| d.name == "pid" && d.value == "/run/nginx/nginx.pid")
        );
        assert!(
            config
                .directives
                .iter()
                .any(|d| d.name == "error_log" && d.value == "stderr")
        );
    }

    #[test]
    fn test_parse_block_structure() {
        let config = parse_nginx_config(SAMPLE_CONFIG);
        // should have events and http blocks
        assert!(config.blocks.iter().any(|b| b.name == "events"));
        assert!(config.blocks.iter().any(|b| b.name == "http"));

        let http = config.blocks.iter().find(|b| b.name == "http").unwrap();
        // http block should have server sub-blocks
        let servers: Vec<&NginxBlock> = http.blocks.iter().filter(|b| b.name == "server").collect();
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn test_parse_nested_blocks() {
        let config = parse_nginx_config(SAMPLE_CONFIG);
        let http = config.blocks.iter().find(|b| b.name == "http").unwrap();
        let server = http.blocks.iter().find(|b| b.name == "server").unwrap();
        // First server should have a location block
        let locations: Vec<&NginxBlock> = server
            .blocks
            .iter()
            .filter(|b| b.name == "location")
            .collect();
        assert_eq!(locations.len(), 1);
    }

    #[test]
    fn test_parse_directives_in_blocks() {
        let config = parse_nginx_config(SAMPLE_CONFIG);
        let http = config.blocks.iter().find(|b| b.name == "http").unwrap();

        assert!(
            http.directives
                .iter()
                .any(|d| d.name == "ssl_protocols" && d.value == "TLSv1.2 TLSv1.3")
        );
        assert!(
            http.directives
                .iter()
                .any(|d| d.name == "server_tokens" && d.value == "off")
        );
    }

    #[test]
    fn test_find_directive() {
        let config = parse_nginx_config(SAMPLE_CONFIG);
        let result = find_directive_in_config(&config, "ssl_protocols");
        assert_eq!(result, Some("TLSv1.2 TLSv1.3".to_string()));

        let result = find_directive_in_config(&config, "server_tokens");
        assert_eq!(result, Some("off".to_string()));

        let result = find_directive_in_config(&config, "nonexistent");
        assert_eq!(result, None);
    }

    #[test]
    fn test_collect_directives() {
        let config = parse_nginx_config(SAMPLE_CONFIG);
        let mut results = Vec::new();
        collect_directives_from_config(&config, "add_header", &mut results);
        assert_eq!(results.len(), 4);
        assert!(results.iter().any(|v| v.starts_with("X-Frame-Options")));
        assert!(
            results
                .iter()
                .any(|v| v.starts_with("Strict-Transport-Security"))
        );
    }

    #[test]
    fn test_comments_and_empty_lines_filtered() {
        let config =
            parse_nginx_config("# this is a comment\n\npid /run/nginx.pid;\n# another comment\n");
        assert_eq!(config.directives.len(), 1);
        assert_eq!(config.directives[0].name, "pid");
    }

    #[test]
    fn test_nginx_header_lines_filtered() {
        let config = parse_nginx_config(
            "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful\npid /run/nginx.pid;\n",
        );
        assert_eq!(config.directives.len(), 1);
    }

    const INHERITANCE_CONFIG: &str = r##"
http {
    server_tokens off;
    add_header X-Frame-Options "DENY" always;
    server {
        listen 80 default_server;
        server_name _;
        return 301 https://$host$request_uri;
    }
    server {
        listen 443 ssl;
        server_name example.com;
        server_tokens on;
        location / {
            add_header X-Custom "1" always;
            return 200 "ok";
        }
        location /safe {
            root /var/www;
        }
    }
}
"##;

    #[test]
    fn test_header_inheritance_dropped_by_own_add_header() {
        let config = parse_nginx_config(INHERITANCE_CONFIG);
        // the location defining its own add_header drops the inherited
        // http-level X-Frame-Options
        let message = config_missing_header(&config, "X-Frame-Options")
            .expect("the leaky location must be reported");
        assert!(message.contains("location /"), "{}", message);
        // a header only set in one location is missing everywhere else
        let message =
            config_missing_header(&config, "X-Custom").expect("X-Custom is not applied everywhere");
        assert!(message.contains("server"), "{}", message);
    }

    #[test]
    fn test_header_requires_always() {
        let config = parse_nginx_config(
            "http {\n    add_header X-Frame-Options \"DENY\";\n    server {\n        listen 80;\n    }\n}\n",
        );
        let message =
            config_missing_header(&config, "X-Frame-Options").expect("the always flag is missing");
        assert!(message.contains("always"), "{}", message);
    }

    #[test]
    fn test_header_from_flattened_conf_d_include() {
        // `nginx -T` flattens the included files, the http-level add_header
        // and the server block of a conf.d drop-in land at the root of the
        // dump, out of the http block
        let config = parse_nginx_config(
            "http {\n    include /etc/nginx/conf.d/*.conf;\n}\nadd_header X-Frame-Options \"DENY\" always;\nserver {\n    listen 80 default_server;\n    server_name _;\n    return 301 https://$host$request_uri;\n}\n",
        );
        assert!(config_missing_header(&config, "X-Frame-Options").is_none());
    }

    #[test]
    fn test_listen_is_http() {
        assert!(listen_is_http("80"));
        assert!(listen_is_http("80 default_server"));
        assert!(listen_is_http("0.0.0.0:80"));
        assert!(listen_is_http("[::]:80 ipv6only=on"));
        assert!(!listen_is_http("443 ssl"));
        assert!(!listen_is_http("8080"));
        assert!(!listen_is_http("[::]:443 ssl"));
        assert!(!listen_is_http("unix:/run/nginx.sock"));
    }

    #[test]
    fn test_https_redirect_anchored_to_port_80_servers() {
        let config = parse_nginx_config(INHERITANCE_CONFIG);
        let mut servers = Vec::new();
        for block in &config.blocks {
            collect_server_blocks(block, &mut servers);
        }
        assert_eq!(servers.len(), 2);
        assert!(server_listens_on_http(servers[0]));
        assert!(block_redirects_to_https(servers[0]));
        assert!(!server_listens_on_http(servers[1]));

        // a server without any listen directive listens on the port 80 by
        // default and must hold the redirect
        let config = parse_nginx_config("http {\n    server {\n        server_name x;\n    }\n}\n");
        let mut servers = Vec::new();
        for block in &config.blocks {
            collect_server_blocks(block, &mut servers);
        }
        assert!(server_listens_on_http(servers[0]));
        assert!(!block_redirects_to_https(servers[0]));
    }
}
