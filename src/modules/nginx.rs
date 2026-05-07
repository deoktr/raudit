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
use std::sync::OnceLock;

use crate::{check, log_debug, log_error, utils};

const NGINX_CONF_PATH: &str = "/etc/nginx/nginx.conf";

static NGINX_CONFIG: OnceLock<NginxConfig> = OnceLock::new();

/// A single nginx configuration directive (key = value).
#[derive(Debug, Clone)]
pub struct NginxDirective {
    pub name: String,
    pub value: String,
}

/// A named block context (http, server, location, events, etc.).
#[derive(Debug, Clone)]
pub struct NginxBlock {
    pub name: String,
    pub args: String,
    pub directives: Vec<NginxDirective>,
    pub blocks: Vec<NginxBlock>,
}

/// Top-level nginx configuration.
#[derive(Debug, Clone)]
pub struct NginxConfig {
    pub directives: Vec<NginxDirective>,
    pub blocks: Vec<NginxBlock>,
}

/// Skip if nginx is not installed
pub fn skip_no_nginx() -> bool {
    utils::which("nginx").is_none()
}

/// Parse nginx -T output into a structured config.
pub fn parse_nginx_config(content: &str) -> NginxConfig {
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
pub fn get_directive(name: &str) -> Option<String> {
    let config = NGINX_CONFIG.get()?;
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
pub fn get_directives(name: &str) -> Vec<String> {
    let config = match NGINX_CONFIG.get() {
        Some(c) => c,
        None => return vec![],
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
pub fn has_header(header_name: &str) -> bool {
    let headers = get_directives("add_header");
    headers.iter().any(|v| v.starts_with(header_name))
}

/// Check a directive value against an expected value.
pub fn check_directive(name: &str, expected: &str) -> check::CheckReturn {
    let config = match NGINX_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Warning,
                Some("nginx configuration not initialized".to_string()),
            );
        }
    };

    match find_directive_in_config(config, name) {
        Some(value) => {
            if value == expected {
                (check::CheckState::Pass, None)
            } else {
                (
                    check::CheckState::Fail,
                    Some(format!("{:?} != {:?}", value, expected)),
                )
            }
        }
        None => (
            check::CheckState::Fail,
            Some(format!("directive {:?} not found", name)),
        ),
    }
}

/// Check that a directive does NOT contain a forbidden substring.
pub fn check_directive_not_contains(name: &str, forbidden: &str) -> check::CheckReturn {
    let config = match NGINX_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Warning,
                Some("nginx configuration not initialized".to_string()),
            );
        }
    };

    match find_directive_in_config(config, name) {
        Some(value) => {
            if value.contains(forbidden) {
                (
                    check::CheckState::Fail,
                    Some(format!("{:?} contains {:?}", value, forbidden)),
                )
            } else {
                (check::CheckState::Pass, Some(value))
            }
        }
        None => (
            check::CheckState::Fail,
            Some(format!("directive {:?} not found", name)),
        ),
    }
}

/// Check that a specific add_header exists.
pub fn check_header_present(header_name: &str) -> check::CheckReturn {
    let config = match NGINX_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Warning,
                Some("nginx configuration not initialized".to_string()),
            );
        }
    };

    let mut results = Vec::new();
    collect_directives_from_config(config, "add_header", &mut results);

    if results.iter().any(|v| v.starts_with(header_name)) {
        (check::CheckState::Pass, None)
    } else {
        (
            check::CheckState::Fail,
            Some(format!("header {:?} not found", header_name)),
        )
    }
}

/// Check that an HTTPS redirect exists (return 301 https).
pub fn check_https_redirect() -> check::CheckReturn {
    let config = match NGINX_CONFIG.get() {
        Some(c) => c,
        None => {
            return (
                check::CheckState::Warning,
                Some("nginx configuration not initialized".to_string()),
            );
        }
    };

    let mut results = Vec::new();
    collect_directives_from_config(config, "return", &mut results);

    if results
        .iter()
        .any(|v| v.contains("301") && v.contains("https"))
    {
        (check::CheckState::Pass, None)
    } else {
        (
            check::CheckState::Fail,
            Some("no HTTP to HTTPS redirect found".to_string()),
        )
    }
}

/// Get nginx config by running `nginx -T`.
fn get_nginx_config() -> Result<NginxConfig, String> {
    let mut cmd = process::Command::new("nginx");
    cmd.stdin(Stdio::null());
    cmd.args(["-c", NGINX_CONF_PATH, "-T"]);

    let output = cmd.output().map_err(|e| e.to_string())?;

    if let Some(code) = output.status.code()
        && code != 0 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("nginx -T exited with code {}: {}", code, stderr));
        }

    Ok(parse_nginx_config(&String::from_utf8_lossy(&output.stdout)))
}

/// Init nginx configuration by running `nginx -T`.
pub fn init_nginx_config() {
    if NGINX_CONFIG.get().is_some() {
        return;
    }

    match get_nginx_config() {
        Ok(c) => {
            NGINX_CONFIG.get_or_init(|| c);
            log_debug!("initialized nginx config");
        }
        Err(err) => log_error!("failed to initialize nginx configuration: {}", err),
    }
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
}
