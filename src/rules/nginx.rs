use crate::*;

pub fn add_checks() {
    check::Check::new(
        "NGX_001",
        "Ensure nginx server_tokens is set to off",
        vec!["nginx", "server"],
        || nginx::check_directive("server_tokens", "off"),
        vec![nginx::init_nginx_config],
    )
    .with_description("The server_tokens directive controls whether nginx sends its version number in error pages and the Server response header. Disabling it reduces information leakage.")
    .with_fix("Add \"server_tokens off;\" in the http block.")
    .register();

    check::Check::new(
        "NGX_002",
        "Ensure nginx X-Frame-Options header is set",
        vec!["nginx", "server"],
        || nginx::check_header_present("X-Frame-Options"),
        vec![nginx::init_nginx_config],
    )
    .with_description("The X-Frame-Options header prevents clickjacking attacks by controlling whether the page can be embedded in frames.")
    .with_fix("Add 'add_header X-Frame-Options \"DENY\" always;' in the http or server block.")
    .with_link("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options")
    .register();

    check::Check::new(
        "NGX_003",
        "Ensure nginx X-Content-Type-Options header is set",
        vec!["nginx", "server"],
        || nginx::check_header_present("X-Content-Type-Options"),
        vec![nginx::init_nginx_config],
    )
    .with_description("The X-Content-Type-Options header prevents MIME type sniffing, which can lead to XSS attacks.")
    .with_fix("Add 'add_header X-Content-Type-Options \"nosniff\" always;' in the http or server block.")
    .with_link("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options")
    .register();

    check::Check::new(
        "NGX_005",
        "Ensure nginx Strict-Transport-Security header is set",
        vec!["nginx", "server"],
        || nginx::check_header_present("Strict-Transport-Security"),
        vec![nginx::init_nginx_config],
    )
    .with_description("HSTS tells browsers to only connect over HTTPS, preventing protocol downgrade attacks and cookie hijacking.")
    .with_fix("Add 'add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;' in the http or server block.")
    .with_link("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security")
    .register();

    check::Check::new(
        "NGX_006",
        "Ensure nginx HTTP to HTTPS redirect is configured",
        vec!["nginx", "server"],
        nginx::check_https_redirect,
        vec![nginx::init_nginx_config],
    )
    .with_description("An HTTP to HTTPS redirect ensures all traffic is encrypted. Without it, users may inadvertently send data over unencrypted connections.")
    .with_fix("Add a server block listening on port 80 with 'return 301 https://$host$request_uri;'.")
    .register();
}
