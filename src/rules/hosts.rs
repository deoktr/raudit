use crate::check;
use crate::check::Severity;
use crate::modules::hosts;

pub fn add_checks() {
    check::Check::new(
        "HST_001",
        "Ensure localhost is resolved to 127.0.0.1 in hosts file",
        Severity::Low,
        vec!["hosts", "server", "workstation"],
        || hosts::entry_present("127.0.0.1", "localhost"),
        vec![hosts::init_hosts],
    )
    .with_description("Ensures localhost resolves to the IPv4 loopback address without relying on DNS, preventing spoofing and breakage of services that bind to, or trust localhost.")
    .register();

    check::Check::new(
        "HST_002",
        "Ensure localhost is resolved to ::1 in hosts file",
        Severity::Low,
        vec!["hosts", "server", "workstation"],
        || hosts::entry_present("::1", "localhost"),
        vec![hosts::init_hosts],
    )
    .with_description("Ensures localhost resolves to the IPv6 loopback address without relying on DNS, preventing spoofing and breakage of services that bind to, or trust localhost.")
    .register();
}
