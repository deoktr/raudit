use crate::check;
use crate::check::Severity;
use crate::modules::hosts;

const IPV4_LOCALHOST: &str = "Ensures localhost resolves to the IPv4 loopback address without relying on DNS, preventing spoofing and breakage of services that bind to, or trust localhost.";
const IPV6_LOCALHOST: &str = "Ensures localhost resolves to the IPv6 loopback address without relying on DNS, preventing spoofing and breakage of services that bind to, or trust localhost.";

pub fn add_checks() {
    check::Check::new(
        "HST_001",
        "Ensure localhost is resolved to 127.0.0.1 in hosts file",
        Severity::Low,
        vec!["hosts", "server", "workstation"],
        || hosts::entry_present("127.0.0.1", "localhost"),
        vec![hosts::init_hosts],
    )
    .with_description(IPV4_LOCALHOST)
    .with_fix("Add `127.0.0.1 localhost` to /etc/hosts.")
    .register();

    check::Check::new(
        "HST_002",
        "Ensure localhost.localdomain is resolved to 127.0.0.1 in hosts file",
        Severity::Low,
        vec!["hosts", "server", "workstation"],
        || hosts::entry_present("127.0.0.1", "localhost.localdomain"),
        vec![hosts::init_hosts],
    )
    .with_description(IPV4_LOCALHOST)
    .with_fix("Add `127.0.0.1 localhost.localdomain` to /etc/hosts.")
    .register();

    check::Check::new(
        "HST_003",
        "Ensure local is resolved to 127.0.0.1 in hosts file",
        Severity::Low,
        vec!["hosts", "server", "workstation"],
        || hosts::entry_present("127.0.0.1", "local"),
        vec![hosts::init_hosts],
    )
    .with_description(IPV4_LOCALHOST)
    .with_fix("Add `127.0.0.1 local` to /etc/hosts.")
    .register();

    check::Check::new(
        "HST_004",
        "Ensure localhost is resolved to ::1 in hosts file",
        Severity::Low,
        vec!["hosts", "server", "workstation"],
        || hosts::entry_present("::1", "localhost"),
        vec![hosts::init_hosts],
    )
    .with_description(IPV6_LOCALHOST)
    .with_fix("Add `::1 localhost` to /etc/hosts.")
    .register();

    check::Check::new(
        "HST_005",
        "Ensure ip6-localhost is resolved to ::1 in hosts file",
        Severity::Low,
        vec!["hosts", "server", "workstation"],
        || hosts::entry_present("::1", "ip6-localhost"),
        vec![hosts::init_hosts],
    )
    .with_description(IPV6_LOCALHOST)
    .with_fix("Add `::1 ip6-localhost` to /etc/hosts.")
    .register();

    check::Check::new(
        "HST_006",
        "Ensure ip6-loopback is resolved to ::1 in hosts file",
        Severity::Low,
        vec!["hosts", "server", "workstation"],
        || hosts::entry_present("::1", "ip6-loopback"),
        vec![hosts::init_hosts],
    )
    .with_description(IPV6_LOCALHOST)
    .with_fix("Add `::1 ip6-loopback` to /etc/hosts.")
    .register();

    check::Check::new(
        "HST_007",
        "Ensure 0.0.0.0 is resolved to 0.0.0.0 in hosts file",
        Severity::Low,
        vec!["hosts", "server", "workstation"],
        || hosts::entry_present("0.0.0.0", "0.0.0.0"),
        vec![hosts::init_hosts],
    )
    .with_description("Ensure 0.0.0.0 never resolves to an host.")
    .with_fix("Add `0.0.0.0 0.0.0.0` to /etc/hosts.")
    .register();
}
