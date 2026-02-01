use crate::*;

pub fn add_checks() {
    check::Check::new(
        "HST_001",
        "Ensure localhost is resolved to 127.0.0.1 in hosts file",
        vec!["hosts", "server", "workstation"],
        || hosts::entry_present("127.0.0.1", "localhost"),
        vec![hosts::init_hosts],
    )
    .register();
    check::Check::new(
        "HST_002",
        "Ensure localhost is resolved to ::1 in hosts file",
        vec!["hosts", "server", "workstation"],
        || hosts::entry_present("::1", "localhost"),
        vec![hosts::init_hosts],
    )
    .register();
}
