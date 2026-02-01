use crate::*;

pub fn add_checks() {
    check::Check::new(
        "SHL_001",
        "Ensure automatic logout from shells is configured",
        vec!["server", "shell", "server"],
        shell::check_shell_timeout,
        vec![],
    )
    .register();
}
