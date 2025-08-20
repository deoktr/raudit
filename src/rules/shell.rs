use crate::*;

pub fn add_checks() {
    check::add_check(
        "SHL_001",
        "Ensure automatic logout from shells is configured",
        vec!["shell"],
        shell::check_shell_timeout,
        vec![],
    );
}
