use crate::check;
use crate::check::Severity;
use crate::modules::shell;

pub fn add_checks() {
    check::Check::new(
        "SHL_001",
        "Ensure automatic logout from shells is configured",
        Severity::Medium,
        vec!["server", "shell", "server"],
        shell::check_shell_timeout,
        vec![],
    )
    .with_description("Avoid leaving opened shells, potentially with elevated permissions.")
    .with_link("https://wiki.archlinux.org/title/Security#Automatic_logout")
    .register();
}
