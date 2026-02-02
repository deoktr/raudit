use crate::*;

pub fn add_checks() {
    check::Check::new(
        "SHL_001",
        "Ensure automatic logout from shells is configured",
        vec!["server", "shell", "server"],
        shell::check_shell_timeout,
        vec![],
    )
    .with_description("Avoid leaving opened shells, potentially with elevated permissions.")
    .with_link("https://wiki.archlinux.org/title/Security#Automatic_logout")
    .register();
}
