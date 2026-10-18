use crate::check;
use crate::check::Severity;
use crate::modules::shell;

pub fn add_checks() {
    check::Check::new(
        "SHL_001",
        "Ensure automatic logout from shells is configured",
        Severity::High,
        vec!["shell", "server"],
        shell::check_shell_timeout,
        vec![],
    )
    .with_description("Avoid leaving opened shells, potentially with elevated permissions. Set readonly \"TMOUT\" shell variable in \"/etc/profile.d/timeout.sh\": \"\nTMOUT=900\nreadonly TMOUT\nexport TMOUT\"")
    .with_link("https://wiki.archlinux.org/title/Security#Automatic_logout")
    .register();
}
