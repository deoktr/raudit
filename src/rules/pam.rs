use crate::check;
use crate::check::Severity;
use crate::modules::pam;

pub fn add_checks() {
    check::Check::new(
        "PAM_001",
        "Ensure PAM service `passwd` has rule `account required pam_unix`",
        Severity::High,
        vec!["pam", "server", "workstation"],
        || pam::check_rule("passwd", "account", "required", "pam_unix"),
        vec![pam::init_pam],
    )
    .with_description("Without `pam_unix` enforcing account validity on password changes, expired or locked accounts could still rotate credentials and regain interactive access, undermining account-lifecycle controls.")
    .with_fix("Add `account required pam_unix.so` to `/etc/pam.d/passwd`.")
    .register();

    // TODO: add pam_pwquality configuration
    check::Check::new(
        "PAM_002",
        "Ensure PAM service `passwd` has rule `password required pam_pwquality`",
        Severity::High,
        vec!["pam", "server", "workstation"],
        || pam::check_rule("passwd", "password", "required", "pam_pwquality"),
        vec![pam::init_pam],
    )
    .with_description("Enforce password policy.")
    .with_fix("Add `password required pam_pwquality.so` to `/etc/pam.d/passwd`.")
    .register();

    check::Check::new(
        "PAM_003",
        "Ensure PAM service `passwd` hashes new passwords with yescrypt",
        Severity::High,
        vec!["pam", "server", "workstation"],
        || pam::check_yescrypt("passwd", "password", "required", "pam_unix"),
        vec![pam::init_pam],
    )
    .with_description("yescrypt is memory-hard, cracking a leaked `/etc/shadow` costs orders of magnitude more than against the MD5 or SHA-crypt hashes an explicit `pam_unix` algorithm flag selects. A rule setting no algorithm flag is accepted, `pam_unix` then takes the default from `ENCRYPT_METHOD` in `/etc/login.defs`. Hashing a password is slower than with SHA-crypt, only noticeable on password changes.")
    .with_fix("Add `yescrypt` to the `pam_unix` rule of the password stack, `password required pam_unix.so yescrypt` in `/etc/pam.d/passwd` (or `common-password`), and remove any weaker algorithm flag (`sha512`, `sha256`, `md5`...).")
    .register();

    check::Check::new(
        "PAM_004",
        "Ensure no PAM `auth` rule of `pam_unix` has flag `nullok`",
        Severity::High,
        vec!["pam", "server", "workstation"],
        || pam::check_no_rule_flag("auth", "pam_unix", "nullok"),
        vec![pam::init_pam],
    )
    .with_description("By default `pam_unix` refuses an account whose password is blank, `nullok` lifts that and lets anyone authenticate as an account with an empty password field in `/etc/shadow`. Those accounts come from a `useradd` without a password, a broken migration, or an attacker able to clear a hash, and they skip the password factor of every module the stack runs after `pam_unix` succeeded, lockout and second factor included.")
    .with_fix("Remove `nullok` from the `pam_unix` rules of `/etc/pam.d/`, listed by `grep -rl nullok /etc/pam.d/`, usually `common-auth` or `system-auth`, then set a password or lock every account with a blank one.")
    .register();

    check::Check::new(
        "PAM_005",
        "Ensure PAM service `passwd` remembers at least 5 previous passwords",
        Severity::Medium,
        vec!["pam", "server", "workstation"],
        || {
            const VAL: i32 = 5;

            match pam::get_rule_flag("passwd", "password", "required", "pam_pwhistory", "remember")
            {
                Ok(Some(value)) => match value.parse::<i32>() {
                    Ok(val) => {
                        if val < VAL {
                            return (
                                check::CheckState::Fail,
                                Some(format!("`remember={}` < {}", val, VAL)),
                            );
                        }
                        // the history is only enforced while `pam_pwhistory`
                        // runs before `pam_unix` writes the new hash
                        match pam::check_rule_before(
                            "passwd",
                            "password",
                            "required",
                            "pam_pwhistory",
                            "required",
                            "pam_unix",
                        ) {
                            (check::CheckState::Pass, _) => (check::CheckState::Pass, Some(value)),
                            order => order,
                        }
                    }
                    Err(err) => (
                        check::CheckState::Warning,
                        Some(format!("`remember={}`: {}", value, err)),
                    ),
                },
                Ok(None) => (
                    check::CheckState::Fail,
                    Some(
                        "no `password required pam_pwhistory` rule with flag `remember`".to_string(),
                    ),
                ),
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![pam::init_pam],
    )
    .with_description("Without password history a user rotates between two passwords and comes back to the original, defeating the rotation and keeping valid a hash an attacker may already have cracked. Only `pam_pwhistory` is accepted, the `remember` flag of `pam_unix` is deprecated and stores the previous passwords as MD5 hashes. The rule must also run before `pam_unix`, the module changing the password: placed after it, a reused password is already written to `/etc/shadow` when `pam_pwhistory` reports the reuse, `passwd` prints its rejection but the change stands. History is kept in `/etc/security/opasswd`, which must stay readable by root only.")
    .with_fix("Add `password required pam_pwhistory.so remember=5 use_authtok` to `/etc/pam.d/passwd` (or `common-password`), before the `pam_unix` rule that writes the new password.")
    .register();

    check::Check::new(
        "PAM_015",
        "Ensure PAM service `su` has rule `auth required pam_wheel`",
        Severity::High,
        vec!["pam", "server", "workstation"],
        || pam::check_rule("su", "auth", "required", "pam_wheel"),
        vec![pam::init_pam],
    )
    .with_description("Without `pam_wheel` gating `su`, any compromised local account can attempt root password attacks. Restricting `su` to a single privileged group narrows the privilege-escalation path and aids audit attribution.")
    .with_fix("Add `auth required pam_wheel.so use_uid` to `/etc/pam.d/su` and add the intended admins to the `wheel` group.")
    .register();

    // TODO: configure in /etc/security/faillock.conf
    check::Check::new(
        "PAM_024",
        "Ensure PAM service `login` has rule `auth required pam_faillock`",
        Severity::High,
        vec!["pam", "server"],
        || pam::check_rule("login", "auth", "required", "pam_faillock"),
        vec![pam::init_pam],
    )
    .with_description("Without `pam_faillock` locking accounts after repeated failed logins, an attacker with console or terminal access can brute-force passwords. Legitimate users who mistype their password too many times will have their account locked out, requiring administrator intervention to unlock.")
    .with_fix("Add `auth required pam_faillock.so preauth` and `auth [default=die] pam_faillock.so authfail` entries to `/etc/pam.d/login` (or common-auth).")
    .register();

    check::Check::new(
        "PAM_030",
        "Ensure PAM service `login` has rule `auth optional pam_faildelay`",
        Severity::Medium,
        vec!["pam", "server", "workstation"],
        || pam::check_rule("login", "auth", "optional", "pam_faildelay"),
        vec![pam::init_pam],
    )
    .with_description("`pam_faildelay` adds a randomized pause after failed authentications, defeating timing side channels that distinguish unknown user from wrong password. Adds latency to failed login attempts, which may be noticeable in automated login scripts or rapid retry scenarios.")
    .with_fix("Add `auth optional pam_faildelay.so delay=4000000` to `/etc/pam.d/login`.")
    .register();
}
