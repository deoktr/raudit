use crate::check;
use crate::check::Severity;
use crate::modules::pam;

// PAM stacks are per service, the checks below name the service they audit
// (`passwd`, `su`, `login`) but on the distros splitting their stacks the rule
// lives in an included file (`common-password`, `system-auth`...), the module
// flattens the includes so both layouts are read the same way.
//
// FIXME:
// The thresholds of the modules (`minlen`, `deny`, `unlock_time`...) can be set
// on the rule or in the configuration file of the module
// (`/etc/security/pwquality.conf`, `/etc/security/faillock.conf`...), the rule
// winning over the file. Only the rules are read, a threshold left to a
// configuration file is reported as undetermined instead of guessed.

pub fn add_checks() {
    check::Check::new(
        "PAM_001",
        "Ensure PAM service `passwd` has rule `account required pam_unix`",
        Severity::High,
        vec!["pam", "server", "workstation"],
        || pam::check_rule("passwd", "account", "required", "pam_unix"),
        vec![pam::init_pam],
    )
    .with_description("The account stack validates the account, the auth stack only validates the password: `pam_unix` reads the shadow entry (expiry date, last change, maximum and minimum age) and refuses an account that is administratively expired or out of its validity window. Without it `passwd` renews the credentials of accounts that were taken out of service, one expired with `chage -E` keeps rotating its password instead of being sent to an administrator, and a reset run by root, a helpdesk script or a provisioning tool puts a fresh working password on an account the lifecycle says is disabled. A service file that only pulls in the password stack has no account stack at all, which is what several distributions ship, so this fails on a stock install rather than on a weakened one.")
    .with_fix("Add an account stack to `/etc/pam.d/passwd`, `@include common-account` where the stacks are split into shared files (before `@include common-password`), `account required pam_unix.so` followed by `account requisite pam_deny.so` otherwise. The bracketed control the shared account files often ship, `account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so`, is accepted as well and lets an expired password go through the change instead of refusing it.")
    .register();

    // TODO: read the thresholds from /etc/security/pwquality.conf, only the ones
    // written on the rule are seen here
    check::Check::new(
        "PAM_002",
        "Ensure PAM service `passwd` enforces password quality with `pam_pwquality`",
        Severity::High,
        vec!["pam", "server", "workstation"],
        || {
            check::require_all([
                pam::check_rule("passwd", "password", "required", "pam_pwquality"),
                pam::check_rule_flag_min(
                    "passwd",
                    "password",
                    "required",
                    "pam_pwquality",
                    "minlen",
                    14,
                    (
                        check::CheckState::Warning,
                        Some(
                            "no `minlen` flag, `/etc/security/pwquality.conf` or the module default (8) decides"
                                .to_string(),
                        ),
                    ),
                ),
            ])
        },
        vec![pam::init_pam],
    )
    .with_description("`pam_pwquality` prompts for the new password, checks it against a dictionary and a set of rules (length, character classes, similarity with the old password, palindromes, the user's own name) and only then hands it to `pam_unix`. Without it every password is accepted and a short or dictionary one falls to an offline attack on `/etc/shadow` in minutes, no matter how strong the hashing algorithm is. It replaced `pam_cracklib` and is backward compatible with its options. The thresholds live on the rule or in `/etc/security/pwquality.conf`, the rule winning, and only the rule is read here: an unset `minlen` is a warning, the module default of 8 being below the bar. Impact: users are rejected at change time, and automation setting passwords without a human (`chpasswd`, provisioning scripts) has to provide passwords that pass, unless `enforce_for_root` is left off, which is the default and lets root set a weak password with only a printed warning.")
    .with_fix("Add `password requisite pam_pwquality.so retry=3 minlen=14 difok=3` to the password stack of `/etc/pam.d/passwd`, or set the thresholds in `/etc/security/pwquality.conf` where the service includes a shared password stack: `minlen = 14`, `retry = 3`, `difok = 3`, and `dcredit = -1`, `ucredit = -1`, `lcredit = -1`, `ocredit = -1` to require one character of each class. Add `enforce_for_root` to refuse weak passwords set by root too.")
    .register();

    check::Check::new(
        "PAM_003",
        "Ensure PAM service `passwd` hashes new passwords with yescrypt",
        Severity::High,
        vec!["pam", "server", "workstation"],
        || pam::check_yescrypt("passwd", "password", "required", "pam_unix"),
        vec![pam::init_pam],
    )
    .with_description("yescrypt is memory-hard, cracking a leaked `/etc/shadow` costs orders of magnitude more than against the MD5 or SHA-crypt hashes an explicit `pam_unix` algorithm flag selects, and the GPUs an attacker rents buy far less than against `sha512crypt`. A rule setting no algorithm flag is accepted, `pam_unix` then takes the algorithm from `ENCRYPT_METHOD` and the work factor from `YESCRYPT_COST_FACTOR` in `/etc/login.defs`. Only the passwords changed after the switch are hashed with it, the existing ones keep their algorithm until their owner changes them. Impact: the cost is paid on every authentication as well as on every change, a slower login that also lets an attacker burn CPU by failing logins on purpose.")
    .with_fix("Add `yescrypt` to the `pam_unix` rule of the password stack, `password required pam_unix.so yescrypt` in `/etc/pam.d/passwd` (or `common-password`), remove any weaker algorithm flag (`sha512`, `sha256`, `md5`...), and set `ENCRYPT_METHOD YESCRYPT` in `/etc/login.defs` for the tools that do not go through PAM. Existing hashes are not migrated, force a change to rehash them.")
    .register();

    check::Check::new(
        "PAM_004",
        "Ensure no PAM `auth` rule of `pam_unix` has flag `nullok`",
        Severity::High,
        vec!["pam", "server", "workstation"],
        || pam::check_no_rule_flag("auth", "pam_unix", "nullok"),
        vec![pam::init_pam],
    )
    .with_description("By default `pam_unix` refuses an account whose password is blank, `nullok` lifts that and lets anyone authenticate as an account with an empty password field in `/etc/shadow`. Those accounts come from a `useradd` without a password, a migration that dropped the hashes, or an attacker able to clear one, and they skip the password factor of the whole stack: the lockout and the second factor stacked around `pam_unix` see a successful authentication and let the session through. The shared auth stack of several distributions sets it, so every service including that file (`login`, `sshd`, `su`, `sudo`, the screensaver) accepts blank passwords at once. The whole of `/etc/pam.d/` is scanned, a flag in an included file weakens every service that includes it. `nullresetok` is the narrower flag for the forced reset flow, it only allows a blank password while a reset is required.")
    .with_fix("Remove `nullok` from the `pam_unix` rules of `/etc/pam.d/`, listed by `grep -rl nullok /etc/pam.d/`, usually `common-auth` or `system-auth`, then give a password to or lock every account with a blank one: `awk -F: '($2 == \"\") { print $1 }' /etc/shadow` lists them and `passwd -l <user>` locks them.")
    .register();

    check::Check::new(
        "PAM_005",
        "Ensure PAM service `passwd` remembers at least 5 previous passwords",
        Severity::Medium,
        vec!["pam", "server", "workstation"],
        || {
            check::require_all([
                pam::check_rule("passwd", "password", "required", "pam_pwhistory"),
                // the history is only enforced while `pam_pwhistory` runs before
                // `pam_unix` writes the new hash
                pam::check_rule_before(
                    "passwd",
                    "password",
                    "required",
                    "pam_pwhistory",
                    "required",
                    "pam_unix",
                ),
                pam::check_rule_flag_min(
                    "passwd",
                    "password",
                    "required",
                    "pam_pwhistory",
                    "remember",
                    5,
                    (
                        check::CheckState::Pass,
                        Some("no `remember` flag, the module keeps the last 10 passwords".to_string()),
                    ),
                ),
            ])
        },
        vec![pam::init_pam],
    )
    .with_description("Without password history a user rotates between two passwords and comes back to the original, defeating the rotation and keeping valid a hash an attacker may already have cracked. `remember` is the depth of the history, the module keeps the last 10 by default and `remember=0` stops checking while leaving the history file untouched. Only `pam_pwhistory` is accepted, the `remember` flag of `pam_unix` is deprecated and stores the previous passwords as MD5 hashes. The rule must also run before `pam_unix`, the module changing the password: placed after it, a reused password is already written to `/etc/shadow` when `pam_pwhistory` reports the reuse, `passwd` prints its rejection but the change stands. `enforce_for_root` is off by default, without it root sets any password it wants, and the history is kept in `/etc/security/opasswd`, which must stay readable by root only. The module is local, it cannot check the history of NIS, LDAP or Kerberos passwords.")
    .with_fix("Add `password required pam_pwhistory.so remember=5 use_authtok enforce_for_root` to the password stack of `/etc/pam.d/passwd` (or `common-password`), before the `pam_unix` rule that writes the new password, and keep `/etc/security/opasswd` owned by root with mode 0600.")
    .register();

    check::Check::new(
        "PAM_015",
        "Ensure PAM service `su` has rule `auth required pam_wheel use_uid`",
        Severity::High,
        vec!["pam", "server", "workstation"],
        || {
            check::require_all([
                pam::check_rule("su", "auth", "required", "pam_wheel"),
                pam::check_rule_flag("su", "auth", "required", "pam_wheel", &["use_uid"]),
                pam::check_rule_no_flag("su", "auth", "required", "pam_wheel", "deny"),
                // `trust` only hands out root without a password when it is
                // stacked as `sufficient`, an enforcing control keeps asking
                // for the password that the next rule checks
                pam::check_rule_no_flag("su", "auth", "sufficient", "pam_wheel", "trust"),
            ])
        },
        vec![pam::init_pam],
    )
    .with_description("`su` asks for the password of the account it targets, so without a restriction any local account can sit at a console and try root's password for as long as it wants, a compromised low-privilege account inheriting that ability. `pam_wheel` refuses the escalation before the password is asked to every account outside the group, narrowing the path to root to a named set of administrators and turning an `su` attempt by anyone else into a hard failure worth alerting on. `use_uid` is what makes the rule mean that: without it the membership is tested on the target account, `root`, which belongs to the group it is tested against, so the rule lets everyone through, and the `auth required pam_wheel.so` line the `su` files ship commented out has exactly that hole. `deny` reverses the rule and refuses the members of the group instead, and `trust` on a `sufficient` rule hands them root without a password. Impact: the administrators must be in the group before the rule goes in, an empty one locks every account out of `su` to root, root itself excepted since `pam_rootok` short-circuits the stack. Not every distribution ships a `wheel` group.")
    .with_fix("Add `auth required pam_wheel.so use_uid` to `/etc/pam.d/su`, after the `pam_rootok` rule, create the group with `groupadd wheel` when the system has none and put the administrators in it with `gpasswd -a <user> wheel`. Where the administrators live in another group, use `auth required pam_wheel.so use_uid group=sudo` instead, and drop any `trust` or `deny` flag. Verify that `su -` from an account outside the group is refused without a password prompt.")
    .register();

    // TODO: check the thresholds, they usually live in /etc/security/faillock.conf
    check::Check::new(
        "PAM_024",
        "Ensure PAM service `login` locks accounts after repeated failures with `pam_faillock`",
        Severity::High,
        vec!["pam", "server"],
        || {
            check::require_all([
                pam::check_rule("login", "auth", "required", "pam_faillock"),
                pam::check_rule_flag("login", "auth", "required", "pam_faillock", &["authfail"]),
                pam::check_rule_flag(
                    "login",
                    "auth",
                    "required",
                    "pam_faillock",
                    &["preauth", "authsucc"],
                ),
            ])
        },
        vec![pam::init_pam],
    )
    .with_description("`pam_faillock` counts the consecutive authentication failures of each account in `/run/faillock` and refuses it once `deny` is reached, which is what turns an unlimited password guessing game into a handful of tries. Without it an attacker with console, serial or terminal access brute-forces a password at the speed of the prompt. Three records make it work and the two that matter are checked: `authfail` writes the failure down, without it nothing is counted and no account is ever locked, and `preauth` refuses an already locked account before asking for a password while `authsucc` clears the counter on success, without one of them a locked account is still prompted and unrelated failures accumulate. The thresholds (`deny`, `unlock_time`, `fail_interval`, `even_deny_root`) belong in `/etc/security/faillock.conf`, the module defaults being `deny=3`, `unlock_time=600` and `fail_interval=900`, and an `account required pam_faillock.so` rule is what keeps a locked account out of the services that authenticate it another way, a key or a certificate for example. `pam_tally2` is gone from linux-pam since 1.4, a stack still using it locks nobody. Impact: a lockout is a denial of service an attacker can trigger on purpose against an account he knows, root is spared by default (`even_deny_root` opts it in) and a short `unlock_time` bounds it.")
    .with_fix("Wrap the auth stack of `/etc/pam.d/login` (or `common-auth`) with the two records, `auth required pam_faillock.so preauth silent deny=5 unlock_time=900` before the `pam_unix` rule and `auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900` after it, add `account required pam_faillock.so` to the account stack, and keep the thresholds in `/etc/security/faillock.conf` rather than on the rules. `faillock` shows the counters, `faillock --user <name> --reset` unlocks an account.")
    .register();

    // TODO: reduce to 1s ?
    // TODO: read the configuration file to see if it's configured correctly, there is a check
    // already ready for login.defs
    check::Check::new(
        "PAM_030",
        "Ensure PAM service `login` has rule `auth optional pam_faildelay` with `delay` >= 4000000",
        Severity::Medium,
        vec!["pam", "server", "workstation"],
        || {
            check::require_all([
                pam::check_rule("login", "auth", "optional", "pam_faildelay"),
                // TODO: add a check::or function to either check here or in
                // the configuration?
                pam::check_rule_flag_min(
                    "login",
                    "auth",
                    "optional",
                    "pam_faildelay",
                    "delay",
                    4_000_000,
                    (
                        check::CheckState::Warning,
                        Some(
                            "no `delay` flag, `FAIL_DELAY` from `/etc/login.defs` decides, in seconds"
                                .to_string(),
                        ),
                    ),
                ),
            ])
        },
        vec![pam::init_pam],
    )
    .with_description("`pam_faildelay` holds a failed authentication for a while before the failure reaches the caller, which buys two things: guessing a password at the console costs seconds per attempt instead of milliseconds, and the pause covers the timing difference between an unknown account and a wrong password, an enumeration oracle `pam_unix` offers for free. The value on the rule is in microseconds, `delay=4000000` being 4 seconds, and without it the module takes `FAIL_DELAY` from `/etc/login.defs`, in seconds, which is not read here, hence the warning. The rule is `optional` because the module only returns `PAM_IGNORE`, it never decides the outcome of the stack. The delay and the account lockout are complementary, one slows every attempt down and the other caps their number. Impact: a user who mistypes waits, and automation authenticating in a loop with a wrong credential slows down by the same amount.")
    .with_fix("Set `auth optional pam_faildelay.so delay=4000000` in `/etc/pam.d/login`, raising the value of the rule where it is already present with a shorter delay, or `FAIL_DELAY 4` in `/etc/login.defs` for the services that do not use the module.")
    .register();
}
