use crate::check;
use crate::check::Severity;
use crate::modules::login_defs;

// login.defs is slowly being replaced by PAM, transfer the rules over to PAM, and maybe add a check
// on the version of login.defs to disable those rules when they are fully deprecated but keeping
// them for system still vulnerable/using it

pub fn add_checks() {
    check::Check::new(
        "LDF_001",
        "Ensure that login.defs \"ENCRYPT_METHOD\" = \"YESCRYPT\"",
        Severity::High,
        vec!["login_defs", "server", "workstation"],
        || login_defs::check_login_defs("ENCRYPT_METHOD", "YESCRYPT"),
        vec![login_defs::init_login_defs],
    )
    .with_description("Use stronger hashing algorithms.")
    .with_fix("Set \"ENCRYPT_METHOD YESCRYPT\" in \"/etc/login.defs\".")
    .register();

    check::Check::new(
        "LDF_002",
        "Ensure that login.defs \"YESCRYPT_COST_FACTOR\" >= 5",
        Severity::High,
        vec![
            "login_defs",
            // YESCRYPT_COST_FACTOR is now used by PAM for yescrypt
            // https://github.com/linux-pam/linux-pam/issues/607
            "pam",
            "server",
            "workstation",
        ],
        || {
            const VAL: i32 = 5;
            match login_defs::get_login_defs_value("YESCRYPT_COST_FACTOR") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            // max value is 11
                            if val >= VAL && val <= 11 {
                                (check::CheckState::Pass, Some(format!("{}", val)))
                            } else {
                                (check::CheckState::Fail, Some(format!("{} < {}", val, VAL)))
                            }
                        }
                        Err(err) => (check::CheckState::Warning, Some(err.to_string())),
                    },
                    None => (check::CheckState::Pass, Some("default (5)".to_string())),
                },
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![login_defs::init_login_defs],
    )
    .with_description("A higher cost factor multiplies the work an attacker must spend per guess in offline cracking. With yescrypt now consumed by PAM, this directly raises the bar for password cracking from any leaked /etc/shadow. Higher cost factors increase CPU time for password hashing during login and password changes, which may cause noticeable delays on systems with many concurrent logins.")
    .with_fix("Set \"YESCRYPT_COST_FACTOR 5\" or higher up to 11 in \"/etc/login.defs\".")
    .with_link("https://github.com/linux-pam/linux-pam/issues/607")
    .register();

    check::Check::new(
        "LDF_003",
        "Ensure that login.defs -1 < \"PASS_MAX_DAYS\" <= 365",
        Severity::High,
        vec!["login_defs", "server"],
        || {
            const VAL: i32 = 365;
            match login_defs::get_login_defs_value("PASS_MAX_DAYS") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val <= VAL && val >= 0 {
                                (check::CheckState::Pass, Some(format!("{}", val)))
                            } else {
                                (check::CheckState::Fail, Some(format!("{} > {}", val, VAL)))
                            }
                        }
                        Err(err) => (check::CheckState::Warning, Some(err.to_string())),
                    },
                    None => (
                        check::CheckState::Fail,
                        Some("key not present (default is -1)".to_string()),
                    ),
                },
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![login_defs::init_login_defs],
    )
    .with_description("Forcing periodic password rotation limits the value of any single leaked credential: an attacker who steals a hash today, and if he is able to crack it, loses access once it expires. Combined with strong hashing, it bounds the window of unauthorized use.")
    .with_fix("Set \"PASS_MAX_DAYS 365\" or lower in \"/etc/login.defs\".")
    .register();

    check::Check::new(
        "LDF_004",
        "Ensure that login.defs \"PASS_MIN_DAYS\" >= 1",
        Severity::Medium,
        vec!["login_defs", "server"],
        || {
            const VAL: i32 = 1;
            match login_defs::get_login_defs_value("PASS_MIN_DAYS") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val >= VAL {
                                (check::CheckState::Pass, Some(format!("{}", val)))
                            } else {
                                (check::CheckState::Fail, Some(format!("{} < {}", val, VAL)))
                            }
                        }
                        Err(err) => (check::CheckState::Warning, Some(err.to_string())),
                    },
                    None => (
                        check::CheckState::Fail,
                        Some("key not present (default is 0)".to_string()),
                    ),
                },
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![login_defs::init_login_defs],
    )
    .with_description("Without a minimum age, a user forced to change their password can rotate it through history many times and return to the original, bypassing reuse-prevention policy.")
    .with_fix("Set \"PASS_MIN_DAYS 1\" or higher in \"/etc/login.defs\".")
    .register();

    check::Check::new(
        "LDF_005",
        "Ensure that login.defs \"PASS_WARN_AGE\" >= 7",
        Severity::Low,
        vec!["login_defs", "server", "workstation"],
        || {
            const VAL: i32 = 7;
            match login_defs::get_login_defs_value("PASS_WARN_AGE") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val >= VAL {
                                (check::CheckState::Pass, Some(format!("{}", val)))
                            } else {
                                (check::CheckState::Fail, Some(format!("{} < {}", val, VAL)))
                            }
                        }
                        Err(err) => (check::CheckState::Warning, Some(err.to_string())),
                    },
                    None => (
                        check::CheckState::Fail,
                        Some("key not present (default is -1)".to_string()),
                    ),
                },
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![login_defs::init_login_defs],
    )
    .with_description("Warning users before passwords expire prevents last-minute panicked rotations to weak passwords.")
    .with_fix("Set \"PASS_WARN_AGE 7\" or higher in \"/etc/login.defs\".")
    .register();

    check::Check::new(
        "LDF_006",
        "Ensure that login.defs \"SYSLOG_SU_ENAB\" = \"yes\"",
        Severity::Medium,
        vec!["login_defs", "server", "workstation"],
        || login_defs::check_login_defs("SYSLOG_SU_ENAB", "yes"),
        vec![login_defs::init_login_defs],
    )
    .with_description("Without `SYSLOG_SU_ENAB`, `su` invocations bypass syslog, making privilege escalations between accounts effectively invisible to centralized logging and SIEM detections.")
    .with_fix("Set \"SYSLOG_SU_ENAB yes\" in \"/etc/login.defs\".")
    .register();

    check::Check::new(
        "LDF_007",
        "Ensure that login.defs \"SYSLOG_SG_ENAB\" = \"yes\"",
        Severity::Medium,
        vec!["login_defs", "server", "workstation"],
        || login_defs::check_login_defs("SYSLOG_SG_ENAB", "yes"),
        vec![login_defs::init_login_defs],
    )
    .with_description("Without `SYSLOG_SG_ENAB`, `sg`/`newgrp` group switches are not syslogged, hiding lateral access to group-owned resources from incident-response timelines.")
    .with_fix("Set \"SYSLOG_SG_ENAB yes\" in \"/etc/login.defs\".")
    .register();

    check::Check::new(
        "LDF_008",
        "Ensure that login.defs \"UMASK\" = \"077\"",
        Severity::Medium,
        vec!["login_defs", "server", "workstation"],
        || login_defs::check_login_defs("UMASK", "077"),
        vec![login_defs::init_login_defs],
    )
    .with_description("A default UMASK of 077 makes new files readable only by their owner. Prevent potential information leak when creating files.")
    .with_fix("Set \"UMASK 077\" in \"/etc/login.defs\".")
    .register();

    check::Check::new(
        "LDF_009",
        "Ensure that login.defs \"LOGIN_RETRIES\" <= 3",
        Severity::Medium,
        vec!["login_defs", "server", "workstation"],
        || {
            const VAL: i32 = 10;
            match login_defs::get_login_defs_value("LOGIN_RETRIES") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val <= VAL {
                                (check::CheckState::Pass, Some(format!("{}", val)))
                            } else {
                                (check::CheckState::Fail, Some(format!("{} > {}", val, VAL)))
                            }
                        }
                        Err(err) => (check::CheckState::Warning, Some(err.to_string())),
                    },
                    None => (
                        check::CheckState::Fail,
                        Some("key not present (default is 5)".to_string()),
                    ),
                },
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![login_defs::init_login_defs],
    )
    .with_description("Maximum number of login retries in case of bad password. This will most likely be overridden by PAM, since the default pam_unix module has its own built in of 3 retries. However, this is a safe fallback in case you are using an authentication module that does not enforce PAM_MAXTRIES.")
    .with_fix("Set \"LOGIN_RETRIES 3\" or lower in \"/etc/login.defs\".")
    .register();

    check::Check::new(
        "LDF_010",
        "Ensure that login.defs \"LOGIN_TIMEOUT\" <= 60",
        Severity::Medium,
        vec!["login_defs", "server", "workstation"],
        || {
            const VAL: i32 = 60;
            match login_defs::get_login_defs_value("LOGIN_TIMEOUT") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val <= VAL {
                                (check::CheckState::Pass, Some(format!("{}", val)))
                            } else {
                                (check::CheckState::Fail, Some(format!("{} > {}", val, VAL)))
                            }
                        }
                        Err(err) => (check::CheckState::Warning, Some(err.to_string())),
                    },
                    None => (
                        check::CheckState::Fail,
                        Some("key not present".to_string()),
                    ),
                },
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![login_defs::init_login_defs],
    )
    .with_description("An unbounded login timeout lets an attacker hold a login prompt open indefinitely, consuming a TTY slot.")
    .with_fix("Set \"LOGIN_TIMEOUT 60\" or lower in \"/etc/login.defs\".")
    .register();

    check::Check::new(
        "LDF_011",
        "Ensure that login.defs \"FAILLOG_ENAB\" = \"yes\"",
        Severity::Medium,
        vec!["login_defs", "server", "workstation"],
        || login_defs::check_login_defs("FAILLOG_ENAB", "yes"),
        vec![login_defs::init_login_defs],
    )
    .with_description("Recording failed login attempts to /var/log/faillog lets administrators and tools reconstruct brute-force or credential-stuffing campaigns. Without it, failed attempts leave no trace on disk. Replaced by pam_faillock.")
    .with_fix("Set \"FAILLOG_ENAB yes\" in \"/etc/login.defs\".")
    .register();

    check::Check::new(
        "LDF_012",
        "Ensure that login.defs \"LOG_OK_LOGINS\" = \"yes\"",
        Severity::Medium,
        vec!["login_defs", "server", "workstation"],
        || login_defs::check_login_defs("LOG_OK_LOGINS", "yes"),
        vec![login_defs::init_login_defs],
    )
    .with_description("Logging successful logins creates an audit trail of who accessed the system and when, enabling detection of unauthorized account use and supporting incident-response timelines.")
    .with_fix("Set \"LOG_OK_LOGINS yes\" in \"/etc/login.defs\".")
    .register();

    check::Check::new(
        "LDF_013",
        "Ensure that login.defs \"LOG_UNKFAIL_ENAB\" = \"no\"",
        Severity::Medium,
        vec!["login_defs", "server", "workstation"],
        || login_defs::check_login_defs("LOG_UNKFAIL_ENAB", "no"),
        vec![login_defs::init_login_defs],
    )
    .with_description("Do not log unknown usernames when login failures are recorded. Logging unknown usernames is an issue if a user enter his password instead of his username.")
    .with_fix("Set \"LOG_UNKFAIL_ENAB no\" in \"/etc/login.defs\".")
    .register();
}
