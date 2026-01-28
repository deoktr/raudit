use crate::*;

pub fn add_checks() {
    // NOTE: this only affect the generation of group passwords, which we also
    // check for absence
    check::add_check(
        "LDF_001",
        "Ensure that login.defs \"ENCRYPT_METHOD\" = \"YESCRYPT\"",
        vec!["login_defs"],
        || login_defs::check_login_defs("ENCRYPT_METHOD", "YESCRYPT"),
        vec![login_defs::init_login_defs],
    );
    // NOTE: YESCRYPT_COST_FACTOR is now used by PAM for yescrypt
    // https://github.com/linux-pam/linux-pam/issues/607
    check::add_check(
        "LDF_002",
        "Ensure that login.defs \"YESCRYPT_COST_FACTOR\" >= 5",
        vec!["login_defs"],
        || {
            const VAL: i32 = 5;
            match login_defs::get_login_defs_value("YESCRYPT_COST_FACTOR") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            // TODO: also check to see if <= 11? even thos this
                            // should not cause any problems, it's still an
                            // invalide value
                            if val <= VAL {
                                (check::CheckState::Passed, Some(format!("{}", val)))
                            } else {
                                (
                                    check::CheckState::Failed,
                                    Some(format!("{} > {}", val, VAL)),
                                )
                            }
                        }
                        Err(err) => (check::CheckState::Error, Some(err.to_string())),
                    },
                    None => (
                        check::CheckState::Error,
                        Some("key not present".to_string()),
                    ),
                },
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_003",
        "Ensure that login.defs \"PASS_MAX_DAYS\" <= 365",
        vec!["login_defs"],
        || {
            const VAL: i32 = 365;
            match login_defs::get_login_defs_value("PASS_MAX_DAYS") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val <= VAL {
                                (check::CheckState::Passed, Some(format!("{}", val)))
                            } else {
                                (
                                    check::CheckState::Failed,
                                    Some(format!("{} > {}", val, VAL)),
                                )
                            }
                        }
                        Err(err) => (check::CheckState::Error, Some(err.to_string())),
                    },
                    None => (
                        check::CheckState::Error,
                        Some("key not present".to_string()),
                    ),
                },
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_004",
        "Ensure that login.defs \"PASS_MIN_DAYS\" >= 1",
        vec!["login_defs"],
        || {
            const VAL: i32 = 1;
            match login_defs::get_login_defs_value("PASS_MIN_DAYS") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val >= VAL {
                                (check::CheckState::Passed, Some(format!("{}", val)))
                            } else {
                                (
                                    check::CheckState::Failed,
                                    Some(format!("{} < {}", val, VAL)),
                                )
                            }
                        }
                        Err(err) => (check::CheckState::Error, Some(err.to_string())),
                    },
                    None => (
                        check::CheckState::Error,
                        Some("key not present".to_string()),
                    ),
                },
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_005",
        "Ensure that login.defs \"PASS_WARN_AGE\" >= 7",
        vec!["login_defs"],
        || {
            const VAL: i32 = 7;
            match login_defs::get_login_defs_value("PASS_WARN_AGE") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val >= VAL {
                                (check::CheckState::Passed, Some(format!("{}", val)))
                            } else {
                                (
                                    check::CheckState::Failed,
                                    Some(format!("{} < {}", val, VAL)),
                                )
                            }
                        }
                        Err(err) => (check::CheckState::Error, Some(err.to_string())),
                    },
                    None => (
                        check::CheckState::Error,
                        Some("key not present".to_string()),
                    ),
                },
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_006",
        "Ensure that login.defs \"SYSLOG_SU_ENAB\" = \"yes\"",
        vec!["login_defs"],
        || login_defs::check_login_defs("SYSLOG_SU_ENAB", "yes"),
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_007",
        "Ensure that login.defs \"SYSLOG_SG_ENAB\" = \"yes\"",
        vec!["login_defs"],
        || login_defs::check_login_defs("SYSLOG_SG_ENAB", "yes"),
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_008",
        "Ensure that login.defs \"UMASK\" = \"077\"",
        vec!["login_defs"],
        || login_defs::check_login_defs("UMASK", "077"),
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_009",
        "Ensure that login.defs \"LOGIN_RETRIES\" <= 10",
        vec!["login_defs"],
        || {
            const VAL: i32 = 10;
            match login_defs::get_login_defs_value("LOGIN_RETRIES") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val <= VAL {
                                (check::CheckState::Passed, Some(format!("{}", val)))
                            } else {
                                (
                                    check::CheckState::Failed,
                                    Some(format!("{} > {}", val, VAL)),
                                )
                            }
                        }
                        Err(err) => (check::CheckState::Error, Some(err.to_string())),
                    },
                    None => (
                        check::CheckState::Error,
                        Some("key not present".to_string()),
                    ),
                },
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_010",
        "Ensure that login.defs \"LOGIN_TIMEOUT\" <= 60",
        vec!["login_defs"],
        || {
            const VAL: i32 = 60;
            match login_defs::get_login_defs_value("LOGIN_TIMEOUT") {
                Ok(value) => match value {
                    Some(vl) => match vl.parse::<i32>() {
                        Ok(val) => {
                            if val <= VAL {
                                (check::CheckState::Passed, Some(format!("{}", val)))
                            } else {
                                (
                                    check::CheckState::Failed,
                                    Some(format!("{} > {}", val, VAL)),
                                )
                            }
                        }
                        Err(err) => (check::CheckState::Error, Some(err.to_string())),
                    },
                    None => (
                        check::CheckState::Error,
                        Some("key not present".to_string()),
                    ),
                },
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_011",
        "Ensure that login.defs \"FAILLOG_ENAB\" = \"yes\"",
        vec!["login_defs"],
        || login_defs::check_login_defs("FAILLOG_ENAB", "yes"),
        vec![login_defs::init_login_defs],
    );
    check::add_check(
        "LDF_012",
        "Ensure that login.defs \"LOG_OK_LOGINS\" = \"yes\"",
        vec!["login_defs"],
        || login_defs::check_login_defs("LOG_OK_LOGINS", "yes"),
        vec![login_defs::init_login_defs],
    );
}
