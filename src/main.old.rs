/*
 * rAudit, a Linux security auditing toolkit
 * Copyright (C) 2024 - 2025  deoktr
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

mod apparmor;
mod audit;
mod base;
mod check;
mod clamav;
mod config;
mod docker;
mod gdm;
mod group;
mod grub;
mod kconfig;
mod kernel;
mod login_defs;
mod malloc;
mod modprobe;
mod mount;
mod nginx;
mod os;
mod pam;
mod ps;
mod sshd;
mod sudo;
mod sysctl;
mod systemd;
mod uptime;
mod users;
mod utils;

use std::sync::OnceLock;
use std::time::Instant;

use clap::Parser;

// TODO: only load configurations if they are needed on a check

// the `OnceLock` wrapper allows for an easy single initialization of the
// configuration of checked apps for performance ans simplicity
static KERNEL_OS_TYPE: OnceLock<String> = OnceLock::new();
static KERNEL_OS_RELEASE: OnceLock<String> = OnceLock::new();
static OS_RELEASE: OnceLock<os::OSRelease> = OnceLock::new();
static PS: OnceLock<ps::Proc> = OnceLock::new();
static SYSCTL_CONFIG: OnceLock<sysctl::SysctlConfig> = OnceLock::new();
static SYSTEMD_CONFIG: OnceLock<systemd::SystemdConfig> = OnceLock::new();
static SSHD_CONFIG: OnceLock<sshd::SshdConfig> = OnceLock::new();
static KERNEL_PARAMS: OnceLock<kernel::KernelParams> = OnceLock::new();
static LOGIN_DEFS: OnceLock<login_defs::LoginDefsConfig> = OnceLock::new();
static MOUNTS: OnceLock<mount::MountConfig> = OnceLock::new();
static NGINX_CONF: OnceLock<nginx::NginxConfig> = OnceLock::new();
static MODPROBE_CONFIG: OnceLock<modprobe::ModprobeConfig> = OnceLock::new();
static MODPROBE_BLACKLIST: OnceLock<modprobe::ModprobeBlacklist> = OnceLock::new();
static MODPROBE_DISABLED: OnceLock<modprobe::ModprobeDisabled> = OnceLock::new();
static LOADED_MODULES: OnceLock<Vec<String>> = OnceLock::new();
static SUDOERS_CONFIG: OnceLock<sudo::SudoConfig> = OnceLock::new();
static SUDOERS_CONFIG_DEFAULTS: OnceLock<sudo::SudoConfigDefaults> = OnceLock::new();
static PAM_CONFIG: OnceLock<pam::PamConfig> = OnceLock::new();
static PASSWD_CONFIG: OnceLock<users::PasswdConfig> = OnceLock::new();
static SHADOW_CONFIG: OnceLock<users::ShadowConfig> = OnceLock::new();
static GROUP_CONFIG: OnceLock<group::GroupConfig> = OnceLock::new();
static AUDIT_RULES: OnceLock<audit::AuditRules> = OnceLock::new();
static AUDIT_CONFIG: OnceLock<audit::AuditConfig> = OnceLock::new();
static GRUB_CFG: OnceLock<grub::GrubCfg> = OnceLock::new();
static LD_SO_PRELOAD: OnceLock<malloc::LdSoPreload> = OnceLock::new();
static KCOMPILE_CONFIG: OnceLock<kconfig::KcompilConfig> = OnceLock::new();

/// Audit Linux systems security configurations
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    // /// Importance level to filter checks
    // #[structopt(short = 'n')]
    // level: Option<usize>,
    //
    /// Disable print individual checks
    #[arg(long, action = clap::ArgAction::SetTrue)]
    disable_print_checks: bool,

    /// Disable print stats
    #[arg(long, action = clap::ArgAction::SetTrue)]
    disable_print_stats: bool,

    /// Comma-separated list of ID prefixes to filter
    #[arg(long, value_delimiter = ',')]
    filters: Vec<String>,

    /// Disable colored output
    #[arg(long, action = clap::ArgAction::SetTrue)]
    disable_colors: bool,
}

macro_rules! check {
    ($checks:tt, $id:tt, $title:expr, $blk:expr) => {
        let mut c = check::Check::new(
            $id.to_string(),
            $title.to_string(),
            &(|| -> (check::CheckState, Option<String>) { $blk }),
        );
        $checks.checks.push(&mut c);
    };
}

macro_rules! check_bool {
    // requires getting the configuration
    ($checks:tt, $id:tt, $title:tt, $conf:tt, $func:expr, $false:tt) => {
        check!($checks, $id, $title, {
            match $conf.get() {
                Some(config) => match $func(config) {
                    true => (check::CheckState::Valid, None),
                    false => (check::CheckState::Invalid, Some($false.to_string())),
                },
                None => (
                    check::CheckState::Error,
                    Some(format!("{} not initialized", stringify!($conf))),
                ),
            }
        })
    };

    // without configuration
    ($checks:tt, $id:tt, $title:tt, $func:expr, $false:tt) => {
        check!($checks, $id, $title, {
            match $func() {
                true => (check::CheckState::Valid, None),
                false => (check::CheckState::Invalid, Some($false.to_string())),
            }
        })
    };
}

macro_rules! check_bool_error {
    ($checks:tt, $id:tt, $title:tt, $conf:tt, $func:expr, $false:tt) => {
        check!($checks, $id, $title, {
            match $conf.get() {
                Some(config) => match $func(config) {
                    Ok(is) => match is {
                        true => (check::CheckState::Valid, None),
                        false => (check::CheckState::Invalid, Some($false.to_string())),
                    },
                    Err(err) => (check::CheckState::Error, Some(err.to_string())),
                },
                None => (
                    check::CheckState::Error,
                    Some(format!("{} not initialized", stringify!($conf))),
                ),
            }
        })
    };

    ($checks:tt, $id:tt, $title:tt, $func:expr, $false:tt) => {
        check!($checks, $id, $title, {
            match $func() {
                Ok(is) => match is {
                    true => (check::CheckState::Valid, None),
                    false => (check::CheckState::Invalid, Some($false.to_string())),
                },
                Err(err) => (check::CheckState::Error, Some(err.to_string())),
            }
        })
    };
}

macro_rules! check_ps_running {
    ($checks:tt, $id:tt, $ps:tt) => {
        check!(
            $checks,
            $id,
            format!("Ensure that {} is running", $ps),
            match PS.get() {
                Some(config) => match ps::is_running(config, $ps.to_string()) {
                    true => (check::CheckState::Valid, None),
                    false => (check::CheckState::Invalid, Some("not running".to_string())),
                },
                None => (
                    check::CheckState::Error,
                    Some(format!("{} not initialized", stringify!($conf))),
                ),
            }
        )
    };
}

// check sysctl arguments
macro_rules! check_sysctl {
    // check sysctl arguments as string values
    ($checks:tt, $id:tt, $key:tt, $expect:tt) => {
        check!($checks, $id, format!("Ensure that sysctl {} == {:?}", $key, $expect), {
         match get_ssyctl($key) {
            Ok(value) => {
                if value == $expect {
                    (check::CheckState::Valid, None)
                } else {
                    (check::CheckState::Invalid, Some(format!("{:?} !== {:?}", value, $expect)))
                }
            },
            Err(err) => (check::CheckState::Error, Some(err)),
        }})
    };

    // check sysctl arguments as i32
    ($checks:tt, $id:tt, $key:tt $comparator:tt $expect:tt) => {
         check_sysctl!($checks, $id, $key $comparator $expect, i32);
    };

    // convert sysctl value to the specified type
    ($checks:tt, $id:tt, $key:tt $comparator:tt $expect:tt, $expect_type:ty) => {
        check!($checks, $id, format!("Ensure that sysctl {} {} {}", $key, stringify!($comparator), $expect), {
        match get_ssyctl($key) {
            Ok(value) => {
                match value.parse::<$expect_type>() {
                    Ok(val) => {
                        if val $comparator $expect {
                            if stringify!($comparator) == "==" {
                                (check::CheckState::Valid, None)
                            } else {
                                // add "(got: ...)" when it's not "==" to help know what value was compared
                                (check::CheckState::Valid, None)
                            }
                        } else {
                            (check::CheckState::Invalid, Some(format!("{} !{} {}", value, stringify!($comparator), $expect)))
                        }
                    },
                    Err(error) => (check::CheckState::Error, Some(format!("failed to convert '{}': {}", value, error.to_string()))),
                }
            },
            Err(err) => (check::CheckState::Error, Some(err)),
        }})
    };
}

macro_rules! check_systemd {
    ($checks:tt, $id:tt, $key:tt, $expect:tt) => {
        check!(
            $checks,
            $id,
            format!("Ensure that systemd config {} == {}", $key, $expect),
            {
                match get_systemd_config($key) {
                    Ok(value) => {
                        if value == $expect {
                            (check::CheckState::Valid, None)
                        } else {
                            (
                                check::CheckState::Invalid,
                                Some(format!("{} !== {}", value, $expect)),
                            )
                        }
                    }
                    Err(err) => (check::CheckState::Error, Some(err)),
                }
            }
        )
    };
}

// check sshd_config arguments
macro_rules! check_sshd_config {
    // check sshd_config arguments as string values
    ($checks:tt, $id:tt, $key:tt, $expect:tt) => {
        check!($checks, $id, format!("Ensure that sshd_config {} == {:?}", $key, $expect), {
         match get_sshd_config($key) {
            Ok(value) => {
                if value == $expect {
                    (check::CheckState::Valid, None)
                } else {
                    (check::CheckState::Invalid, Some(format!("{:?} !== {:?}", value, $expect)))
                }
            }
            Err(err) => (check::CheckState::Error, Some(err)),
        }})
    };

    // check sshd_config arguments as i32
    ($checks:tt, $id:tt, $key:tt $comparator:tt $expect:tt) => {
         check_sshd_config!($checks, $id, $key $comparator $expect, i32);
    };

    // convert sshd_config value to the specified type
    ($checks:tt, $id:tt, $key:tt $comparator:tt $expect:tt, $expect_type:ty) => {
        check!($checks, $id, format!("Ensure that sshd_config {} {} {}", $key, stringify!($comparator), stringify!($expect)), {
        match get_sshd_config($key) {
            Ok(value) => {
                match value.parse::<$expect_type>() {
                    Ok(val) => {
                        if val $comparator $expect {
                            if stringify!($comparator) == "==" {
                                (check::CheckState::Valid, None)
                            } else {
                                // add "(got: ...)" when it's not "==" to help know what value was compared
                                (check::CheckState::Valid, None)
                            }
                        } else {
                            (check::CheckState::Invalid, Some(format!("{} !{} {}", value, stringify!($comparator), $expect)))
                        }
                    },
                    Err(error) => (check::CheckState::Error, Some(format!("failed to convert '{}': {}", value, error.to_string()))),
                }
            },
            Err(err) => (check::CheckState::Error, Some(err)),
        }})
    };
}

// check kernel params arguments
macro_rules! check_kernel_param {
    // check kernel params as string values
    ($checks:tt, $id:tt, $key:tt) => {
        check!(
            $checks,
            $id,
            format!("Ensure that kernel flag {} is present", $key),
            {
                match get_kernel_params($key) {
                    Ok(value) => {
                        if value {
                            (check::CheckState::Valid, None)
                        } else {
                            (check::CheckState::Invalid, Some("missing".to_string()))
                        }
                    }
                    Err(err) => (check::CheckState::Error, Some(err)),
                }
            }
        )
    };
}

// check kernel compilation config
macro_rules! check_kconfig_params {
    // check kernel compilation flag is present (set to y)
    ($checks:tt, $id:tt, $key:tt) => {
        check_kconfig_params!($checks, $id, $key, "y");
    };

    // check kconfig_param arguments as string values
    ($checks:tt, $id:tt, $flag:tt, $expect:tt) => {
        check!($checks, $id, format!("Ensure that kernel compilation flag {} == {:?}", format!("CONFIG_{}", $flag), $expect), {
        match get_kcompile_config(format!("CONFIG_{}", $flag)) {
            Ok(value) => {
                if value == $expect {
                    (check::CheckState::Valid, None)
                } else {
                    (check::CheckState::Invalid, Some(format!("{:?} !== {:?}", value, $expect)))
                }
            }
            Err(err) => (check::CheckState::Error, Some(err)),
        }})
    };

    // check kconfig_param arguments as i32
    ($checks:tt, $id:tt, $key:tt $comparator:tt $expect:tt) => {
         check_kconfig_param!($checks, $id, $key $comparator $expect, i32);
    };

    // convert kconfig_param value to the specified type
    ($checks:tt, $id:tt, $flag:tt $comparator:tt $expect:tt, $expect_type:ty) => {
        let full_flag = format!("CONFIG_{}", $flag);
        check!($checks, $id, format!("Ensure that kernel compilation flag {} {} {}", full_flag, stringify!($comparator), stringify!($expect)), {
        match get_kcompile_config(full_flag) {
            Ok(value) => {
                match value.parse::<$expect_type>() {
                    Ok(val) => {
                        if val $comparator $expect {
                            if stringify!($comparator) == "==" {
                                (check::CheckState::Valid, None)
                            } else {
                                // add "(got: ...)" when it's not "==" to help know what value was compared
                                (check::CheckState::Valid, None)
                            }
                        } else {
                            (check::CheckState::Invalid, Some(format!("{} !{} {}", value, stringify!($comparator), $expect)))
                        }
                    },
                    Err(error) => (check::CheckState::Error, format!("failed to convert '{}': {}", value, error.to_string())),
                }
            },
            Err(err) => (check::CheckState::Error, Some(err)),
        }})
    };
}

macro_rules! check_kconfig_not_set_param {
    ($checks:tt, $id:tt, $flag:tt) => {
        check!(
            $checks,
            $id,
            format!(
                "Ensure that kernel compilation flag {} is not set",
                format!("CONFIG_{}", $flag)
            ),
            {
                match get_kcompile_not_set_config(format!("CONFIG_{}", $flag)) {
                    Ok(is) => {
                        if is {
                            (check::CheckState::Valid, None)
                        } else {
                            (
                                check::CheckState::Invalid,
                                Some("found to be set".to_string()),
                            )
                        }
                    }
                    Err(err) => (check::CheckState::Error, Some(err)),
                }
            }
        )
    };
}

// check login defs
macro_rules! check_login_defs {
    // check login defs arguments as string values
    ($checks:tt, $id:tt, $key:tt, $expect:tt) => {
        check!($checks, $id, format!("Ensure that login.defs {} == {:?}", $key, $expect), {
        match get_login_defs($key) {
            Ok(value) => {
                if value == $expect {
                    (check::CheckState::Valid, None)
                } else {
                    (check::CheckState::Invalid, Some(format!("{:?} !== {:?}", value, $expect)))
                }
            }
            Err(err) => (check::CheckState::Error, Some(err)),
        }})
    };

    // check login defs arguments as i32
    ($checks:tt, $id:tt, $key:tt $comparator:tt $expect:tt) => {
         check_login_defs!($checks, $id, $key $comparator $expect, i32);
    };

    // convert login defs value to the specified type
    ($checks:tt, $id:tt, $key:tt $comparator:tt $expect:tt, $expect_type:ty) => {
        check!($checks, $id, format!("Ensure that login.defs {} {} {}", $key, stringify!($comparator), $expect), {
        match get_login_defs($key) {
            Ok(value) => {
                match value.parse::<$expect_type>() {
                    Ok(val) => {
                        if val $comparator $expect {
                            if stringify!($comparator) == "==" {
                                (check::CheckState::Valid, None)
                            } else {
                                // add "(got: ...)" when it's not "==" to help know what value was compared
                                (check::CheckState::Valid, None)
                            }
                        } else {
                            (check::CheckState::Invalid, Some(format!("{} !{} {}", value, stringify!($comparator), $expect)))
                        }
                    },
                    Err(error) => {
                        (check::CheckState::Error, Some(format!("failed to convert '{}': {}", value, error.to_string())))
                    }
                }
            },
            Err(err) => (check::CheckState::Error, Some(err)),
        }})
    };
}

// check mount existance
// TODO: ensure they are persistent in `/etc/fstab`
macro_rules! check_mount {
    ($checks:tt, $id:tt, $mount:tt) => {
        check!(
            $checks,
            $id,
            format!("Ensure that mount {} exist", $mount),
            {
                match get_mount($mount) {
                    Ok(value) => match value {
                        Some(_) => (check::CheckState::Valid, None),
                        None => (check::CheckState::Invalid, Some("missing".to_string())),
                    },
                    Err(err) => (check::CheckState::Error, Some(err)),
                }
            }
        )
    };
}

// check mount options
// TODO: add options as a list, and every elements checked independantly
macro_rules! check_mount_option {
    ($checks:tt, $id:tt, $mount:tt, $option:tt) => {
        check!(
            $checks,
            $id,
            format!("Ensure that mount {} option {} is set", $mount, $option),
            {
                match get_mount_options($mount) {
                    Ok(value) => {
                        if value.contains(&$option.to_string()) {
                            (check::CheckState::Valid, None)
                        } else {
                            (check::CheckState::Invalid, Some("missing".to_string()))
                        }
                    }
                    Err(err) => (check::CheckState::Error, Some(err)),
                }
            }
        )
    };
}

// check modprobe blacklist
// ensure module is blacklisted AND not currently loaded
// TODO: check for both `-` and `_` variants
macro_rules! check_modprobe_blacklist {
    ($checks:tt, $id:tt, $module:tt) => {
        check!(
            $checks,
            $id,
            format!("Ensure that kernel module {} is blacklisted", $module),
            {
                match is_module_blacklisted($module) {
                    Ok(value) => {
                        if value {
                            // ensure module is not currently loaded
                            match is_module_loaded($module) {
                                Ok(is_loaded) => {
                                    if is_loaded {
                                        (
                                            check::CheckState::Invalid,
                                            Some("module is blacklisted but is loaded".to_string()),
                                        )
                                    } else {
                                        (check::CheckState::Valid, None)
                                    }
                                }
                                Err(err) => (check::CheckState::Error, Some(err)),
                            }
                        } else {
                            (
                                check::CheckState::Invalid,
                                Some("not blacklisted".to_string()),
                            )
                        }
                    }
                    Err(err) => (check::CheckState::Error, Some(err)),
                }
            }
        )
    };
}

// check modprobe disabled
// ensure module is disabled AND not currently loaded
// TODO: check for both `-` and `_` variants
macro_rules! check_modprobe_disabled {
    ($checks:tt, $id:tt, $module:tt) => {
        check!(
            $checks,
            $id,
            format!("Ensure that kernel module {} is disabled", $module),
            {
                match is_module_disabled($module) {
                    Ok(value) => {
                        if value {
                            // ensure module is not currently loaded
                            match is_module_loaded($module) {
                                Ok(is_loaded) => {
                                    if is_loaded {
                                        (
                                            check::CheckState::Invalid,
                                            Some("module is disabled but is loaded".to_string()),
                                        )
                                    } else {
                                        (check::CheckState::Valid, None)
                                    }
                                }
                                Err(err) => (check::CheckState::Error, Some(err)),
                            }
                        } else {
                            (check::CheckState::Invalid, Some("not disabled".to_string()))
                        }
                    }
                    Err(err) => (check::CheckState::Error, Some(err)),
                }
            }
        )
    };
}

// check sudoers defaults
// TODO: not sure about that but the order may be of importance, if the defaults
// are after a matching rule then I thinks they are not applied, maybe only
// consider defaults in the main file?
macro_rules! check_sudoers_default {
    ($checks:tt, $id:tt, $defaults:tt) => {
        check!(
            $checks,
            $id,
            format!("Ensure that sudoers config has `Defaults {}`", $defaults),
            {
                match is_sudoers_defaults($defaults) {
                    Ok(is) => {
                        if is {
                            (check::CheckState::Valid, None)
                        } else {
                            (check::CheckState::Invalid, Some("not present".to_string()))
                        }
                    }
                    Err(err) => (check::CheckState::Error, Some(err)),
                }
            }
        )
    };
}

// check that sudo config does not contain `NOPASSWD`
macro_rules! check_sudoers_nopasswd {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure that sudoers config does not contain `NOPASSWD`",
            SUDOERS_CONFIG_DEFAULTS,
            sudo::has_no_nopaswd,
            "found `NOPASSWD`"
        );
    };
}

macro_rules! check_sudoers_re_auth {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure that sudoers re authentication is not disabled",
            SUDOERS_CONFIG_DEFAULTS,
            sudo::re_authentication_not_disabled,
            "found `!authenticate`"
        );
    };
}

// check PAM rule
// TODO: add ability to check if it after or before another rule, the order
// counts a lot in PAM
macro_rules! check_pam_rule {
    // ensure the PAM rule is present
    ($checks:tt, $id:tt, $service:tt, $rule_type:tt, $module:tt) => {
        check!($checks, $id,
            format!(
                "Ensure that {} PAM is configured correctly with {} {}",
                $service, $rule_type, $module
            ), {
        match get_pam_rule($service, $rule_type, $module) {
            Ok(res) => match res {
                Some(_rule) => (check::CheckState::Valid, None),
                None => (check::CheckState::Invalid, Some("not present".to_string())),
            },
            Err(err) => (check::CheckState::Error, Some(err)),
        }})
    };

    // ensure the PAM rule is correctly configured
    ($checks:tt, $id:tt, $service:tt, $rule_type:tt, $module:tt, $control:tt) => {
        check!($checks, $id,
            format!(
                "Ensure that {} PAM control is configured correctly with {} {} set to {}",
                $service, $rule_type, $module, $control
            ), {
        match get_pam_rule($service, $rule_type, $module) {
            Ok(res) => match res {
                Some(rule) => {
                    if rule.control == $control {
                        (check::CheckState::Valid, None)
                    } else {
                        (
                            check::CheckState::Invalid,
                            Some(format!(
                                "control should be `{}` got: `{}`",
                                $control, rule.control,
                            )),
                        )
                    }
                }
                None => (check::CheckState::Invalid, Some("not present".to_string())),
            },
            Err(err) => (check::CheckState::Error, Some(err)),
        }})
    };

    // TODO: this only checks for key and value, also have a way to check for
    // just the key, since some (if not most) flags are just a key without a
    // value
    // TODO: add a variant that convert the type of the value to be compared
    ($checks:tt, $id:tt, $service:tt, $rule_type:tt, $module:tt, $key:tt $comparator:tt $value:tt) => {
        check!($checks, $id,
        if $value == "" {
            format!(
                "Ensure that {} PAM is configured correctly with {} {} arg {} is present",
                $service,
                $rule_type,
                $module,
                $key,
            )
        } else {
            format!(
                "Ensure that {} PAM is configured correctly with {} {} arg {} {} {}",
                $service,
                $rule_type,
                $module,
                $key,
                stringify!($comparator),
                $value
            )
        },
        {
            match get_pam_rule($service, $rule_type, $module) {
                Ok(res) => match res {
                    Some(rule) => {
                        if !rule.settings.contains_key($key) {
                            (
                                check::CheckState::Invalid,
                                Some(format!(
                                    "missing arg: {} {} {}",
                                    $key,
                                    stringify!($comparator),
                                    $value
                                )),
                            )
                        } else if $value == "" {
                            (check::CheckState::Valid, None)
                        } else {
                            if rule.settings.get($key).unwrap() $comparator $value {
                                (check::CheckState::Valid, None)
                            } else {
                                (
                                    check::CheckState::Invalid,
                                    Some(format!(
                                        "arg: {} !{} {}",
                                        $key,
                                        stringify!($comparator),
                                        $value
                                    )),
                                )
                            }
                        }
                    }
                    None => (check::CheckState::Invalid, Some("not present".to_string())),
                },
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        })
    };
}

macro_rules! check_no_dup_username {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure no duplicate user names exist",
            PASSWD_CONFIG,
            users::no_dup_username,
            "duplicates found"
        );
    };
}

macro_rules! check_no_dup_uid {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure no duplicate UIDs exist",
            PASSWD_CONFIG,
            users::no_dup_uid,
            "duplicates found"
        );
    };
}

// check sysctl arguments
macro_rules! check_audit_rule {
    ($checks:tt, $id:tt, $rule:tt) => {
        check!(
            $checks,
            $id,
            format!("Ensure that audit rule `{}` is present", $rule),
            {
                match is_audit_rule_pesent($rule.to_string()) {
                    Ok(value) => {
                        if value {
                            (check::CheckState::Valid, None)
                        } else {
                            (
                                check::CheckState::Invalid,
                                Some("rule not found".to_string()),
                            )
                        }
                    }
                    Err(err) => (check::CheckState::Error, Some(err)),
                }
            }
        )
    };
}

macro_rules! check_audit_config {
    ($checks:tt, $id:tt, $key:tt, $expect:tt) => {
        check!(
            $checks,
            $id,
            format!(
                "Ensure that audit is configured correctly with `{}={}`",
                $key, $expect
            ),
            {
                match get_audit_config($key.to_string()) {
                    Ok(value) => {
                        if value == $expect.to_string() {
                            (check::CheckState::Valid, None)
                        } else {
                            (
                                check::CheckState::Invalid,
                                Some(format!("{:?} !== {:?}", value, $expect)),
                            )
                        }
                    }
                    Err(err) => (check::CheckState::Error, Some(err)),
                }
            }
        )
    };
}

macro_rules! check_grub_password {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure that bootloader password is set",
            GRUB_CFG,
            grub::password_is_set,
            "not set"
        );
    };
}

macro_rules! check_hardened_malloc {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure an hardened malloc is used",
            LD_SO_PRELOAD,
            malloc::has_hardened_malloc,
            "not in use"
        );
    };
}

macro_rules! check_no_login_sys_users {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure no login is available on system accounts",
            PASSWD_CONFIG,
            users::no_login_sys_users,
            "system account found with shell"
        );
    };
}

macro_rules! check_no_empty_passwd_password {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure /etc/passwd password fields are not empty",
            PASSWD_CONFIG,
            users::no_empty_passwd_password,
            ""
        );
    };
}

macro_rules! check_no_empty_shadow_password {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure /etc/shadow password fields are not empty",
            SHADOW_CONFIG,
            users::no_empty_shadow_password,
            ""
        );
    };
}

macro_rules! check_empty_securetty {
    ($checks:tt, $id:tt) => {
        check_bool_error!(
            $checks,
            $id,
            "Ensure that `/etc/securetty` is empty",
            users::empty_securetty,
            "not empty"
        );
    };
}

macro_rules! check_empty_gshadow {
    ($checks:tt, $id:tt) => {
        check_bool_error!(
            $checks,
            $id,
            "Ensure that `/etc/gshadow` is empty",
            group::empty_gshadow,
            "not empty"
        );
    };
}

macro_rules! check_no_password_in_group {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure that no password is present in `/etc/group`",
            GROUP_CONFIG,
            group::no_password_in_group,
            "password found"
        );
    };
}

macro_rules! check_password_in_passwd {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure accounts in /etc/passwd use shadowed passwords",
            PASSWD_CONFIG,
            users::no_password_in_passwd,
            "password found in passwd"
        );
    };
}

macro_rules! check_no_uid_zero {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure that root is the only user with UID 0",
            PASSWD_CONFIG,
            users::no_uid_zero,
            ""
        );
    };
}

macro_rules! check_yescrypt_hashes {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure all passwords are hashed with yescrypt",
            SHADOW_CONFIG,
            users::yescrypt_hashes,
            "found password not using yescrypt"
        );
    };
}

macro_rules! check_no_locked_account {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure no accounts are locked, delete them",
            SHADOW_CONFIG,
            users::no_locked_account,
            "found expired accounts"
        );
    };
}

macro_rules! check_no_missing_home {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure that all home directories exist",
            PASSWD_CONFIG,
            users::no_missing_home,
            "missing home"
        );
    };
}

macro_rules! check_one_gid_zero {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure that only root has GID 0",
            GROUP_CONFIG,
            group::one_gid_zero,
            "dup found"
        );
    };
}

macro_rules! check_no_dup_gid {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure no duplicate GIDs exist",
            GROUP_CONFIG,
            group::no_dup_gid,
            "dup found"
        );
    };
}

macro_rules! check_no_dup_group_name {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure no duplicate group names exist",
            GROUP_CONFIG,
            group::no_dup_name,
            "dup found"
        );
    };
}

macro_rules! check_no_gdm_auto_logon {
    ($checks:tt, $id:tt) => {
        check_bool_error!(
            $checks,
            $id,
            "Ensure no automatic logon to the system via a GUI is possible",
            gdm::no_gdm_auto_logon,
            "not configured"
        );
    };
}

macro_rules! check_reboot_required {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure no reboot is required",
            kernel::check_reboot_required,
            "reboot is required"
        );
    };
}

macro_rules! check_apparmor_enabled {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure AppArmor is enabled",
            apparmor::apparmor_enabled,
            "AppArmor not enabled"
        );
    };
}

macro_rules! check_docker_not_privileged {
    ($checks:tt, $id:tt) => {
        check_bool_error!(
            $checks,
            $id,
            "Ensure containers are not started with `--privileged` flag",
            docker::docker_not_privileged,
            "containers running with `--privileged`"
        );
    };
}

macro_rules! check_docker_cap_drop {
    ($checks:tt, $id:tt) => {
        check_bool_error!(
            $checks,
            $id,
            "Ensure containers capabilities are dopped",
            docker::docker_cap_drop,
            "caps not dropped"
        );
    };
}

macro_rules! check_clamav_installed {
    ($checks:tt, $id:tt) => {
        check_bool!(
            $checks,
            $id,
            "Ensure ClamAV is installed",
            clamav::clamav_installed,
            ""
        );
    };
}

fn main() {
    let args = Cli::parse();

    let now = Instant::now();

    // initialize configuration, this is the slow part
    init();

    // do the checks
    checks(args);

    println!("\ntook: {}ms", now.elapsed().as_millis());
}

/// Run checks.
fn checks(args: Cli) {
    config::set_colored_output(!args.disable_colors);

    let mut checks = check::CheckList { checks: Vec::new() };

    check_pam_rule!(checks, "PAM_001", "passwd", "account", "pam_unix", "required");
    check_pam_rule!(
        checks,
        "PAM_002",
        "passwd",
        "password",
        "pam_pwquality",
        "required"
    );
    check_pam_rule!(
        checks,
        "PAM_003",
        "passwd",
        "password",
        "pam_pwquality",
        "retry" == "4"
    );
    check_pam_rule!(
        checks,
        "PAM_004",
        "passwd",
        "password",
        "pam_pwquality",
        "shadowretry" == "3"
    );
    check_pam_rule!(
        checks,
        "PAM_005",
        "passwd",
        "password",
        "pam_pwquality",
        "minlen" == "16"
    );
    check_pam_rule!(
        checks,
        "PAM_006",
        "passwd",
        "password",
        "pam_pwquality",
        "difok" == "14"
    );
    check_pam_rule!(
        checks,
        "PAM_007",
        "passwd",
        "password",
        "pam_pwquality",
        "dcredit" == "-1"
    );
    check_pam_rule!(
        checks,
        "PAM_008",
        "passwd",
        "password",
        "pam_pwquality",
        "ucredit" == "-1"
    );
    check_pam_rule!(
        checks,
        "PAM_009",
        "passwd",
        "password",
        "pam_pwquality",
        "ocredit" == "-1"
    );
    check_pam_rule!(
        checks,
        "PAM_010",
        "passwd",
        "password",
        "pam_pwquality",
        "lcredit" == "-1"
    );
    check_pam_rule!(
        checks,
        "PAM_011",
        "passwd",
        "password",
        "pam_pwquality",
        "gecoscheck" == "1"
    );
    check_pam_rule!(
        checks,
        "PAM_012",
        "passwd",
        "password",
        "pam_pwquality",
        "maxrepeat" == "3"
    );
    check_pam_rule!(
        checks,
        "PAM_013",
        "passwd",
        "password",
        "pam_pwquality",
        "enforce_for_root" == ""
    );
    check_pam_rule!(
        checks,
        "PAM_014",
        "passwd",
        "password",
        "pam_unix",
        "rounds" == "65536"
    );

    // Ensure access to the su command is restricted (CIS)
    check_pam_rule!(checks, "PAM_015", "su", "auth", "pam_wheel", "required");
    check_pam_rule!(
        checks,
        "PAM_016",
        "su",
        "auth",
        "pam_wheel",
        "use_uid" == ""
    );
    check_pam_rule!(
        checks,
        "PAM_017",
        "su",
        "auth",
        "pam_wheel",
        "root_only" == ""
    );

    // PAM sshd faillock
    check_pam_rule!(
        checks,
        "PAM_018",
        "sshd",
        "auth",
        "pam_faillock",
        "required"
    );

    // TODO: alternatively set inside `/etc/security/faillock.conf`
    check_pam_rule!(
        checks,
        "PAM_019",
        "sshd",
        "auth",
        "pam_faillock",
        "deny" == "8"
    );
    check_pam_rule!(
        checks,
        "PAM_020",
        "sshd",
        "auth",
        "pam_faillock",
        "unlock_time" == "600"
    );
    check_pam_rule!(
        checks,
        "PAM_021",
        "sshd",
        "auth",
        "pam_faillock",
        "fail_interval" == "900"
    );
    check_pam_rule!(
        checks,
        "PAM_022",
        "sshd",
        "auth",
        "pam_faillock",
        "audit" == ""
    );
    check_pam_rule!(
        checks,
        "PAM_023",
        "sshd",
        "auth",
        "pam_faillock",
        "silent" == ""
    );

    // PAM login faillock
    // FIXME: on Arch `login` is: `system-login`
    check_pam_rule!(
        checks,
        "PAM_024",
        "login",
        "auth",
        "pam_faillock",
        "required"
    );
    check_pam_rule!(
        checks,
        "PAM_025",
        "login",
        "auth",
        "pam_faillock",
        "deny" == "8"
    );
    check_pam_rule!(
        checks,
        "PAM_026",
        "login",
        "auth",
        "pam_faillock",
        "unlock_time" == "600"
    );
    check_pam_rule!(
        checks,
        "PAM_027",
        "login",
        "auth",
        "pam_faillock",
        "fail_interval" == "900"
    );
    check_pam_rule!(
        checks,
        "PAM_028",
        "login",
        "auth",
        "pam_faillock",
        "audit" == ""
    );
    check_pam_rule!(
        checks,
        "PAM_029",
        "login",
        "auth",
        "pam_faillock",
        "silent" == ""
    );

    // PAM login faildelay
    check_pam_rule!(
        checks,
        "PAM_030",
        "login",
        "auth",
        "pam_faildelay",
        "optional"
    );
    check_pam_rule!(
        checks,
        "PAM_031",
        "login",
        "auth",
        "pam_faildelay",
        "delay" == "4000000"
    );

    // TODO: ensure that `nullok` is NOT present in `passwd auth`
    // TODO: ensure pam_pwhistory is setup

    check_password_in_passwd!(checks, "USR_001");

    check_ps_running!(checks, "AUD_001", "auditd");

    check_audit_config!(checks, "AUD_010", "disk_full_action", "HALT");

    // FIXME: add numbers to AUD_
    check_audit_rule!(checks, "AUD_100", "-e 2"); // ensure auditd rules are immutable

    // temp remove audit rules, since they are so context dependant
    // check_audit_rule!(checks, "AUD_101", "-w /var/log/sudo.log -p wa -k log_file");
    // check_audit_rule!(checks, "AUD_102", "-w /etc/group -p wa -k identity");
    // check_audit_rule!(checks, "AUD_103", "-w /etc/passwd -p wa -k identity");
    // check_audit_rule!(checks, "AUD_104", "-w /etc/gshadow -p wa -k identity");
    // check_audit_rule!(checks, "AUD_105", "-w /etc/shadow -p wa -k identity");
    // check_audit_rule!(
    //     checks,
    //     "AUD_106",
    //     "-w /etc/security/opasswd -p wa -k identity"
    // );
    // // 1000 being the min UID
    // check_audit_rule!(checks, "AUD_107", "-a always,exit -F arch=b64 -S create_module,init_module,delete_module,query_module,finit_module -F auid>=1000 -F auid!=-1 -F key=kernel_modules");
    //
    // // <https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/finding/V-258195>
    // // check_audit_rule!(checks, "AUD_001", "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k modules"); // STIG
    // check_audit_rule!(checks, "AUD_108", "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules"); // FIXME: on NixOS change to `/run/current-system/sw/bin/kmod`
    // check_audit_rule!(checks, "AUD_109", "-w /var/log/lastlog -p wa -k login");
    // check_audit_rule!(checks, "AUD_110", "-w /var/run/faillog -p wa -k login"); // FIXME: where is it on NixOS ?
    // check_audit_rule!(checks, "AUD_111", "-w /var/run/faillock -p wa -k login"); // FIXME: where is it on NixOS ?
    // check_audit_rule!(checks, "AUD_112", "-w /etc/apparmor -p wa -k mac_policy");
    // check_audit_rule!(checks, "AUD_113", "-w /etc/apparmor.d -p wa -k mac_policy");
    // check_audit_rule!(
    //     checks,
    //     "AUD_114",
    //     "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
    // ); // FIXME: on NixOS change to `/run/current-system/sw/bin/chcon`
    // check_audit_rule!(checks, "AUD_115", "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng");
    // check_audit_rule!(
    //     checks,
    //     "AUD_116",
    //     "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
    // ); // FIXME: on NixOS change to `/run/current-system/sw/bin/chacl`
    // check_audit_rule!(checks, "AUD_117", "-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng");
    // check_audit_rule!(
    //     checks,
    //     "AUD_118",
    //     "-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd"
    // );
    // check_audit_rule!(checks, "AUD_119", "-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd");
    // check_audit_rule!(
    //     checks,
    //     "AUD_120",
    //     "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd"
    // );
    //
    // check_audit_rule!(checks, "AUD_121", "-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access");
    // check_audit_rule!(checks, "AUD_122", "-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access");
    // check_audit_rule!(checks, "AUD_123", "-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access");
    // check_audit_rule!(checks, "AUD_124", "-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access");
    //
    // check_audit_rule!(checks, "AUD_125", "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng");
    // check_audit_rule!(checks, "AUD_126", "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng");
    //
    // check_audit_rule!(checks, "AUD_127", "-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng");
    // check_audit_rule!(checks, "AUD_128", "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng");
    //
    // check_audit_rule!(checks, "AUD_129", "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod");
    // check_audit_rule!(checks, "AUD_130", "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod");
    // check_audit_rule!(checks, "AUD_131", "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod");
    // check_audit_rule!(checks, "AUD_132", "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod");
    //
    // check_audit_rule!(checks, "AUD_133", "-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh");
    // check_audit_rule!(checks, "AUD_134", "-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh");
    //
    // check_audit_rule!(checks, "AUD_135", "-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-umount");
    // check_audit_rule!(checks, "AUD_136", "-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount");
    //
    // check_audit_rule!(checks, "AUD_137", "-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chfn");
    //
    // check_audit_rule!(checks, "AUD_138", "-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change");
    //
    // // <https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/finding/V-258217>
    // // check_audit_rule!(checks, "AUD_001", "-w /etc/sudoers -p wa -k identity"); // STIG
    // check_audit_rule!(checks, "AUD_139", "-w /etc/sudoers -p wa -k scope");
    // check_audit_rule!(checks, "AUD_140", "-w /etc/sudoers.d -p wa -k scope"); // FIXME: not needed on NixOS
    // check_audit_rule!(checks, "AUD_141", "-w /var/run/utmp -p wa -k session");
    // check_audit_rule!(checks, "AUD_142", "-w /var/log/wtmp -p wa -k session");
    // check_audit_rule!(checks, "AUD_143", "-w /var/log/btmp -p wa -k session");
    // check_audit_rule!(
    //     checks,
    //     "AUD_144",
    //     "-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system_locale"
    // );
    // check_audit_rule!(
    //     checks,
    //     "AUD_145",
    //     "-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system_locale"
    // );
    // check_audit_rule!(checks, "AUD_146", "-w /etc/issue -p wa -k system_locale");
    // check_audit_rule!(
    //     checks,
    //     "AUD_147",
    //     "-w /etc/issue.net -p wa -k system_locale"
    // ); // FIXME: not needed on NixOS
    // check_audit_rule!(checks, "AUD_148", "-w /etc/hosts -p wa -k system_locale");
    // check_audit_rule!(checks, "AUD_149", "-w /etc/networks -p wa -k system_locale"); // FIXME: not needed on NixOS
    // check_audit_rule!(checks, "AUD_150", "-w /etc/network/ -p wa -k system_locale"); // FIXME: not needed on NixOS
    // check_audit_rule!(
    //     checks,
    //     "AUD_151",
    //     "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -F key=time_change"
    // );
    // check_audit_rule!(
    //     checks,
    //     "AUD_152",
    //     "-a always,exit -F arch=b32 -S settimeofday,adjtimex,clock_settime -F key=time_change"
    // );
    // check_audit_rule!(checks, "AUD_153", "-w /etc/localtime -p wa -k time_change");
    // check_audit_rule!(
    //     checks,
    //     "AUD_154",
    //     "-a always,exit -F arch=b64 -S execve -C euid!=uid -F auid!=-1 -F key=user_emulation"
    // );
    // check_audit_rule!(
    //     checks,
    //     "AUD_155",
    //     "-a always,exit -F arch=b32 -S execve -C euid!=uid -F auid!=-1 -F key=user_emulation"
    // );
    // check_audit_rule!(checks, "AUD_156", "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod");
    //
    // check_audit_rule!(checks, "AUD_157", "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd");
    //
    // // <https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/finding/V-258194>
    // check_audit_rule!(checks, "AUD_158", "-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-gpasswd"); // STIG
    //
    // // <https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/finding/V-258192>
    // check_audit_rule!(
    //     checks,
    //     "AUD_159",
    //     "-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd"
    // ); // STIG
    //
    // // <https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/finding/V-258193>
    // check_audit_rule!(checks, "AUD_160", "-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-crontab"); // STIG
    //
    // // <https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/finding/V-258190>
    // check_audit_rule!(checks, "AUD_161", "-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng"); // STIG
    // check_audit_rule!(checks, "AUD_162", "-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng"); // STIG
    //
    // // <https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/finding/V-258191>
    // check_audit_rule!(checks, "AUD_163", "-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage"); // STIG
    //
    // // <https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/finding/V-258215>
    // check_audit_rule!(
    //     checks,
    //     "AUD_164",
    //     "-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=unset -k privileged-umount"
    // ); // STIG
    //
    // // <https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/finding/V-258214>
    // check_audit_rule!(checks, "AUD_165", "-a always,exit -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=unset -k privileged-shutdown"); // STIG

    // TODO: ensure Grub is configured to load audit

    check_grub_password!(checks, "GRB_001");
    // TODO: add owner and permissions checks on /boot/grub/grub.cfg
    // to: 0600 and root:root

    // TODO: Ensure all groups in /etc/passwd exist in /etc/group
    // TODO: Ensure shadow group is empty
    // TODO: Ensure no duplicate UIDs exist
    // TODO: Ensure no duplicate GIDs exist
    // TODO: Ensure no duplicate group names exist

    check_no_uid_zero!(checks, "USR_001");
    check_no_dup_username!(checks, "USR_002");
    check_no_dup_uid!(checks, "USR_003");
    check_empty_securetty!(checks, "USR_004");
    check_no_login_sys_users!(checks, "USR_005");
    check_yescrypt_hashes!(checks, "USR_006");
    check_no_locked_account!(checks, "USR_007");
    check_no_missing_home!(checks, "USR_008");
    check_no_empty_shadow_password!(checks, "USR_009");
    check_no_empty_passwd_password!(checks, "USR_010");

    check_empty_gshadow!(checks, "GRP_001");
    check_one_gid_zero!(checks, "GRP_002");
    check_no_dup_gid!(checks, "GRP_003");
    check_no_dup_group_name!(checks, "GRP_004");
    check_no_password_in_group!(checks, "GRP_005");

    check_no_gdm_auto_logon!(checks, "GDM_001");

    check_hardened_malloc!(checks, "LIB_001");

    check_reboot_required!(checks, "SYS_001");

    check_apparmor_enabled!(checks, "AAR_001");

    check_docker_cap_drop!(checks, "CNT_001");
    check_docker_not_privileged!(checks, "CNT_002");

    check_clamav_installed!(checks, "CAV_001");

    // TODO: `/var/log` 0755 or less permissive - STIG

    // TODO: Ensure that library files have mode 755 or less permissive - STIG
    // sudo find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec ls -l {} \;

    // TODO: systemd coredump <https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/finding/V-257812>
    // TODO: coredumps <https://www.stigviewer.com/stig/red_hat_enterprise_linux_9/2024-06-04/finding/V-257813>
    // TODO: shost <https://www.stigviewer.com/stig/oracle_linux_8/2024-06-04/finding/V-248598>

    checks.filter_id(args.filters);

    checks.run();

    if !args.disable_print_checks {
        checks.print();
    }

    if !args.disable_print_stats {
        checks.print_stats();
    }
}

macro_rules! init_or_log {
    ($func:expr, $store:tt) => {
        assert!($store.get().is_none());
        match $func() {
            Ok(config) => {
                $store.get_or_init(|| config);
            }
            Err(err) => println!("{} error: {}", stringify!($func), err),
        };
    };
}

/// Initialize all configurations before running checks.
fn init() {
    // get first
    init_or_log!(os::init_kernel_os_type, KERNEL_OS_TYPE);
    init_or_log!(os::init_kernel_os_release, KERNEL_OS_RELEASE);
    init_or_log!(os::init_os_release, OS_RELEASE);

    init_or_log!(ps::init_proc, PS);
    init_or_log!(sysctl::init_sysctl_config, SYSCTL_CONFIG);
    init_or_log!(systemd::init_systemd_config, SYSTEMD_CONFIG);
    init_or_log!(sshd::init_sshd_config, SSHD_CONFIG);
    init_or_log!(kernel::init_kernel_params, KERNEL_PARAMS);
    init_or_log!(kconfig::init_kcompile_config, KCOMPILE_CONFIG);
    init_or_log!(login_defs::init_login_defs, LOGIN_DEFS);
    init_or_log!(mount::init_mounts, MOUNTS);
    init_or_log!(nginx::init_nginx_config, NGINX_CONF);
    init_or_log!(modprobe::init_modprobe, MODPROBE_CONFIG);
    init_modprobe_blacklist();
    init_modprobe_disabled();
    init_or_log!(modprobe::init_loaded_modules, LOADED_MODULES);
    init_or_log!(sudo::init_sudoer, SUDOERS_CONFIG);
    init_sudoer_defaults();
    init_or_log!(pam::init_pam, PAM_CONFIG);
    init_or_log!(users::init_passwd, PASSWD_CONFIG);
    init_or_log!(users::init_shadow, SHADOW_CONFIG);
    init_or_log!(group::init_group, GROUP_CONFIG);
    init_or_log!(audit::init_audit_rules, AUDIT_RULES);
    init_or_log!(audit::init_audit_config, AUDIT_CONFIG);
    init_or_log!(grub::init_grub_cfg, GRUB_CFG);
    init_or_log!(malloc::init_ld_so_preload, LD_SO_PRELOAD);

    let _ = uptime::init_uptime();
}

/// Initialize sudoers `Defaults` configuration.
fn init_sudoer_defaults() {
    assert!(SUDOERS_CONFIG.get().is_some());
    assert!(SUDOERS_CONFIG_DEFAULTS.get().is_none());
    SUDOERS_CONFIG_DEFAULTS
        .get_or_init(|| sudo::init_sudoer_defaults(SUDOERS_CONFIG.get().unwrap()));
}

/// Initialize blacklisted modules configuration.
fn init_modprobe_blacklist() {
    assert!(MODPROBE_CONFIG.get().is_some());
    assert!(MODPROBE_BLACKLIST.get().is_none());
    let config = modprobe::init_modprobe_blacklist(MODPROBE_CONFIG.get().unwrap());
    MODPROBE_BLACKLIST.get_or_init(|| config);
}

/// Initialize disabled modules configuration.
fn init_modprobe_disabled() {
    assert!(MODPROBE_CONFIG.get().is_some());
    assert!(MODPROBE_DISABLED.get().is_none());
    let config = modprobe::init_modprobe_disabled(MODPROBE_CONFIG.get().unwrap());
    MODPROBE_DISABLED.get_or_init(|| config);
}

fn get_ssyctl(variable: &str) -> Result<&'static str, String> {
    match SYSCTL_CONFIG.get() {
        Some(config) => sysctl::get_ssyctl(config, variable),
        None => Err("sysctl config not initialized".to_string()),
    }
}

fn get_sshd_config(variable: &str) -> Result<&'static str, String> {
    match SSHD_CONFIG.get() {
        Some(config) => sshd::get_sshd_config(config, variable),
        None => Err("sshd config not initialized".to_string()),
    }
}

fn get_systemd_config(variable: &str) -> Result<&'static str, String> {
    match SYSTEMD_CONFIG.get() {
        Some(config) => systemd::get_systemd_config(config, variable),
        None => Err("SYSTEMD_CONFIG not initialized".to_string()),
    }
}

fn get_kernel_params(variable: &str) -> Result<bool, String> {
    match KERNEL_PARAMS.get() {
        Some(params) => Ok(kernel::get_kernel_params(params, variable.to_string())),
        None => Err("kernel param not initialized".to_string()),
    }
}

fn get_login_defs(variable: &str) -> Result<&'static str, String> {
    match LOGIN_DEFS.get() {
        Some(config) => login_defs::get_login_defs(config, variable),
        None => Err("login.defs not initialized".to_string()),
    }
}

fn get_mount(target: &str) -> Result<Option<&mount::Mount>, String> {
    match MOUNTS.get() {
        Some(mounts) => mount::get_mount(mounts, target),
        None => Err("mount not initialized".to_string()),
    }
}

fn get_mount_options(target: &str) -> Result<Vec<String>, String> {
    match MOUNTS.get() {
        Some(mounts) => mount::get_mount_options(mounts, target),
        None => Err("mount not initialized".to_string()),
    }
}

fn is_module_blacklisted(module: &str) -> Result<bool, String> {
    match MODPROBE_BLACKLIST.get() {
        Some(params) => Ok(params.contains(&module.to_string())),
        None => Err("modprobe blacklist not initialized".to_string()),
    }
}

fn is_module_disabled(module: &str) -> Result<bool, String> {
    match MODPROBE_DISABLED.get() {
        Some(params) => Ok(params.contains(&module.to_string())),
        None => Err("modprobe disabled not initialized".to_string()),
    }
}

fn is_sudoers_defaults(defaults: &str) -> Result<bool, String> {
    match SUDOERS_CONFIG_DEFAULTS.get() {
        Some(params) => Ok(params.contains(&defaults.to_string())),
        None => Err("sudoers config defaults not initialized".to_string()),
    }
}

fn is_module_loaded(module: &str) -> Result<bool, String> {
    match LOADED_MODULES.get() {
        Some(params) => Ok(params.contains(&module.to_string())),
        None => Err("loaded modules not initialized".to_string()),
    }
}

fn get_pam_rule<'a>(
    service: &'a str,
    rule_type: &'a str,
    module: &'a str,
) -> Result<Option<&'a pam::PamRule>, String> {
    match PAM_CONFIG.get() {
        Some(config) => pam::get_pam_rule(config, service, rule_type, module),
        None => Err("pam config not initialized".to_string()),
    }
}

fn is_audit_rule_pesent(rule: String) -> Result<bool, String> {
    // TOOD: add an alternative to ignore the name of the rule, `-k` param
    match AUDIT_RULES.get() {
        Some(rules) => Ok(rules.contains(&rule)),
        None => Err("audit rules not initialized".to_string()),
    }
}

fn get_audit_config(key: String) -> Result<String, String> {
    match AUDIT_CONFIG.get() {
        Some(config) => audit::get_audit_config(config, key),
        None => Err("audit config not initialized".to_string()),
    }
}

fn get_kcompile_config(key: String) -> Result<String, String> {
    match KCOMPILE_CONFIG.get() {
        Some(kconfig) => kconfig::get_kcompile_config(kconfig, key),
        None => Err("kernel compile config not initialized".to_string()),
    }
}

fn get_kcompile_not_set_config(key: String) -> Result<bool, String> {
    match KCOMPILE_CONFIG.get() {
        Some(kconfig) => kconfig::get_kcompile_not_set_config(kconfig, key),
        None => Err("kernel compile config not initialized".to_string()),
    }
}
