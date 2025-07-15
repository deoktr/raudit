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

// TODO: only run checks if they are not ignored
// TODO: add a way to automatically generate checks ID
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
    //
    // /// Disable colored output
    // #[arg(long, action = clap::ArgAction::SetTrue)]
    // disable_colors: bool,
    //
    /// Comma-separated list of ID prefixes to filter
    #[arg(long, value_delimiter = ',')]
    filters: Vec<String>,
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
    let mut checks = check::CheckList { checks: Vec::new() };

    check_sysctl!(checks, "SYS_001", "kernel.kptr_restrict" == 2);
    check_sysctl!(checks, "SYS_002", "kernel.ftrace_enabled" == 0);
    check_sysctl!(checks, "SYS_003", "kernel.randomize_va_space" == 2); // CIS
    check_sysctl!(checks, "SYS_004", "kernel.dmesg_restrict" == 1);
    check_sysctl!(checks, "SYS_005", "kernel.printk", "3\t3\t3\t3");
    check_sysctl!(checks, "SYS_006", "kernel.perf_cpu_time_max_percent" == 1);
    check_sysctl!(checks, "SYS_007", "kernel.perf_event_max_sample_rate" == 1);
    check_sysctl!(checks, "SYS_008", "kernel.perf_event_paranoid" >= 2); // 2 or 3
    check_sysctl!(checks, "SYS_009", "kernel.sysrq" == 0);
    check_sysctl!(checks, "SYS_010", "kernel.kexec_load_disabled" == 1);
    check_sysctl!(checks, "SYS_011", "kernel.unprivileged_bpf_disabled" == 1);
    check_sysctl!(checks, "SYS_012", "net.core.bpf_jit_harden" == 2);
    check_sysctl!(checks, "SYS_013", "kernel.panic_on_oops" == 1);
    check_sysctl!(checks, "SYS_014", "kernel.panic", "-1");
    check_sysctl!(checks, "SYS_015", "kernel.modules_disabled" == 1);
    check_sysctl!(checks, "SYS_016", "kernel.unprivileged_userns_clone" == 0); // TODO: only available on Debian
    check_sysctl!(checks, "SYS_017", "kernel.yama.ptrace_scope" >= 1); // 2 or 3, CIS recommends 1
    check_sysctl!(checks, "SYS_018", "kernel.io_uring_disabled" == 2);
    check_sysctl!(checks, "SYS_019", "kernel.core_pattern", "|/bin/false");
    check_sysctl!(checks, "SYS_020", "kernel.core_uses_pid" == 1);
    check_sysctl!(checks, "SYS_021", "vm.unprivileged_userfaultfd" == 0);
    check_sysctl!(checks, "SYS_022", "vm.mmap_rnd_bits" == 32);
    check_sysctl!(checks, "SYS_023", "vm.mmap_rnd_compat_bits" == 16);
    check_sysctl!(checks, "SYS_024", "vm.mmap_min_addr" == 65536);
    check_sysctl!(checks, "SYS_025", "dev.tty.ldisc_autoload" == 0);
    check_sysctl!(checks, "SYS_026", "dev.tty.legacy_tiocsti" == 0);
    check_sysctl!(checks, "SYS_027", "vm.max_map_count" == 1048576);
    check_sysctl!(checks, "SYS_028", "vm.swappiness" == 1);
    check_sysctl!(checks, "SYS_029", "fs.suid_dumpable" == 0); // CIS
    check_sysctl!(checks, "SYS_030", "fs.protected_fifos" == 2);
    check_sysctl!(checks, "SYS_031", "fs.protected_regular" == 2);
    check_sysctl!(checks, "SYS_032", "fs.protected_symlinks" == 1);
    check_sysctl!(checks, "SYS_033", "fs.protected_hardlinks" == 1);
    check_sysctl!(checks, "SYS_034", "fs.binfmt_misc.status" == 0); // TODO: ignore if not present
    check_sysctl!(checks, "SYS_035", "net.ipv4.ip_forward" == 0); // CIS
    check_sysctl!(
        checks,
        "SYS_036",
        "net.ipv4.conf.all.accept_source_route" == 0
    ); // CIS
    check_sysctl!(
        checks,
        "SYS_037",
        "net.ipv4.conf.default.accept_source_route" == 0
    ); // CIS STIG
    check_sysctl!(
        checks,
        "SYS_038",
        "net.ipv6.conf.all.accept_source_route" == 0
    ); // CIS
    check_sysctl!(
        checks,
        "SYS_039",
        "net.ipv6.conf.default.accept_source_route" == 0
    ); // CIS
    check_sysctl!(checks, "SYS_040", "net.ipv4.conf.all.accept_redirects" == 0); // CIS
    check_sysctl!(
        checks,
        "SYS_041",
        "net.ipv4.conf.default.accept_redirects" == 0
    ); // CIS STIG
    check_sysctl!(checks, "SYS_042", "net.ipv4.conf.all.secure_redirects" == 0); // CIS
    check_sysctl!(
        checks,
        "SYS_043",
        "net.ipv4.conf.default.secure_redirects" == 0
    ); // CIS
    check_sysctl!(checks, "SYS_044", "net.ipv4.conf.all.send_redirects" == 0); // CIS
    check_sysctl!(
        checks,
        "SYS_045",
        "net.ipv4.conf.default.send_redirects" == 0
    ); // CIS
    check_sysctl!(checks, "SYS_046", "net.ipv6.conf.all.accept_redirects" == 0); // CIS
    check_sysctl!(
        checks,
        "SYS_047",
        "net.ipv6.conf.default.accept_redirects" == 0
    ); // CIS
    check_sysctl!(checks, "SYS_048", "net.ipv6.conf.all.send_redirects" == 0);
    check_sysctl!(
        checks,
        "SYS_049",
        "net.ipv6.conf.default.send_redirects" == 0
    );
    check_sysctl!(checks, "SYS_050", "net.ipv4.icmp_echo_ignore_all" == 1);
    check_sysctl!(checks, "SYS_051", "net.ipv6.icmp.echo_ignore_all" == 1);
    check_sysctl!(
        checks,
        "SYS_052",
        "net.ipv4.icmp_echo_ignore_broadcasts" == 1
    ); // CIS
    check_sysctl!(checks, "SYS_053", "net.ipv4.conf.all.rp_filter" == 1); // CIS STIG
    check_sysctl!(checks, "SYS_054", "net.ipv4.conf.default.rp_filter" == 1); // CIS
    check_sysctl!(
        checks,
        "SYS_055",
        "net.ipv4.icmp_ignore_bogus_error_responses" == 1
    ); // CIS STIG
    check_sysctl!(checks, "SYS_056", "net.ipv4.icmp_ratelimit" <= 100);
    check_sysctl!(checks, "SYS_057", "net.ipv4.icmp_ratemask" == 88089);
    check_sysctl!(checks, "SYS_058", "net.ipv4.tcp_syncookies" == 1); // CIS
    check_sysctl!(checks, "SYS_059", "net.ipv4.conf.all.accept_local" == 0);
    check_sysctl!(checks, "SYS_060", "net.ipv4.conf.all.shared_media" == 1);
    check_sysctl!(checks, "SYS_061", "net.ipv4.conf.default.shared_media" == 1);
    check_sysctl!(checks, "SYS_062", "net.ipv4.conf.all.arp_filter" == 1);
    check_sysctl!(checks, "SYS_063", "net.ipv4.conf.all.arp_ignore" == 2);
    check_sysctl!(checks, "SYS_064", "net.ipv4.conf.default.arp_ignore" == 2);
    check_sysctl!(checks, "SYS_065", "net.ipv4.conf.default.arp_announce" == 2);
    check_sysctl!(checks, "SYS_066", "net.ipv4.conf.all.arp_announce" == 2);
    check_sysctl!(checks, "SYS_067", "net.ipv4.conf.all.route_localnet" == 0);
    check_sysctl!(
        checks,
        "SYS_068",
        "net.ipv4.conf.all.drop_gratuitous_arp" == 1
    );
    check_sysctl!(
        checks,
        "SYS_069",
        "net.ipv4.ip_local_port_range",
        "32768\t65535"
    );
    check_sysctl!(checks, "SYS_070", "net.ipv4.tcp_rfc1337" == 1);
    check_sysctl!(checks, "SYS_071", "net.ipv6.conf.all.forwarding" == 0); // CIS
    check_sysctl!(checks, "SYS_072", "net.ipv6.conf.default.forwarding" == 0);
    check_sysctl!(checks, "SYS_073", "net.ipv6.conf.all.accept_ra" == 0); // CIS
    check_sysctl!(checks, "SYS_074", "net.ipv6.conf.default.accept_ra" == 0); // CIS
    check_sysctl!(checks, "SYS_075", "net.ipv4.tcp_timestamps" == 0);
    check_sysctl!(checks, "SYS_076", "net.ipv4.conf.all.log_martians" == 1); // CIS STIG
    check_sysctl!(checks, "SYS_077", "net.ipv4.conf.default.log_martians" == 1); // CIS STIG
    check_sysctl!(
        checks,
        "SYS_078",
        "net.ipv6.conf.all.router_solicitations" == 0
    );
    check_sysctl!(
        checks,
        "SYS_079",
        "net.ipv6.conf.default.router_solicitations" == 0
    );
    check_sysctl!(
        checks,
        "SYS_080",
        "net.ipv6.conf.all.accept_ra_rtr_pref" == 0
    );
    check_sysctl!(
        checks,
        "SYS_081",
        "net.ipv6.conf.default.accept_ra_rtr_pref" == 0
    );
    check_sysctl!(checks, "SYS_082", "net.ipv6.conf.all.accept_ra_defrtr" == 0);
    check_sysctl!(
        checks,
        "SYS_083",
        "net.ipv6.conf.default.accept_ra_defrtr" == 0
    );
    check_sysctl!(checks, "SYS_084", "net.ipv6.conf.all.autoconf" == 0);
    check_sysctl!(checks, "SYS_085", "net.ipv6.conf.default.autoconf" == 0);
    check_sysctl!(checks, "SYS_086", "net.ipv6.conf.all.max_addresses" == 1);
    check_sysctl!(
        checks,
        "SYS_087",
        "net.ipv6.conf.default.max_addresses" == 1
    );
    check_sysctl!(checks, "SYS_088", "net.core.bpf_jit_enable" == 0); // TODO: paranoid
    check_sysctl!(checks, "SYS_089", "net.ipv4.tcp_sack" == 0); // TODO: paranoid
    check_sysctl!(checks, "SYS_090", "net.ipv4.tcp_dsack" == 0); // TODO: paranoid
    check_sysctl!(checks, "SYS_091", "net.ipv4.tcp_fack" == 0); // TODO: paranoid
    check_sysctl!(checks, "SYS_092", "net.ipv6.conf.all.use_tempaddr" == 2); // TODO: paranoid
    check_sysctl!(checks, "SYS_093", "net.ipv6.conf.default.use_tempaddr" == 2); // TODO: paranoid

    // from kernel-hardening-checker:
    check_sysctl!(checks, "SYS_094", "user.max_user_namespaces" <= 31231); // may break the upower daemon in Ubuntu
    check_sysctl!(checks, "SYS_095", "kernel.warn_limit" <= 100);
    check_sysctl!(checks, "SYS_096", "kernel.oops_limit" <= 100);

    // https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/40_kernel_hardening.cfg
    check_kernel_param!(checks, "KNP_001", "slab_nomerge");
    check_kernel_param!(checks, "KNP_002", "slab_debug=FZ");
    check_kernel_param!(checks, "KNP_003", "page_poison=1");
    check_kernel_param!(checks, "KNP_004", "page_alloc.shuffle=1");
    check_kernel_param!(checks, "KNP_005", "init_on_alloc=1");
    check_kernel_param!(checks, "KNP_006", "init_on_free=1");
    check_kernel_param!(checks, "KNP_007", "pti=on");
    check_kernel_param!(checks, "KNP_008", "randomize_kstack_offset=on");
    check_kernel_param!(checks, "KNP_009", "vsyscall=none");
    check_kernel_param!(checks, "KNP_010", "debugfs=off");
    check_kernel_param!(checks, "KNP_011", "oops=panic");
    check_kernel_param!(checks, "KNP_012", "module.sig_enforce=1");
    check_kernel_param!(checks, "KNP_013", "lockdown=confidentiality");
    check_kernel_param!(checks, "KNP_014", "mce=0");
    check_kernel_param!(checks, "KNP_016", "kfence.sample_interval=100");
    check_kernel_param!(checks, "KNP_017", "vdso32=0");
    check_kernel_param!(checks, "KNP_018", "amd_iommu=force_isolation");
    check_kernel_param!(checks, "KNP_019", "intel_iommu=on");
    check_kernel_param!(checks, "KNP_020", "iommu=force");
    check_kernel_param!(checks, "KNP_021", "iommu.passthrough=0");
    check_kernel_param!(checks, "KNP_022", "iommu.strict=1");
    check_kernel_param!(checks, "KNP_023", "efi=disable_early_pci_dma");
    check_kernel_param!(checks, "KNP_024", "random.trust_bootloader=off");
    check_kernel_param!(checks, "KNP_025", "random.trust_cpu=off");
    check_kernel_param!(checks, "KNP_026", "extra_latent_entropy");
    check_kernel_param!(checks, "KNP_028", "ipv6.disable=1");
    check_kernel_param!(checks, "KNP_029", "ia32_emulation=0"); // TODO: mark as 'paranoid'
    check_kernel_param!(checks, "KNP_016", "cfi=kcfi"); // TODO: mark as 'paranoid'
    check_kernel_param!(checks, "KNP_017", "random.trust_cpu=off"); // TODO: mark as 'paranoid'

    // from: kernel-hardening-checker
    // https://lwn.net/Articles/695991/
    check_kernel_param!(checks, "KNP_020", "hardened_usercopy=1");

    // Remount secure
    // https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/40_remount_secure.cfg
    check_kernel_param!(checks, "KNP_027", "remountsecure=3");

    // X86 64 and 32 CPU mitigations
    // https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/40_cpu_mitigations.cfg
    check_kernel_param!(checks, "KNP_030", "mitigations=auto");
    check_kernel_param!(checks, "KNP_030", "mitigations=auto,nosmt"); // TODO: paranoid
    check_kernel_param!(checks, "KNP_031", "nosmt=force"); // TODO: paranoid
    check_kernel_param!(checks, "KNP_032", "spectre_v2=on");
    check_kernel_param!(checks, "KNP_033", "spectre_bhi=on");
    check_kernel_param!(checks, "KNP_034", "spec_store_bypass_disable=on");
    check_kernel_param!(checks, "KNP_035", "l1tf=full,force");
    check_kernel_param!(checks, "KNP_036", "mds=full");
    check_kernel_param!(checks, "KNP_036", "mds=full,nosm"); // TODO: paranoid
    check_kernel_param!(checks, "KNP_037", "tsx=off");
    check_kernel_param!(checks, "KNP_038", "tsx_async_abort=full");
    check_kernel_param!(checks, "KNP_038", "tsx_async_abort=full,nosmt"); // TODO: paranoid
    check_kernel_param!(checks, "KNP_039", "kvm.nx_huge_pages=force");
    check_kernel_param!(checks, "KNP_040", "l1d_flush=on");
    check_kernel_param!(checks, "KNP_041", "mmio_stale_data=full");
    check_kernel_param!(checks, "KNP_041", "mmio_stale_data=full,nosmt"); // TODO: paranoid
    check_kernel_param!(checks, "KNP_042", "retbleed=auto");
    check_kernel_param!(checks, "KNP_042", "retbleed=auto,nosmt"); // TODO: paranoid
    check_kernel_param!(checks, "KNP_043", "spec_rstack_overflow=safe-ret");
    check_kernel_param!(checks, "KNP_044", "gather_data_sampling=force");
    check_kernel_param!(checks, "KNP_045", "reg_file_data_sampling=on");
    // from: kernel-hardening-checker
    check_kernel_param!(checks, "KNP_050", "spectre_v2_user=on");
    check_kernel_param!(checks, "KNP_051", "srbds=auto,nosmt");

    // ARM CPU mitigations
    // check_kernel_param!("KNP_055", "kpti=auto,nosmt");
    // check_kernel_param!("KNP_056", "ssbd=force-on");
    // check_kernel_param!("KNP_057", "rodata=full");

    // Quiet boot
    // https://github.com/Kicksecure/security-misc/blob/master/etc/default/grub.d/41_quiet_boot.cfg
    check_kernel_param!(checks, "KNP_060", "loglevel=0");
    check_kernel_param!(checks, "KNP_061", "quiet");

    // check_kconfig_not_set_param!("KNC_38, "EFI");
    // check_kconfig_params!("KNC_039, "CC_IS_GCC"); // since v4.18
    // check_kconfig_params!("KNC_040, "CC_IS_CLANG"); // since v4.18

    check_kconfig_not_set_param!(checks, "KNC_042", "CPU_SUP_AMD");
    check_kconfig_not_set_param!(checks, "KNC_043", "CPU_SUP_INTEL");
    check_kconfig_not_set_param!(checks, "KNC_044", "MODULES"); // TODO: paranoid
    check_kconfig_not_set_param!(checks, "KNC_045", "DEVMEM");
    check_kconfig_not_set_param!(checks, "KNC_046", "BPF_SYSCALL");
    check_kconfig_params!(checks, "KNC_047", "BUG");
    check_kconfig_params!(checks, "KNC_049", "THREAD_INFO_IN_TASK");
    check_kconfig_params!(checks, "KNC_050", "IOMMU_SUPPORT");
    check_kconfig_params!(checks, "KNC_051", "RANDOMIZE_BASE");
    check_kconfig_params!(checks, "KNC_052", "LIST_HARDENED");
    check_kconfig_params!(checks, "KNC_053", "RANDOM_KMALLOC_CACHES");
    check_kconfig_params!(checks, "KNC_054", "SLAB_MERGE_DEFAULT");
    check_kconfig_params!(checks, "KNC_055", "PAGE_TABLE_CHECK");
    check_kconfig_params!(checks, "KNC_056", "PAGE_TABLE_CHECK_ENFORCED");
    check_kconfig_params!(checks, "KNC_057", "BUG_ON_DATA_CORRUPTION");
    check_kconfig_params!(checks, "KNC_058", "SLAB_FREELIST_HARDENED");
    check_kconfig_params!(checks, "KNC_059", "SLAB_FREELIST_RANDOM");
    check_kconfig_params!(checks, "KNC_060", "SHUFFLE_PAGE_ALLOCATOR");
    check_kconfig_params!(checks, "KNC_061", "FORTIFY_SOURCE");
    check_kconfig_params!(checks, "KNC_065", "INIT_ON_ALLOC_DEFAULT_ON");
    check_kconfig_params!(checks, "KNC_066", "STATIC_USERMODEHELPER");
    check_kconfig_params!(checks, "KNC_067", "SCHED_CORE");
    check_kconfig_params!(checks, "KNC_068", "SECURITY_LOCKDOWN_LSM");
    check_kconfig_params!(checks, "KNC_069", "SECURITY_LOCKDOWN_LSM_EARLY");
    check_kconfig_params!(checks, "KNC_070", "LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY");

    // security policy
    check_kconfig_params!(checks, "KNC_073", "SECURITY");
    check_kconfig_params!(checks, "KNC_074", "SECURITY_YAMA");
    check_kconfig_params!(checks, "KNC_075", "SECURITY_LANDLOCK");
    check_kconfig_not_set_param!(checks, "KNC_076", "SECURITY_SELINUX_DISABLE");
    check_kconfig_not_set_param!(checks, "KNC_077", "SECURITY_SELINUX_BOOTPARAM"); // TODO: set N
    check_kconfig_not_set_param!(checks, "KNC_078", "SECURITY_SELINUX_DEVELOP");
    check_kconfig_not_set_param!(checks, "KNC_079", "SECURITY_WRITABLE_HOOKS");
    check_kconfig_not_set_param!(checks, "KNC_080", "SECURITY_SELINUX_DEBUG");
    check_kconfig_params!(checks, "KNC_081", "SECCOMP");
    check_kconfig_params!(checks, "KNC_082", "SECCOMP_FILTER");
    check_kconfig_params!(checks, "KNC_083", "BPF_UNPRIV_DEFAULT_OFF");
    check_kconfig_params!(checks, "KNC_084", "STRICT_DEVMEM");
    check_kconfig_params!(checks, "KNC_085", "X86_INTEL_TSX_MODE_OFF");

    check_kconfig_params!(checks, "KNC_087", "SECURITY_DMESG_RESTRICT");
    check_kconfig_not_set_param!(checks, "KNC_088", "ACPI_CUSTOM_METHOD");
    check_kconfig_not_set_param!(checks, "KNC_089", "COMPAT_BRK");
    check_kconfig_not_set_param!(checks, "KNC_090", "DEVKMEM");
    check_kconfig_not_set_param!(checks, "KNC_091", "BINFMT_MISC");
    check_kconfig_not_set_param!(checks, "KNC_092", "INET_DIAG");
    check_kconfig_not_set_param!(checks, "KNC_093", "KEXEC");
    check_kconfig_not_set_param!(checks, "KNC_094", "PROC_KCORE");
    check_kconfig_not_set_param!(checks, "KNC_095", "LEGACY_PTYS");
    check_kconfig_not_set_param!(checks, "KNC_096", "HIBERNATION");
    check_kconfig_not_set_param!(checks, "KNC_097", "COMPAT");
    check_kconfig_not_set_param!(checks, "KNC_098", "IA32_EMULATION");
    check_kconfig_not_set_param!(checks, "KNC_099", "X86_X32");
    check_kconfig_not_set_param!(checks, "KNC_100", "X86_X32_ABI");
    check_kconfig_not_set_param!(checks, "KNC_101", "MODIFY_LDT_SYSCALL");
    check_kconfig_not_set_param!(checks, "KNC_102", "OABI_COMPAT");
    check_kconfig_not_set_param!(checks, "KNC_103", "X86_MSR");
    check_kconfig_not_set_param!(checks, "KNC_104", "LEGACY_TIOCSTI");
    check_kconfig_not_set_param!(checks, "KNC_105", "MODULE_FORCE_LOAD");
    check_kconfig_not_set_param!(checks, "KNC_106", "DRM_LEGACY");
    check_kconfig_not_set_param!(checks, "KNC_107", "FB");
    check_kconfig_not_set_param!(checks, "KNC_108", "VT");
    check_kconfig_not_set_param!(checks, "KNC_109", "BLK_DEV_FD");
    check_kconfig_not_set_param!(checks, "KNC_110", "BLK_DEV_FD_RAWCMD");
    check_kconfig_not_set_param!(checks, "KNC_111", "NOUVEAU_LEGACY_CTX_SUPPORT");
    check_kconfig_not_set_param!(checks, "KNC_112", "N_GSM");

    // grsec
    check_kconfig_not_set_param!(checks, "KNC_116", "ZSMALLOC_STAT");
    check_kconfig_not_set_param!(checks, "KNC_117", "DEBUG_KMEMLEAK");
    check_kconfig_not_set_param!(checks, "KNC_118", "BINFMT_AOUT");
    check_kconfig_not_set_param!(checks, "KNC_119", "KPROBE_EVENTS");
    check_kconfig_not_set_param!(checks, "KNC_120", "UPROBE_EVENTS");
    check_kconfig_not_set_param!(checks, "KNC_121", "GENERIC_TRACER");
    check_kconfig_not_set_param!(checks, "KNC_122", "FUNCTION_TRACER");
    check_kconfig_not_set_param!(checks, "KNC_123", "STACK_TRACER");
    check_kconfig_not_set_param!(checks, "KNC_124", "HIST_TRIGGERS");
    check_kconfig_not_set_param!(checks, "KNC_125", "BLK_DEV_IO_TRACE");
    check_kconfig_not_set_param!(checks, "KNC_126", "PROC_VMCORE");
    check_kconfig_not_set_param!(checks, "KNC_127", "PROC_PAGE_MONITOR");
    check_kconfig_not_set_param!(checks, "KNC_128", "USELIB");
    check_kconfig_not_set_param!(checks, "KNC_129", "CHECKPOINT_RESTORE");
    check_kconfig_not_set_param!(checks, "KNC_130", "USERFAULTFD");
    check_kconfig_not_set_param!(checks, "KNC_131", "HWPOISON_INJECT");
    check_kconfig_not_set_param!(checks, "KNC_132", "MEM_SOFT_DIRTY");
    check_kconfig_not_set_param!(checks, "KNC_133", "DEVPORT");
    check_kconfig_not_set_param!(checks, "KNC_134", "DEBUG_FS");
    check_kconfig_not_set_param!(checks, "KNC_135", "NOTIFIER_ERROR_INJECTION");
    check_kconfig_not_set_param!(checks, "KNC_136", "FAIL_FUTEX");
    check_kconfig_not_set_param!(checks, "KNC_137", "PUNIT_ATOM_DEBUG");
    check_kconfig_not_set_param!(checks, "KNC_138", "ACPI_CONFIGFS");
    check_kconfig_not_set_param!(checks, "KNC_139", "EDAC_DEBUG");
    check_kconfig_not_set_param!(checks, "KNC_140", "DRM_I915_DEBUG");
    check_kconfig_not_set_param!(checks, "KNC_141", "BCACHE_CLOSURES_DEBUG");
    check_kconfig_not_set_param!(checks, "KNC_142", "DVB_C8SECTPFE");
    check_kconfig_not_set_param!(checks, "KNC_143", "MTD_SLRAM");
    check_kconfig_not_set_param!(checks, "KNC_144", "MTD_PHRAM");
    check_kconfig_not_set_param!(checks, "KNC_145", "IO_URING");
    check_kconfig_not_set_param!(checks, "KNC_146", "KCMP");
    check_kconfig_not_set_param!(checks, "KNC_147", "RSEQ");
    check_kconfig_not_set_param!(checks, "KNC_148", "LATENCYTOP");
    check_kconfig_not_set_param!(checks, "KNC_149", "KCOV");
    check_kconfig_not_set_param!(checks, "KNC_150", "PROVIDE_OHCI1394_DMA_INIT");
    check_kconfig_not_set_param!(checks, "KNC_151", "SUNRPC_DEBUG");
    check_kconfig_not_set_param!(checks, "KNC_152", "X86_16BIT");
    check_kconfig_not_set_param!(checks, "KNC_153", "BLK_DEV_UBLK");
    check_kconfig_not_set_param!(checks, "KNC_154", "SMB_SERVER");
    check_kconfig_not_set_param!(checks, "KNC_155", "XFS_ONLINE_SCRUB_STATS");
    check_kconfig_not_set_param!(checks, "KNC_156", "CACHESTAT_SYSCALL");
    check_kconfig_not_set_param!(checks, "KNC_157", "PREEMPTIRQ_TRACEPOINTS");
    check_kconfig_not_set_param!(checks, "KNC_158", "ENABLE_DEFAULT_TRACERS");
    check_kconfig_not_set_param!(checks, "KNC_159", "PROVE_LOCKING");
    check_kconfig_not_set_param!(checks, "KNC_160", "TEST_DEBUG_VIRTUAL");
    check_kconfig_not_set_param!(checks, "KNC_161", "MPTCP");
    check_kconfig_not_set_param!(checks, "KNC_162", "TLS");
    check_kconfig_not_set_param!(checks, "KNC_163", "TIPC");
    check_kconfig_not_set_param!(checks, "KNC_164", "IP_SCTP");
    check_kconfig_not_set_param!(checks, "KNC_165", "KGDB");
    check_kconfig_not_set_param!(checks, "KNC_166", "PTDUMP_DEBUGFS");
    check_kconfig_not_set_param!(checks, "KNC_167", "X86_PTDUMP");

    // clipos
    check_kconfig_not_set_param!(checks, "KNC_170", "STAGING");
    check_kconfig_not_set_param!(checks, "KNC_171", "KSM");
    check_kconfig_not_set_param!(checks, "KNC_172", "KALLSYMS");
    check_kconfig_not_set_param!(checks, "KNC_173", "KEXEC_FILE");
    check_kconfig_not_set_param!(checks, "KNC_174", "CRASH_DUMP");
    check_kconfig_not_set_param!(checks, "KNC_175", "USER_NS");
    check_kconfig_not_set_param!(checks, "KNC_176", "X86_CPUID");
    check_kconfig_not_set_param!(checks, "KNC_177", "X86_IOPL_IOPERM");
    check_kconfig_not_set_param!(checks, "KNC_178", "ACPI_TABLE_UPGRADE");
    check_kconfig_not_set_param!(checks, "KNC_179", "EFI_CUSTOM_SSDT_OVERLAYS");
    check_kconfig_not_set_param!(checks, "KNC_180", "AIO");
    check_kconfig_not_set_param!(checks, "KNC_181", "MAGIC_SYSRQ");
    check_kconfig_not_set_param!(checks, "KNC_182", "MAGIC_SYSRQ_DEFAULT_ENABLE");
    check_kconfig_not_set_param!(checks, "KNC_183", "MAGIC_SYSRQ_SERIAL");

    // grapheneos
    check_kconfig_not_set_param!(checks, "KNC_187", "EFI_TEST");
    check_kconfig_not_set_param!(checks, "KNC_188", "MMIOTRACE_TEST");
    check_kconfig_not_set_param!(checks, "KNC_189", "KPROBES");

    check_kconfig_not_set_param!(checks, "KNC_191", "MMIOTRACE");
    check_kconfig_not_set_param!(checks, "KNC_192", "LIVEPATCH");
    check_kconfig_not_set_param!(checks, "KNC_193", "IP_DCCP");
    check_kconfig_not_set_param!(checks, "KNC_194", "FTRACE");
    check_kconfig_not_set_param!(checks, "KNC_195", "VIDEO_VIVID");
    check_kconfig_not_set_param!(checks, "KNC_196", "INPUT_EVBUG");
    check_kconfig_not_set_param!(checks, "KNC_197", "CORESIGHT");
    check_kconfig_not_set_param!(checks, "KNC_198", "XFS_SUPPORT_V4");
    check_kconfig_not_set_param!(checks, "KNC_199", "BLK_DEV_WRITE_MOUNTED");
    check_kconfig_not_set_param!(checks, "KNC_200", "FAULT_INJECTION");
    check_kconfig_not_set_param!(checks, "KNC_201", "LKDTM");

    // configured to not reboot the system when Ctrl-Alt-Delete is pressed seven times within two seconds
    check_systemd!(checks, "SMD_001", "CtrlAltDelBurstAction", "none");

    check_login_defs!(checks, "LDF_001", "ENCRYPT_METHOD", "YESCRYPT");
    check_login_defs!(checks, "LDF_002", "SHA_CRYPT_MIN_ROUNDS", "65536");
    check_login_defs!(checks, "LDF_003", "PASS_MAX_DAYS" <= 60); // TOOD: range, max: 365
    check_login_defs!(checks, "LDF_004", "PASS_MIN_DAYS" >= 1); // TOOD: range, under the PASS_MAX_DAYS!
    check_login_defs!(checks, "LDF_005", "PASS_WARN_AGE" >= 7);
    check_login_defs!(checks, "LDF_006", "SYSLOG_SU_ENAB", "yes");
    check_login_defs!(checks, "LDF_007", "SYSLOG_SG_ENAB", "yes");
    check_login_defs!(checks, "LDF_008", "UMASK", "077");
    check_login_defs!(checks, "LDF_009", "LOGIN_RETRIES" <= 5); // TODO: have acceptable values at 10
    check_login_defs!(checks, "LDF_010", "LOGIN_TIMEOUT" <= 60);
    check_login_defs!(checks, "LDF_011", "FAILLOG_ENAB", "yes");
    check_login_defs!(checks, "LDF_012", "LOG_OK_LOGINS", "yes");

    // check mount prence
    check_mount!(checks, "MNT_001", "/boot");
    check_mount!(checks, "MNT_002", "/tmp"); // CIS
    check_mount!(checks, "MNT_003", "/home"); // CIS
    check_mount!(checks, "MNT_004", "/var"); // CIS
    check_mount!(checks, "MNT_005", "/var/log"); // CIS
    check_mount!(checks, "MNT_006", "/var/log/audit"); // CIS
    check_mount!(checks, "MNT_007", "/var/tmp"); // CIS
    check_mount!(checks, "MNT_008", "/dev/shm"); // CIS

    check_mount_option!(checks, "MOP_001", "/", "errors=remount-ro");
    check_mount_option!(checks, "MOP_002", "/boot", "nodev");
    check_mount_option!(checks, "MOP_003", "/boot", "nosuid");
    check_mount_option!(checks, "MOP_004", "/boot", "noexec");
    check_mount_option!(checks, "MOP_005", "/boot", "noauto"); // TODO: optional
    check_mount_option!(checks, "MOP_006", "/home", "nodev"); // CIS
    check_mount_option!(checks, "MOP_007", "/home", "nosuid"); // CIS
    check_mount_option!(checks, "MOP_008", "/home", "noexec"); // TODO: optional
    check_mount_option!(checks, "MOP_009", "/tmp", "nodev"); // CIS
    check_mount_option!(checks, "MOP_010", "/tmp", "nosuid"); // CIS
    check_mount_option!(checks, "MOP_011", "/tmp", "noexec"); // CIS
    check_mount_option!(checks, "MOP_012", "/var", "nodev"); // CIS
    check_mount_option!(checks, "MOP_013", "/var", "nosuid"); // CIS
    check_mount_option!(checks, "MOP_014", "/var", "noexec"); // TODO: optional
    check_mount_option!(checks, "MOP_015", "/var/log", "nodev"); // CIS
    check_mount_option!(checks, "MOP_016", "/var/log", "nosuid"); // CIS
    check_mount_option!(checks, "MOP_017", "/var/log", "noexec"); // CIS
    check_mount_option!(checks, "MOP_018", "/var/log/audit", "nodev"); // CIS
    check_mount_option!(checks, "MOP_019", "/var/log/audit", "nosuid"); // CIS
    check_mount_option!(checks, "MOP_010", "/var/log/audit", "noexec"); // CIS
    check_mount_option!(checks, "MOP_011", "/var/tmp", "nodev"); // CIS
    check_mount_option!(checks, "MOP_012", "/var/tmp", "nosuid"); // CIS
    check_mount_option!(checks, "MOP_013", "/var/tmp", "noexec"); // CIS
    check_mount_option!(checks, "MOP_014", "/proc", "nodev");
    check_mount_option!(checks, "MOP_015", "/proc", "nosuid");
    check_mount_option!(checks, "MOP_016", "/proc", "noexec");
    check_mount_option!(checks, "MOP_017", "/proc", "hidepid=invisible");
    check_mount_option!(checks, "MOP_018", "/dev", "nosuid");
    check_mount_option!(checks, "MOP_019", "/dev", "noexec");
    check_mount_option!(checks, "MOP_020", "/dev/shm", "nodev"); // CIS
    check_mount_option!(checks, "MOP_021", "/dev/shm", "nosuid"); // CIS
    check_mount_option!(checks, "MOP_022", "/dev/shm", "noexec"); // CIS

    // blacklisting prevents kernel modules from automatically starting
    // GrapheneOS:
    // https://github.com/GrapheneOS/infrastructure/blob/main/modprobe.d/local.conf
    check_modprobe_blacklist!(checks, "MBL_001", "snd_intel8x0");
    check_modprobe_blacklist!(checks, "MBL_002", "snd_intel8x0m");
    check_modprobe_blacklist!(checks, "MBL_003", "sr_mod");
    // disabled instead
    // check_modprobe_blacklist!(checks, "MBL_004", "joydev");
    // check_modprobe_blacklist!(checks, "MBL_005", "pcspkr");
    // check_modprobe_blacklist!(checks, "MBL_006", "floppy");
    // check_modprobe_disabled!(checks, "MBD_023", "cfg80211");
    // check_modprobe_blacklist!(checks, "MBL_008", "intel_agp");
    // check_modprobe_blacklist!(checks, "MBL_009", "ip_tables");
    // check_modprobe_blacklist!(checks, "MBL_010", "mousedev");
    // check_modprobe_blacklist!(checks, "MBL_011", "psmouse");
    // check_modprobe_blacklist!(checks, "MBL_012", "tls");
    // check_modprobe_blacklist!(checks, "MBL_013", "virtio_balloon");
    // check_modprobe_blacklist!(checks, "MBL_014", "virtio_console");

    // https://github.com/Kicksecure/security-misc/blob/master/etc/modprobe.d/30_security-misc_blacklist.conf
    check_modprobe_blacklist!(checks, "MBL_015", "cdrom");
    check_modprobe_blacklist!(checks, "MBL_016", "amd76x_edac");
    check_modprobe_blacklist!(checks, "MBL_017", "ath_pci");
    check_modprobe_blacklist!(checks, "MBL_018", "evbug");
    check_modprobe_blacklist!(checks, "MBL_019", "snd_aw2");
    check_modprobe_blacklist!(checks, "MBL_020", "snd_pcsp");
    check_modprobe_blacklist!(checks, "MBL_021", "usbkbd");
    check_modprobe_blacklist!(checks, "MBL_022", "usbmouse");

    // Ubuntu: either duplicates, or disabled
    // https://git.launchpad.net/ubuntu/+source/kmod/tree/debian/modprobe.d/blacklist.conf?h=ubuntu/disco

    // disabling prohibits kernel modules from starting
    // https://github.com/Kicksecure/security-misc/blob/master/etc/modprobe.d/30_security-misc_disable.conf
    check_modprobe_disabled!(checks, "MBD_094", "cfg80211");
    check_modprobe_disabled!(checks, "MBD_095", "intel_agp");
    check_modprobe_disabled!(checks, "MBD_095", "ip_tables");
    check_modprobe_disabled!(checks, "MBD_098", "mousedev");
    check_modprobe_disabled!(checks, "MBD_099", "psmouse");
    check_modprobe_disabled!(checks, "MBD_001", "tls");
    check_modprobe_disabled!(checks, "MBD_001", "virtio_balloon");
    check_modprobe_disabled!(checks, "MBD_001", "virtio_console");

    // Network protocols
    check_modprobe_disabled!(checks, "MBD_006", "af_802154");
    check_modprobe_disabled!(checks, "MBD_007", "appletalk");
    check_modprobe_disabled!(checks, "MBD_008", "dccp"); // CIS
    check_modprobe_disabled!(checks, "MBD_009", "netrom");
    check_modprobe_disabled!(checks, "MBD_010", "rose");
    check_modprobe_disabled!(checks, "MBD_011", "n_hdlc");
    check_modprobe_disabled!(checks, "MBD_005", "ax25");
    // check_modprobe_disabled!(checks, "MBD_005", "brcm80211");
    check_modprobe_disabled!(checks, "MBD_012", "x25");
    check_modprobe_disabled!(checks, "MBD_013", "decnet");
    check_modprobe_disabled!(checks, "MBD_014", "econet");
    check_modprobe_disabled!(checks, "MBD_015", "ipx");
    check_modprobe_disabled!(checks, "MBD_016", "psnap");
    check_modprobe_disabled!(checks, "MBD_017", "p8023");
    check_modprobe_disabled!(checks, "MBD_018", "p8022");
    check_modprobe_disabled!(checks, "MBD_019", "eepro100");
    check_modprobe_disabled!(checks, "MBD_020", "eth1394");

    // Asynchronous Transfer Mode (ATM)
    check_modprobe_disabled!(checks, "MBD_001", "atm");
    check_modprobe_disabled!(checks, "MBD_002", "ueagle_atm");
    check_modprobe_disabled!(checks, "MBD_003", "usbatm");
    check_modprobe_disabled!(checks, "MBD_004", "xusbatm");

    check_modprobe_disabled!(checks, "MBD_021", "n_hdlc");

    // Controller Area Network (CAN) Protocol
    check_modprobe_disabled!(checks, "MBD_022", "c_can");
    check_modprobe_disabled!(checks, "MBD_023", "c_can_pci");
    check_modprobe_disabled!(checks, "MBD_024", "c_can_platform");
    check_modprobe_disabled!(checks, "MBD_025", "can");
    check_modprobe_disabled!(checks, "MBD_026", "can_bcm");
    check_modprobe_disabled!(checks, "MBD_027", "can_dev");
    check_modprobe_disabled!(checks, "MBD_028", "can_gw");
    check_modprobe_disabled!(checks, "MBD_029", "can_isotp");
    check_modprobe_disabled!(checks, "MBD_030", "can_raw");
    check_modprobe_disabled!(checks, "MBD_031", "can_j1939");
    check_modprobe_disabled!(checks, "MBD_032", "can327");
    check_modprobe_disabled!(checks, "MBD_033", "ifi_canfd");
    check_modprobe_disabled!(checks, "MBD_034", "janz_ican3");
    check_modprobe_disabled!(checks, "MBD_035", "m_can");
    check_modprobe_disabled!(checks, "MBD_036", "m_can_pci");
    check_modprobe_disabled!(checks, "MBD_037", "m_can_platform");
    check_modprobe_disabled!(checks, "MBD_038", "phy_can_transceiver");
    check_modprobe_disabled!(checks, "MBD_039", "slcan");
    check_modprobe_disabled!(checks, "MBD_040", "ucan");
    check_modprobe_disabled!(checks, "MBD_041", "vxcan");
    check_modprobe_disabled!(checks, "MBD_042", "vcan");

    // Transparent Inter Process Communication (TIPC)
    check_modprobe_disabled!(checks, "MBD_043", "tipc"); // CIS
    check_modprobe_disabled!(checks, "MBD_044", "tipc_diag");

    // Reliable Datagram Sockets (RDS)
    check_modprobe_disabled!(checks, "MBD_045", "rds"); // CIS
    check_modprobe_disabled!(checks, "MBD_046", "rds_rdma");
    check_modprobe_disabled!(checks, "MBD_047", "rds_tcp");

    // Stream Control Transmission Protocol (SCTP)
    check_modprobe_disabled!(checks, "MBD_048", "sctp"); // CIS
    check_modprobe_disabled!(checks, "MBD_049", "sctp_diag");

    check_modprobe_disabled!(checks, "MBD_050", "adfs");
    check_modprobe_disabled!(checks, "MBD_051", "affs");
    check_modprobe_disabled!(checks, "MBD_052", "bfs");
    check_modprobe_disabled!(checks, "MBD_053", "befs");
    check_modprobe_disabled!(checks, "MBD_054", "cramfs"); // CIS
    check_modprobe_disabled!(checks, "MBD_055", "efs");
    check_modprobe_disabled!(checks, "MBD_056", "erofs");
    check_modprobe_disabled!(checks, "MBD_057", "exofs");
    check_modprobe_disabled!(checks, "MBD_058", "freevxfs"); // CIS
    check_modprobe_disabled!(checks, "MBD_059", "f2fs");
    check_modprobe_disabled!(checks, "MBD_060", "hfs"); // CIS
    check_modprobe_disabled!(checks, "MBD_061", "hfsplus"); // CIS
    check_modprobe_disabled!(checks, "MBD_062", "squashfs"); // CIS
    check_modprobe_disabled!(checks, "MBD_063", "hpfs");
    check_modprobe_disabled!(checks, "MBD_064", "jfs");
    check_modprobe_disabled!(checks, "MBD_065", "jffs2"); // CIS
    check_modprobe_disabled!(checks, "MBD_066", "minix");
    check_modprobe_disabled!(checks, "MBD_067", "nilfs2");
    check_modprobe_disabled!(checks, "MBD_068", "ntfs");
    check_modprobe_disabled!(checks, "MBD_069", "omfs");
    check_modprobe_disabled!(checks, "MBD_070", "qnx4");
    check_modprobe_disabled!(checks, "MBD_071", "qnx6");
    check_modprobe_disabled!(checks, "MBD_072", "sysv");
    check_modprobe_disabled!(checks, "MBD_073", "ufs");
    check_modprobe_disabled!(checks, "MBD_074", "udf"); // CIS
    check_modprobe_disabled!(checks, "MBD_075", "reiserfs");

    // Network File Systems
    check_modprobe_disabled!(checks, "MBD_079", "ksmbd");
    check_modprobe_disabled!(checks, "MBD_080", "gfs2");

    // Common Internet File System (CIFS)
    check_modprobe_disabled!(checks, "MBD_076", "cifs");
    check_modprobe_disabled!(checks, "MBD_077", "cifs_arc4");
    check_modprobe_disabled!(checks, "MBD_078", "cifs_md4");

    // Network File System (NFS)
    check_modprobe_disabled!(checks, "MBD_081", "nfs");
    check_modprobe_disabled!(checks, "MBD_082", "nfs_acl");
    check_modprobe_disabled!(checks, "MBD_083", "nfs_layout_nfsv41_files");
    check_modprobe_disabled!(checks, "MBD_084", "nfs_layout_flexfiles");
    check_modprobe_disabled!(checks, "MBD_085", "nfsd");
    check_modprobe_disabled!(checks, "MBD_086", "nfsv2");
    check_modprobe_disabled!(checks, "MBD_087", "nfsv3");
    check_modprobe_disabled!(checks, "MBD_088", "nfsv4");

    check_modprobe_disabled!(checks, "MBD_089", "usb_storage"); // CIS
    check_modprobe_disabled!(checks, "MBD_091", "vivid");
    check_modprobe_disabled!(checks, "MBD_094", "floppy");
    check_modprobe_disabled!(checks, "MBD_097", "joydev");

    // bluetooth
    // disable Bluetooth to reduce attack surface due to extended history of
    // security vulnerabilities
    check_modprobe_disabled!(checks, "MBD_105", "bluetooth");
    check_modprobe_disabled!(checks, "MBD_106", "bluetooth_6lowpan");
    check_modprobe_disabled!(checks, "MBD_107", "bt3c_cs");
    check_modprobe_disabled!(checks, "MBD_108", "btbcm");
    check_modprobe_disabled!(checks, "MBD_109", "btintel");
    check_modprobe_disabled!(checks, "MBD_110", "btmrvl");
    check_modprobe_disabled!(checks, "MBD_111", "btmrvl_sdio");
    check_modprobe_disabled!(checks, "MBD_112", "btmtk");
    check_modprobe_disabled!(checks, "MBD_113", "btmtksdio");
    check_modprobe_disabled!(checks, "MBD_114", "btmtkuart");
    check_modprobe_disabled!(checks, "MBD_115", "btnxpuart");
    check_modprobe_disabled!(checks, "MBD_116", "btqca");
    check_modprobe_disabled!(checks, "MBD_117", "btrsi");
    check_modprobe_disabled!(checks, "MBD_118", "btrtl");
    check_modprobe_disabled!(checks, "MBD_119", "btsdio");
    check_modprobe_disabled!(checks, "MBD_120", "btusb");
    check_modprobe_disabled!(checks, "MBD_121", "virtio_bt");

    // firewire (IEEE 1394)
    check_modprobe_disabled!(checks, "MBD_122", "dv1394");
    check_modprobe_disabled!(checks, "MBD_123", "firewire_core");
    check_modprobe_disabled!(checks, "MBD_124", "firewire_ohci");
    check_modprobe_disabled!(checks, "MBD_125", "firewire_net");
    check_modprobe_disabled!(checks, "MBD_126", "firewire_sbp2");
    check_modprobe_disabled!(checks, "MBD_127", "ohci1394");
    check_modprobe_disabled!(checks, "MBD_128", "raw1394");
    check_modprobe_disabled!(checks, "MBD_129", "sbp2");
    check_modprobe_disabled!(checks, "MBD_130", "video1394");

    // GPS
    check_modprobe_disabled!(checks, "MBD_131", "garmin_gps");
    check_modprobe_disabled!(checks, "MBD_132", "gnss");
    check_modprobe_disabled!(checks, "MBD_133", "gnss_mtk");
    check_modprobe_disabled!(checks, "MBD_134", "gnss_serial");
    check_modprobe_disabled!(checks, "MBD_135", "gnss_sirf");
    check_modprobe_disabled!(checks, "MBD_136", "gnss_ubx");
    check_modprobe_disabled!(checks, "MBD_137", "gnss_usb");

    // Intel Management Engine (ME)
    // disabling may lead to breakages in numerous places without clear
    // debugging/error messages, may cause issues with firmware updates,
    // security, power management, display, and DRM.
    // check_modprobe_disabled!(checks, "MBD_137", "mei");
    // check_modprobe_disabled!(checks, "MBD_137", "mei_gsc");
    // check_modprobe_disabled!(checks, "MBD_137", "mei_gsc_proxy");
    // check_modprobe_disabled!(checks, "MBD_137", "mei_hdcp");
    // check_modprobe_disabled!(checks, "MBD_137", "mei_me");
    // check_modprobe_disabled!(checks, "MBD_137", "mei_phy");
    // check_modprobe_disabled!(checks, "MBD_137", "mei_pxp");
    // check_modprobe_disabled!(checks, "MBD_137", "mei_txe");
    // check_modprobe_disabled!(checks, "MBD_137", "mei_vsc");
    // check_modprobe_disabled!(checks, "MBD_137", "mei_vsc_hw");
    // check_modprobe_disabled!(checks, "MBD_137", "mei_wdt");
    // check_modprobe_disabled!(checks, "MBD_137", "microread_mei");

    // Intel Platform Monitoring Technology (PMT) Telemetry
    check_modprobe_disabled!(checks, "MBD_138", "pmt_class");
    check_modprobe_disabled!(checks, "MBD_139", "pmt_crashlog");
    check_modprobe_disabled!(checks, "MBD_140", "pmt_telemetry");

    // Thunderbolt
    check_modprobe_disabled!(checks, "MBD_141", "intel_wmi_thunderbolt");
    check_modprobe_disabled!(checks, "MBD_142", "thunderbolt");
    check_modprobe_disabled!(checks, "MBD_143", "thunderbolt_net");

    // Miscellaneous
    check_modprobe_disabled!(checks, "MBD_144", "hamradio");
    // check_modprobe_disabled!(checks, "MBD_144", "msr");

    // Framebuffer (fbdev)
    // video drivers are known to be buggy, cause kernel panics, and are
    // generally only used by legacy devices
    check_modprobe_disabled!(checks, "MBD_146", "aty128fb");
    check_modprobe_disabled!(checks, "MBD_147", "atyfb");
    check_modprobe_disabled!(checks, "MBD_148", "cirrusfb");
    check_modprobe_disabled!(checks, "MBD_149", "cyber2000fb");
    check_modprobe_disabled!(checks, "MBD_150", "cyblafb");
    check_modprobe_disabled!(checks, "MBD_151", "gx1fb");
    check_modprobe_disabled!(checks, "MBD_152", "hgafb");
    check_modprobe_disabled!(checks, "MBD_153", "i810fb");
    check_modprobe_disabled!(checks, "MBD_154", "intelfb");
    check_modprobe_disabled!(checks, "MBD_155", "kyrofb");
    check_modprobe_disabled!(checks, "MBD_156", "lxfb");
    check_modprobe_disabled!(checks, "MBD_157", "matroxfb_bases");
    check_modprobe_disabled!(checks, "MBD_158", "neofb");
    check_modprobe_disabled!(checks, "MBD_159", "nvidiafb");
    check_modprobe_disabled!(checks, "MBD_160", "pm2fb");
    check_modprobe_disabled!(checks, "MBD_161", "radeonfb");
    check_modprobe_disabled!(checks, "MBD_162", "rivafb");
    check_modprobe_disabled!(checks, "MBD_163", "s1d13xxxfb");
    check_modprobe_disabled!(checks, "MBD_164", "savagefb");
    check_modprobe_disabled!(checks, "MBD_165", "sisfb");
    check_modprobe_disabled!(checks, "MBD_166", "sstfb");
    check_modprobe_disabled!(checks, "MBD_167", "tdfxfb");
    check_modprobe_disabled!(checks, "MBD_168", "tridentfb");
    check_modprobe_disabled!(checks, "MBD_169", "vesafb");
    check_modprobe_disabled!(checks, "MBD_170", "vfb");
    check_modprobe_disabled!(checks, "MBD_171", "viafb");
    check_modprobe_disabled!(checks, "MBD_172", "vt8623fb");
    check_modprobe_disabled!(checks, "MBD_173", "udlfb");

    // replaced modules
    check_modprobe_disabled!(checks, "MBD_174", "asus_acpi");
    check_modprobe_disabled!(checks, "MBD_175", "bcm43xx");
    check_modprobe_disabled!(checks, "MBD_176", "de4x5");
    check_modprobe_disabled!(checks, "MBD_177", "prism54");

    // USB Video Device Class
    check_modprobe_disabled!(checks, "MBD_090", "uvcvideo");

    // Ubuntu
    check_modprobe_disabled!(checks, "MBD_178", "arkfb");
    check_modprobe_disabled!(checks, "MBD_179", "matroxfb_base");
    check_modprobe_disabled!(checks, "MBD_180", "mb862xxfb");
    check_modprobe_disabled!(checks, "MBD_181", "pm3fb");
    check_modprobe_disabled!(checks, "MBD_182", "s3fb");
    check_modprobe_disabled!(checks, "MBD_183", "snd_mixer_oss");
    check_modprobe_disabled!(checks, "MBD_184", "acquirewdt");
    check_modprobe_disabled!(checks, "MBD_185", "advantech_ec_wdt");
    check_modprobe_disabled!(checks, "MBD_186", "advantechwdt");
    check_modprobe_disabled!(checks, "MBD_187", "alim1535_wdt");
    check_modprobe_disabled!(checks, "MBD_188", "cadence_wdt");
    check_modprobe_disabled!(checks, "MBD_189", "cpu5wdt");
    check_modprobe_disabled!(checks, "MBD_190", "da9055_wdt");
    check_modprobe_disabled!(checks, "MBD_191", "da9063_wdt");
    check_modprobe_disabled!(checks, "MBD_192", "dw_wdt");
    check_modprobe_disabled!(checks, "MBD_193", "eurotechwdt");
    check_modprobe_disabled!(checks, "MBD_194", "f71808e_wdt");
    check_modprobe_disabled!(checks, "MBD_195", "i6300esb");
    check_modprobe_disabled!(checks, "MBD_196", "iTCO_wdt");
    check_modprobe_disabled!(checks, "MBD_197", "ibmasr");
    check_modprobe_disabled!(checks, "MBD_198", "it8712f_wdt");
    check_modprobe_disabled!(checks, "MBD_199", "kempld_wdt");
    check_modprobe_disabled!(checks, "MBD_200", "max63xx_wdt");
    check_modprobe_disabled!(checks, "MBD_201", "mena21_wdt");
    check_modprobe_disabled!(checks, "MBD_202", "menz69_wdt");
    check_modprobe_disabled!(checks, "MBD_203", "ni903x_wdt");
    check_modprobe_disabled!(checks, "MBD_204", "nv_tco");
    check_modprobe_disabled!(checks, "MBD_205", "pc87413_wdt");
    check_modprobe_disabled!(checks, "MBD_206", "pcwd_usb");
    check_modprobe_disabled!(checks, "MBD_207", "rave_sp_wdt");
    check_modprobe_disabled!(checks, "MBD_208", "sbc60xxwdt");
    check_modprobe_disabled!(checks, "MBD_209", "sbc_fitpc2_wdt");
    check_modprobe_disabled!(checks, "MBD_210", "sch311x_wdt");
    check_modprobe_disabled!(checks, "MBD_211", "smsc37b787_wdt");
    check_modprobe_disabled!(checks, "MBD_212", "sp5100_tco");
    check_modprobe_disabled!(checks, "MBD_213", "twl4030_wdt");
    check_modprobe_disabled!(checks, "MBD_214", "w83627hf_wdt");
    check_modprobe_disabled!(checks, "MBD_215", "w83977f_wdt");
    check_modprobe_disabled!(checks, "MBD_216", "wdat_wdt");
    check_modprobe_disabled!(checks, "MBD_217", "wm831x_wdt");
    check_modprobe_disabled!(checks, "MBD_218", "xen_wdt");
    check_modprobe_disabled!(checks, "MBD_219", "snd_pcm_oss");
    check_modprobe_disabled!(checks, "MBD_220", "alim7101_wdt");
    check_modprobe_disabled!(checks, "MBD_221", "da9052_wdt");
    check_modprobe_disabled!(checks, "MBD_222", "da9062_wdt");
    check_modprobe_disabled!(checks, "MBD_223", "ebc_c384_wdt");
    check_modprobe_disabled!(checks, "MBD_224", "exar_wdt");
    check_modprobe_disabled!(checks, "MBD_225", "hpwdt");
    check_modprobe_disabled!(checks, "MBD_226", "iTCO_vendor_support");
    check_modprobe_disabled!(checks, "MBD_227", "ib700wdt");
    check_modprobe_disabled!(checks, "MBD_228", "ie6xx_wdt");
    check_modprobe_disabled!(checks, "MBD_229", "it87_wdt");
    check_modprobe_disabled!(checks, "MBD_230", "machzwd");
    check_modprobe_disabled!(checks, "MBD_231", "mei_wdt");
    check_modprobe_disabled!(checks, "MBD_232", "menf21bmc_wdt");
    check_modprobe_disabled!(checks, "MBD_233", "mlx_wdt");
    check_modprobe_disabled!(checks, "MBD_234", "nic7018_wdt");
    check_modprobe_disabled!(checks, "MBD_235", "of_xilinx_wdt");
    check_modprobe_disabled!(checks, "MBD_236", "pcwd_pci");
    check_modprobe_disabled!(checks, "MBD_237", "pretimeout_panic");
    check_modprobe_disabled!(checks, "MBD_238", "retu_wdt");
    check_modprobe_disabled!(checks, "MBD_239", "sbc_epx_c3");
    check_modprobe_disabled!(checks, "MBD_240", "sc1200wdt");
    check_modprobe_disabled!(checks, "MBD_241", "simatic_ipc_wdt");
    check_modprobe_disabled!(checks, "MBD_242", "softdog");
    check_modprobe_disabled!(checks, "MBD_243", "tqmx86_wdt");
    check_modprobe_disabled!(checks, "MBD_244", "via_wdt");
    check_modprobe_disabled!(checks, "MBD_245", "w83877f_wdt");
    check_modprobe_disabled!(checks, "MBD_246", "wafer5823wdt");
    check_modprobe_disabled!(checks, "MBD_247", "wdt_pci");
    check_modprobe_disabled!(checks, "MBD_248", "wm8350_wdt");
    check_modprobe_disabled!(checks, "MBD_249", "ziirave_wdt");
    check_modprobe_disabled!(checks, "MBD_258", "pcspkr");
    check_modprobe_disabled!(checks, "MBD_260", "ac97");
    check_modprobe_disabled!(checks, "MBD_261", "ac97_codec");
    check_modprobe_disabled!(checks, "MBD_262", "ac97_plugin_ad1980");
    check_modprobe_disabled!(checks, "MBD_263", "ad1848");
    check_modprobe_disabled!(checks, "MBD_264", "ad1889");
    check_modprobe_disabled!(checks, "MBD_265", "adlib_card");
    check_modprobe_disabled!(checks, "MBD_266", "aedsp16");
    check_modprobe_disabled!(checks, "MBD_267", "ali5455");
    check_modprobe_disabled!(checks, "MBD_268", "btaudio");
    check_modprobe_disabled!(checks, "MBD_269", "cmpci");
    check_modprobe_disabled!(checks, "MBD_270", "cs4232");
    check_modprobe_disabled!(checks, "MBD_271", "cs4281");
    check_modprobe_disabled!(checks, "MBD_272", "cs461x");
    check_modprobe_disabled!(checks, "MBD_273", "cs46xx");
    check_modprobe_disabled!(checks, "MBD_274", "emu10k1");
    check_modprobe_disabled!(checks, "MBD_275", "es1370");
    check_modprobe_disabled!(checks, "MBD_276", "es1371");
    check_modprobe_disabled!(checks, "MBD_277", "esssolo1");
    check_modprobe_disabled!(checks, "MBD_278", "forte");
    check_modprobe_disabled!(checks, "MBD_279", "gus");
    check_modprobe_disabled!(checks, "MBD_280", "i810_audio");
    check_modprobe_disabled!(checks, "MBD_281", "kahlua");
    check_modprobe_disabled!(checks, "MBD_282", "mad16");
    check_modprobe_disabled!(checks, "MBD_283", "maestro");
    check_modprobe_disabled!(checks, "MBD_284", "maestro3");
    check_modprobe_disabled!(checks, "MBD_285", "maui");
    check_modprobe_disabled!(checks, "MBD_286", "mpu401");
    check_modprobe_disabled!(checks, "MBD_287", "nm256_audio");
    check_modprobe_disabled!(checks, "MBD_288", "opl3");
    check_modprobe_disabled!(checks, "MBD_289", "opl3sa");
    check_modprobe_disabled!(checks, "MBD_290", "opl3sa2");
    check_modprobe_disabled!(checks, "MBD_291", "pas2");
    check_modprobe_disabled!(checks, "MBD_292", "pss");
    check_modprobe_disabled!(checks, "MBD_293", "rme96xx");
    check_modprobe_disabled!(checks, "MBD_294", "sb");
    check_modprobe_disabled!(checks, "MBD_295", "sb_lib");
    check_modprobe_disabled!(checks, "MBD_296", "sgalaxy");
    check_modprobe_disabled!(checks, "MBD_297", "sonicvibes");
    check_modprobe_disabled!(checks, "MBD_298", "sound");
    check_modprobe_disabled!(checks, "MBD_299", "sscape");
    check_modprobe_disabled!(checks, "MBD_300", "trident");
    check_modprobe_disabled!(checks, "MBD_301", "trix");
    check_modprobe_disabled!(checks, "MBD_302", "uart401");
    check_modprobe_disabled!(checks, "MBD_303", "uart6850");
    check_modprobe_disabled!(checks, "MBD_304", "via82cxxx_audio");
    check_modprobe_disabled!(checks, "MBD_305", "v_midi");
    check_modprobe_disabled!(checks, "MBD_306", "wavefront");
    check_modprobe_disabled!(checks, "MBD_307", "ymfpci");
    check_modprobe_disabled!(checks, "MBD_308", "ac97_plugin_wm97xx");
    check_modprobe_disabled!(checks, "MBD_309", "ad1816");
    check_modprobe_disabled!(checks, "MBD_310", "audio");
    check_modprobe_disabled!(checks, "MBD_311", "awe_wave");
    check_modprobe_disabled!(checks, "MBD_312", "dmasound_core");
    check_modprobe_disabled!(checks, "MBD_313", "dmasound_pmac");
    check_modprobe_disabled!(checks, "MBD_314", "harmony");
    check_modprobe_disabled!(checks, "MBD_315", "sequencer");
    check_modprobe_disabled!(checks, "MBD_316", "soundcard");
    check_modprobe_disabled!(checks, "MBD_317", "usb_midi");
    check_modprobe_disabled!(checks, "MBD_324", "microcode");

    // TODO: check from file
    // check_sshd_config!(checks, "protocol" == 2);

    // TODO: check for disabled SFTP
    // TODO: check for configuration file permissions
    // TODO: check ciphers, MACs, and KexAlgorithms
    check_sshd_config!(checks, "SSH_001", "fingerprinthash", "SHA256");
    check_sshd_config!(checks, "SSH_002", "syslogfacility", "AUTH");
    check_sshd_config!(checks, "SSH_003", "loglevel", "VERBOSE"); // CIS
    check_sshd_config!(checks, "SSH_004", "logingracetime" <= 60); // CIS // TODO: strict: 30, relaxed: 60
    check_sshd_config!(checks, "SSH_005", "permitrootlogin", "no"); // CIS
    check_sshd_config!(checks, "SSH_006", "strictmodes", "yes");
    check_sshd_config!(checks, "SSH_007", "maxauthtries" <= 2); // CIS // TODO: strict: 2, relaxed: 4 (CIS)
    check_sshd_config!(checks, "SSH_008", "maxsessions" <= 2); // CIS // TODO: strict: 2, relaxed: 10 (CIS)
    check_sshd_config!(checks, "SSH_009", "hostbasedauthentication", "no"); // CIS
    check_sshd_config!(checks, "SSH_010", "ignorerhosts", "yes"); // CIS
    check_sshd_config!(checks, "SSH_011", "ignoreuserknownhosts", "yes");
    check_sshd_config!(checks, "SSH_012", "pubkeyauthentication", "yes"); // TODO: allow for no ?
    check_sshd_config!(checks, "SSH_013", "passwordauthentication", "no");
    check_sshd_config!(checks, "SSH_014", "kbdinteractiveauthentication", "no");
    check_sshd_config!(checks, "SSH_015", "permitemptypasswords", "no"); // CIS STIG
    check_sshd_config!(checks, "SSH_016", "kerberosauthentication", "no");
    check_sshd_config!(checks, "SSH_017", "kerberosorlocalpasswd", "no");
    check_sshd_config!(checks, "SSH_018", "kerberosticketcleanup", "yes");
    check_sshd_config!(checks, "SSH_019", "gssapiauthentication", "no"); // CIS
    check_sshd_config!(checks, "SSH_020", "gssapicleanupcredentials", "yes");
    check_sshd_config!(checks, "SSH_037", "usepam", "yes"); // CIS STIG
    check_sshd_config!(checks, "SSH_025", "disableforwarding", "yes"); // CIS
    check_sshd_config!(checks, "SSH_021", "x11forwarding", "no");
    check_sshd_config!(checks, "SSH_022", "allowagentforwarding", "no");
    check_sshd_config!(checks, "SSH_023", "allowstreamlocalforwarding", "no");
    check_sshd_config!(checks, "SSH_024", "allowtcpforwarding", "no");
    check_sshd_config!(checks, "SSH_026", "gatewayports", "no");
    check_sshd_config!(checks, "SSH_027", "x11uselocalhost", "yes");
    check_sshd_config!(checks, "SSH_028", "printmotd", "no");
    check_sshd_config!(checks, "SSH_029", "permituserenvironment", "no"); // CIS
    check_sshd_config!(checks, "SSH_030", "clientaliveinterval" <= 15); // TODO: range ?
    check_sshd_config!(checks, "SSH_031", "clientalivecountmax", "0");
    check_sshd_config!(checks, "SSH_032", "tcpkeepalive", "no");
    check_sshd_config!(checks, "SSH_033", "usedns", "no");
    check_sshd_config!(checks, "SSH_034", "permittunnel", "no");
    check_sshd_config!(checks, "SSH_035", "maxstartups", "10:30:60"); // CIS
    check_sshd_config!(checks, "SSH_036", "printlastlog", "no");
    check_sshd_config!(checks, "SSH_037", "allowgroups", "sshusers"); // TODO: only check for "not empty"

    check_sudoers_default!(checks, "SUD_001", "noexec");
    check_sudoers_default!(checks, "SUD_002", "requiretty");
    check_sudoers_default!(checks, "SUD_003", "use_pty"); // CIS
    check_sudoers_default!(checks, "SUD_004", "umask=0027");
    check_sudoers_default!(checks, "SUD_005", "ignore_dot");
    check_sudoers_default!(checks, "SUD_006", "passwd_timeout=1");
    check_sudoers_default!(checks, "SUD_007", "env_reset, timestamp_timeout=15");
    check_sudoers_default!(checks, "SUD_008", "timestamp_timeout=15");
    check_sudoers_default!(checks, "SUD_009", "env_reset");
    check_sudoers_default!(checks, "SUD_010", "mail_badpass");
    check_sudoers_default!(checks, "SUD_011", "logfile=\"/var/log/sudo.log\""); // CIS
    check_sudoers_default!(checks, "SUD_012", ":%sudo !noexec"); // TODO: `sudo` being the group allowed to use sudo

    // TODO: add this? if we do we should probably have rules to check the
    // content of the lecture file
    //check_sudoers_default!(checks, "SUD_013", "lecture=\"always\"");
    //check_sudoers_default!(checks, "SUD_014", "lecture_file=\"/usr/share/doc/sudo_lecture.txt\"");

    check_sudoers_nopasswd!(checks, "SUD_015"); // CIS
    check_sudoers_re_auth!(checks, "SUD_016");

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

    // TODO: Ensure /etc/shadow password fields are not empty

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

    // TODO: `/var/log` 0755 or less permissive - STIG
    // TODO: Ensure that library files have mode 755 or less permissive - STIG
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
