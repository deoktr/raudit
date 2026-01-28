use crate::*;

pub fn add_checks() {
    // TODO: check for configuration file permissions
    check::add_check(
        "SSH_001",
        "Ensure that sshd is configured with \"fingerprinthash\" = \"SHA256\"",
        vec!["sshd"],
        || sshd::check_sshd_config("fingerprinthash", "SHA256"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_002",
        "Ensure that sshd is configured with \"syslogfacility\" = \"AUTH\"",
        vec!["sshd"],
        || sshd::check_sshd_config("syslogfacility", "AUTH"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_003",
        "Ensure that sshd is configured with \"loglevel\" = \"VERBOSE\"",
        vec!["sshd", "CIS", "mozilla"],
        || sshd::check_sshd_config("loglevel", "VERBOSE"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_004",
        "Ensure that sshd is configured with \"logingracetime\" <= 60",
        vec!["sshd", "CIS"],
        || {
            const VAL: i32 = 60;
            match sshd::get_sshd_config_value("logingracetime") {
                Ok(str_value) => match str_value.parse::<i32>() {
                    Ok(value) => {
                        if value <= VAL {
                            (check::CheckState::Passed, Some(format!("{}", value)))
                        } else {
                            (
                                check::CheckState::Failed,
                                Some(format!("{} > {}", value, VAL)),
                            )
                        }
                    }
                    Err(err) => (check::CheckState::Error, Some(err.to_string())),
                },
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_005",
        "Ensure that sshd is configured with \"permitrootlogin\" = \"no\"",
        vec!["sshd", "CIS", "mozilla"],
        || sshd::check_sshd_config("permitrootlogin", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_006",
        "Ensure that sshd is configured with \"strictmodes\" = \"yes\"",
        vec!["sshd"],
        || sshd::check_sshd_config("strictmodes", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_007",
        "Ensure that sshd is configured with \"maxauthtries\" <= 4",
        vec!["sshd", "CIS"],
        || {
            const VAL: i32 = 4;
            match sshd::get_sshd_config_value("maxauthtries") {
                Ok(str_value) => match str_value.parse::<i32>() {
                    Ok(value) => {
                        if value <= VAL {
                            (check::CheckState::Passed, Some(format!("{}", value)))
                        } else {
                            (
                                check::CheckState::Failed,
                                Some(format!("{} > {}", value, VAL)),
                            )
                        }
                    }
                    Err(err) => (check::CheckState::Error, Some(err.to_string())),
                },
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_008",
        "Ensure that sshd is configured with \"maxsessions\" <= 5",
        vec!["sshd", "CIS"],
        || {
            const VAL: i32 = 5;
            match sshd::get_sshd_config_value("maxsessions") {
                Ok(str_value) => match str_value.parse::<i32>() {
                    Ok(value) => {
                        if value <= VAL {
                            (check::CheckState::Passed, Some(format!("{}", value)))
                        } else {
                            (
                                check::CheckState::Failed,
                                Some(format!("{} > {}", value, VAL)),
                            )
                        }
                    }
                    Err(err) => (check::CheckState::Error, Some(err.to_string())),
                },
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_009",
        "Ensure that sshd is configured with \"hostbasedauthentication\" = \"no\"",
        vec!["sshd", "CIS"],
        || sshd::check_sshd_config("hostbasedauthentication", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_010",
        "Ensure that sshd is configured with \"ignorerhosts\" = \"yes\"",
        vec!["sshd", "CIS"],
        || sshd::check_sshd_config("ignorerhosts", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_011",
        "Ensure that sshd is configured with \"ignoreuserknownhosts\" = \"yes\"",
        vec!["sshd"],
        || sshd::check_sshd_config("ignoreuserknownhosts", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_012",
        "Ensure that sshd is configured with \"pubkeyauthentication\" = \"yes\"",
        vec!["sshd"],
        || sshd::check_sshd_config("pubkeyauthentication", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_013",
        "Ensure that sshd is configured with \"passwordauthentication\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("passwordauthentication", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_014",
        "Ensure that sshd is configured with \"kbdinteractiveauthentication\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("kbdinteractiveauthentication", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_015",
        "Ensure that sshd is configured with \"permitemptypasswords\" = \"no\"",
        vec!["sshd", "CIS", "STIG"],
        || sshd::check_sshd_config("permitemptypasswords", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_016",
        "Ensure that sshd is configured with \"kerberosauthentication\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("kerberosauthentication", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_017",
        "Ensure that sshd is configured with \"kerberosorlocalpasswd\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("kerberosorlocalpasswd", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_018",
        "Ensure that sshd is configured with \"kerberosticketcleanup\" = \"yes\"",
        vec!["sshd"],
        || sshd::check_sshd_config("kerberosticketcleanup", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_019",
        "Ensure that sshd is configured with \"gssapiauthentication\" = \"no\"",
        vec!["sshd", "CIS"],
        || sshd::check_sshd_config("gssapiauthentication", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_020",
        "Ensure that sshd is configured with \"gssapicleanupcredentials\" = \"yes\"",
        vec!["sshd"],
        || sshd::check_sshd_config("gssapicleanupcredentials", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_037",
        "Ensure that sshd is configured with \"usepam\" = \"yes\"",
        vec!["sshd", "CIS", "STIG"],
        || sshd::check_sshd_config("usepam", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_025",
        "Ensure that sshd is configured with \"disableforwarding\" = \"yes\"",
        vec!["sshd", "CIS"],
        || sshd::check_sshd_config("disableforwarding", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_021",
        "Ensure that sshd is configured with \"x11forwarding\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("x11forwarding", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_022",
        "Ensure that sshd is configured with \"allowagentforwarding\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("allowagentforwarding", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_023",
        "Ensure that sshd is configured with \"allowstreamlocalforwarding\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("allowstreamlocalforwarding", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_024",
        "Ensure that sshd is configured with \"allowtcpforwarding\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("allowtcpforwarding", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_026",
        "Ensure that sshd is configured with \"gatewayports\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("gatewayports", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_027",
        "Ensure that sshd is configured with \"x11uselocalhost\" = \"yes\"",
        vec!["sshd"],
        || sshd::check_sshd_config("x11uselocalhost", "yes"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_028",
        "Ensure that sshd is configured with \"printmotd\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("printmotd", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_029",
        "Ensure that sshd is configured with \"permituserenvironment\" = \"no\"",
        vec!["sshd", "CIS"],
        || sshd::check_sshd_config("permituserenvironment", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_030",
        "Ensure that sshd is configured with \"clientaliveinterval\" <= 15",
        vec!["sshd", "CIS"],
        || {
            const VAL: i32 = 15;
            match sshd::get_sshd_config_value("clientaliveinterval") {
                Ok(str_value) => match str_value.parse::<i32>() {
                    Ok(value) => {
                        if value <= VAL {
                            (check::CheckState::Passed, Some(format!("{}", value)))
                        } else {
                            (
                                check::CheckState::Failed,
                                Some(format!("{} > {}", value, VAL)),
                            )
                        }
                    }
                    Err(err) => (check::CheckState::Error, Some(err.to_string())),
                },
                Err(err) => (check::CheckState::Error, Some(err)),
            }
        },
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_031",
        "Ensure that sshd is configured with \"clientalivecountmax\" = \"3\"",
        vec!["sshd"],
        || sshd::check_sshd_config("clientalivecountmax", "3"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_032",
        "Ensure that sshd is configured with \"tcpkeepalive\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("tcpkeepalive", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_033",
        "Ensure that sshd is configured with \"usedns\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("usedns", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_034",
        "Ensure that sshd is configured with \"permittunnel\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("permittunnel", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_035",
        "Ensure that sshd is configured with \"maxstartups\" = \"10:30:60\"",
        vec!["sshd", "CIS"],
        || sshd::check_sshd_config("maxstartups", "10:30:60"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_036",
        "Ensure that sshd is configured with \"printlastlog\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("printlastlog", "no"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_037",
        "Ensure that sshd is configured with \"allowgroups\" = \"sshusers\"",
        vec!["sshd"],
        // TODO: ensure the group also exist
        || sshd::check_sshd_config("allowgroups", "sshusers"),
        vec![sshd::init_sshd_config],
    );
    // TODO: make skip it depending based on version, OpenSSH 6.7+
    // TODO: for OpenSSH 10+:
    // "mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521",
    check::add_check(
        "SSH_038",
        "Ensure that sshd is configured with \"kexalgorithms\" = \"curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256\"",
        vec!["sshd", "mozilla"],
        || {
            sshd::check_sshd_config(
                "kexalgorithms",
                "curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256",
            )
        },
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_039",
        "Ensure that sshd is configured with \"ciphers\" = \"chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\"",
        vec!["sshd", "mozilla"],
        || {
            sshd::check_sshd_config(
                "ciphers",
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
            )
        },
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_040",
        "Ensure that sshd is configured with \"macs\" = \"hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com\"",
        vec!["sshd", "mozilla"],
        || {
            sshd::check_sshd_config(
                "macs",
                "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com",
            )
        },
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_041",
        "Ensure that sshd is configured with \"authenticationmethods\" = \"publickey\"",
        vec!["sshd", "mozilla"],
        || sshd::check_sshd_config("authenticationmethods", "publickey"),
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_042",
        "Ensure that sshd is configured with \"subsystem\" = \"sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO\"",
        vec!["sshd", "mozilla"],
        || {
            sshd::check_sshd_config(
                "subsystem",
                "sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO",
            )
        },
        vec![sshd::init_sshd_config],
    );
    check::add_check(
        "SSH_043",
        "Ensure that sshd is configured with \"kbdinteractiveauthentication\" = \"no\"",
        vec!["sshd"],
        || sshd::check_sshd_config("kbdinteractiveauthentication", "no"),
        vec![sshd::init_sshd_config],
    );
    // TODO: check the content of File: /etc/ssh/moduli from: https://infosec.mozilla.org/guidelines/openssh
    // TODO: add OpenSSH client rules: https://infosec.mozilla.org/guidelines/openssh#openssh-client
}
