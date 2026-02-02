use crate::*;

pub fn add_checks() {
    check::Check::new(
        "SSH_001",
        "Ensure that sshd is configured with \"fingerprinthash SHA256\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("fingerprinthash", "SHA256"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"FingerprintHash SHA256\"")
    .register();

    check::Check::new(
        "SSH_002",
        "Ensure that sshd is configured with \"syslogfacility AUTH\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("syslogfacility", "AUTH"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"SyslogFacility AUTH\"")
    .register();

    check::Check::new(
        "SSH_003",
        "Ensure that sshd is configured with \"loglevel VERBOSE\"",
        vec!["sshd", "CIS", "mozilla", "server"],
        || sshd::check_sshd_config("loglevel", "VERBOSE"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"LogLevel VERBOSE\"")
    .register();

    check::Check::new(
        "SSH_004",
        "Ensure that sshd is configured with \"logingracetime\" <= 60",
        vec!["sshd", "CIS", "server"],
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
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"LoginGraceTime 60\"")
    .register();

    check::Check::new(
        "SSH_005",
        "Ensure that sshd is configured with \"permitrootlogin no\"",
        vec!["sshd", "CIS", "mozilla", "server"],
        || sshd::check_sshd_config("permitrootlogin", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"PermitRootLogin no\"")
    .register();

    check::Check::new(
        "SSH_006",
        "Ensure that sshd is configured with \"strictmodes yes\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("strictmodes", "yes"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"StrictModes yes\"")
    .register();

    check::Check::new(
        "SSH_007",
        "Ensure that sshd is configured with \"maxauthtries\" <= 4",
        vec!["sshd", "CIS", "server"],
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
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"MaxAuthTries 4\"")
    .register();

    check::Check::new(
        "SSH_008",
        "Ensure that sshd is configured with \"maxsessions\" <= 5",
        vec!["sshd", "CIS", "server"],
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
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"MaxSessions 5\"")
    .register();

    check::Check::new(
        "SSH_009",
        "Ensure that sshd is configured with \"hostbasedauthentication no\"",
        vec!["sshd", "CIS", "server"],
        || sshd::check_sshd_config("hostbasedauthentication", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"HostbasedAuthentication no\"")
    .register();

    // TODO: removed configuration
    // check::Check::new(
    //     "SSH_010",
    //     "Ensure that sshd is configured with \"ignorerhosts\" = \"yes\"",
    //     vec!["sshd", "CIS", "server"],
    //     || sshd::check_sshd_config("ignorerhosts", "yes"),
    //     vec![sshd::init_sshd_config],
    // )
    // .register();

    check::Check::new(
        "SSH_011",
        "Ensure that sshd is configured with \"ignoreuserknownhosts yes\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("ignoreuserknownhosts", "yes"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"IgnoreUserKnownHosts yes\"")
    .register();

    check::Check::new(
        "SSH_012",
        "Ensure that sshd is configured with \"pubkeyauthentication yes\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("pubkeyauthentication", "yes"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"AuthenticationMethods publickey\"")
    .register();

    check::Check::new(
        "SSH_013",
        "Ensure that sshd is configured with \"passwordauthentication no\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("passwordauthentication", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"PasswordAuthentication no\"")
    .register();

    check::Check::new(
        "SSH_014",
        "Ensure that sshd is configured with \"kbdinteractiveauthentication no\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("kbdinteractiveauthentication", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"KbdInteractiveAuthentication no\"")
    .register();

    check::Check::new(
        "SSH_015",
        "Ensure that sshd is configured with \"permitemptypasswords no\"",
        vec!["sshd", "CIS", "STIG", "server"],
        || sshd::check_sshd_config("permitemptypasswords", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"PermitEmptyPasswords yes\"")
    .register();

    check::Check::new(
        "SSH_016",
        "Ensure that sshd is configured with \"kerberosauthentication no\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("kerberosauthentication", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"KerberosAuthentication yes\"")
    .register();

    check::Check::new(
        "SSH_017",
        "Ensure that sshd is configured with \"kerberosorlocalpasswd no\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("kerberosorlocalpasswd", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"KerberosOrLocalPasswd no\"")
    .register();

    check::Check::new(
        "SSH_018",
        "Ensure that sshd is configured with \"kerberosticketcleanup yes\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("kerberosticketcleanup", "yes"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"KerberosTicketCleanup yes\"")
    .register();

    check::Check::new(
        "SSH_019",
        "Ensure that sshd is configured with \"gssapiauthentication no\"",
        vec!["sshd", "CIS", "server"],
        || sshd::check_sshd_config("gssapiauthentication", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"GSSAPIAuthentication yes\"")
    .register();

    check::Check::new(
        "SSH_020",
        "Ensure that sshd is configured with \"gssapicleanupcredentials yes\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("gssapicleanupcredentials", "yes"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"GSSAPICleanupCredentials no\"")
    .register();

    check::Check::new(
        "SSH_044",
        "Ensure that sshd is configured with \"usepam yes\"",
        vec!["sshd", "CIS", "STIG", "server"],
        || sshd::check_sshd_config("usepam", "yes"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"UsePAM yes\"")
    .register();

    check::Check::new(
        "SSH_025",
        "Ensure that sshd is configured with \"disableforwarding yes\"",
        vec!["sshd", "CIS", "server"],
        || sshd::check_sshd_config("disableforwarding", "yes"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"DisableForwarding yes\"")
    .register();

    check::Check::new(
        "SSH_021",
        "Ensure that sshd is configured with \"x11forwarding no\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("x11forwarding", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"DisableForwarding yes\"")
    .register();

    check::Check::new(
        "SSH_026",
        "Ensure that sshd is configured with \"gatewayports no\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("gatewayports", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"Gatewayports yes\"")
    .register();

    check::Check::new(
        "SSH_027",
        "Ensure that sshd is configured with \"x11uselocalhost yes\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("x11uselocalhost", "yes"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"X11UseLocalhost no\"")
    .register();

    check::Check::new(
        "SSH_028",
        "Ensure that sshd is configured with \"printmotd no\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("printmotd", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"PrintMotd no\"")
    .register();

    check::Check::new(
        "SSH_029",
        "Ensure that sshd is configured with \"permituserenvironment no\"",
        vec!["sshd", "CIS", "server"],
        || sshd::check_sshd_config("permituserenvironment", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"PermitUserEnvironment yes\"")
    .register();

    check::Check::new(
        "SSH_030",
        "Ensure that sshd is configured with \"clientaliveinterval\" <= 15",
        vec!["sshd", "CIS", "server"],
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
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"ClientAliveInterval 15\"")
    .register();

    check::Check::new(
        "SSH_031",
        "Ensure that sshd is configured with \"clientalivecountmax 3\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("clientalivecountmax", "3"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"ClientAliveCountMax *\"")
    .register();

    check::Check::new(
        "SSH_032",
        "Ensure that sshd is configured with \"tcpkeepalive no\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("tcpkeepalive", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"TCPKeepAlive no\"")
    .register();

    check::Check::new(
        "SSH_033",
        "Ensure that sshd is configured with \"usedns no\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("usedns", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"UseDNS yes\"")
    .register();

    check::Check::new(
        "SSH_034",
        "Ensure that sshd is configured with \"permittunnel no\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("permittunnel", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"PermitTunnel yes\"")
    .register();

    check::Check::new(
        "SSH_035",
        "Ensure that sshd is configured with \"maxstartups 10:30:60\"",
        vec!["sshd", "CIS", "server"],
        || sshd::check_sshd_config("maxstartups", "10:30:60"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"MaxStartups 10:30:60\"")
    .register();

    check::Check::new(
        "SSH_036",
        "Ensure that sshd is configured with \"printlastlog no\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("printlastlog", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"PrintLastLog no\"")
    .register();

    check::Check::new(
        "SSH_037",
        "Ensure that sshd is configured with \"allowgroups sshusers\"",
        vec!["sshd", "server"],
        // TODO: ensure the group also exist
        || sshd::check_sshd_config("allowgroups", "sshusers"),
        vec![sshd::init_sshd_config],
    )
    .with_description("SSH access should be restricted to a group of users.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"AllowGroups sshusers\"")
    .register();

    // TODO: make skip it depending based on version, OpenSSH 6.7+
    // check::Check::new(
    //     "SSH_038",
    //     "Ensure that sshd is configured with \"kexalgorithms\" = \"curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256\"",
    //     vec!["sshd", "mozilla", "server"],
    //     || {
    //         sshd::check_sshd_config(
    //             "kexalgorithms",
    //             "curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256",
    //         )
    //     },
    //     vec![sshd::init_sshd_config],
    // ).register();
    // NOTE: for OpenSSH 10+:
    check::Check::new(
        "SSH_038",
        "Ensure that sshd is configured with \"kexalgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521\"",
        vec!["sshd", "mozilla", "server"],
        || {
            sshd::check_sshd_config(
                "kexalgorithms",
                "mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521",
            )
        },
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521\"")
    .register();

    check::Check::new(
        "SSH_039",
        "Ensure that sshd is configured with \"ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\"",
        vec!["sshd", "mozilla", "server"],
        || {
            sshd::check_sshd_config(
                "ciphers",
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
            )
        },
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\"")
    .register();

    check::Check::new(
        "SSH_040",
        "Ensure that sshd is configured with \"macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com\"",
        vec!["sshd", "mozilla", "server"],
        || {
            sshd::check_sshd_config(
                "macs",
                "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com",
            )
        },
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com\"")
    .register();

    check::Check::new(
        "SSH_041",
        "Ensure that sshd is configured with \"authenticationmethods publickey\"",
        vec!["sshd", "mozilla", "server"],
        || sshd::check_sshd_config("authenticationmethods", "publickey"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"AuthenticationMethods publickey\"")
    .register();

    check::Check::new(
        "SSH_042",
        "Ensure that sshd is configured with \"subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO\"",
        vec!["sshd", "mozilla", "server"],
        || {
            sshd::check_sshd_config(
                "subsystem",
                "sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO",
            )
        },
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO\"")
    .register();

    check::Check::new(
        "SSH_043",
        "Ensure that sshd is configured with \"kbdinteractiveauthentication no\"",
        vec!["sshd", "server"],
        || sshd::check_sshd_config("kbdinteractiveauthentication", "no"),
        vec![sshd::init_sshd_config],
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"KbdInteractiveAuthentication no\"")
    .register();

    check::Check::new(
        "SSH_045",
        "Ensure sshd service file is owned by root",
        vec!["sshd", "systemd", "server"],
        || match systemd::get_service_file("sshd") {
            Some(path) => base::check_file_owner_id(&path, 0, 0),
            None => (
                check::CheckState::Error,
                Some("systemd sshd service file not found".to_string()),
            ),
        },
        vec![],
    )
    .with_fix("chown root:root /etc/systemd/system/sshd.service")
    .register();

    check::Check::new(
        "SSH_046",
        "Ensure sshd service file permissions 644 are set",
        vec!["sshd", "systemd", "server"],
        || match systemd::get_service_file("sshd") {
            Some(path) => base::check_file_permission(&path, 0o644),
            None => (
                check::CheckState::Error,
                Some("systemd sshd service file not found".to_string()),
            ),
        },
        vec![],
    )
    .with_fix("chmod 644 /etc/systemd/system/sshd.service")
    .register();

    check::Check::new(
        "SSH_047",
        "Ensure /etc/ssh directory is owned by root",
        vec!["sshd", "server"],
        || base::check_dir_owner_id("/etc/ssh", 0, 0),
        vec![],
    )
    .with_fix("chown root:root /etc/ssh")
    .register();

    check::Check::new(
        "SSH_048",
        "Ensure /etc/ssh directory permissions is 755",
        vec!["sshd", "server"],
        || base::check_dir_permission("/etc/ssh", 0o755),
        vec![],
    )
    .with_fix("chmod 755 /etc/ssh")
    .register();

    check::Check::new(
        "SSH_049",
        "Ensure /etc/ssh/sshd_config file is owned by root",
        vec!["sshd", "server"],
        || base::check_file_owner_id("/etc/ssh/sshd_config", 0, 0),
        vec![],
    )
    .with_fix("chown root:root /etc/ssh/sshd_config")
    .register();

    check::Check::new(
        "SSH_050",
        "Ensure /etc/ssh/sshd_config file permissions is 644",
        vec!["sshd", "server"],
        || base::check_file_permission("/etc/ssh/sshd_config", 0o644),
        vec![],
    )
    .with_fix("chmod 644 /etc/ssh/sshd_config")
    .register();

    check::Check::new(
        "SSH_051",
        "Ensure /etc/ssh/sshd_config.d/ directory is owned by root",
        vec!["sshd", "server"],
        || base::check_dir_owner_id("/etc/ssh/sshd_config.d", 0, 0),
        vec![],
    )
    .with_fix("chown root:root /etc/ssh/sshd_config.d")
    .register();

    check::Check::new(
        "SSH_052",
        "Ensure /etc/ssh/sshd_config.d/ files are owned by root",
        vec!["sshd", "server"],
        || base::check_dir_files_owner_id("/etc/ssh/sshd_config.d/", 0, 0),
        vec![],
    )
    .with_fix("chown -R root:root /etc/ssh/sshd_config.d/*")
    .register();

    check::Check::new(
        "SSH_053",
        "Ensure /etc/ssh/sshd_config.d/ files permissions are 644",
        vec!["sshd", "server"],
        || base::check_dir_files_permission("/etc/ssh/sshd_config.d/", 0o644),
        vec![],
    )
    .with_fix("chmod -R 644 /etc/ssh/sshd_config.d/*")
    .register();

    // TODO: check the content of File: /etc/ssh/moduli from: https://infosec.mozilla.org/guidelines/openssh
    // TODO: add OpenSSH client rules: https://infosec.mozilla.org/guidelines/openssh#openssh-client
    //
    // removed rules
    //
    // Note that disabling agent forwarding does not improve security unless
    // users are also denied shell access, as they can always install their
    // own forwarders.
    // check::Check::new(
    //     "SSH_022",
    //     "Ensure that sshd is configured with \"allowagentforwarding\" = \"no\"",
    //     vec!["sshd", "server"],
    //     || sshd::check_sshd_config("allowagentforwarding", "no"),
    //     vec![sshd::init_sshd_config],
    // ).register();
    // Note that disabling StreamLocal forwarding does not improve security
    // unless users are also denied shell access, as they  can  always install
    // their own forwarders.
    // check::Check::new(
    //     "SSH_023",
    //     "Ensure that sshd is configured with \"allowstreamlocalforwarding\" = \"no\"",
    //     vec!["sshd", "server"],
    //     || sshd::check_sshd_config("allowstreamlocalforwarding", "no"),
    //     vec![sshd::init_sshd_config],
    // ).register();
    // Note that disabling TCP forwarding does not improve security unless users
    // arealso denied shell access, as they can always install their own
    // forwarders.
    // check::Check::new(
    //     "SSH_024",
    //     "Ensure that sshd is configured with \"allowtcpforwarding\" = \"no\"",
    //     vec!["sshd", "server"],
    //     || sshd::check_sshd_config("allowtcpforwarding", "no"),
    //     vec![sshd::init_sshd_config],
    // ).register();
}
