use crate::check;
use crate::check::Severity;
use crate::modules::{base, sshd, systemd};

pub fn add_checks() {
    check::Check::new(
        "SSH_001",
        "Ensure that sshd is configured with \"fingerprinthash SHA256\"",
        Severity::Medium,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("fingerprinthash", "SHA256"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"FingerprintHash SHA256\"")
    .register();

    check::Check::new(
        "SSH_002",
        "Ensure that sshd is configured with \"syslogfacility AUTH\"",
        Severity::Low,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("syslogfacility", "AUTH"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"SyslogFacility AUTH\"")
    .register();

    check::Check::new(
        "SSH_003",
        "Ensure that sshd is configured with \"loglevel VERBOSE\"",
        Severity::Low,
        vec!["sshd", "CIS", "mozilla", "server"],
        || sshd::check_sshd_config("loglevel", "VERBOSE"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"LogLevel VERBOSE\"")
    .register();

    check::Check::new(
        "SSH_004",
        "Ensure that sshd is configured with \"logingracetime\" <= 60",
        Severity::Medium,
        vec!["sshd", "CIS", "server"],
        || {
            const VAL: i32 = 60;
            match sshd::get_sshd_config_value("logingracetime") {
                Ok(str_value) => match str_value.parse::<i32>() {
                    Ok(value) => {
                        if value <= VAL {
                            (check::CheckState::Pass, Some(format!("{}", value)))
                        } else {
                            (
                                check::CheckState::Fail,
                                Some(format!("{} > {}", value, VAL)),
                            )
                        }
                    }
                    Err(err) => (check::CheckState::Warning, Some(err.to_string())),
                },
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("A long LoginGraceTime lets an attacker hold open many half-finished auth attempts that consume sshd connection slots, enabling slow-DoS or password-spray campaigns. 60s is enough for legitimate logins. Increase on very slow connection if you timeout.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"LoginGraceTime 60\"")
    .register();

    check::Check::new(
        "SSH_005",
        "Ensure that sshd is configured with \"permitrootlogin no\"",
        Severity::Critical,
        vec!["sshd", "CIS", "mozilla", "server"],
        || sshd::check_sshd_config("permitrootlogin", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Direct SSH login as root collapses two security barriers into one: an attacker who phishes or cracks the root password gets immediate full control with no intermediate user account, and audit logs cannot attribute the action to a specific user.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"PermitRootLogin no\"")
    .register();

    check::Check::new(
        "SSH_006",
        "Ensure that sshd is configured with \"strictmodes yes\"",
        Severity::Medium,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("strictmodes", "yes"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("StrictModes makes sshd refuse to read authorized_keys/.ssh files that are world- or group-writable. Without it, an attacker who gains any write access to a user's home dir can append a key to authorized_keys and gain persistent SSH login.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"StrictModes yes\"")
    .register();

    check::Check::new(
        "SSH_007",
        "Ensure that sshd is configured with \"maxauthtries\" <= 4",
        Severity::Medium,
        vec!["sshd", "CIS", "server"],
        || {
            const VAL: i32 = 4;
            match sshd::get_sshd_config_value("maxauthtries") {
                Ok(str_value) => match str_value.parse::<i32>() {
                    Ok(value) => {
                        if value <= VAL {
                            (check::CheckState::Pass, Some(format!("{}", value)))
                        } else {
                            (
                                check::CheckState::Fail,
                                Some(format!("{} > {}", value, VAL)),
                            )
                        }
                    }
                    Err(err) => (check::CheckState::Warning, Some(err.to_string())),
                },
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Capping authentication attempts per TCP connection, increasing the protection against brute-force attacks.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"MaxAuthTries 4\"")
    .register();

    check::Check::new(
        "SSH_008",
        "Ensure that sshd is configured with \"maxsessions\" <= 5",
        Severity::Medium,
        vec!["sshd", "CIS", "server"],
        || {
            const VAL: i32 = 5;
            match sshd::get_sshd_config_value("maxsessions") {
                Ok(str_value) => match str_value.parse::<i32>() {
                    Ok(value) => {
                        if value <= VAL {
                            (check::CheckState::Pass, Some(format!("{}", value)))
                        } else {
                            (
                                check::CheckState::Fail,
                                Some(format!("{} > {}", value, VAL)),
                            )
                        }
                    }
                    Err(err) => (check::CheckState::Warning, Some(err.to_string())),
                },
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"MaxSessions 5\"")
    .register();

    check::Check::new(
        "SSH_009",
        "Ensure that sshd is configured with \"hostbasedauthentication no\"",
        Severity::High,
        vec!["sshd", "CIS", "server"],
        || sshd::check_sshd_config("hostbasedauthentication", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("HostbasedAuthentication trusts the client host's identity rather than a user credential, an attacker who compromises any trusted client can hop into the server as any user without further authentication.")
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
        Severity::Medium,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("ignoreuserknownhosts", "yes"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"IgnoreUserKnownHosts yes\"")
    .register();

    check::Check::new(
        "SSH_012",
        "Ensure that sshd is configured with \"pubkeyauthentication yes\"",
        Severity::Critical,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("pubkeyauthentication", "yes"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"AuthenticationMethods publickey\"")
    .register();

    check::Check::new(
        "SSH_013",
        "Ensure that sshd is configured with \"passwordauthentication no\"",
        Severity::Critical,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("passwordauthentication", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Use key authentication instead of password based.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"PasswordAuthentication no\"")
    .register();

    check::Check::new(
        "SSH_014",
        "Ensure that sshd is configured with \"kbdinteractiveauthentication no\"",
        Severity::High,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("kbdinteractiveauthentication", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"KbdInteractiveAuthentication no\"")
    .register();

    check::Check::new(
        "SSH_015",
        "Ensure that sshd is configured with \"permitemptypasswords no\"",
        Severity::Critical,
        vec!["sshd", "CIS", "STIG", "server"],
        || sshd::check_sshd_config("permitemptypasswords", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("PermitEmptyPasswords yes lets accounts with empty password fields log in over SSH with no password. Use as security in depth if password authentication must be enabled.")
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"PermitEmptyPasswords yes\"")
    .register();

    check::Check::new(
        "SSH_016",
        "Ensure that sshd is configured with \"kerberosauthentication no\"",
        Severity::Medium,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("kerberosauthentication", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Unless the host is on a Kerberos realm, KerberosAuthentication just adds attack surface and a parser exposed to network input. Disabling it removes that surface entirely.")
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"KerberosAuthentication yes\"")
    .register();

    check::Check::new(
        "SSH_017",
        "Ensure that sshd is configured with \"kerberosorlocalpasswd no\"",
        Severity::High,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("kerberosorlocalpasswd", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("KerberosOrLocalPasswd yes lets sshd silently fall back to \"/etc/passwd-style\" authentication when Kerberos fails, defeating the intent to require Kerberos and re-exposing local password attacks. Defence-in-depth in case Kerberos is used.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"KerberosOrLocalPasswd no\"")
    .register();

    check::Check::new(
        "SSH_018",
        "Ensure that sshd is configured with \"kerberosticketcleanup yes\"",
        Severity::Medium,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("kerberosticketcleanup", "yes"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Without ticket cleanup, Kerberos credentials linger after the SSH session ends, a later attacker who reaches the host can reuse them to access other Kerberized services as the ticket's principal. Defence-in-depth in case Kerberos is used.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"KerberosTicketCleanup yes\"")
    .register();

    check::Check::new(
        "SSH_019",
        "Ensure that sshd is configured with \"gssapiauthentication no\"",
        Severity::Medium,
        vec!["sshd", "CIS", "server"],
        || sshd::check_sshd_config("gssapiauthentication", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("GSSAPI exposes additional code and parsers to remote attackers before authentication completes, on hosts not on a GSSAPI/Kerberos realm it is pure attack surface.")
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"GSSAPIAuthentication yes\"")
    .register();

    check::Check::new(
        "SSH_020",
        "Ensure that sshd is configured with \"gssapicleanupcredentials yes\"",
        Severity::Low,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("gssapicleanupcredentials", "yes"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Leftover GSSAPI credentials after a session ends are reusable by anyone who later reaches the host as that user. Security in depth in case Kerberos is used.")
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"GSSAPICleanupCredentials no\"")
    .register();

    check::Check::new(
        "SSH_044",
        "Ensure that sshd is configured with \"usepam yes\"",
        Severity::Critical,
        vec!["sshd", "CIS", "STIG", "server"],
        || sshd::check_sshd_config("usepam", "yes"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("\"UsePAM yes\" routes sshd through PAM, picking up account-lockout, faillock, lecturing, and other PAM-stack hardening. Without it, those controls are bypassed entirely on the SSH path.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"UsePAM yes\"")
    .register();

    check::Check::new(
        "SSH_025",
        "Ensure that sshd is configured with \"disableforwarding yes\"",
        Severity::Medium,
        vec!["sshd", "CIS", "server"],
        || sshd::check_sshd_config("disableforwarding", "yes"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"DisableForwarding yes\"")
    .register();

    check::Check::new(
        "SSH_021",
        "Ensure that sshd is configured with \"x11forwarding no\"",
        Severity::Medium,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("x11forwarding", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"DisableForwarding yes\"")
    .register();

    check::Check::new(
        "SSH_026",
        "Ensure that sshd is configured with \"gatewayports no\"",
        Severity::Medium,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("gatewayports", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"Gatewayports yes\"")
    .register();

    check::Check::new(
        "SSH_027",
        "Ensure that sshd is configured with \"x11uselocalhost yes\"",
        Severity::Medium,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("x11uselocalhost", "yes"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"X11UseLocalhost no\"")
    .register();

    check::Check::new(
        "SSH_028",
        "Ensure that sshd is configured with \"printmotd no\"",
        Severity::Low,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("printmotd", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"PrintMotd no\"")
    .register();

    check::Check::new(
        "SSH_029",
        "Ensure that sshd is configured with \"permituserenvironment no\"",
        Severity::High,
        vec!["sshd", "CIS", "server"],
        || sshd::check_sshd_config("permituserenvironment", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"PermitUserEnvironment yes\"")
    .register();

    check::Check::new(
        "SSH_030",
        "Ensure that sshd is configured with \"clientaliveinterval\" <= 15",
        Severity::Medium,
        vec!["sshd", "CIS", "server"],
        || {
            const VAL: i32 = 15;
            match sshd::get_sshd_config_value("clientaliveinterval") {
                Ok(str_value) => match str_value.parse::<i32>() {
                    Ok(value) => {
                        if value <= VAL {
                            (check::CheckState::Pass, Some(format!("{}", value)))
                        } else {
                            (
                                check::CheckState::Fail,
                                Some(format!("{} > {}", value, VAL)),
                            )
                        }
                    }
                    Err(err) => (check::CheckState::Warning, Some(err.to_string())),
                },
                Err(err) => (check::CheckState::Warning, Some(err)),
            }
        },
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"ClientAliveInterval 15\"")
    .register();

    check::Check::new(
        "SSH_031",
        "Ensure that sshd is configured with \"clientalivecountmax 3\"",
        Severity::Medium,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("clientalivecountmax", "3"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Together with ClientAliveInterval, this caps how many missed keepalives a session can survive before sshd terminates it, closing dead sessions denies attackers a parked authenticated channel to reuse.")
    .with_fix("In \"/etc/ssh/sshd_config\" set: \"ClientAliveCountMax 3\"")
    .register();

    check::Check::new(
        "SSH_032",
        "Ensure that sshd is configured with \"tcpkeepalive no\"",
        Severity::Low,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("tcpkeepalive", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"TCPKeepAlive no\"")
    .register();

    check::Check::new(
        "SSH_033",
        "Ensure that sshd is configured with \"usedns no\"",
        Severity::Low,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("usedns", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"UseDNS yes\"")
    .register();

    check::Check::new(
        "SSH_034",
        "Ensure that sshd is configured with \"permittunnel no\"",
        Severity::Medium,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("permittunnel", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Prevent SSH session from creating a tun/tap device, making it a bit harder for an attacker to bridge networks.")
    .with_fix("In \"/etc/ssh/sshd_config\" remove: \"PermitTunnel yes\"")
    .register();

    check::Check::new(
        "SSH_035",
        "Ensure that sshd is configured with \"maxstartups 10:30:60\"",
        Severity::Medium,
        vec!["sshd", "CIS", "server"],
        || sshd::check_sshd_config("maxstartups", "10:30:60"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"MaxStartups 10:30:60\"")
    .register();

    check::Check::new(
        "SSH_036",
        "Ensure that sshd is configured with \"printlastlog yes\"",
        Severity::Low,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("printlastlog", "yes"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description(
        "Could help detect an unauthorized connection if the last login is not recognized.",
    )
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"PrintLastLog yes\"")
    .register();

    check::Check::new(
        "SSH_037",
        "Ensure that sshd is configured with \"allowgroups sshusers\"",
        Severity::High,
        vec!["sshd", "server"],
        // TODO: ensure the group also exist
        || sshd::check_sshd_config("allowgroups", "sshusers"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
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
        Severity::High,
        vec!["sshd", "mozilla", "server"],
        || {
            sshd::check_sshd_config(
                "kexalgorithms",
                "mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521",
            )
        },
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Pinning key-exchange algorithms to a vetted modern set blocks downgrade to weak/legacy KEX (e.g. SHA-1-based DH groups) and includes post-quantum hybrids (mlkem, sntrup) so today's recorded sessions cannot be decrypted by future quantum-capable adversaries.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521\"")
    .register();

    check::Check::new(
        "SSH_039",
        "Ensure that sshd is configured with \"ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\"",
        Severity::High,
        vec!["sshd", "mozilla", "server"],
        || {
            sshd::check_sshd_config(
                "ciphers",
                "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
            )
        },
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Pinning ciphers to authenticated-encryption (AEAD) and CTR-with-MAC modes blocks downgrade to CBC, RC4, and 3DES, historically broken to recover plaintext from captured SSH traffic.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\"")
    .register();

    check::Check::new(
        "SSH_040",
        "Ensure that sshd is configured with \"macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com\"",
        Severity::High,
        vec!["sshd", "mozilla", "server"],
        || {
            sshd::check_sshd_config(
                "macs",
                "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com",
            )
        },
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Pinning MACs to encrypt-then-MAC (ETM) SHA-2 family blocks the historically-broken MD5/SHA-1 MACs and the encrypt-and-MAC ordering that has produced timing oracles in OpenSSH.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com\"")
    .register();

    check::Check::new(
        "SSH_041",
        "Ensure that sshd is configured with \"authenticationmethods publickey\"",
        Severity::Critical,
        vec!["sshd", "mozilla", "server"],
        || sshd::check_sshd_config("authenticationmethods", "publickey"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Enforces the use of publickey for authentication, eliminating fall-back paths to credential auth.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"AuthenticationMethods publickey\"")
    .register();

    check::Check::new(
        "SSH_042",
        "Ensure that sshd is configured with \"subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO\"",
        Severity::Low,
        vec!["sshd", "mozilla", "server"],
        || {
            sshd::check_sshd_config(
                "subsystem",
                "sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO",
            )
        },
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Configure SFTP to log to AUTHPRIV at INFO, every file transfer over SFTP appears in the auth log, turning otherwise-silent file exfil over SSH into something that can be detected and audited.")
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO\"")
    .register();

    check::Check::new(
        "SSH_043",
        "Ensure that sshd is configured with \"kbdinteractiveauthentication no\"",
        Severity::High,
        vec!["sshd", "server"],
        || sshd::check_sshd_config("kbdinteractiveauthentication", "no"),
        vec![sshd::init_sshd_config],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_fix("In \"/etc/ssh/sshd_config\" add: \"KbdInteractiveAuthentication no\"")
    .register();

    check::Check::new(
        "SSH_045",
        "Ensure sshd service file is owned by root",
        Severity::High,
        vec!["sshd", "systemd", "server"],
        || match systemd::get_service_file("sshd") {
            Some(path) => base::check_file_owner_id(&path, 0, 0),
            None => (
                check::CheckState::Warning,
                Some("systemd sshd service file not found".to_string()),
            ),
        },
        vec![],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("If a non-root user owns the sshd systemd unit file, they can edit it and have that wrapper run as root the next time sshd is started, would allow for full local privilege escalation.")
    .with_fix("chown root:root /etc/systemd/system/sshd.service")
    .register();

    check::Check::new(
        "SSH_046",
        "Ensure sshd service file permissions 644 are set",
        Severity::High,
        vec!["sshd", "systemd", "server"],
        || match systemd::get_service_file("sshd") {
            Some(path) => base::check_file_permission(&path, 0o644),
            None => (
                check::CheckState::Warning,
                Some("systemd sshd service file not found".to_string()),
            ),
        },
        vec![],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("If a non-root user as permissions on the sshd systemd unit file, they can edit it and have that wrapper run as root the next time sshd is started, would allow for full local privilege escalation.")
    .with_fix("chmod 644 /etc/systemd/system/sshd.service")
    .register();

    check::Check::new(
        "SSH_047",
        "Ensure \"/etc/ssh\" directory is owned by root",
        Severity::High,
        vec!["sshd", "server"],
        || base::check_dir_owner_id("/etc/ssh", 0, 0),
        vec![],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("/etc/ssh holds host private keys and sshd_config, non-root ownership lets that user steal host keys or rewrite sshd_config to weaken the security policy.")
    .with_fix("chown root:root /etc/ssh")
    .register();

    check::Check::new(
        "SSH_048",
        "Ensure \"/etc/ssh\" directory permissions is 755",
        Severity::High,
        vec!["sshd", "server"],
        || base::check_dir_permission("/etc/ssh", 0o755),
        vec![],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("/etc/ssh holds host private keys and sshd_config, open permissions lets users steal host keys or rewrite sshd_config to weaken the security policy.")
    .with_fix("chmod 755 /etc/ssh")
    .register();

    check::Check::new(
        "SSH_049",
        "Ensure \"/etc/ssh/sshd_config\" file is owned by root",
        Severity::High,
        vec!["sshd", "server"],
        || base::check_file_owner_id("/etc/ssh/sshd_config", 0, 0),
        vec![],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Could allow an attacker to reconfigure sshd.")
    .with_fix("chown root:root /etc/ssh/sshd_config")
    .register();

    check::Check::new(
        "SSH_050",
        "Ensure \"/etc/ssh/sshd_config\" file permissions is 644",
        Severity::High,
        vec!["sshd", "server"],
        || base::check_file_permission("/etc/ssh/sshd_config", 0o644),
        vec![],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Could allow an attacker to reconfigure sshd.")
    .with_fix("chmod 644 /etc/ssh/sshd_config")
    .register();

    check::Check::new(
        "SSH_051",
        "Ensure \"/etc/ssh/sshd_config.d/\" directory is owned by root",
        Severity::High,
        vec!["sshd", "server"],
        || base::check_dir_owner_id("/etc/ssh/sshd_config.d", 0, 0),
        vec![],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Could allow an attacker to reconfigure sshd.")
    .with_fix("chown root:root /etc/ssh/sshd_config.d")
    .register();

    check::Check::new(
        "SSH_052",
        "Ensure \"/etc/ssh/sshd_config.d/\" files are owned by root",
        Severity::High,
        vec!["sshd", "server"],
        || base::check_dir_files_owner_id("/etc/ssh/sshd_config.d/", 0, 0),
        vec![],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Could allow an attacker to reconfigure sshd.")
    .with_fix("chown -R root:root /etc/ssh/sshd_config.d/*")
    .register();

    check::Check::new(
        "SSH_053",
        "Ensure \"/etc/ssh/sshd_config.d/\" files permissions are 644",
        Severity::High,
        vec!["sshd", "server"],
        || base::check_dir_files_permission("/etc/ssh/sshd_config.d/", 0o644),
        vec![],
    )
    .skip_when(sshd::skip_no_sshd)
    .with_description("Could allow an attacker to reconfigure sshd.")
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
