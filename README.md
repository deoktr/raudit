# rAudit

rAudit is a security audit tool to help you create your own security audit checks.

Goals:

- Fast audit
- Make it easy to extend and create your own checks
- Output to JSON

What it is NOT:

- A configuration tool, no change is ever applied, just checks
- A vulnerability checker, no attempts to find vulnerable versions of applications are made

What is supported:

- Mounts including options
- Kenel params
- Kernel compilation params
- Sysctl params
- Docker/Podman containers
- Login.defs configuration
- Modprobe including blacklisted and disabled modules
- PAM rules
- OpenSSH server configuration
- Sudo configuration
- Users and groups
- Uptime
- Systemd configuration
- Processes
- Audit rules and configuration
- Grub configuration
- GDM configuration

Support planned:

- AppArmor
- SELinux
- ip and nftables
- systemd units
- nginx
- Apache
- Redis
- MySQL
- Squid
- Traefik
- Caddy
- PostgreSQL
- ProFTPD
- firejail

## Usage

Build:

```bash
cargo build --release
```

Run:

```bash
./target/release/raudit
```

## Develop

Test:

```bash
cargo test
```

## Alternatives

- [lynis](https://github.com/CISOfy/lynis)
- [kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker)

## Benchmark

With: `hyperfine -i ./target/release/raudit`:

```
Benchmark 1: ./target/release/raudit
  Time (mean ± σ):      70.0 ms ±   0.7 ms    [User: 7.8 ms, System: 62.2 ms]
  Range (min … max):    68.9 ms …  71.7 ms    41 runs
```

## TODO

- Give much more detailed logs of the error
- Add a "criticity", "hardening level" value linked to a check
- Add tags to checks and the ability to filter them
- Add JSON output format
- Generate linux audit logs
- Add AppArmor profile
- Create custom parsers for complex configurations (sudo, nginx, etc.)
- Give the user's the ability to specify config paths, with globing
- Get configuration from file
- Check permissions on startup (root or not) and warn user if needed
- Add flag to only print failed checks
- Add firejail rules
- Add firejail profile for raudit
- Ensure localhost is resolved on `127.0.0.1` in `/etc/hosts`
- Run `systemd-analyze security ...` on all systemd services and raise errors based on results
- Ensure DNS supports DNSSEC and is secured with DoT DoH or DNSCRYPT
- Ensure NTP is configured with NTS
- Ensure logrotate is used
- Ensure rsyslog is used
- Ensure secure boot and TPM are setup
- Ensure LSM is configured at boot with either AppArmor or SELiinux
- Ensure AppArmor profiles are used for some processes
- Ensure firejail is used for some processes
- Ensure `/tmp` is managed by systemd `tmp.mount` unit, and is cleaned on shutdown
- Ensure systemd services are hardened (with sandboxing options) `systemctl cat`
- Ensure cron is disabled if not needed
- Use [OPA](https://www.openpolicyagent.org/) to define rules?

## License

rAudit is licensed under [GPLv3](./LICENSE).
