# rAudit

rAudit is a security audit tool to help you create your own security audit checks.

Goals:

- Fast and reliable audits
- Easy to extend and create your own checks
- JSON output

What it is NOT:

- A configuration tool, no change is ever applied, just checks
- A vulnerability checker, no attempts to find vulnerable versions of applications are made

## Usage

Build:

```bash
cargo build --release
```

Will generate executable in `./target/release/raudit`.

Run checks:

```bash
raudit
```

Usage:

```
Audit Linux systems security configurations

Usage: raudit [OPTIONS]

Options:
      --tags [<TAGS>...]        Comma-separated list of tags to filter
      --filters [<FILTERS>...]  Comma-separated list of ID prefixes to filter
      --log-level <LOG_LEVEL>   Log level [default: warn] [possible values: error, warn, info, debug, trace]
      --no-parallelization      Disable multi-threading parallelization
      --no-print-checks         Disable print of individual checks
      --no-print-passed         Disable print of passed checks
      --no-stats                Disable print of stats
      --no-colors               Disable colored output
      --no-time                 Disable timer
      --json <JSON>             Generate JSON output [default: off] [possible values: short, pretty, off]
  -h, --help                    Print help
  -V, --version                 Print version
```

Generate JSON report:

```bash
raudit --json=pretty > report.json
```

Example JSON output:

```bash
raudit --json=pretty --filters USR_001,USR_002
```

```json
{
  "checks": [
    {
      "id": "USR_001",
      "title": "Ensure that root is the only user with UID 0",
      "tags": [
        "user",
        "passwd"
      ],
      "message": null,
      "state": "Passed"
    },
    {
      "id": "USR_002",
      "title": "Ensure no duplicate user names exist",
      "tags": [
        "user",
        "passwd"
      ],
      "message": null,
      "state": "Passed"
    }
  ],
  "stats": {
    "total": 2,
    "passed": 2,
    "failed": 0,
    "error": 0,
    "waiting": 0
  }
}
```

## Rules

Default rules exist, but you should customize them to suit your own needs.

Some modules help with specific configuration checks.

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
- Shell configuration

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
  Time (mean ± σ):      75.0 ms ±   2.8 ms    [User: 90.9 ms, System: 123.3 ms]
  Range (min … max):    71.3 ms …  80.7 ms    36 runs
```

## TODO

- Give much more detailed logs of the error
- Support tag negation with `!` this could be used if a setting changed based on a tag, for example `paranoid` could have stricter rules compared to `!paranoid` for the same config
- Add a "criticity", "hardening level" value linked to a check
- Generate linux audit logs
- Add AppArmor profile
- Create custom parsers for complex configurations (sudo, nginx, etc.)
- Give the user's the ability to specify config paths, with globing
- Get configuration from file
- Check permissions on startup (root or not) and warn user if needed
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
- Work on performance, convert to String to &str
- Add metadata to JSON report, like start/end time, elapsed, version, username, hostname etc.
- Add documentation, both user and dev
- Add option to only have `id`, `message` and `state` in JSON output of checks

## License

rAudit is licensed under [GPLv3](./LICENSE).
