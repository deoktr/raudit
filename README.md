# rAudit

rAudit is a security audit tool to help you create your own security audit
checks.

Goals:

- Fast and reliable audits.
- Easy to extend and create your own checks.
- JSON output.
- Easy to maintain.

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

Generate JSON report:

```bash
raudit --json=pretty > report.json
```

Note that you can also use env vars to control CLI flags:

```bash
JSON=pretty raudit > report.json
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
      "message": null,
      "state": "Passed"
    },
    {
      "id": "USR_002",
      "title": "Ensure no duplicate user names exist",
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
  },
  "version": "0.21.0"
}
```

Usage:

```
Audit Linux systems security configurations

Usage: raudit [OPTIONS]

Options:
      --tags [<TAGS>...]
          Comma-separated list of tags to include [env: TAGS=]
      --tags-exclude [<TAGS_EXCLUDE>...]
          Comma-separated list of tags to exclude [env: TAGS_EXCLUDE=]
      --filters [<FILTERS>...]
          Comma-separated list of ID prefixes to include [env: FILTERS=]
      --filters-exclude [<FILTERS_EXCLUDE>...]
          Comma-separated list of ID prefixes to exclude [env: FILTERS_EXCLUDE=]
      --log-level <LOG_LEVEL>
          Log level [env: LOG_LEVEL=] [default: info] [possible values: error, warn, info, debug, trace]
      --no-parallelization
          Disable multi-threading parallelization [env: NO_PARALLELIZATION=]
      --no-print-checks
          Disable print of individual checks [env: NO_PRINT_CHECKS=]
      --no-print-passed
          Disable print of passed checks [env: NO_PRINT_PASSED=]
      --no-stats
          Disable print of stats [env: NO_STATS=]
      --no-colors
          Disable colored output [env: NO_COLORS=]
      --no-time
          Disable timer [env: NO_TIME=]
      --json <JSON>
          Generate JSON output [env: JSON=] [default: off] [possible values: short, pretty, off]
  -h, --help
          Print help
  -V, --version
          Print version
```

> [!NOTE]
> You can get the list of tags and filters, by using their corresponding flags
> without any value.

## Rules

Default rules are based on various sources including CIS, STIG, Mozilla,
ArchLinux wiki. You should customize them to suit your own needs.

Some modules help with specific configuration checks.

What is supported:

- Mounts including options.
- Kenel params.
- Kernel compilation params.
- Sysctl params.
- Docker and Podman.
- Login.defs configuration.
- Modprobe including blacklisted and disabled modules.
- PAM rules.
- OpenSSH server configuration.
- Sudo configuration.
- Users and groups.
- Uptime.
- Systemd configuration.
- Processes.
- Audit rules and configuration.
- Grub configuration.
- GDM configuration.
- Shell configuration.
- APT package manager configuration.
- Hosts configuration.
- AppArmor.

Support planned:

- SELinux.
- IP and nftables.
- Systemd units.
- Nginx.
- Apache.
- Redis.
- MySQL.
- Squid.
- PostgreSQL.
- ProFTPD.
- Firejail.

## Build

Build inside a container:

```bash
podman build -t raudit-build .
podman run --rm --network none -v ./target:/src/target raudit-build
```

This will generate in `./target/x86_64-unknown-linux-gnu/release/raudit`.

## Develop

Test:

```bash
cargo test
```

Build updated version inside the container:

```bash
podman run --rm --network none -v ./:/src raudit-build
```

## Security

[cargo-audit](https://github.com/RustSec/rustsec/tree/main/cargo-audit) is used
to audit dependencies for crates with security vulnerabilities, the check is
made in Github CI.

You can also manually run the audit:

```bash
cargo install cargo-audit --locked
cargo audit
```

## Benchmark

With: `hyperfine -i ./target/release/raudit`:

```
Benchmark 1: ./target/release/raudit
  Time (mean ± σ):     116.5 ms ±   5.3 ms    [User: 89.7 ms, System: 127.8 ms]
  Range (min … max):   110.6 ms … 132.7 ms    24 runs
```

## Alternatives

- [lynis](https://github.com/CISOfy/lynis)
- [kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker)
- [konstruktoid/hardening](https://github.com/konstruktoid/hardening)

## TODO

- Give much more detailed logs of the error
- Add a "criticity", "hardening level" value linked to a check
- Create custom parsers for complex configurations (sudo, nginx, etc.)
- Give the user's the ability to specify config paths, with globing
- Get raudit configuration from file
- Check permissions on startup (root or not) and warn user if needed
- Use [OPA](https://www.openpolicyagent.org/) to define rules?
- Work on performance, convert to String to &str
- Add metadata to JSON report, like start/end time, elapsed, version, username,
  hostname etc.
- Add documentation, both user and dev
- Add option to only have `id`, `message` and `state` in JSON output of checks
  maybe with a `--format` cli flag
- Add check timeout, if they take too long just stop them, maybe even with
  ctrl+c?
- Build in CI on release
- Add configurations for whitelist on some rules, for example whitelist trusted
  users in a docker group, instead of failling the check that would force admins
  to create config
- Add check to avoid check name collision
- Use macro `run!()` to log commands
- Add way more details to checks, an explaination of why it's a problem, and
  details on how to fix it, that way on failed checks the user would have
  effective info on what to do

Rules:

- Run `systemd-analyze security ...` on all systemd services and raise errors
  based on results
- Ensure DNS supports DNSSEC and is secured with DoT DoH or DNSCRYPT
- Ensure NTP is configured by running `timedatectl`
- Ensure NTP is configured with NTS
- Ensure logrotate is used
- Ensure rsyslog is used
- Ensure secure boot and TPM are setup
- Ensure LSM is configured at boot with either AppArmor or SELinux
- Ensure AppArmor profiles are used for some processes
- Ensure firejail is used for some processes
- Ensure `/tmp` is managed by systemd `tmp.mount` unit, and is cleaned on shutdown
- Ensure systemd services are hardened (with sandboxing options) `systemctl cat`
- Ensure cron is disabled if not needed

## License

rAudit is licensed under [GPLv3](./LICENSE).
