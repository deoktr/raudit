# rAudit

rAudit is a Linux security audit tool to help you create your own security audit
checks.

Goals:

- Fast and reliable audits.
- Easy to extend and create your own checks.
- Easy to maintain.
- Work for both servers and workstations.
- Human readable or
  [OCSF Compliance Finding](https://schema.ocsf.io/1.7.0/classes/compliance_finding)
  JSON output format.

## Install

Install for pre-compiled Github release:

```bash
# download and verify
curl -fsSL -O https://github.com/deoktr/raudit/releases/latest/download/raudit-x86_64-unknown-linux-gnu.tar.gz
curl -fsSL -O https://github.com/deoktr/raudit/releases/latest/download/raudit-x86_64-unknown-linux-gnu.sha256
sha256sum -c raudit-x86_64-unknown-linux-gnu.sha256

# install
tar -xzf raudit-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 raudit /usr/local/bin/raudit

# verify install
raudit --version

# clean
rm raudit raudit-x86_64-unknown-linux-gnu.sha256 raudit-x86_64-unknown-linux-gnu.tar.gz
```

## Usage

By default, all checks are running, you can reduce the number by filtering for
your specific needs, and for cleaner outputs do not print checks that passed:

Workstation:

```bash
raudit --tags workstation --tags-exclude paranoid,useless --no-print-passed
```

Server:

```bash
raudit --tags server --tags-exclude paranoid,useless --no-print-passed
```

> [!NOTE]
> Some checks requires root permissions to run.

Generate JSON report following
[OCSF Compliance Finding (class 2003, schema 1.7.0)](https://schema.ocsf.io/1.7.0/classes/compliance_finding):

```bash
raudit --json > report.json
```

> [!NOTE]
> You can also use env vars to control CLI flags:
>
> ```bash
> JSON=true raudit > report.json
> ```

<details>

<summary>Example JSON output:</summary>

```bash
raudit --json --filters USR_001
```

```json
{
  "findings": [
    {
      "activity_id": 1,
      "activity_name": "Create",
      "category_uid": 2,
      "category_name": "Findings",
      "class_uid": 2003,
      "class_name": "Compliance Finding",
      "type_uid": 200301,
      "finding_info": {
        "uid": "USR_001",
        "title": "Ensure that root is the only user with UID 0",
        "desc": "Multiple accounts with UID 0 have unrestricted root-level access, making it impossible to trace privileged actions to a specific user."
      },
      "compliance": {
        "standards": [
          "rAudit"
        ],
        "status_id": 1,
        "status": "Pass"
      },
      "metadata": {
        "version": "1.7.0",
        "product": {
          "name": "raudit",
          "version": "0.30.0"
        }
      },
      "severity_id": 5,
      "severity": "Critical",
      "status_id": 4,
      "status": "Resolved",
      "time": 1773777067196
    }
  ],
  "stats": {
    "total": 1,
    "pass": 1,
    "fail": 0,
    "warning": 0,
    "unknown": 0,
    "fail_critical": 0,
    "fail_high": 0,
    "fail_medium": 0,
    "fail_low": 0,
    "fail_informational": 0
  },
  "metadata": {
    "version": "1.7.0",
    "product": {
      "name": "raudit",
      "version": "0.30.0"
    }
  }
}
```

</details>

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
      --no-print-description
          Disable print of check description [env: NO_PRINT_DESCRIPTION=]
      --no-print-fix
          Disable print of check fix if it failed [env: NO_PRINT_FIX=]
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

Default builtin rules are based on various sources including CIS, STIG, Mozilla,
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
- OpenSSH server service and configuration.
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
- Bin.
- Cron service and configuration.

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

## Build Locally

Build from source with `cargo`:

```bash
cargo build --release
```

Will generate executable in `./target/release/raudit`.

## Develop

Test:

```bash
cargo test
```

Run locally:

```bash
cargo run -- --help
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

## Sources

- [Linux self-protection.rst](https://github.com/torvalds/linux/blob/master/Documentation/security/self-protection.rst)
- [Tails kernel_hardening](https://tails.net/contribute/design/kernel_hardening/)
- [Kicksecure/security-misc](https://github.com/Kicksecure/security-misc)

## Alternatives

- [lynis](https://github.com/CISOfy/lynis)
- [kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker)
- [konstruktoid/hardening](https://github.com/konstruktoid/hardening)

## TODO

- Give much more detailed logs of the error
- Create custom parsers for complex configurations (sudo, nginx, etc.)
- Give the user's the ability to specify config paths, with globing
- Check permissions on startup (root or not) and warn user if needed
- Use [OPA](https://www.openpolicyagent.org/) to define rules?
- Work on performance, convert to String to &str
- Add metadata to JSON report, like start/end time, elapsed, version, username,
  hostname etc.
- Add documentation, both user and dev
- Add check timeout, if they take too long just stop them, maybe even with
  ctrl+c?
- Add configurations for whitelist on some rules, for example whitelist trusted
  users in a docker group, instead of failling the check that would force admins
  to create config
- Add check to avoid check name collision
- Use macro `run!()` to log commands
- Add way more details to checks, an explaination of why it's a problem, and
  details on how to fix it, that way on failed checks the user would have
  effective info on what to do
- Fix all TODO and FIXME in code
- Skip tests based on distro or installed application: sshd, podman, docker, apt

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
