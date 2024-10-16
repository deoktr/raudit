# rAudit

rAudit is a security audit tool to help you create your own security audit checks.

Goals:

- Very fast audit
- Make it easy to extend and create your own checks
- No package dependancies, just Rust std libs
- Output to JSON

Why Rust and not Bash:

- Better parsing
- Easier output formating (like JSON, or colored and formatted text)
- Better performance
- No dependancies, just a single executable to run

What it is NOT:

- A configuration tool, no change is ever applied, just checks
- A vulnerability checker, no attempts to find vulnerable versions of applications are made

What is supported:

- Mounts including options
- Audit rules and configuration
- Kenel params
- Kernel compilation params
- Sysctl params
- Login.defs configuration
- Modprobe including blacklisted and disabled modules
- PAM rules
- OpenSSH configuration
- Sudo configuration
- Users and groups
- Uptime
- Systemd
- Process
- Audit(d) rules and configuration
- Grub
- GDM

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

- Config file to skip checks
- Add a "criticity", "hardening level" value linked to a check
- Add tags to checks and the ability to filter them

## License

rAudit is licensed under [GPLv3](./LICENSE).
