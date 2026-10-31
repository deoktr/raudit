# Findings from the Ubuntu container tests

Bugs, false positives/negatives and platform limitations found while building
and running the Ubuntu images (`ubuntu:24.04`, noble, the release the QEMU VMs
run) under `e2e/container/<app>/ubuntu/`. They complement
[findings.md](findings.md), which collects what the QEMU VMs and the Alpine
containers found: that file numbers its findings `1`..`24`, this one numbers
them `U1`..`U7` and refers to the other file as "finding N".

**Every finding below is still open**, raudit's code was not changed by the
Ubuntu container work. The Ubuntu baselines in
`e2e/container/<app>/ubuntu/expected/` therefore record the current (buggy)
behavior: regenerate them with `just e2e_container_update` after a fix, the
entries say which baselines move.

Each one was reproduced inside a container built by the e2e harness, running
the same static musl binary it uploads
(`target/x86_64-unknown-linux-musl/release/raudit`):

```bash
just e2e_container_ubuntu                      # build every ubuntu image
docker run -d --name probe raudit-e2e-user-ubuntu hardened
docker cp target/x86_64-unknown-linux-musl/release/raudit probe:/usr/local/bin/raudit
docker exec probe raudit --json --filters USR_101
```

## Summary

| # | Area | Checks | Type | Debian-only |
| - | ---- | ------ | ---- | ----------- |
| [U1](#u1-apt_103-and-apt_107-are-tagged-cron) | apt check tags | APT_103, APT_107 | mistag / false negative | yes |
| [U2](#u2-grp_102-and-grp_104-titles-promise-rootroot-on-debian) | gshadow ownership titles | GRP_102, GRP_104 | title/behavior mismatch | yes |
| [U3](#u3-ssh_038-pins-a-kexalgorithms-list-that-only-recent-openssh-provides) | sshd KexAlgorithms | SSH_038 | version gap | no (noble shows it) |
| [U4](#u4-stricter-permissions-on-the-shadow-family-and-the-host-keys-are-failures) | file mode checks | USR_101, USR_103, USR_105, GRP_103, GRP_105, SSH_054, SSH_055 | false positive | no (the `0640` branch is) |
| [U5](#u5-ldf_009-allows-login_retries-up-to-10-while-its-title-says--3) | login.defs range | LDF_009 | false pass | no |
| [U6](#u6-logindefs-failure-messages-print-expected--actual) | login.defs messages | LDF_001, LDF_008, LDF_012, ... | UX | no |
| [U7](#u7-thirteen-checks-fail-without-a-message-in-a-container) | messages | AUD_001, HST_002/003/007, LIB_001, MNT_001..MNT_007, SCB_001 | UX | no |

## Debian/Ubuntu family only

These need `os::is_debian()` to be true, so the Alpine containers and their
baselines cannot show them at all.

### U1. APT_103 and APT_107 are tagged `cron`

- Checks: `APT_103` (`/etc/apt/sources.list.d/` files owned by root) and
  `APT_107` (`/etc/apt/apt.conf.d/` files owned by root),
  `src/rules/apt.rs:218` and `src/rules/apt.rs:274`.
- Both carry `vec!["cron", "server", "workstation"]` while their 15 siblings —
  including `APT_102`/`APT_106`, the *permission* checks of the very same two
  directories — carry `vec!["apt", ...]`. Both are also
  `.skip_when(os::skip_not_debian)`, so they only ever run on the Debian
  family, and only under the `cron` tag.
- Consequences, both reproduced in the weak cron container (its entrypoint
  hands the two directories to `nobody:nogroup`):

  ```console
  $ docker run -d --name probe raudit-e2e-cron-ubuntu weak
  $ docker exec probe ls -l /etc/apt/apt.conf.d/
  -rw-r--r-- 1 nobody nogroup  92 Mar 22  2024 01-vendor-ubuntu
  -rw-r--r-- 1 nobody nogroup 399 Mar 31  2024 01autoremove
  $ docker exec probe raudit --json --tags apt    # 17 findings, APT_103/107 absent
  $ docker exec probe raudit --json --tags cron   # APT_103 New, APT_107 New
  ```

  An apt audit misses two mis-owned configuration directories (false
  negative), and a cron audit reports apt configuration on Debian hosts but
  not on the others, so the number of `--tags cron` findings depends on the
  distro: 28 in `e2e/container/cron/ubuntu/expected/`, 26 in
  `e2e/container/cron/alpine/expected/`. The Ubuntu cron entrypoint has to
  fix and sabotage `/etc/apt/{sources.list.d,apt.conf.d}` along with the cron
  directories to keep its baselines meaningful.
- Same class as finding 15 (`USR_100`..`USR_107` were tagged `group`).
- Fix: retag both `apt` (add `cron` too if the intent was to keep them in a
  cron-driven periodic-updates selection), then regenerate the cron baselines
  of both distros and, if an apt container is added later, its baselines.

### U2. GRP_102 and GRP_104 titles promise `root:root` on Debian

- Checks: `GRP_102` (`/etc/gshadow` owner) and `GRP_104` (`/etc/gshadow-`
  owner), `src/rules/group.rs:107` and `src/rules/group.rs:151`.
- Both are titled "Ensure `/etc/gshadow[-]` file owner is `root:root` or file
  is missing", but their closure passes
  `utils::gid_from_name("shadow").unwrap_or(42)` as the expected gid when
  `os::is_debian()`, i.e. they require `root:shadow` on Ubuntu. Their own
  `.with_fix()` text is correct ("On Debian: `chown root:shadow`"), only the
  title — what the report, the JSON output and `--list` show — is wrong.
- Reproduction, in the Ubuntu group container:

  ```console
  $ docker run -d --name probe raudit-e2e-group-ubuntu hardened
  $ docker exec probe chown root:root /etc/gshadow   # the owner the title asks for
  $ docker exec probe raudit --json --filters GRP_102
  GRP_102 New 'wanted `0:42` got `0:0`'
  #  title: "Ensure `/etc/gshadow` file owner is `root:root` or file is missing"
  ```

  The hardened profile has to use `root:shadow`
  (`e2e/container/group/ubuntu/entrypoint.sh`) to pass. The Alpine baselines
  cannot show it, the check takes the `root:root` branch there.
- Same class as finding 20 (`USR_007` described a lock but checked an
  expiration).
- Fix: retitle to "…is `root:shadow` on Debian, `root:root` elsewhere, or file
  is missing" (or make the title generic like `USR_100`'s "owner is correct"),
  and check `GRP_103`/`GRP_105`, whose "permissions are set" titles are
  equally vague about the `0640`/`0600` split. Titles only, but
  `e2e/compare.py` compares titles, so all four group baselines have to be
  regenerated.

### U3. SSH_038 pins a KexAlgorithms list that only recent openssh provides

- Check: `SSH_038`, `src/rules/sshd.rs:549`. **Version gap, not fixable by
  configuration.**
- The check compares the `kexalgorithms` value of `sshd -T` against one exact
  list starting with `mlkem768x25519-sha256`, and the comment above it says
  "for OpenSSH 10+" (the previous exact list is kept commented out at
  `src/rules/sshd.rs:536`). That post-quantum hybrid — and the un-suffixed
  `sntrup761x25519-sha512` name next to it — only exist in recent openssh
  releases, Ubuntu 24.04 ships `OpenSSH_9.6p1`, so no configuration of a noble
  host can satisfy the check. Writing the expected value is rejected outright:

  ```console
  $ sshd -t -f /tmp/k.conf   # KexAlgorithms mlkem768x25519-sha256,curve25519-sha256
  Unsupported KEX algorithm "mlkem768x25519-sha256"
  /tmp/k.conf line 1: Bad SSH2 KexAlgorithms 'mlkem768x25519-sha256,curve25519-sha256'.
  ```

  and the 9.6 default list, reported verbatim as the failure message, has
  neither (`sntrup761x25519-sha512@openssh.com,curve25519-sha256,...` plus the
  `diffie-hellman-group1*` entries openssh 10 dropped).
- Evidence: `e2e/container/openssh/ubuntu/expected/hardened.json` records
  `SSH_038` as `New` while the 48 other checks of the hardened profile pass;
  the Alpine image (`openssh 10.0_p1`) passes it with the defaults
  (`e2e/container/openssh/alpine/expected/hardened.json`).
- Like finding 1 a correctly hardened host fails because of its package
  version, not its configuration, and unlike finding 1 there is no warning to
  fall back on: the key *is* reported, it just cannot hold the expected value.
- Fix: make the expectation version aware — the TODO right above the
  commented-out list ("make skip it depending based on version") asks for the
  same thing. Either accept the post-quantum hybrids the running openssh
  supports, or keep a per-version list and warn (like `BUILD_OPTIONAL_KEYS`
  does) when the running sshd is too old for the recommended one.

## Not Ubuntu-specific, surfaced by the Ubuntu runs

Reproducible on Alpine or on any distro, but the Debian defaults are what made
them visible: noble ships the values that trip them.

### U4. Stricter permissions on the shadow family and the host keys are failures

- Checks: `USR_101` (`/etc/shadow`), `USR_103` (`/etc/shadow-`), `USR_105`
  (`/etc/security/opasswd`), `GRP_103` (`/etc/gshadow`), `GRP_105`
  (`/etc/gshadow-`), `SSH_054` (private host keys), `SSH_055` (public host
  keys).
- All of them call `base::check_file_permission[_ignore_missing]`, i.e.
  `ModeMatch::Exact` (`src/modules/base.rs:326`), so a *stricter* mode is
  reported as a failure — the class finding 18 fixed for `SUD_200`/`SUD_202`/
  `SUD_205` and the cron directories, which now use the `_or_stricter`
  variants.
- On Ubuntu the natural hardening trips it, because the expected mode is the
  distro default `0640 root:shadow` and tightening it to `0600` is what CIS
  ("640 or more restrictive") and most hardening guides recommend:

  ```console
  $ docker run -d --name probe raudit-e2e-user-ubuntu hardened
  $ docker exec probe chmod 600 /etc/shadow          # was 640 root:shadow
  $ docker exec probe raudit --json --filters USR_101
  USR_101 New 'wanted `640` got `600`'
  ```

  The same with the other checks (all in the Ubuntu openssh/group containers):

  | change | result |
  | --- | --- |
  | `/etc/shadow` `0600`, `/etc/shadow-` `0600` | `USR_101`, `USR_103` fail |
  | `/etc/gshadow` `0600` or `0400` | `GRP_103` fails |
  | `/etc/gshadow-` `0600` | `GRP_105` fails |
  | `ssh_host_ed25519_key` `0400` | `SSH_054` fails, wanted `600` got `400` |
  | `ssh_host_ed25519_key.pub` `0600` | `SSH_055` fails, wanted `644` got `600` |

  The non-Debian branch has the same problem one step lower: `chmod 400
  /etc/shadow` in the Alpine user container fails `USR_101` with
  "wanted 600 got 400".
- Not affected on purpose: `USR_106` (`/etc/passwd`) and `GRP_101`
  (`/etc/group`), whose descriptions explain that tighter than `0644` breaks
  name resolution for unprivileged tools. `SSH_050`/`SSH_053` already use the
  or-stricter variants (`src/rules/sshd.rs:717`, `:756`) and pass with `0600`.
- Other exact call sites worth reviewing at the same time:
  `/etc/audit/auditd.conf` and `/etc/audit/audit.rules` (`0640`,
  `src/rules/audit.rs`), `/etc/apt/sources.list`, `/etc/apt/apt.conf` and
  their `.d` directories (`0644`, `src/rules/apt.rs`), `/etc/hostname`,
  `/etc/hosts`, `/etc/resolv.conf` (`0644`) and `/etc/machine-id` (`0444`,
  `src/rules/system.rs`), and the systemd unit files of sshd, cron, anacron
  and docker (`0644`, `src/rules/sshd.rs:659`, `src/rules/cron.rs`,
  `src/rules/docker.rs`). None of them is reachable from a container (no
  systemd, no auditd), they would need the QEMU VMs or a dedicated probe.
- Fix: switch the seven checks above to
  `base::check_file_permission_or_stricter[_ignore_missing]`, retitle them
  "…or stricter", and regenerate the baselines that record a stricter mode
  (none today: the profiles use the distro defaults, so only the message texts
  of the weak profiles could move).

### U5. LDF_009 allows LOGIN_RETRIES up to 10 while its title says <= 3

- Check: `LDF_009`, `src/rules/login_defs.rs:197`.
- Title: "Ensure that login.defs `LOGIN_RETRIES` <= 3", fix text: "Set
  `LOGIN_RETRIES 3` or lower", but the closure hardcodes `const VAL: i32 = 10`
  and passes anything `<= 10` (`src/rules/login_defs.rs:202`).
- A stock Ubuntu 24.04 sits exactly in the gap and is reported compliant with
  a control it does not meet:

  ```console
  $ docker run -d --name probe docker.io/ubuntu:24.04 sleep 600
  $ docker exec probe grep LOGIN_RETRIES /etc/login.defs
  LOGIN_RETRIES		5
  $ docker exec probe raudit --json --tags login_defs
  LDF_009 Resolved '5'      # "Ensure that login.defs `LOGIN_RETRIES` <= 3"
  LDF_004 New '0 < 1'       # the neighbouring checks do report the real values
  ```

- False negative, worse than a wrong message: the report says the control is
  satisfied. The `login_defs` tag is not exercised by any container today (the
  pam containers only run `LDF_002`, which is tagged `pam`), which is why
  neither the Alpine nor the QEMU baselines caught it.
- Fix: `const VAL: i32 = 3` (the title and the fix text agree on 3, and the
  missing-key branch of the same check already says "default is 5" is too
  much). Consider a `login_defs` container, or add the `pam` tag to the checks
  the pam profiles can decide, so the family is covered by e2e.

### U6. login.defs failure messages print `<expected> != <actual>`

- Checks: every `LDF_*` built on `login_defs::check_login_defs`
  (`src/modules/login_defs.rs:71`): `format!("{} != {}", value, conf_value)`
  where `value` is the *expected* one.
- The message therefore reads as if the found value came first, the opposite
  of the truth, and unlike every other family it does not say which is which
  (`base.rs` prints an explicit "wanted X got Y" pair, sshd prints the
  offending value or "not reported by `sshd -T`"):

  ```console
  $ docker exec probe raudit --json --tags login_defs    # stock ubuntu:24.04
  LDF_001 New 'YESCRYPT != SHA512'   # login.defs has ENCRYPT_METHOD SHA512
  LDF_008 New '077 != 022'           # login.defs has UMASK 022
  LDF_012 New 'yes != no'            # login.defs has LOG_OK_LOGINS no
  ```

  `077 != 022` reads as "raudit found 077 and wants 022"; the host actually
  has `022` and raudit wants `077`.
- Reproduced on a stock Ubuntu because that is where a fresh install differs
  from the hardened expectations on several keys at once; the code path is
  distro independent.
- Same class as finding 22 (failed checks without a usable message).
- Fix: build the same "wanted/got" pair the other families use:

  ```rust
  Some(format!("wanted `{}` got `{}`", value, conf_value))
  ```

  `LDF_009`'s and `LDF_002`'s range messages (`5 > 3`, `3 not in [5..11]`)
  already read correctly and can stay.

### U7. Thirteen checks fail without a message in a container

- A full run (`raudit --json`, no tag filter) in any e2e container reports
  these `New` findings with `"message": null`:

  | check | title |
  | --- | --- |
  | `AUD_001` | Ensure `auditd` is running |
  | `HST_002`, `HST_003`, `HST_007` | hosts file entries (`localhost.localdomain`, `local`, `0.0.0.0`) |
  | `LIB_001` | Ensure `scudo` hardened malloc is used system wide |
  | `MNT_001`..`MNT_007` | Ensure mount point `/boot`, `/tmp`, `/home`, `/var`, `/var/log`, `/var/log/audit`, `/var/tmp` exist |
  | `SCB_001` | Ensure Secure Boot is enabled |

  ```console
  $ docker exec probe raudit --json          # raudit-e2e-user-ubuntu, 1585 findings
  $ # 13 findings with status New and no message
  $ docker exec probe-alpine raudit --json   # raudit-e2e-user-alpine: same 13
  ```

- Not Ubuntu-specific: the Alpine user container reports the identical 13
  uids. Finding 22 fixed this for the sshd directives and `USR_018`, these
  families were not covered.
- Two distinct problems, both worth fixing:
  - a `Fail` without a message leaves the operator nothing to act on (which
    hosts entry is missing, which mount point, what the malloc setting is);
  - several of them can never pass in a container at all (`SCB_001` needs
    EFI/firmware access, `MNT_001` needs a `/boot`, `AUD_001` needs auditd,
    which cannot run unprivileged, see finding 4). They should warn or skip
    like the systemd unit checks of finding 4 do, instead of failing: a
    container report full of unfixable `Fail`s hides the real ones.
