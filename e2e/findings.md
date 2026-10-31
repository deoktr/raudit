# Findings from the end-to-end tests

Bugs, false positives/negatives and platform limitations found while building
and running the e2e tests (QEMU VMs and the per-app containers under
`e2e/container/`). Every finding lists the affected checks, how it was
observed (baseline file or reproduction) and where the behavior comes from in
the code.

**All raudit-side findings below have been fixed**; each entry ends with a
`Fixed:` note describing the change and how it is now verified. Findings that
are platform limitations (not raudit bugs) are marked as such. The baselines
in `e2e/container/<app>/<distro>/expected/` and `e2e/expected/` were
regenerated after the fixes, so the "evidence" quoted from baselines refers to
the state at discovery time (visible in the git history); the current baselines
verify the fixed behavior.

The containers are built on two distros (Alpine and Ubuntu, see
[e2e/README.md](README.md)): most findings reproduce on both, the ones that
depend on a package build or version are marked with the distro that shows
them. What the Ubuntu images surfaced on top of this list — the Debian-only
checks, and the version gaps of noble's packages — is collected in
[findings_ubuntu.md](findings_ubuntu.md), numbered `U1`..`U7`; those are still
open.

In the JSON baselines, `Pass` is recorded as status `Resolved`, `Fail` as
`New` and `Warning` as `Unknown`.

## Summary

| # | Area | Checks | Type | Status |
| - | ---- | ------ | ---- | ------ |
| [1](#1-openssh-options-that-alpine-does-not-support) | OpenSSH on Alpine | SSH_016..SSH_020, SSH_036, SSH_044 | distro gap | fixed (warning) |
| [2](#2-pam-checks-exact-control-flags-vs-distro-conventions) | PAM control flags | PAM_001, PAM_002 | false fail | fixed |
| [3](#3-pam_024-requires-a-single-faillock-rule) | PAM faillock uniqueness | PAM_024 | false fail | fixed |
| [4](#4-sudo-rs-systemd-and-auditd-gaps) | sudo-rs / systemd / auditd | SUD_002, SUD_011, SUD_900, CRN_001, CRN_002, SSH_045, SSH_046 | platform gaps | partially fixed (skips) |
| [5](#5-shl_001-hardcodes-one-file-name-and-one-pattern) | shell timeout | SHL_001 | false fail | fixed |
| [6](#6-cron-periodic-scripts-must-be-644-but-run-parts-needs-them-executable) | cron script modes | CRN_009/013/017/021/025 | false positive | fixed |
| [7](#7-missing-cron-directories-are-not-a-problem) | cron.yearly & co | CRN_003..CRN_026 | warning noise | fixed |
| [8](#8-usr_005-flags-stock-shutdown-and-halt-accounts) | system account shells | USR_005 | false positive | fixed |
| [9](#9-yescrypt-is-unreachable-with-musl-tooling) | yescrypt on musl | USR_006 | platform gap | documented (not raudit) |
| [10](#10-grp_001-requires-an-empty-gshadow) | gshadow content | GRP_001 | false fail | fixed |
| [11](#11-usr_017-demands-inactivity0-from-every-account) | shadow inactivity | USR_017 | false fail | fixed |
| [12](#12-pam-include-parsing-is-broken) | PAM `@include` parser | PAM_015, PAM_024, PAM_030 | bug + crash risk | fixed |
| [13](#13-grp_002-flags-locked-group-passwords) | group passwords | GRP_002 | false positive | fixed |
| [14](#14-usr_010-declares-the-wrong-dependency) | check dependencies | USR_010 | bug | fixed |
| [15](#15-usr_100usr_107-are-mistagged-group) | tags | USR_100..USR_107 | bug | fixed |
| [16](#16-sudo-defaults-matching-is-exact-text) | sudoers Defaults | SUD_001..SUD_014 | false negatives | fixed |
| [17](#17-sud_202sud_203-audit-files-sudo-itself-ignores) | sudoers.d file set | SUD_202, SUD_203 | false positive | fixed |
| [18](#18-exact-permission-matches-flag-stricter-modes) | file mode checks | SUD_200, SUD_202, SUD_205, CRN_* | false positive | fixed |
| [19](#19-sud_016-describes-a-rule-tag-that-classic-sudo-rejects) | sudoers syntax | SUD_016 | text inaccuracy | fixed |
| [20](#20-usr_007-checks-expiration-not-password-lock) | locked accounts | USR_007 | title/behavior mismatch | fixed |
| [21](#21-nginx-checks-are-shallow-text-matches) | nginx directives | NGX_001..NGX_006 | false passes | fixed |
| [22](#22-failed-checks-without-a-message) | messages | SSH_*, USR_018 | UX | fixed |
| [23](#23-clamav-coverage) | clamav | CAV_001 | coverage note | open |
| [24](#24-test-infrastructure-notes) | e2e harness | - | infra notes | handled |

## Distro and platform gaps

These behave like the OpenSSH example: the configuration is as valid and
hardened as the platform allows, yet the check can never reach `Pass`.

### 1. OpenSSH options that Alpine does not support

- Checks: `SSH_016`..`SSH_020` (Kerberos/GSSAPI), `SSH_044` (`UsePAM`),
  `SSH_036` (`PrintLastLog`), `SSH_045`/`SSH_046` (systemd unit files).
- The Alpine `openssh-server` package (`10.0_p1-r10` at the time of writing)
  is built without Kerberos/GSSAPI/PAM support and musl has no wtmp/lastlog,
  so `sshd -T` never reports `kerberos*`, `gssapi*`, `usepam` or
  `printlastlog`. `check_sshd_config` failed with no message when a key was
  absent, so no possible configuration could make these checks pass,
  including `SSH_044` (severity Critical, CIS/STIG).
- Evidence at discovery: `e2e/container/openssh/alpine/expected/hardened.json`
  recorded `SSH_016`..`SSH_020`, `SSH_036`, `SSH_044` as `New` with no
  message. Note the reported keys change with the package revision, an older
  locally cached image of the same pinned `alpine:3.22` had an openssh build
  that did report them (see finding 24).
- **Fixed:** `src/modules/sshd.rs` keeps a `BUILD_OPTIONAL_KEYS` list
  (kerberos*, gssapi*, usepam, printlastlog); when such a key is absent from
  `sshd -T` the check now returns a Warning explaining the option is
  unsupported by the build, like the sudo-rs skips. Any other absent key
  fails with an explicit `not reported by sshd -T` message (finding 22).
   `SSH_045`/`SSH_046` are skipped on non-systemd hosts (finding 4). Verified
   by the openssh container baselines: hardened has 0 failures, the seven
   options are `Unknown` with the new message. The Ubuntu openssh container
   covers the other side of the same checks: its build reports all seven, the
   hardened profile sets them to the expected values and passes, the weak
   profile sets them insecurely and fails
   (`e2e/container/openssh/ubuntu/expected/*.json`).

### 2. PAM checks' exact control flags vs distro conventions

- Checks: `PAM_001` (`account required pam_unix` in `passwd`), `PAM_002`
  (`password required pam_pwquality` in `passwd`).
- `get_pam_rule` required the control token to be exactly `required`. The
  stock Debian/Ubuntu layout — which the QEMU hardened profile deliberately
  keeps — uses
  `account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so` and
  `password requisite pam_pwquality.so` (also what CIS recommends there). A
  correctly hardened Debian/Ubuntu could therefore never pass these two
  checks.
- Evidence at discovery: `e2e/expected/hardened.json` (hardened Ubuntu VM)
  had `PAM_001`/`PAM_002` as `New 'rule not found'`.
- **Fixed:** `control_matches` in `src/modules/pam.rs` accepts `requisite`
  and the bracketed forms (`[success=1 ...]`, `[default=die]`, ...) as
  enforcing equivalents of an expected `required`; `optional` expectations
  stay exact. Unit-tested (`test_control_matches`), and verified by the pam
  container hardened profile (stock Debian layout, all checks pass) and the
  regenerated QEMU hardened baseline. Note `PAM_001` needed one more step on
  Ubuntu: the stock `/etc/pam.d/passwd` only includes `common-password`, it
  has no account stack at all, the hardened setup (and the hardened
  container profile) add `@include common-account` to it.

### 3. PAM_024 requires a single faillock rule

- Check: `PAM_024` (`auth required pam_faillock` in `login`).
- `get_pam_rule` failed with "more than one rule found" when several rules
  matched. The common RHEL/Fedora hardening pattern writes both faillock
  records as `required`:

  ```text
  auth required pam_faillock.so preauth ...
  auth required pam_faillock.so authfail ...
  ```

  which is a valid, fully hardened stack, yet the check failed (verified at
  discovery by flipping the hardened pam container's `authfail` control to
  `required` → `New 'more than one rule found'`).
- **Fixed:** the checks are presence checks, at least one matching rule now
  passes (`src/modules/pam.rs`, `get_pam_rule`). Verified by the pam
  container hardened baseline (`PAM_024` passes with preauth `required` +
  authfail `[default=die]`, i.e. two matching rules under the new control
  equivalence).

### 4. sudo-rs, systemd and auditd gaps

- `SUD_002` (`requiretty`) and `SUD_011` (`logfile`) are skipped when
  sudo-rs is present (`src/rules/sudo.rs`) because sudo-rs does not
  implement them. On distros shipping sudo-rs the CIS controls simply cannot
  be configured, and the skip hides that gap from the report.
- `CRN_001`/`CRN_002` and `SSH_045`/`SSH_046` only know the systemd unit
  layout; on non-systemd systems (containers, Alpine/OpenRC, runit, ...) they
  permanently warned "systemd ... service file not found".
- `SUD_900` needs `auditctl`, which is absent (and auditd cannot run) in an
  unprivileged container, so it permanently warns there.
- **Fixed (partially):** the four systemd unit checks now carry
  `.skip_when(systemd::skip_no_systemd)` and disappear on non-systemd hosts
  (visible in the cron and openssh container baselines: 26 and 49 findings
  instead of 28 and 51). The sudo-rs skips already existed. `SUD_900` stays
  a warning without auditctl, consistent with the whole audit check family:
  "could not verify" is the honest result, silently skipping would hide a
  missing auditd on systems that should have one.

### 5. SHL_001 hardcodes one file name and one pattern

- Check: `SHL_001`, `src/modules/shell.rs`.
- The check only accepted `/etc/profile.d/timeout.sh` containing exactly:

  ```sh
  TMOUT=<n>
  readonly TMOUT
  export TMOUT
  ```

  A valid timeout enforced from any other file
  (`/etc/profile.d/shell-timeout.sh`, `/etc/bash.bashrc`, ...) failed. The
  QEMU hardened VM set `TMOUT` in `/etc/profile.d/shell-timeout.sh` and
  recorded `SHL_001` as `New 'file not found'` — a hardened system that
  could never pass.
- **Fixed:** the check now scans `/etc/profile` and every file in
  `/etc/profile.d/` for the pattern, the file name no longer matters. The
  strict `readonly` pattern is kept on purpose, it is what stops a user from
  unsetting `TMOUT`; the QEMU hardened setup was updated to write the
  recommended form (`e2e/qemu/hardened-setup.sh`), and the regenerated
  hardened baseline passes `SHL_001`. The shell container weak profile keeps
  exercising the "file present but pattern not matched" path.

### 6. cron periodic scripts must be 644 but run-parts needs them executable

- Checks: `CRN_009`, `CRN_013`, `CRN_017`, `CRN_021`, `CRN_025` required
  the mode of every file in `/etc/cron.{hourly,daily,weekly,monthly,yearly}`
  to be *exactly* `644`.
- Debian/Ubuntu ship those periodic scripts as `0755` (logrotate, man-db,
  apt-compat, ...) and `run-parts` — what actually executes them — skips
  non-executable files. So on a stock distro these checks failed, and
  "fixing" them to `644` silently disabled the periodic jobs. The QEMU
  hardened setup did exactly that (`find ... -type f -exec chmod 0644`) to
  make the checks pass. `0644` is the right target for `/etc/cron.d`
  *drop-in crontabs* (`CRN_005`, those must not be executable), but not for
  the periodic *script* directories.
- **Fixed:** the periodic-script checks now require "not group or world
  writable" (`base::check_dir_files_not_group_world_writable_ignore_missing`,
  same semantics as the home-directory check `USR_014`), which accepts the
  stock `0755` scripts while still catching the escalation vector. Titles
  and fixes updated. The QEMU hardened setup no longer strips the execute
  bit from the periodic scripts, only `/etc/cron.d` is chmod'ed. Verified by
  the regenerated QEMU and cron container baselines.

### 7. Missing cron directories are not a problem

- Checks: `CRN_003`..`CRN_026`.
- Debian/Ubuntu/Alpine create `cron.{d,hourly,daily,weekly,monthly}` but
  `/etc/cron.yearly` only exists on some releases (present on Ubuntu noble,
  absent on Alpine/dcron), and a distro or an admin may legitimately not
  have any of them. A missing directory warned `No such file or directory`
  forever: a plain `alpine:3.22` container with only `dcron` installed
  answered `raudit --tags cron` with 22 `Unknown` findings.
- **Fixed:** all cron directory and directory-files checks now use
  ignore-missing variants, a missing directory passes with the message
  `directory missing` (same philosophy as `CRN_027`/`CRN_028` for
  `/etc/crontab`). Nothing to protect, nothing to report.

### 8. USR_005 flags stock shutdown and halt accounts

- Check: `USR_005`, `src/modules/users.rs`.
- System-account shells were only accepted when they ended in `/nologin`,
  `/false` or `/sync`. Stock Alpine ships `shutdown:x:6:...:/sbin/shutdown`
  and `halt:x:7:...:/sbin/halt`; these are administrative, non-login shells
  (same spirit as the whitelisted `/bin/sync`) but were reported as
  failures, so a stock — or otherwise well hardened — Alpine failed.
- Evidence at discovery: the user weak baseline message was
  `'bin, shutdown, halt'`.
- **Fixed:** `/shutdown`, `/halt`, `/poweroff` and `/reboot` shells are
  whitelisted. The user container hardened profile now keeps the *stock*
  Alpine shells for those accounts and passes (regression guard); the weak
  profile only provokes `USR_005` via `bin`.

### 9. yescrypt is unreachable with musl tooling

- Check: `USR_006`. **Platform limitation, not a raudit bug — documented,
  no code change.**
- musl's `crypt(3)` has no yescrypt, and Alpine's `mkpasswd -m yescrypt`
  (whois package) *silently falls back to MD5*: verified on `alpine:3.22`,
  `mkpasswd -m yescrypt -S J9T.xq5H test123` returned a `$1$...` hash. An
  administrator following the `USR_006` fix on Alpine gets a weaker hash than
  requested with no warning, and the check can only be satisfied with hashes
  generated on another system (the hardened user container ships such a
  hash, see its `Containerfile` comment). Worth reporting upstream
  (Alpine/musl), raudit's check itself is correct.

### 10. GRP_001 requires an empty gshadow

- Check: `GRP_001`, `src/modules/group.rs`.
- Debian-family systems normally keep `/etc/gshadow` populated with locked
  (`!`/`*`) entries — no password hashes, nothing to crack — yet the check
  only accepted an empty or missing file. The QEMU hardened setup had to
  truncate gshadow (`: >/etc/gshadow`) to pass.
- **Fixed:** renamed to `no_usable_gshadow_passwords`, the check now passes
  when the file is missing or when every entry's password field is locked
  (`!`/`*`) or empty, and reports the groups holding a real hash. Title,
  description and fix updated ("Ensure `/etc/gshadow` has no usable group
  password"). The QEMU hardened setup no longer truncates gshadow; the
  insecure setup sets a real hash on the `games` gshadow entry so the fail
  path stays covered.

### 11. USR_017 demands inactivity=0 from every account

- Check: `USR_017`, `src/modules/users.rs`.
- Every `/etc/shadow` entry whose inactivity field was not exactly `0` was
  reported, including non-loginable system accounts (`*`/`!` passwords) for
  which password expiry is meaningless. On the hardened QEMU VM the check
  failed listing `root, daemon, bin, sys, sync, games, ...`, i.e. it failed
  on essentially every stock system.
- **Fixed:** scoped to human accounts (UID >= 1000, `nobody` excluded) via a
  join with `/etc/passwd` (`is_human_account`, unit-tested), and the check
  now depends on `init_passwd` too. The QEMU hardened setup sets
  `chage -I 0` for its human accounts and `INACTIVE=0` in
  `/etc/default/useradd` (USR_018), so the hardened baseline passes both.

## rAudit bugs

### 12. PAM `@include` parsing is broken

- Checks affected: every `PAM_*` check on any system using `@include`
  (Debian/Ubuntu stock layout), i.e. `PAM_015`, `PAM_024`, `PAM_030` in the
  e2e runs.
- In `parse_pam_file` (`src/modules/pam.rs`), the `@include X` branch
  re-read the *current* file (`fs::read_to_string(path.clone())`) instead of
  the included file `X`, then parsed that content under `X`'s name.
  Consequences:
  - the parent file's own rules were parsed again for every `@include` line,
    and the included file's rules ended up parsed multiple times through the
    recursion, so `get_pam_rule` saw duplicates and returned
    `more than one rule found` for rules written exactly once;
  - rules were attributed to the wrong service;
  - include cycles (a file including itself, directly or not) recursed
    forever — the parser had no depth limit — a self-including service file
    crashed raudit with a stack overflow.
- Evidence at discovery: the QEMU hardened Ubuntu VM kept the stock
  `@include` layout and was properly hardened, yet
  `e2e/expected/hardened.json` recorded `PAM_015`, `PAM_024`, `PAM_030` as
  `New 'more than one rule found'`.
- **Fixed:** the include branch now reads `parent.join(<include>)` (absolute
  include paths work through `Path::join` semantics), a per-service `visited`
  set stops cycles and duplicate includes, and `MAX_INCLUDE_DEPTH` (16) caps
  the recursion. Verified by the pam container hardened profile, which is
  exactly the stock Debian `@include` layout: all five PAM checks pass, and
  by the regenerated QEMU hardened baseline.

### 13. GRP_002 flags locked group passwords

- Check: `GRP_002`, `src/modules/group.rs`.
- Any `/etc/group` password field that was not exactly `x` was reported as
  "has a password", including the locked values `!`, `*`, `!!` that
  `gpasswd -r` and the distro tooling produce. Locking a group password —
  the recommended hardening — made the check fail (verified at discovery:
  `wheel:!:10:` → `New 'wheel'`).
- **Fixed:** `x` (delegated to gshadow), empty (no password) and locked
  (`!`/`*` prefixes) fields pass; only a real hash is reported, mirroring
  what `yescrypt_hashes` does for shadow. The group weak profile keeps
  failing via the `admins` group hash.

### 14. USR_010 declares the wrong dependency

- Check: `USR_010`, `src/rules/user.rs`.
- The check reads `/etc/passwd` (`no_empty_passwd_password`) but declared
  `vec![users::init_shadow]`. Full runs only worked by accident because
  other user checks initialize `PASSWD_CONFIG` first; any selection that did
  not include them broke:

  ```console
  $ raudit --json --filters USR_010
  USR_010 Unknown 'internal error: passwd was never initialized, a dependency is missing'
  ```

- **Fixed:** the dependency is `users::init_passwd`. Verified: the same
  command now returns a normal result in the user container.

### 15. USR_100..USR_107 are mistagged `group`

- Checks: `USR_100`..`USR_105` (`/etc/shadow`, `/etc/shadow-`,
  `/etc/security/opasswd`) and `USR_106`/`USR_107` (`/etc/passwd`),
  `src/rules/user.rs`.
- All eight carried the `group` tag instead of `user`, so
  `raudit --tags user` audited the user database without a single file
  permission check on `/etc/passwd`/`/etc/shadow`, while `raudit --tags
  group` reported `USR_*` findings.
- **Fixed:** retagged `user` (they keep their `CIS` and role tags). The
  containers were restructured to match: the user container now sabotages
  passwd/shadow/shadow-/opasswd permissions in its weak profile (all eight
  fail) and passes them in hardened; the group container only handles
  group/gshadow/gshadow-.

### 16. sudo Defaults matching is exact text

- Checks: `SUD_001`..`SUD_014`, `check_sudo_defaults` over
  `get_sudoer_defaults` (`src/modules/sudo.rs`).
- A sudoers line was reduced to the exact string after `Defaults` and had to
  equal the expected value. Valid sudoers syntax that `visudo -c` accepted
  was missed, producing false negatives on hardened systems (verified at
  discovery, `visudo -c` reported `parsed OK` for all four forms while
  `SUD_001`, `SUD_003`, `SUD_004`, `SUD_005` failed):
  - trailing comments: `Defaults noexec # required by policy`;
  - spaces around `=`: `Defaults umask = 0027`;
  - comma lists on one line: `Defaults requiretty,ignore_dot`;
  - line continuations: `Defaults secure_path="\` + newline + `..."`.
- `parse_sudoer` also did not strip trailing comments, so a `NOPASSWD`
  mentioned in a comment was flagged by `SUD_015`.
- **Fixed:** `parse_sudoer` joins line continuations and strips comments
  (quote-aware, a `#` inside `"..."` is not a comment);
  `parse_defaults_line` collapses whitespace, removes the spaces around `=`
  and splits comma lists. Scoped defaults (`Defaults>root ...`,
  `Defaults:%wheel ...`) keep their scope prefix and deliberately do not
  satisfy a global expectation, they do not apply to every invocation.
  Unit-tested (`test_strip_comment`, `test_parse_sudoer`,
  `test_parse_defaults_line`).

### 17. SUD_202/SUD_203 audit files sudo itself ignores

- Checks: `SUD_202`/`SUD_203` (`src/rules/sudo.rs`) vs the sudoers loader
  (`src/modules/sudo.rs`).
- The loader skipped — exactly like sudo — files in `/etc/sudoers.d` whose
  name contains a `.`, ends with `~`, or is `README`. The filesystem checks
  audited *every* file in the directory. Distros that ship
  `/etc/sudoers.d/README` at `0644` (RHEL/Fedora, older Debian/Ubuntu)
  could therefore never pass `SUD_202`, even though sudo never reads that
  file at runtime.
- Evidence at discovery: the sudo hardened profile kept a stock-style
  `README` at `0644` and its baseline recorded
  `SUD_202 New 'file /etc/sudoers.d/README permission: wanted 440 got 644'`.
- **Fixed:** `SUD_202`/`SUD_203` now use `sudo::check_sudoers_d_files_*`,
  which share the parser's `sudoers_d_files()` filter, and a missing
  `/etc/sudoers.d` passes. The sudo hardened container keeps the `README`
  (0644) and the `10-custom.conf` dot-file (holding a `NOPASSWD` rule that
  the parser must not see) as regression guards: its baseline is now all
  pass except the `SUD_900` auditctl warning.

### 18. Exact permission matches flag stricter modes

- Checks: `SUD_200`/`SUD_202` (`440` exactly), `SUD_205` (`750` exactly,
  while its own title said "750 or stricter"), the cron directory checks
  (`755` exactly) and the `/etc/cron.d` file check (`644` exactly).
- A *stricter* mode was reported as a failure: the QEMU insecure baseline
  recorded `SUD_202 New 'file /etc/sudoers.d/99-insecure permission: wanted
  440 got 400'` — `0400` is perfectly usable by sudo and more restrictive
  than `0440`. raudit already had "or stricter" variants used elsewhere
  (`CRN_028`, `ModeMatch::OrStricter` in `src/modules/base.rs`).
- **Fixed:** `SUD_200`/`SUD_202`/`SUD_205`, the cron directory permission
  checks and the `/etc/cron.d` file check now use or-stricter matching,
  titles updated where they promised it. A stricter mode cannot break the
  consumers (sudo and cron read these files as root).

### 19. SUD_016 describes a rule tag that classic sudo rejects

- Check: `SUD_016` (`src/rules/sudo.rs`).
- The description called `!authenticate` "the negated tag form" of
  `NOPASSWD` on a rule, but classic sudo only accepts it as a `Defaults`
  flag: writing `%wheel ALL=(ALL) !authenticate: ALL` fails `visudo -c` with
  `expected a fully-qualified path name` (verified while building the weak
  sudo profile).
- **Fixed:** the description now points at `Defaults !authenticate` (global
  or scoped like `Defaults:user !authenticate`). The check itself already
  matched any line containing `!authenticate`; the weak sudo profile uses
  the valid `Defaults !authenticate` form.

### 20. USR_007 checks expiration, not password lock

- Check: `USR_007`, `src/modules/users.rs`.
- Title and fix talked about *locked* accounts (`passwd -l`, the `!`
  password prefix), but the implementation only looked at the shadow
  *account expiration* field. An account locked with `passwd -l` and no
  expiration date passed, an expired but unlocked account failed.
- **Fixed:** behavior kept (expiration is the meaningful signal; flagging
  `!`-locked accounts would report every key-only human account and every
  parked system account), the check is renamed `no_expired_account`, retitled
  "Ensure no user account is expired, delete them", scoped to human accounts
  like `USR_017` (finding 11), and the description/fix text now match.

### 21. nginx checks are shallow text matches

- Checks: `NGX_001`..`NGX_006`, `src/modules/nginx.rs`.
- `NGX_001`: `find_directive_in_config` returned the *first* `server_tokens`
  found in the parse tree. A vhost that set `server_tokens on;` under an
  http-level `off` passed the check while leaking its version (verified at
  discovery).
- `NGX_002`/`NGX_003`/`NGX_005`: `check_header_present` passed if an
  `add_header <name>` existed *anywhere*, ignoring nginx's inheritance
  rules: a `location` (or `server`) that defines any `add_header` of its own
  silently drops all the http-level security headers. Verified at discovery
  in the hardened container: adding a location with its own `add_header`
  made the server answer with only that header (no `X-Frame-Options`, no
  `X-Content-Type-Options`, no HSTS) while all three checks stayed
  `Resolved`. The `always` flag was also not required, so headers could be
  missing on 4xx/5xx responses.
- `NGX_006`: `check_https_redirect` passed if any `return` directive
  anywhere contained both `301` and `https` — it did not verify the
  redirect lived in a port-80 server.
- **Fixed:**
  - `NGX_001` uses `check_all_directives`: every `server_tokens` instance
    must be `off`, offenders are listed in the message;
  - the header checks walk the block tree applying nginx's `add_header`
    inheritance (a block with its own `add_header` drops the inherited set)
    and require the header, with the `always` flag, to be effective in every
    `server` and `location` block, the message names the offending context;
  - `NGX_006` collects every `server` block listening on port 80 (including
    servers without `listen`, which default to 80) and requires an HTTPS
    `return 301/302/307/308` or `rewrite` in each; a configuration without
    any port-80 listener passes.
  - Unit tests added (`test_header_inheritance_dropped_by_own_add_header`,
    `test_header_requires_always`, `test_listen_is_http`,
    `test_https_redirect_anchored_to_port_80_servers`,
    `test_header_from_flattened_conf_d_include`) and the leaky-location
    scenario re-verified live: `NGX_002` now reports
    `header 'X-Frame-Options' not applied in 'location /'` while the server
    really serves the page without it.
  - The implementation also had to learn that `nginx -T` dumps the included
    files *flattened*: the http-level `add_header`/`server_tokens`/`server`
    of a `conf.d` drop-in appear at the root of the output, outside the
    `http {}` block. Root-level `add_header` directives (not valid nginx
    outside a dump) seed the inheritance walk, which is what makes the
    distro-style QEMU hardened config pass (`test_header_from_flattened_conf_d_include`).
- Remaining known limitation: the parser is line-based over `nginx -T`
  output, a block written on a single line (`location / { return 200 "ok"; }`)
  is mis-parsed. `nginx -T` echoes the files verbatim, so this only affects
  configs written in that style.

### 22. Failed checks without a message

- `check_sshd_config` (`src/modules/sshd.rs`) returned `Fail` with no
  message when the directive was absent from `sshd -T`, so the openssh
  baselines showed `New` findings with an empty message (`SSH_016`..`SSH_020`,
  `SSH_036`, `SSH_037` in weak, `SSH_044`) that did not distinguish
  "unsupported by this build" from "not configured". `USR_018`
  (`useradd_inactive`) also failed with no message, hiding the actual
  `INACTIVE` value.
- **Fixed:** absent sshd directives now report
  `` `<key>` not reported by `sshd -T` `` (or the unsupported-build variant,
  finding 1), and `USR_018` reports `INACTIVE=<value>` (or `INACTIVE=<unset>`),
  visible in the openssh weak and user weak baselines.

### 23. ClamAV coverage

- `CAV_001` is the only clamav check (and is tagged `useless`,
  `src/rules/clamav.rs`): it just probes `clamscan` in `PATH`. The daemon
  state, database freshness (`freshclam`), socket/scan directories and
  permissions are not audited, so the clamav container can only exercise
  installed/not-installed. **Open**: adding those checks is a feature, out of
  scope of this bug-fix pass.

## Test infrastructure

### 24. Test infrastructure notes

- **Pinning `alpine:3.22` does not pin package revisions.** `apk add` at
  build time floats within the 3.22 repository. A stale locally cached
  openssh image (same Containerfile) had an openssh build whose `sshd -T`
  reported `kerberos*`/`gssapi*`/`usepam`; the current build
  (`openssh-server 10.0_p1-r10`) reports none of them, flipping
  `SSH_016`..`SSH_020`/`SSH_044` between states with otherwise identical
  sources. Expect baseline drift when Alpine updates a package that feeds a
  check (`sshd -T`, `nginx -T`, defaults...), review and regenerate with
  `just e2e_container_update`. Truly pinning would require package versions
  (`apk add openssh-server=10.0_p1-r10`) or image digests. *Handled by
  documenting; finding 1 makes the drift show up as warnings with clear
  messages instead of silent failures.* The same applies to the Ubuntu
  contexts: `ubuntu:24.04` plus `apt-get install` floats inside noble
  (openssh `9.6p1-3ubuntu13.20` and nginx `1.24.0-2ubuntu7.19` at the time of
  writing), pinning would need `apt-get install pkg=version` or image digests.
- **Every app has one build context per distro.**
  `e2e/container/<app>/{alpine,ubuntu}/` each hold a `Containerfile`, an
  `entrypoint.sh`, the profile data and their own `expected/` baselines, and
  `container_test.py` selects them with `--distro` (default `all`). The
  contexts are self-contained on purpose: the profile files that are not distro
  specific (pam.d, sudoers, the cron jobs, `profile.d/timeout.sh`) are
  duplicated verbatim instead of shared, so a distro can always diverge where
  its conventions differ. *Handled by documenting; keep the copies in sync when
  a shared profile changes.*
- **`--tags cron` selects two apt checks on the Debian family.** `APT_103` and
  `APT_107` (ownership of `/etc/apt/sources.list.d/` and `/etc/apt/apt.conf.d/`)
  carry the `cron` tag and `.skip_when(os::skip_not_debian)`, so the Ubuntu cron
  container audits 28 findings where the Alpine one audits 26, and its
  entrypoint fixes (hardened) or sabotages (weak) the ownership of those two
  directories as well. *Handled: both are covered by the Ubuntu cron baselines;
  the tag itself is a bug, see
  [findings_ubuntu.md](findings_ubuntu.md#u1-apt_103-and-apt_107-are-tagged-cron).*
- **The Ubuntu weak clamav profile purges at runtime.** The profiles are
  selected by the entrypoint argument in one image, so "ClamAV not installed"
  is produced with `apt-get -y purge clamav clamav-daemon clamav-base` (dpkg
  only, no network needed), the mirror of `apk del clamav` on Alpine.
- **`e2e/container/openssh/alpine/entrypoint.sh` was committed non-executable**
  (mode `100644`): with the exec-form `ENTRYPOINT` a fresh checkout builds an
  image that dies with "permission denied". *Fixed: all `entrypoint.sh`
  files are `0755`.*
- **dcron cannot be PID 1.** `crond -f` calls `setpgid(0,0)` at startup,
  which fails with `EPERM` for the container PID 1 (session leader):
  `setpgid: Operation not permitted`. *Handled: the cron entrypoint runs
  crond as a child and `wait`s on it.*
- **clamd needs a database.** clamd refuses to start with an empty database
  directory and `freshclam` needs network access. *Handled: the hardened
  clamav profile seeds a minimal offline signature database (a one-line
  `.hdb` file, `md5:size:name` of a 1-byte file).* The Ubuntu image needs one
  more step: `/run/clamav` is created by tmpfiles.d on a real boot, the
  entrypoint creates it and hands it to the `clamav` user, and Debian's
  `clamd.conf` puts the socket at `/run/clamav/clamd.ctl` (Alpine uses
  `clamd.sock`).
- **Readiness probes need stdout.** The harness only considers a container
  ready when the probe returns 0 *and* prints something
  (`e2e/container_test.py`, `start_container`). *Handled: configuration-only
  apps use `sh -c 'test -e /run/app-ready && echo ready'`
  (`READY_FILE_CMD`).*
- **The pam container also runs `LDF_002`.** `LDF_002`
  (`YESCRYPT_COST_FACTOR`, `src/rules/login_defs.rs`) is intentionally
  tagged `pam`, so `--tags pam` includes this login.defs check; both pam
  profiles ship an `/etc/login.defs` to keep it deterministic.
- **Ubuntu has no init system in the container either.** The openssh
  entrypoint creates the `/run/sshd` privilege separation directory (tmpfiles.d
  would do it on a real boot) and creates the `sshusers` group of `AllowGroups`
  with `groupadd --system` instead of Alpine's `addgroup -S`; sshd then runs
  fine as PID 1 with `-D -e`.
- **Open: `utils::which` does not check the execute bit.** On the insecure
  QEMU VM the nginx checks run (`skip_no_nginx` found a `nginx` file in
  `PATH`) yet `Command::new("nginx")` fails with `No such file or
  directory`, so `NGX_001`..`NGX_006` sit at `Unknown` in
  `e2e/expected/insecure.json` (pre-existing behavior, stable across runs,
  root cause not identified). `which()` only tests `is_file()`; requiring
  the execute bit would align the skip predicates with what `Command` can
  actually spawn. Left unfixed for now: it would change the skip behavior
  of every `skip_no_*` predicate and needs its own investigation.
