# End-to-end tests

Two kinds of e2e tests, both compare raudit JSON output against baselines:

- **QEMU VM**: full-system audit of hardened and insecure Ubuntu VMs.
- **Container**: single-application audit inside a docker/podman container
  (OpenSSH, ClamAV, cron, groups, nginx, PAM, shell timeout, sudo and users),
  built once on Alpine and once on Ubuntu.

Bugs and limitations found by these tests are collected in
[findings.md](findings.md), the ones the Ubuntu container images surfaced in
[findings_ubuntu.md](findings_ubuntu.md) (still open).

## QEMU VM tests

```bash
just e2e_install_deps   # install QEMU and dependencies
just e2e_hardened       # test hardened VM and compare JSON to baseline
just e2e_insecure       # test insecure VM and compare JSON to baseline
just e2e_all            # test both VMs and compare JSON to baselines
just e2e_update         # test both VMs and save output as new baselines
```

Or directly:

```bash
python3 e2e/qemu_test.py hardened
python3 e2e/qemu_test.py insecure
python3 e2e/qemu_test.py all
python3 e2e/qemu_test.py all --distro ubuntu
python3 e2e/qemu_test.py all --update-baselines
```

Each distro has one directory under `e2e/qemu/<distro>/` (`ubuntu` for now,
noble), with its setup scripts (`hardened-setup.sh`, `insecure-setup.sh`), its
generated SSH keys (`keys/`) and its expected baselines (`expected/`).

### How it works

1. Downloads the distro cloud image (cached in `target/qemu-cache/`)
2. Creates copy-on-write disk images in `target/qemu-work/`
3. Generates cloud-init ISOs
4. Boots QEMU VMs with KVM acceleration (if available)
5. Waits for SSH
6. Applies hardening or insecure configuration via SSH
7. Uploads and runs raudit
8. Collects JSON output
9. Shuts down VMs
10. Compares JSON output against expected baselines in
    `e2e/qemu/<distro>/expected/`

### Requirements

- `qemu-system-x86` (QEMU emulator)
- `qemu-utils` (disk image tools)
- `cloud-image-utils` (cloud-init ISO creation)
- `genisoimage` (ISO creation)
- `sshpass` (non-interactive SSH password)
- KVM support (`/dev/kvm`) recommended for performance

### Baselines

Expected JSON outputs are stored in `e2e/qemu/<distro>/expected/`. Each profile
has a baseline file (`hardened.json`, `insecure.json`). Tests fail if the output
differs from the baseline.

Timestamps (`time` fields) are stripped and the raudit version
(`metadata.product.version`) is blanked before saving, so baselines only change
when check results actually change.

To generate or update baselines after intentional changes:

```bash
just e2e_update
```

### Adding a new distro

1. Create `e2e/qemu/<distro>/` with one setup script per profile
   (`hardened-setup.sh`, `insecure-setup.sh`).
2. Register it in the `DISTROS` dict of `e2e/qemu_test.py` (release, cloud image
   URL and file name, SSH user and password).
3. Generate the baselines: `python3 e2e/qemu_test.py all --distro <distro>
   --update-baselines`, they are saved in `e2e/qemu/<distro>/expected/`.

## Container tests (single application)

Audit a single application running inside a container. Each application has one
build context per distro, `e2e/container/<app>/<distro>/` (`alpine` and
`ubuntu`), built as a minimal image that runs the app with one of several
profiles (`hardened`, `weak`). raudit is uploaded into the container and runs
only the checks targeting that app (e.g. `--tags sshd` for OpenSSH). The
expected baselines live next to the distro Containerfile, in
`e2e/container/<app>/<distro>/expected/<profile>.json`.

| app | tags | profiles | notes |
| --- | --- | --- | --- |
| `openssh` | `sshd` | hardened, weak | sshd runs in the foreground |
| `clamav` | `clamav` | hardened, weak | hardened runs clamd with a minimal offline signature DB, weak uninstalls ClamAV |
| `cron` | `cron` | hardened, weak | Debian-style `/etc/cron.*` layout, dcron on Alpine and Vixie cron on Ubuntu |
| `group` | `group` | hardened, weak | static group/gshadow databases and file permissions |
| `nginx` | `nginx` | hardened, weak | hardened serves HTTPS behind a redirect with a self-signed cert |
| `pam` | `pam` | hardened, weak | hardened reproduces the stock Debian `@include` layout, also runs `LDF_002` (tagged `pam`) |
| `shell` | `shell` | hardened, weak | `TMOUT` in `/etc/profile.d/` |
| `sudo` | `sudo` | hardened, weak | sudoers drop-ins validated with `visudo -c`, hardened keeps a distro-style `README` and a dot-file drop-in as parser regression guards |
| `user` | `user` | hardened, weak | static passwd/shadow databases, home directories and file permissions (`USR_100`..`USR_107`) |

### Why both distros

The same profiles are applied on both, but the two families exercise different
check paths, which is the point of running both:

| | alpine | ubuntu |
| --- | --- | --- |
| base image | `alpine:3.22` (musl) | `ubuntu:24.04`, noble, the release the QEMU VMs run |
| cron daemon | dcron, `crond` | Vixie cron, `cron` |
| `SSH_016`..`SSH_020`, `SSH_036`, `SSH_044` | warn, the Alpine openssh build does not report those options (finding 1) | configured by both profiles: they pass in hardened and fail in weak |
| `SSH_001` (`FingerprintHash`) | the weak profile cannot set `md5`, openssh rejects it | the weak profile sets `md5` and fails |
| `SSH_038` (`KexAlgorithms`) | passes with the openssh 10.0 defaults | can never pass, openssh 9.6p1 has no `mlkem768x25519-sha256` ([U3](findings_ubuntu.md#u3-ssh_038-pins-a-kexalgorithms-list-that-only-recent-openssh-provides)) |
| `SSH_042` (sftp-server path) | needs a `/usr/lib/openssh/sftp-server` symlink | native path |
| `GRP_006` (`shadow` group) | skipped, Alpine is not Debian | runs: empty in hardened, one member in weak |
| `/etc/shadow`, `/etc/gshadow`, `/etc/gshadow-` | `root:root` `0600`, the hardened profile has no gshadow at all | `root:shadow` `0640`, gshadow populated with locked entries |
| `USR_016` (root disabled) | root shell is `/sbin/nologin` | root keeps `/bin/bash` with a locked (`*`) shadow entry |
| `USR_005` (system account shells) | the stock `/sbin/shutdown` and `/sbin/halt` accounts | the stock `/usr/sbin/nologin` set and `sync` |
| periodic cron scripts | none, dcron ships nothing | the stock `0755` scripts are kept, regression guard for finding 6 |
| `--tags cron` findings | 26 | 28, `APT_103`/`APT_107` carry the `cron` tag and only run on the Debian family ([U1](findings_ubuntu.md#u1-apt_103-and-apt_107-are-tagged-cron)) |
| `--tags group` findings | 11 | 12 (`GRP_006`) |

Profile files that are not distro specific (`pam.d`, the sudoers files, the
cron jobs, `profile.d/timeout.sh`) are duplicated verbatim in both contexts, so
each context stays self-contained and buildable on its own; keep the two copies
in sync when a profile changes.

```bash
just e2e_container_hardened   # hardened OpenSSH containers, both distros
just e2e_container_weak       # weak OpenSSH containers, both distros
just e2e_container_alpine     # every app and profile on Alpine
just e2e_container_ubuntu     # every app and profile on Ubuntu
just e2e_container_all        # every app, profile and distro vs baselines
just e2e_container_update     # save outputs as new baselines
```

Or directly:

```bash
python3 e2e/container_test.py openssh hardened
python3 e2e/container_test.py nginx weak --distro ubuntu
python3 e2e/container_test.py all all
python3 e2e/container_test.py all all --distro alpine --update-baselines
python3 e2e/container_test.py openssh all --runtime podman
```

### How it works

1. Auto-detects a working runtime (`docker`, then `podman`, override with
   `--runtime`)
2. Builds one image per app and distro from
   `e2e/container/<app>/<distro>/Containerfile`
3. Starts one container per profile, waits until the app is running (a daemon
   probe like `pidof sshd`, or the `/run/app-ready` marker for apps that are
   pure configuration)
4. Copies the release raudit binary into the container
5. Runs `raudit --json --tags <app tags>` inside it
6. Compares the JSON against the baselines in
   `e2e/container/<app>/<distro>/expected/` (`<profile>.json`), with the same
   volatile-field stripping as the QEMU tests

### Requirements

- `docker` or `podman` (with a running daemon for docker)
- `rustup` (to add the musl target; raudit is built static for musl like in the
  release CI, so one binary runs on Alpine without a glibc compatibility layer
  and on Ubuntu whatever its glibc version is)

### Checks that cannot pass in containers

Some checks can never reach `Pass` inside a container, they are recorded as
such in the baselines (see [findings.md](findings.md) and
[findings_ubuntu.md](findings_ubuntu.md) for the details):

- OpenSSH on Alpine: `SSH_016`..`SSH_020` (Kerberos/GSSAPI), `SSH_044` (PAM)
  and `SSH_036` (`PrintLastLog`, no wtmp/lastlog on musl) warn because the
  current Alpine `openssh-server` build does not report those options in
  `sshd -T`. On Ubuntu those seven are configured and pass, but `SSH_038`
  fails instead: noble ships openssh 9.6p1 and the check pins an openssh 10
  `KexAlgorithms` list ([findings_ubuntu.md](findings_ubuntu.md), `U3`).
  `SSH_045`/`SSH_046` (systemd unit files) are skipped on both.
- cron: `CRN_001`/`CRN_002` (systemd unit files) and `CRN_200`..`CRN_203`
  (anacron, not installed) are skipped on both distros.
- sudo: `SUD_900` warns without auditctl, auditd cannot run in an
  unprivileged container.

Every other check passes in every hardened profile, except `SSH_038` on Ubuntu.

### Adding a new application

1. Create `e2e/container/<app>/alpine/` and `e2e/container/<app>/ubuntu/`, each
   with a `Containerfile` that runs the app in the foreground and accepts the
   profile name as argument. For apps without a daemon, apply the profile,
   `touch /run/app-ready` and `exec sleep infinity`.
2. Register it in the `APPS` dict of `e2e/container_test.py` (raudit tags,
   profiles, readiness probe command of each distro).
3. Generate the baselines: `python3 e2e/container_test.py <app> all
   --update-baselines`, they are saved in
   `e2e/container/<app>/<distro>/expected/`.

## TODO

- Install Podman or Docker on hardened and insecure and run containers
- Add e2e test on the following plateforms: debian, elementary, cachyos,
  bazzite, arch, vanillaos, tinycore, tails, rockylinux, pureos, proxmox-ve,
  popos, mint, opensuse, manjaro, nixos, guix, gentoo, fedora, endless,
  endeavouros, void, zorin, azurelinux, zorin, and if possible all the major
  cloud Linux OS like AWSLinux
