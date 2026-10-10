# End-to-end tests

Run tests inside QEMU VM and compare to expected results.

## Usage

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
python3 e2e/qemu_test.py all --update-baselines
```

## How it works

1. Downloads an Ubuntu cloud image (cached in `target/qemu-cache/`)
2. Creates copy-on-write disk images
3. Generates cloud-init ISOs
4. Boots QEMU VMs with KVM acceleration (if available)
5. Waits for SSH
6. Applies hardening or insecure configuration via SSH
7. Uploads and runs raudit
8. Collects JSON output
9. Shuts down VMs
10. Compares JSON output against expected baselines in `e2e/expected/`

## Requirements

- `qemu-system-x86` (QEMU emulator)
- `qemu-utils` (disk image tools)
- `cloud-image-utils` (cloud-init ISO creation)
- `genisoimage` (ISO creation)
- `sshpass` (non-interactive SSH password)
- KVM support (`/dev/kvm`) recommended for performance

## Baselines

Expected JSON outputs are stored in `e2e/expected/`. Each profile has a baseline
file (`hardened.json`, `insecure.json`). Tests fail if the output differs from
the baseline.

Timestamps (`time` fields) are stripped before saving, so baselines only change
when check results actually change.

To generate or update baselines after intentional changes:

```bash
just e2e_update
```
