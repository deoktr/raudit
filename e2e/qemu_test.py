#!/usr/bin/env python3

import argparse
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

logger = logging.getLogger(__name__)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
QEMU_DIR = os.path.join(SCRIPT_DIR, "qemu")
EXPECTED_DIR = os.path.join(SCRIPT_DIR, "expected")

sys.path.insert(0, SCRIPT_DIR)
from compare import compare, save_json

UBUNTU_RELEASE = "noble"
UBUNTU_IMAGE_URL = f"https://cloud-images.ubuntu.com/{UBUNTU_RELEASE}/current/{UBUNTU_RELEASE}-server-cloudimg-amd64.img"
IMAGE_CACHE_DIR = os.path.join(PROJECT_DIR, "target", "qemu-cache")
# the VM disks are sparse qcow2 images that grow to a few GB, they must not end
# up on a small tmpfs (which is the default TMPDIR on many systems)
WORK_DIR_ROOT = os.path.join(PROJECT_DIR, "target", "qemu-work")
CACHED_IMAGE = os.path.join(
    IMAGE_CACHE_DIR, f"{UBUNTU_RELEASE}-server-cloudimg-amd64.img"
)

VM_SSH_USER = "ubuntu"
VM_SSH_PASSWORD = "ubuntu"
VM_SSH_KEY = os.path.join(QEMU_DIR, "keys", "test_key")
VM_SSH_PORT_BASE = 2222
VM_RAM = "2G"
VM_CPUS = "2"

VM_RAUDIT_PATH = "/usr/local/bin/raudit"

PROFILES = {
    "hardened": {
        "setup": "hardened-setup.sh",
    },
    "insecure": {
        "setup": "insecure-setup.sh",
    },
}

TIMEOUT_BOOT = 300
TIMEOUT_SSH = 900
TIMEOUT_CLOUD_INIT = 300
TIMEOUT_SETUP = 1800
TIMEOUT_RAUDIT = 900

SSH_COMMON_OPTS = [
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ServerAliveInterval=5",
    "-o",
    "AddressFamily=inet",
    "-o",
    "GSSAPIAuthentication=no",
    "-o",
    "LogLevel=ERROR",
]


def setup_logging(level: str = "INFO"):
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(levelname)s %(message)s\x1b[39m")
    logging.addLevelName(logging.DEBUG, "\x1b[36m[*]")
    logging.addLevelName(logging.INFO, "\x1b[32m[+]")
    logging.addLevelName(logging.WARNING, "\x1b[33m[?]")
    logging.addLevelName(logging.ERROR, "\x1b[31m[!]")
    logging.addLevelName(logging.CRITICAL, "\x1b[31m[!!!]")
    handler.setFormatter(formatter)
    logging.basicConfig(level=getattr(logging, level.upper()), handlers=[handler])


def log(msg):
    logger.info(msg)


def log_err(msg):
    logger.error(msg)


def log_warn(msg):
    logger.warning(msg)


def log_debug(msg):
    logger.debug(msg)


def check_tools():
    for tool in [
        "qemu-system-x86_64",
        "qemu-img",
        "cloud-localds",
        "genisoimage",
        "ssh",
        "scp",
    ]:
        if not shutil.which(tool):
            log_err(f"required tool not found: {tool}")
            sys.exit(1)

    if not os.path.exists(VM_SSH_KEY):
        log(f"generating SSH key: {VM_SSH_KEY}")
        os.makedirs(os.path.dirname(VM_SSH_KEY), exist_ok=True)
        subprocess.check_call(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                VM_SSH_KEY,
                "-N",
                "",
                "-q",
            ]
        )

    pub_key = VM_SSH_KEY + ".pub"
    if not os.path.exists(pub_key):
        log_err(f"SSH public key not found: {pub_key}")
        sys.exit(1)


def download_image():
    if os.path.exists(CACHED_IMAGE):
        log(f"using cached image: {CACHED_IMAGE}")
        return

    os.makedirs(IMAGE_CACHE_DIR, exist_ok=True)
    log("downloading ubuntu cloud image")
    subprocess.check_call(
        ["wget", "-q", "--show-progress", "-O", CACHED_IMAGE, UBUNTU_IMAGE_URL]
    )
    log("image downloaded")


def create_work_disk(base_img, work_img, size="20G"):
    subprocess.check_call(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", base_img, work_img]
    )
    subprocess.check_call(["qemu-img", "resize", work_img, size])
    log(f"created work disk: {work_img}")


def create_cloud_init_iso(iso_path, work_dir):
    with open(VM_SSH_KEY + ".pub") as f:
        ssh_pub_key = f.read().strip()

    user_data_path = os.path.join(work_dir, "user-data")
    with open(user_data_path, "w") as f:
        f.write(f"""#cloud-config
hostname: raudit-test
ssh_pwauth: true
chpasswd:
  expire: false
  list: |
    ubuntu:ubuntu
ssh_authorized_keys:
  - {ssh_pub_key}
users:
  - default
  - name: test
    groups: sudo
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    ssh_authorized_keys:
      - {ssh_pub_key}
system_info:
  default_user:
    name: ubuntu
sudo: ALL=(ALL) NOPASSWD:ALL
final_message: "cloud-init complete"
""")

    meta_data = os.path.join(work_dir, "meta-data")
    with open(meta_data, "w") as f:
        f.write("instance-id: raudit-test\nlocal-hostname: raudit-test\n")
    subprocess.check_call(["cloud-localds", iso_path, user_data_path, meta_data])
    log(f"created cloud-init ISO: {iso_path}")


def boot_qemu(disk_img, cidata_iso, ssh_port, log_file):
    kvm_flag = ["-enable-kvm"] if os.path.exists("/dev/kvm") else []

    cmd = [
        "qemu-system-x86_64",
        "-m",
        VM_RAM,
        "-smp",
        VM_CPUS,
        "-drive",
        f"file={disk_img},format=qcow2",
        "-drive",
        f"file={cidata_iso},format=raw",
        "-netdev",
        f"user,id=net0,hostfwd=tcp::{ssh_port}-:22",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-object",
        "rng-random,id=rng0,filename=/dev/urandom",
        "-device",
        "virtio-rng-pci,rng=rng0",
        "-cpu",
        "max",
        "-nographic",
        "-no-reboot",
    ] + kvm_flag

    log(f"booting QEMU (ssh port {ssh_port})")
    log_debug(f"qemu cmd: {' '.join(cmd)}")

    proc = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        start_new_session=True,
    )
    return proc


def wait_for_ssh(ssh_port, timeout=TIMEOUT_SSH):
    import socket

    start = time.time()
    log(f"waiting for SSH on port {ssh_port}...")
    attempt = 0
    has_sshpass = shutil.which("sshpass") is not None
    while time.time() - start < timeout:
        attempt += 1
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                if s.connect_ex(("127.0.0.1", ssh_port)) != 0:
                    if attempt % 6 == 0:
                        log(
                            f"  port not open yet ({int(time.time() - start)}s elapsed)"
                        )
                    time.sleep(5)
                    continue
        except (TimeoutError, OSError):
            time.sleep(5)
            continue

        for prefix in _ssh_prefixes(has_sshpass):
            batch_mode = "no" if prefix and "sshpass" in prefix[0] else "yes"
            try:
                result = subprocess.run(
                    prefix
                    + [
                        "ssh",
                        "-i",
                        VM_SSH_KEY,
                    ]
                    + SSH_COMMON_OPTS
                    + [
                        "-o",
                        f"BatchMode={batch_mode}",
                        "-p",
                        str(ssh_port),
                        f"{VM_SSH_USER}@127.0.0.1",
                        "echo SSH_READY",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=12,
                    check=False,
                )
                if result.returncode == 0 and "SSH_READY" in result.stdout:
                    elapsed = int(time.time() - start)
                    log(f"SSH is ready (after {elapsed}s, {attempt} attempts)")
                    return True
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass

        if attempt % 5 == 0:
            log(f"  attempt {attempt}: not ready ({int(time.time() - start)}s)")
        time.sleep(2)
    log_err(f"SSH not ready after {timeout}s")
    return False


def _ssh_prefixes(has_sshpass):
    prefixes = [[]]
    if has_sshpass:
        prefixes.append(["sshpass", "-p", "ubuntu"])
    return prefixes


def ssh_cmd(ssh_port, cmd, timeout=60, check=True):
    ssh_opts = (
        [
            "ssh",
            "-i",
            VM_SSH_KEY,
        ]
        + SSH_COMMON_OPTS
        + [
            "-o",
            "BatchMode=yes",
            "-p",
            str(ssh_port),
            f"{VM_SSH_USER}@127.0.0.1",
            cmd,
        ]
    )

    log_debug(f"ssh: {cmd[:100]}")
    result = subprocess.run(
        ssh_opts,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )

    if result.returncode != 0:
        log_debug(f"ssh rc={result.returncode} stderr={result.stderr[:200]}")
        if check:
            log_warn(f"ssh cmd failed: {result.stderr[:200]}")

    return result


def scp_to_vm(ssh_port, local_path, remote_path):
    scp_opts = (
        [
            "scp",
            "-i",
            VM_SSH_KEY,
        ]
        + SSH_COMMON_OPTS
        + [
            "-P",
            str(ssh_port),
            local_path,
            f"{VM_SSH_USER}@127.0.0.1:{remote_path}",
        ]
    )
    subprocess.check_call(scp_opts)


def wait_for_cloud_init(ssh_port, timeout=TIMEOUT_CLOUD_INIT):
    log("waiting for cloud-init to finish...")
    start = time.time()
    last_status = ""
    while time.time() - start < timeout:
        try:
            result = ssh_cmd(
                ssh_port,
                "cloud-init status 2>&1",
                timeout=30,
                check=False,
            )
            status = result.stdout.strip()
            if status != last_status:
                log_debug(f"cloud-init status: {status}")
                last_status = status

            if "done" in status:
                log("cloud-init finished: done")
                return True
            if "error" in status:
                log_err(f"cloud-init error: {status}")
                return False
        except subprocess.TimeoutExpired:
            log_debug("cloud-init check timed out")
        except Exception as e:
            log_debug(f"cloud-init check error: {e}")

        time.sleep(5)

    log_err(f"cloud-init did not finish after {timeout}s (last: {last_status})")
    return False


def sudo_wrap(cmd):
    """Run cmd through sudo, feeding the password on stdin.

    The hardened profile removes passwordless sudo and never caches credentials
    (`timestamp_timeout=0`), so every privileged command has to authenticate.
    """

    return f"printf '%s\\n' '{VM_SSH_PASSWORD}' | sudo -S -p '' {cmd}"


def run_setup_script(ssh_port, script_name, timeout=TIMEOUT_SETUP):
    script_path = os.path.join(QEMU_DIR, script_name)
    log(f"uploading {script_name}...")
    scp_to_vm(ssh_port, script_path, f"/tmp/{script_name}")
    log(f"running {script_name} (this may take a while)...")
    result = ssh_cmd(
        ssh_port,
        sudo_wrap(f"bash /tmp/{script_name} 2>&1"),
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        log_err(f"{script_name} failed (rc={result.returncode})")
        log_err(f"stdout tail: {result.stdout[-2000:]}")
        return False

    for line in result.stdout.splitlines():
        if "COMPLETE" in line or "WARNING" in line:
            log(f"  {line.strip()}")
    return True


def build_raudit():
    raudit_bin = os.path.join(PROJECT_DIR, "target", "release", "raudit")
    if os.path.exists(raudit_bin):
        log(f"raudit binary exists: {raudit_bin}")
        return raudit_bin

    log("building raudit...")
    subprocess.check_call(["cargo", "build", "--release"], cwd=PROJECT_DIR)
    return raudit_bin


def install_raudit(ssh_port, raudit_bin):
    """Upload raudit and install it outside of the noexec /tmp mount."""

    log("uploading raudit...")
    scp_to_vm(ssh_port, raudit_bin, "/tmp/raudit")
    result = ssh_cmd(
        ssh_port,
        sudo_wrap(f"install -m 0755 -o root -g root /tmp/raudit {VM_RAUDIT_PATH}"),
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        log_err(f"failed to install raudit: {result.stderr[-500:]}")
        return False
    return True


def run_raudit(ssh_port, output_path, timeout=TIMEOUT_RAUDIT):
    log("running raudit in VM...")
    result = ssh_cmd(
        ssh_port,
        sudo_wrap(f"{VM_RAUDIT_PATH} --json --no-skip --no-time"),
        timeout=timeout,
        check=False,
    )

    stdout = result.stdout.strip()
    log_debug(f"raudit stdout length: {len(stdout)}")
    log_debug(f"raudit stderr: {result.stderr[:500]}")

    if not stdout:
        log_err("raudit produced no output")
        log_err(f"stderr: {result.stderr[-2000:]}")
        return False

    json_start = stdout.find("{")
    if json_start == -1:
        log_err("no JSON found in output")
        log_err(f"raw output (first 500): {stdout[:500]}")
        return False

    json_str = stdout[json_start:]
    try:
        data = json.loads(json_str)
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        log(f"raudit output saved: {output_path}")

        findings = data.get("findings", [])
        statuses = {}
        for f in findings:
            st = f.get("status", "unknown")
            statuses[st] = statuses.get(st, 0) + 1
        log(f"findings: {len(findings)} total")
        for st, cnt in sorted(statuses.items()):
            log(f"  {st}: {cnt}")
        return True
    except json.JSONDecodeError as e:
        log_err(f"failed to parse JSON: {e}")
        log_err(f"raw (first 500): {stdout[:500]}")
        return False


def kill_qemu(proc):
    if proc and proc.poll() is None:
        log("shutting down QEMU...")
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=15)
        except Exception:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait(timeout=5)
            except Exception:
                pass


def run_vm_test(profile, output_path, ssh_port, work_dir):
    disk_img = os.path.join(work_dir, f"disk-{profile}.qcow2")
    cidata_iso = os.path.join(work_dir, f"cidata-{profile}.iso")
    qemu_log_path = os.path.join(work_dir, f"qemu-{profile}.log")

    setup_script = {
        "hardened": "hardened-setup.sh",
        "insecure": "insecure-setup.sh",
    }[profile]

    log(f"[{profile}] starting test")
    create_work_disk(CACHED_IMAGE, disk_img)
    create_cloud_init_iso(cidata_iso, work_dir)

    with open(qemu_log_path, "w") as log_file:
        proc = boot_qemu(disk_img, cidata_iso, ssh_port, log_file)

        try:
            if not wait_for_ssh(ssh_port):
                log_err(f"[{profile}] SSH not available")
                log_err(f"check QEMU log: {qemu_log_path}")
                return False

            if not wait_for_cloud_init(ssh_port):
                log_err(f"[{profile}] cloud-init failed")
                return False

            if not run_setup_script(ssh_port, setup_script):
                log_err(f"[{profile}] setup failed")
                return False

            raudit_bin = build_raudit()
            if not install_raudit(ssh_port, raudit_bin):
                log_err(f"[{profile}] could not install raudit")
                return False

            if not run_raudit(ssh_port, output_path):
                log_err(f"[{profile}] raudit failed")
                return False

            log(f"[{profile}] SUCCESS")
            return True

        finally:
            kill_qemu(proc)


def compare_against_baseline(profile, output_path):
    baseline_path = os.path.join(EXPECTED_DIR, f"{profile}.json")

    if not os.path.exists(baseline_path):
        log_warn(f"no baseline found for {profile}: {baseline_path}")
        log_warn("run with --update-baselines to create it")
        return False

    with open(baseline_path) as f:
        baseline = json.load(f)
    with open(output_path) as f:
        output = json.load(f)

    errors = compare(baseline, output)
    if errors == 0:
        log(f"[{profile}] JSON matches baseline")
        return True

    log_err(f"[{profile}] JSON differs from baseline: {errors} differences")
    log_err(f"baseline: {baseline_path}")
    log_err(f"output:   {output_path}")
    return False


def update_baseline(profile, output_path):
    os.makedirs(EXPECTED_DIR, exist_ok=True)
    baseline_path = os.path.join(EXPECTED_DIR, f"{profile}.json")
    with open(output_path) as f:
        output = json.load(f)
    save_json(baseline_path, output)
    log(f"[{profile}] baseline updated: {baseline_path}")


def main():
    parser = argparse.ArgumentParser(description="raudit QEMU VM e2e test runner")
    parser.add_argument("profile", choices=["hardened", "insecure", "all"])
    parser.add_argument(
        "--compare", action="store_true", help="(deprecated, comparison is now default)"
    )
    parser.add_argument(
        "--update-baselines",
        action="store_true",
        help="save output as expected baselines instead of comparing",
    )
    parser.add_argument(
        "--log-level", default="info", choices=["debug", "info", "warning", "error"]
    )
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--ssh-port-hardened", type=int, default=VM_SSH_PORT_BASE)
    parser.add_argument("--ssh-port-insecure", type=int, default=VM_SSH_PORT_BASE + 1)
    args = parser.parse_args()

    setup_logging(args.log_level)
    check_tools()
    download_image()

    os.makedirs(WORK_DIR_ROOT, exist_ok=True)
    work_dir = tempfile.mkdtemp(prefix="raudit-qemu-", dir=WORK_DIR_ROOT)
    log(f"work dir: {work_dir}")

    profiles = ["hardened", "insecure"] if args.profile == "all" else [args.profile]
    success = True
    outputs = {}

    try:
        for profile in profiles:
            output_path = os.path.join(work_dir, f"raudit-{profile}.json")
            ssh_port = {
                "hardened": args.ssh_port_hardened,
                "insecure": args.ssh_port_insecure,
            }[profile]

            if not run_vm_test(profile, output_path, ssh_port, work_dir):
                success = False
            else:
                outputs[profile] = output_path

        if success and args.update_baselines:
            for profile, output_path in outputs.items():
                update_baseline(profile, output_path)
        elif success:
            for profile, output_path in outputs.items():
                if not compare_against_baseline(profile, output_path):
                    success = False

    finally:
        if args.keep:
            log(f"keeping: {work_dir}")
        else:
            shutil.rmtree(work_dir, ignore_errors=True)

    if success:
        log("all tests passed")
    else:
        log_err("some tests failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
