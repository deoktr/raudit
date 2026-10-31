#!/usr/bin/env python3
"""End-to-end tests running raudit inside a container against a single app.

Each app under e2e/container/<app>/ is built as a minimal image running the app
with one of several profiles (e.g. `hardened` and `weak` for OpenSSH), once per
distro (`alpine` and `ubuntu`, each with its own build context under
e2e/container/<app>/<distro>/). raudit is uploaded into the container and only
runs the checks targeting that app, then the JSON output is compared against
the baselines stored next to the distro Containerfile, in
e2e/container/<app>/<distro>/expected/<profile>.json.

Works with docker or podman.
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time

logger = logging.getLogger(__name__)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
CONTAINER_DIR = os.path.join(SCRIPT_DIR, "container")
WORK_DIR_ROOT = os.path.join(PROJECT_DIR, "target", "container-e2e")

sys.path.insert(0, SCRIPT_DIR)
from compare import compare, save_json

# Readiness probe for apps that are pure configuration (no daemon to wait
# for): their entrypoints touch /run/app-ready once the profile is applied.
READY_FILE_CMD = ["sh", "-c", "test -e /run/app-ready && echo ready"]

# Distros each app is built for. Every app has one build context per distro,
# e2e/container/<app>/<distro>/, with its own baselines.
DISTROS = ["alpine", "ubuntu"]

# Registry of containerized apps. Add new apps here, each with its own build
# context per distro under e2e/container/, the raudit tags selecting only its
# checks, the profiles its entrypoint accepts and the readiness probe of each
# distro (the daemon name differs, dcron calls itself `crond`).
APPS = {
    "openssh": {
        "tags": "sshd",
        "profiles": ["hardened", "weak"],
        "ready_cmd": {"alpine": ["pidof", "sshd"], "ubuntu": ["pidof", "sshd"]},
    },
    "clamav": {
        "tags": "clamav",
        "profiles": ["hardened", "weak"],
        "ready_cmd": {"alpine": READY_FILE_CMD, "ubuntu": READY_FILE_CMD},
    },
    "cron": {
        "tags": "cron",
        "profiles": ["hardened", "weak"],
        "ready_cmd": {"alpine": ["pidof", "crond"], "ubuntu": ["pidof", "cron"]},
    },
    "group": {
        "tags": "group",
        "profiles": ["hardened", "weak"],
        "ready_cmd": {"alpine": READY_FILE_CMD, "ubuntu": READY_FILE_CMD},
    },
    "nginx": {
        "tags": "nginx",
        "profiles": ["hardened", "weak"],
        "ready_cmd": {"alpine": ["pidof", "nginx"], "ubuntu": ["pidof", "nginx"]},
    },
    "pam": {
        "tags": "pam",
        "profiles": ["hardened", "weak"],
        "ready_cmd": {"alpine": READY_FILE_CMD, "ubuntu": READY_FILE_CMD},
    },
    "shell": {
        "tags": "shell",
        "profiles": ["hardened", "weak"],
        "ready_cmd": {"alpine": READY_FILE_CMD, "ubuntu": READY_FILE_CMD},
    },
    "sudo": {
        "tags": "sudo",
        "profiles": ["hardened", "weak"],
        "ready_cmd": {"alpine": READY_FILE_CMD, "ubuntu": READY_FILE_CMD},
    },
    "user": {
        "tags": "user",
        "profiles": ["hardened", "weak"],
        "ready_cmd": {"alpine": READY_FILE_CMD, "ubuntu": READY_FILE_CMD},
    },
}

TIMEOUT_BUILD = 600
TIMEOUT_READY = 60
TIMEOUT_RAUDIT = 120

IMAGE_PULL_TIMEOUT = 300


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


def detect_runtime(preferred: str = "auto") -> str | None:
    """Return the first working container runtime (docker or podman)."""

    candidates = ["docker", "podman"] if preferred == "auto" else [preferred]
    for runtime in candidates:
        if not shutil.which(runtime):
            continue
        result = subprocess.run(
            [runtime, "info"],
            capture_output=True,
            timeout=60,
            check=False,
        )
        if result.returncode == 0:
            return runtime
        log_debug(f"{runtime} found but not usable")
    return None


def run_cmd(cmd, timeout=60, check=False):
    log_debug(f"exec: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stdout: {result.stdout[-2000:]}\nstderr: {result.stderr[-2000:]}"
        )
    return result


def app_context(app, distro):
    """Build context of an app for a distro, e2e/container/<app>/<distro>/."""

    return os.path.join(CONTAINER_DIR, app, distro)


def app_image(app, distro):
    """Image name of an app for a distro."""

    return f"raudit-e2e-{app}-{distro}"


def build_image(runtime, app, distro):
    image = app_image(app, distro)
    context = app_context(app, distro)
    log(f"[{app}/{distro}] building image {image}")
    result = run_cmd(
        [
            runtime,
            "build",
            "-t",
            image,
            "-f",
            os.path.join(context, "Containerfile"),
            context,
        ],
        timeout=TIMEOUT_BUILD,
    )
    if result.returncode != 0:
        log_err(f"[{app}/{distro}] image build failed")
        log_err(result.stderr[-2000:])
        return False
    return True


def musl_target() -> str:
    """Return the musl target triple for the host arch (same as release CI)."""

    machine = os.uname().machine
    targets = {
        "x86_64": "x86_64-unknown-linux-musl",
        "aarch64": "aarch64-unknown-linux-musl",
    }
    if machine not in targets:
        raise RuntimeError(f"unsupported architecture for musl build: {machine}")
    return targets[machine]


def build_raudit():
    """Build (or locate) the static musl raudit binary for the containers.

    Alpine uses musl libc, so the glibc-linked release binary would need a
    compatibility layer there. Instead the binary is built for the musl target,
    exactly like the release CI does: it is fully static and runs unchanged on
    both Alpine and Ubuntu.
    """

    target = musl_target()
    raudit_bin = os.path.join(PROJECT_DIR, "target", target, "release", "raudit")
    if os.path.exists(raudit_bin):
        log(f"raudit musl binary exists: {raudit_bin}")
        return raudit_bin

    log(f"building raudit for {target}...")
    if shutil.which("rustup"):
        subprocess.check_call(["rustup", "target", "add", target], cwd=PROJECT_DIR)
    subprocess.check_call(
        ["cargo", "build", "--release", "--target", target],
        cwd=PROJECT_DIR,
    )
    return raudit_bin


def start_container(runtime, app, distro, app_conf, profile):
    name = f"raudit-e2e-{app}-{distro}-{profile}"
    ready_cmd = app_conf["ready_cmd"][distro]
    run_cmd([runtime, "rm", "-f", name], timeout=60)
    log(f"[{app}/{distro}/{profile}] starting container {name}")
    result = run_cmd(
        [
            runtime,
            "run",
            "-d",
            "--name",
            name,
            app_image(app, distro),
            profile,
        ],
        timeout=120,
    )
    if result.returncode != 0:
        log_err(f"[{app}/{distro}/{profile}] failed to start container")
        log_err(result.stderr[-1000:])
        return None

    start = time.time()
    while time.time() - start < TIMEOUT_READY:
        probe = run_cmd(
            [runtime, "exec", name, *ready_cmd],
            timeout=30,
        )
        if probe.returncode == 0 and probe.stdout.strip():
            log(f"[{app}/{distro}/{profile}] app is running ({' '.join(ready_cmd)})")
            return name
        # fail fast if the container already exited (bad config)
        state = run_cmd(
            [runtime, "inspect", "-f", "{{.State.Running}}", name],
            timeout=30,
        )
        if state.stdout.strip() != "true":
            logs = run_cmd([runtime, "logs", name], timeout=30)
            log_err(f"[{app}/{distro}/{profile}] container exited")
            log_err(logs.stdout[-2000:] + logs.stderr[-2000:])
            return None
        time.sleep(1)

    log_err(f"[{app}/{distro}/{profile}] app not running after {TIMEOUT_READY}s")
    return None


def run_raudit_in_container(runtime, name, tags, raudit_bin):
    """Upload raudit into the container and run only this app's checks."""

    result = run_cmd(
        [runtime, "cp", raudit_bin, f"{name}:/usr/local/bin/raudit"],
        timeout=120,
    )
    if result.returncode != 0:
        log_err(f"failed to copy raudit into {name}")
        log_err(result.stderr[-1000:])
        return None

    log(f"running raudit (--tags {tags}) in {name}...")
    result = run_cmd(
        [
            runtime,
            "exec",
            name,
            "/usr/local/bin/raudit",
            "--json",
            "--tags",
            tags,
            "--no-time",
        ],
        timeout=TIMEOUT_RAUDIT,
    )

    stdout = result.stdout.strip()
    if not stdout:
        log_err("raudit produced no output")
        log_err(f"stderr: {result.stderr[-2000:]}")
        return None

    json_start = stdout.find("{")
    if json_start == -1:
        log_err("no JSON found in output")
        log_err(f"raw output (first 500): {stdout[:500]}")
        return None

    try:
        return json.loads(stdout[json_start:])
    except json.JSONDecodeError as e:
        log_err(f"failed to parse JSON: {e}")
        log_err(f"raw (first 500): {stdout[:500]}")
        return None


def stop_container(runtime, name):
    run_cmd([runtime, "rm", "-f", name], timeout=120)


def run_app_profile(runtime, app, distro, app_conf, profile, raudit_bin, output_path):
    tag = f"{app}/{distro}/{profile}"
    name = None
    try:
        name = start_container(runtime, app, distro, app_conf, profile)
        if name is None:
            return False

        data = run_raudit_in_container(runtime, name, app_conf["tags"], raudit_bin)
        if data is None:
            log_err(f"[{tag}] raudit failed")
            return False

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        log(f"[{tag}] raudit output saved: {output_path}")

        statuses = {}
        for finding in data.get("findings", []):
            st = finding.get("status", "unknown")
            statuses[st] = statuses.get(st, 0) + 1
        log(f"[{tag}] findings: {len(data.get('findings', []))} total")
        for st, cnt in sorted(statuses.items()):
            log(f"[{tag}]   {st}: {cnt}")
        return True
    finally:
        if name is not None:
            stop_container(runtime, name)


def baseline_path(app, distro, profile):
    """Path of the expected baseline, stored next to the distro Containerfile."""

    return os.path.join(app_context(app, distro), "expected", f"{profile}.json")


def compare_against_baseline(app, distro, profile, output_path):
    expected_path = baseline_path(app, distro, profile)

    if not os.path.exists(expected_path):
        log_warn(f"no baseline found for {app}/{distro}/{profile}: {expected_path}")
        log_warn("run with --update-baselines to create it")
        return False

    with open(expected_path) as f:
        baseline = json.load(f)
    with open(output_path) as f:
        output = json.load(f)

    errors = compare(baseline, output)
    if errors == 0:
        log(f"[{app}/{distro}/{profile}] JSON matches baseline")
        return True

    log_err(
        f"[{app}/{distro}/{profile}] JSON differs from baseline: {errors} differences"
    )
    log_err(f"baseline: {expected_path}")
    log_err(f"output:   {output_path}")
    return False


def update_baseline(app, distro, profile, output_path):
    expected_path = baseline_path(app, distro, profile)
    os.makedirs(os.path.dirname(expected_path), exist_ok=True)
    with open(output_path) as f:
        output = json.load(f)
    save_json(expected_path, output)
    log(f"[{app}/{distro}/{profile}] baseline updated: {expected_path}")


def main():
    parser = argparse.ArgumentParser(
        description="raudit container e2e test runner (single app per container)"
    )
    parser.add_argument("app", choices=[*APPS.keys(), "all"], default="all", nargs="?")
    parser.add_argument(
        "profile",
        choices=["hardened", "weak", "all"],
        default="all",
        nargs="?",
        help="profile to run (default: all profiles of the app)",
    )
    parser.add_argument(
        "--distro",
        choices=[*DISTROS, "all"],
        default="all",
        help="distro the app images are built from (default: all)",
    )
    parser.add_argument(
        "--runtime",
        choices=["auto", "docker", "podman"],
        default="auto",
        help="container runtime (default: auto-detect docker, then podman)",
    )
    parser.add_argument(
        "--update-baselines",
        action="store_true",
        help="save output as expected baselines instead of comparing",
    )
    parser.add_argument(
        "--log-level", default="info", choices=["debug", "info", "warning", "error"]
    )
    parser.add_argument(
        "--keep", action="store_true", help="keep the work dir with raw outputs"
    )
    args = parser.parse_args()

    setup_logging(args.log_level)

    runtime = detect_runtime(args.runtime)
    if runtime is None:
        log_err("no working container runtime found (docker or podman)")
        sys.exit(1)
    log(f"using container runtime: {runtime}")

    apps = list(APPS) if args.app == "all" else [args.app]
    distros = DISTROS if args.distro == "all" else [args.distro]

    raudit_bin = build_raudit()

    os.makedirs(WORK_DIR_ROOT, exist_ok=True)
    work_dir = tempfile.mkdtemp(prefix="raudit-container-", dir=WORK_DIR_ROOT)
    log(f"work dir: {work_dir}")

    success = True
    outputs = {}

    try:
        for app in apps:
            app_conf = APPS[app]
            for distro in distros:
                if not build_image(runtime, app, distro):
                    success = False
                    continue

                profiles = (
                    app_conf["profiles"]
                    if args.profile == "all"
                    else [args.profile]
                )
                for profile in profiles:
                    if profile not in app_conf["profiles"]:
                        log_err(f"[{app}/{distro}] unknown profile: {profile}")
                        success = False
                        continue

                    output_path = os.path.join(
                        work_dir, f"{app}-{distro}-{profile}.json"
                    )
                    if run_app_profile(
                        runtime, app, distro, app_conf, profile, raudit_bin, output_path
                    ):
                        outputs[(app, distro, profile)] = output_path
                    else:
                        success = False

        if success and args.update_baselines:
            for (app, distro, profile), output_path in outputs.items():
                update_baseline(app, distro, profile, output_path)
        elif success:
            for (app, distro, profile), output_path in outputs.items():
                if not compare_against_baseline(app, distro, profile, output_path):
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
