#!/usr/bin/env python3

import argparse
import json
import logging
import sys

logger = logging.getLogger(__name__)

SKIP_MESSAGE = ["UPT_001", "AAR_004", "AUD_001"]

TIMESTAMP_KEYS = ["time"]


def finding_uid(data) -> str | None:
    """Return the uid of a finding, or None if data is not a finding."""

    if not isinstance(data, dict):
        return None
    finding_info = data.get("finding_info")
    if not isinstance(finding_info, dict):
        return None
    return finding_info.get("uid")


def strip_volatile(data):
    """Recursively drop timestamps, volatile messages and the raudit version.

    Timestamps, the raudit product version and the messages of findings listed
    in SKIP_MESSAGE (pids, uptime, ...) change on every run or release, so they
    are stripped to keep baselines stable in git.
    """

    if isinstance(data, dict):
        uid = finding_uid(data)
        out = {}
        for key, value in data.items():
            if key in TIMESTAMP_KEYS:
                continue
            if key == "message" and uid in SKIP_MESSAGE:
                continue
            if key == "product" and isinstance(value, dict) and "version" in value:
                value = {**value, "version": ""}
            out[key] = strip_volatile(value)
        return out
    if isinstance(data, list):
        return [strip_volatile(item) for item in data]
    return data


def save_json(path, data):
    """Write data as indented json, without timestamps or raudit version."""

    with open(path, "w") as f:
        json.dump(strip_volatile(data), f, indent=2)


def compare_stat(base, target, stat_name) -> int:
    """Compare a single stat."""

    if "stats" not in base:
        logger.error("wrong json format, missing stats from base")
        return 1
    if "stats" not in target:
        logger.error("wrong json format, missing stats from target")
        return 1

    if stat_name not in base["stats"]:
        logger.error(f"wrong json format, missing stat '{stat_name}' from base")
        return 1
    if stat_name not in target["stats"]:
        logger.error(f"wrong json format, missing stat '{stat_name}' from target")
        return 1

    base_stat = base["stats"][stat_name]
    target_stat = target["stats"][stat_name]

    if base_stat != target_stat:
        logger.warning(
            f"stat {stat_name} are not the same: '{base_stat}' != '{target_stat}'"
        )
        return 1
    else:
        logger.debug(f"valid stat '{stat_name}'")
        return 0


def compare_number_of_findings(base, target) -> int:
    """Compare the total amount of findings."""

    if "findings" not in base:
        logger.error("wrong json format, missing findings from base")
        return 1
    if "findings" not in target:
        logger.error("wrong json format, missing findings from target")
        return 1

    num_base = len(base["findings"])
    num_target = len(target["findings"])
    if num_base != num_target:
        logger.warning(
            f"number of findings are not the same: '{num_base}' != '{num_target}'"
        )
        return 1
    else:
        logger.debug(f"valid number of findings '{num_base}'")
        return 0


def compare_findings(base, target) -> int:
    """Compare all findings, one by one.

    Ensure they have the same id, title, message, status, and severity.
    """

    out = 0
    for index in range(len(base["findings"])):
        base_finding = base["findings"][index]

        if len(target["findings"]) < index + 1:
            out += 1
            continue

        target_finding = target["findings"][index]

        base_id = base_finding["finding_info"]["uid"]
        target_id = target_finding["finding_info"]["uid"]

        if base_id != target_id:
            logger.warning(
                f"finding at index {index} do not have same id: '{base_id}' != '{target_id}'"
            )
            out += 1
            continue

        finding_id = base_id

        base_title = base_finding["finding_info"]["title"]
        target_title = target_finding["finding_info"]["title"]
        if base_title != target_title:
            logger.warning(
                f"finding {finding_id} do not have same title: '{base_title}' != '{target_title}'"
            )
            out += 1

        base_message = base_finding.get("message")
        target_message = target_finding.get("message")
        if finding_id not in SKIP_MESSAGE and base_message != target_message:
            logger.warning(
                f"finding {finding_id} do not have same message: '{base_message}' != '{target_message}'"
            )
            out += 1

        if base_finding["status"] != target_finding["status"]:
            logger.warning(
                f"finding {finding_id} do not have same status: '{base_finding['status']}' != '{target_finding['status']}'"
            )
            out += 1

        if base_finding["severity"] != target_finding["severity"]:
            logger.warning(
                f"finding {finding_id} do not have same severity: '{base_finding['severity']}' != '{target_finding['severity']}'"
            )
            out += 1

    return out


def unique_finding_id(base) -> int:
    out = 0
    ids = []
    for finding in base["findings"]:
        finding_id = finding["finding_info"]["uid"]
        if finding_id in ids:
            logger.warning(f"duplicate finding id: {finding_id}")
            out += 1
        else:
            ids.append(finding_id)
    return out


def compare(base, target) -> int:
    check_sum = sum(
        [
            compare_stat(base, target, "total"),
            compare_stat(base, target, "pass"),
            compare_stat(base, target, "fail"),
            compare_stat(base, target, "warning"),
            compare_stat(base, target, "unknown"),
            compare_stat(base, target, "fail_critical"),
            compare_stat(base, target, "fail_high"),
            compare_stat(base, target, "fail_medium"),
            compare_stat(base, target, "fail_low"),
            compare_stat(base, target, "fail_informational"),
            compare_number_of_findings(base, target),
            compare_findings(base, target),
            unique_finding_id(base),
        ]
    )
    return check_sum


def handle(args) -> int:
    logger.info(
        f"comparing raudit json {args.base_json.name} to {args.target_json.name}"
    )

    if args.base_json.name == args.target_json.name:
        logger.error(f"comparing the same file: {args.base_json.name}")
        return 1

    base_raw = args.base_json.read()
    base = json.loads(base_raw)
    logger.debug(f"loaded raudit base json from: {args.base_json.name}")

    target_raw = args.target_json.read()
    target = json.loads(target_raw)
    logger.debug(f"loaded raudit target json from: {args.target_json.name}")

    check_sum = compare(base, target)
    if check_sum == 0:
        logger.info("valid, all checks passed")
        return 0

    logger.error(f"invalid, {check_sum} checks failed")
    if (
        not args.no_ask_changes
        and input("\nDo you want to accept changes? y/[n] ").lower() == "y"
    ):
        save_json(args.base_json.name, target)
    return 0


def setup_logging(log_level: str = "INFO"):
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(levelname)s %(message)s\x1b[39m")
    logging.addLevelName(logging.DEBUG, "\x1b[36m[*]")
    logging.addLevelName(logging.INFO, "\x1b[32m[+]")
    logging.addLevelName(logging.WARNING, "\x1b[33m[?]")
    logging.addLevelName(logging.ERROR, "\x1b[31m[!]")
    logging.addLevelName(logging.CRITICAL, "\x1b[31m[!!!]")
    handler.setFormatter(formatter)
    logging.basicConfig(level=getattr(logging, log_level.upper()), handlers=[handler])


def cli() -> int:
    parser = argparse.ArgumentParser(
        description="%(prog)s raudit JSON comparator.",
    )

    parser.add_argument(
        "--logging",
        help="logging level, debug, info, error, critical",
        default="info",
    )

    parser.add_argument(
        "-b",
        "--base-json",
        help="base json file",
        type=argparse.FileType("r"),
        default="base.json",
    )
    parser.add_argument(
        "-t",
        "--target-json",
        help="target json file",
        type=argparse.FileType("r"),
        default="target.json",
    )
    parser.add_argument(
        "--no-ask-changes",
        help="do not ask to accept changes",
        action="store_true",
    )

    args = parser.parse_args()

    setup_logging(args.logging)

    try:
        return handle(args)
    except Exception as e:
        logger.error(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(cli())
