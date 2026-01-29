#!/usr/bin/env python3

import shutil
import argparse
import logging
import sys
import json


SKIP_MESSAGE = ["UPT_001"]


def compare_stat(base, target, stat_name) -> int:
    """Compare a single stat."""

    if "stats" not in base:
        logging.error("wrong json format, missing stats from base")
        return 1
    if "stats" not in target:
        logging.error("wrong json format, missing stats from target")
        return 1

    if stat_name not in base["stats"]:
        logging.error(f"wrong json format, missing stat '{stat_name}' from base")
        return 1
    if stat_name not in target["stats"]:
        logging.error(f"wrong json format, missing stat '{stat_name}' from target")
        return 1

    base_stat = base["stats"][stat_name]
    target_stat = target["stats"][stat_name]

    if base_stat != target_stat:
        logging.warning(
            f"stat {stat_name} are not the same: '{base_stat}' != '{target_stat}'"
        )
        return 1
    else:
        logging.debug(f"valid stat '{stat_name}'")
        return 0


def compare_number_of_checks(base, target) -> int:
    """Compare the total ammount of checks."""

    if "checks" not in base:
        logging.error("wrong json format, missing checks from base")
        return 1
    if "checks" not in target:
        logging.error("wrong json format, missing checks from target")
        return 1

    num_base = len(base["checks"])
    num_target = len(target["checks"])
    if num_base != num_target:
        logging.warning(
            f"number of checks are not the same: '{num_base}' != '{num_target}'"
        )
        return 1
    else:
        logging.debug(f"valid number of checks '{num_base}'")
        return 0


def compare_checks(base, target) -> int:
    """Compare all checks, one by one.

    Ensure they have the same id, title, message, and state.
    """

    out = 0
    for index in range(len(base["checks"])):
        base_check = base["checks"][index]
        target_check = target["checks"][index]

        if base_check["id"] != target_check["id"]:
            logging.warning(
                f"check at index {index} do not have same id: '{base_check['id']}' != '{target_check['id']}'"
            )
            out += 1
            continue

        check_id = base_check["id"]

        if base_check["title"] != target_check["title"]:
            logging.warning(
                f"check {check_id} do not have same title: '{base_check['title']}' != '{target_check['title']}'"
            )
            out += 1

        if (
            check_id not in SKIP_MESSAGE
            and base_check["message"] != target_check["message"]
        ):
            logging.warning(
                f"check {check_id} do not have same message: '{base_check['message']}' != '{target_check['message']}'"
            )
            out += 1

        if base_check["state"] != target_check["state"]:
            logging.warning(
                f"check {check_id} do not have same state: '{base_check['state']}' != '{target_check['state']}'"
            )
            out += 1

    return out


def unique_check_id(base) -> int:
    out = 0
    ids = []
    for check in base["checks"]:
        id = check["id"]
        if id in ids:
            logging.warning(f"duplicate check id: {id}")
            out += 1
        else:
            ids.append(id)
    return out


def compare(base, target) -> int:
    check_sum = sum(
        [
            compare_stat(base, target, "total"),
            compare_stat(base, target, "passed"),
            compare_stat(base, target, "failed"),
            compare_stat(base, target, "error"),
            compare_stat(base, target, "waiting"),
            compare_number_of_checks(base, target),
            compare_checks(base, target),
            unique_check_id(base),
        ]
    )
    return check_sum


def handle(args) -> int:
    logging.info(
        f"comparing raudit json {args.base_json.name} to {args.target_json.name}"
    )

    if args.base_json.name == args.target_json.name:
        logging.error(f"comparing the same file: {args.base_json.name}")
        return 1

    base_raw = args.base_json.read()
    base = json.loads(base_raw)
    logging.debug(f"loaded raudit base json from: {args.base_json.name}")

    target_raw = args.target_json.read()
    target = json.loads(target_raw)
    logging.debug(f"loaded raudit target json from: {args.target_json.name}")

    check_sum = compare(base, target)
    if check_sum == 0:
        logging.info("valid, all checks passed")
        return 0

    logging.error(f"invalid, {check_sum} checks failed")
    if not args.no_ask_changes:
        if input("\nDo you want to accept changes? y/[n] ").lower() == "y":
            shutil.copyfile(args.target_json.name, args.base_json.name)


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
        logging.error(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(cli())
