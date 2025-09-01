#!/usr/bin/env python3

import argparse
import logging
import sys
import json

try:
    from jinja2 import DictLoader, Environment
except ImportError:
    print("To generate reports install jinja2")
    print("run: pip install jinja2")
    raise


def handle(args) -> int:
    logging.info(f"reading raudit json result from {args.raudit_json.name}")
    input = args.raudit_json.read()
    result = json.loads(input)

    logging.info(f"loading template file {args.template.name}")
    template_content = args.template.read()
    env = Environment(
        loader=DictLoader({"template": template_content}),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("template")

    out = template.render(**result)

    logging.info(f"writing output to {args.output.name}")
    args.output.write(out)
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
        description="%(prog)s raudit JSON to HTML.",
    )

    parser.add_argument(
        "--logging",
        help="logging level, DEBUG, INFO, ERROR, CRITICAL",
        default="INFO",
    )

    parser.add_argument(
        "raudit_json",
        nargs="?",  # required to be able to pipe to stdin
        help="JSON raudit results",
        type=argparse.FileType("r"),
        default=sys.stdin,
    )
    parser.add_argument(
        "-t",
        "--template",
        help="template file",
        type=argparse.FileType("r"),
        default="template.html.jinja",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="output file",
        type=argparse.FileType("w"),
        default=sys.stdout,
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
