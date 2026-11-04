"""All logging settings live here. Any other file only needs:

    import logger_config
    log = logger_config.get_logger(__name__)

main.py calls add_args() and setup() once at startup.
"""
import argparse
import logging
import os

LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR"]
DEFAULT_LEVEL = "INFO"
FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"

# Log level used to report each check's result
STATUS_LEVELS = {"PASS": logging.INFO, "WARN": logging.WARNING, "FAIL": logging.ERROR, "ERROR": logging.ERROR}


def _level(value):
    level = value.upper()
    if level not in LEVELS:
        raise argparse.ArgumentTypeError(f"invalid log level '{value}' (choose from {', '.join(LEVELS)})")
    return level


def add_args(parser):
    # argparse also runs type= on string defaults, so a bad LOG_LEVEL env var is rejected too
    parser.add_argument("--log-level", type=_level, default=os.environ.get("LOG_LEVEL") or DEFAULT_LEVEL,
                        help=", ".join(LEVELS))


def setup(level=DEFAULT_LEVEL):
    logging.basicConfig(level=level, format=FORMAT)


def get_logger(name):
    return logging.getLogger(name)


def status_level(status):
    return STATUS_LEVELS.get(status, logging.WARNING)
