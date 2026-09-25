"""Command-line entry point: credmon scan / credmon notify."""

from __future__ import annotations

import argparse
import sys

from credmon import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="credmon", description=__doc__)
    parser.add_argument("--version", action="version", version=f"credmon {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan the tenant and write reports")
    scan.add_argument("--config", default="config.yaml", help="path to config.yaml")
    scan.add_argument("--out", default="report", help="output directory for reports")
    scan.add_argument(
        "--format",
        choices=["table", "files"],
        default="files",
        help="print a table to stdout, or write summary.md/credentials.csv/credentials.json",
    )

    notify = sub.add_parser("notify", help="open or close GitHub issues from a report")
    notify.add_argument("--report", default="report/credentials.json", help="path to credentials.json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(f"credmon {args.command}: not implemented yet", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
