"""Command-line entry point: credmon scan / credmon notify."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import UTC, datetime

from credmon import __version__
from credmon.collect import Credential, parse_graph_datetime
from credmon.config import Config
from credmon.notify import client_from_env, sync, tally
from credmon.report import display_status, load_json, type_label
from credmon.runner import run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="credmon", description=__doc__)
    parser.add_argument("--version", action="version", version=f"credmon {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
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
    notify.add_argument("--dry-run", action="store_true", help="print planned issue changes without touching GitHub")

    for p in (scan, notify):  # ISO 8601 clock override for reproducible runs and tests
        p.add_argument("--now", help=argparse.SUPPRESS)
    return parser


def format_table(records: list[Credential]) -> str:
    headers = ("Status", "Object", "App", "Type", "Name", "Expires", "Days")
    rows = [
        (
            display_status(c),
            "App" if c.object_type == "application" else "SP",
            c.display_name,
            type_label(c),
            c.name,
            f"{c.end:%Y-%m-%d}",
            str(c.days),
        )
        for c in records
    ]
    widths = [max(len(v) for v in column) for column in zip(headers, *rows, strict=True)]

    def line(row: tuple[str, ...]) -> str:
        last = len(row) - 1
        return "  ".join(
            v.rjust(w) if i == last else v.ljust(w) for i, (v, w) in enumerate(zip(row, widths, strict=True))
        )

    return "\n".join([line(headers), "  ".join("-" * w for w in widths), *map(line, rows)])


def cmd_scan(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    now = parse_graph_datetime(args.now) or datetime.now(UTC)
    result = run_scan(config, now, out_dir=None if args.format == "table" else args.out)
    print(result.headline(), file=sys.stderr)
    print("  ".join(f"{k}={v}" for k, v in result.counts.items() if v), file=sys.stderr)
    if result.paths:
        print(f"Wrote {result.paths.summary}, {result.paths.csv}, {result.paths.json}", file=sys.stderr)
    else:
        print(format_table(result.records))
    if result.failed:
        print(f"credmon: credentials at or above fail_on={config.fail_on}", file=sys.stderr)
        return 1
    return 0


def cmd_notify(args: argparse.Namespace) -> int:
    now = parse_graph_datetime(args.now) or datetime.now(UTC)
    client = None if args.dry_run else client_from_env()
    actions = sync(load_json(args.report), client, now)
    for a in actions:
        print(("would " if args.dry_run else "") + a.describe(), file=sys.stderr)
    print(tally(actions) + (" (dry run)" if args.dry_run else ""), file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    return {"scan": cmd_scan, "notify": cmd_notify}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
