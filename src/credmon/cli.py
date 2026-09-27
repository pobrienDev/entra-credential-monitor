"""Command-line entry point: credmon scan / credmon notify."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone

from credmon import __version__
from credmon.collect import Credential, parse_graph_datetime
from credmon.config import Config
from credmon.graph import get_session
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

    scan.add_argument("--now", help=argparse.SUPPRESS)  # ISO 8601 clock override for reproducible runs

    notify = sub.add_parser("notify", help="open or close GitHub issues from a report")
    notify.add_argument("--report", default="report/credentials.json", help="path to credentials.json")
    notify.add_argument("--dry-run", action="store_true", help="print planned issue changes without touching GitHub")
    notify.add_argument("--now", help=argparse.SUPPRESS)
    return parser


def format_table(records: list[Credential]) -> str:
    rows = [
        (
            display_status(c),
            "App" if c.object_type == "application" else "SP",
            c.display_name,
            type_label(c),
            c.name,
            c.end.strftime("%Y-%m-%d"),
            str(c.days),
        )
        for c in records
    ]
    headers = ("Status", "Object", "App", "Type", "Name", "Expires", "Days")
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    last = len(headers) - 1
    line = lambda r: "  ".join(v.rjust(widths[i]) if i == last else v.ljust(widths[i]) for i, v in enumerate(r))
    return "\n".join([line(headers), "  ".join("-" * w for w in widths), *(line(r) for r in rows)])


def cmd_scan(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    now = parse_graph_datetime(args.now) if args.now else datetime.now(timezone.utc)
    result = run_scan(config, now=now, out_dir=None if args.format == "table" else args.out, session=get_session())
    print(result.headline(), file=sys.stderr)
    print("  ".join(f"{k}={v}" for k, v in result.counts.items() if v), file=sys.stderr)
    if args.format == "table":
        print(format_table(result.records))
    else:
        p = result.paths
        print(f"Wrote {p.summary}, {p.csv}, {p.json}", file=sys.stderr)
    if result.failed:
        print(f"credmon: credentials at or above fail_on={config.fail_on}", file=sys.stderr)
        return 1
    return 0


def cmd_notify(args: argparse.Namespace) -> int:
    from credmon.notify import client_from_env, plan_actions, apply_actions

    records, meta = load_json(args.report)
    now = parse_graph_datetime(args.now) if args.now else datetime.now(timezone.utc)
    client = None if args.dry_run else client_from_env()
    open_issues = client.list_open_issues() if client else []
    actions = plan_actions(records, open_issues)
    result = apply_actions(actions, client, now, dry_run=args.dry_run)
    for a in actions:
        print(("would " if args.dry_run else "") + a.describe(), file=sys.stderr)
    print(
        f"notify: {result.count('create')} opened, {result.count('update')} updated, "
        f"{result.count('close')} closed, {result.count('noop')} unchanged"
        + (" (dry run)" if args.dry_run else ""),
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    return {"scan": cmd_scan, "notify": cmd_notify}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
