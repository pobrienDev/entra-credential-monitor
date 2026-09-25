"""Command-line entry point: credmon scan / credmon notify."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone

from credmon import __version__
from credmon.classify import classify, should_fail, summarize
from credmon.collect import Credential, collect, parse_graph_datetime
from credmon.config import Config
from credmon.graph import get_session
from credmon.report import display_status, type_label, write_reports


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
    session = get_session()
    result = collect(session, config)
    records = classify(result.credentials, config, now)
    print(
        f"Scanned {result.applications_scanned} applications and "
        f"{result.saml_service_principals_scanned} SAML service principals · "
        f"{len(result.credentials)} credentials"
        + (f" · skipped {result.first_party_skipped} first-party" if result.first_party_skipped else ""),
        file=sys.stderr,
    )
    counts = summarize(records)
    print(
        "  ".join(f"{k}={v}" for k, v in counts.items() if v),
        file=sys.stderr,
    )
    if args.format == "table":
        print(format_table(records))
    else:
        paths = write_reports(records, result, now, args.out)
        print(f"Wrote {paths.summary}, {paths.csv}, {paths.json}", file=sys.stderr)
    if should_fail(records, config):
        print(f"credmon: credentials at or above fail_on={config.fail_on}", file=sys.stderr)
        return 1
    return 0


def cmd_notify(args: argparse.Namespace) -> int:
    print("credmon notify: implemented in Phase 5", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    return {"scan": cmd_scan, "notify": cmd_notify}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
