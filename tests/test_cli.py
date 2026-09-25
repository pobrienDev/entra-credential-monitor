from credmon.cli import build_parser


def test_scan_defaults():
    args = build_parser().parse_args(["scan"])
    assert args.command == "scan"
    assert args.config == "config.yaml"
    assert args.format == "files"


def test_notify_defaults():
    args = build_parser().parse_args(["notify"])
    assert args.report == "report/credentials.json"
