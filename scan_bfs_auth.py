#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from g.bfs_scan_service import apply_scan_report, preview_scan, set_token_bound_override


BASE_DIR = Path(__file__).resolve().parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BFS historical auth preview/apply tool")
    sub = parser.add_subparsers(dest="command", required=True)
    preview = sub.add_parser("preview", help="scan only and create a redacted report")
    preview.add_argument("paths", nargs="*", type=Path, default=[BASE_DIR / "converted_auth" / "cpa"])
    preview.add_argument("--report-dir", type=Path, default=BASE_DIR / "data" / "bfs_scans")
    apply_cmd = sub.add_parser("apply", help="apply one previously generated report")
    apply_cmd.add_argument("report", type=Path)
    override = sub.add_parser("override", help="bind a BFS override to the current token")
    override.add_argument("auth_file", type=Path)
    override.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    if args.command == "preview":
        result = preview_scan(args.paths, args.report_dir)
    elif args.command == "apply":
        result = apply_scan_report(args.report)
    else:
        result = set_token_bound_override(args.auth_file, reason=args.reason)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
