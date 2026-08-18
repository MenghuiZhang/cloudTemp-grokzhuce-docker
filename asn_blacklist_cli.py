#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from g.asn_blacklist import AsnBlacklistStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage the local ASN blacklist")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    add = sub.add_parser("add")
    add.add_argument("asn")
    add.add_argument("--note", default="")
    remove = sub.add_parser("remove")
    remove.add_argument("asn")
    args = parser.parse_args(argv)
    store = AsnBlacklistStore(Path(__file__).resolve().parent / "data" / "asn_blacklist.json")
    if args.command == "add":
        store.add_manual(args.asn, args.note)
    elif args.command == "remove":
        store.remove(args.asn)
    print(json.dumps({"ok": True, **store.public()}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
