"""Minimal CLI for the standalone prompt evidence collector."""

from __future__ import annotations

import argparse
import json

from .collector import PromptEvidenceCollector


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Native readback: store root, permissions, receipt directory state."""
    collector = PromptEvidenceCollector()
    report = {
        "schema": "ellmos.prompt-evidence-collector-doctor.v1",
        "store_root": str(collector._store_root),
        "raw_dir_exists": collector.raw_dir.is_dir(),
        "receipt_dir_exists": collector.receipt_dir.is_dir(),
        "receipt_count": len(list(collector.receipt_dir.glob("*.json"))),
    }
    print(json.dumps(report, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="prompt-evidence-collector")
    sub = parser.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor", help="native store readback (no capture)")
    doctor.set_defaults(func=_cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
