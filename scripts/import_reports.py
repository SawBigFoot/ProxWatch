"""Backfill existing JSON reports into Elasticsearch."""

from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from config import OUTPUT_DIR
from elastic_export import export_report, reset_indices, _create_client


def iter_report_files(directory: str):
    for filename in sorted(os.listdir(directory)):
        if filename.startswith("patch_report_") and filename.endswith(".json"):
            yield os.path.join(directory, filename)


def main():
    parser = argparse.ArgumentParser(description="Import patch reports into Elasticsearch")
    parser.add_argument(
        "--dir",
        default=OUTPUT_DIR,
        help=f"Directory containing patch_report_*.json files (default: {OUTPUT_DIR})",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete and recreate Elasticsearch indices before import",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.dir):
        print(f"Directory not found: {args.dir}", file=sys.stderr)
        sys.exit(1)

    files = list(iter_report_files(args.dir))
    if not files:
        print(f"No report files found in {args.dir}")
        sys.exit(0)

    if args.reset:
        print("Resetting Elasticsearch indices...")
        reset_indices(_create_client())

    total_indexed = 0
    previous_summary = None

    for scan_index, path in enumerate(files, start=1):
        with open(path, encoding="utf-8") as handle:
            report = json.load(handle)

        summary = report.get("summary") or {}
        total_updates = summary.get("total_updates") or summary.get("updates_total")

        result = export_report(
            report,
            scan_index=scan_index,
            report_file=os.path.basename(path),
            previous_summary=previous_summary,
        )
        if not result.get("enabled"):
            print("Elasticsearch is disabled. Set ELASTICSEARCH_ENABLED=true in .env")
            sys.exit(1)

        total_indexed += result["indexed"]
        print(
            f"Imported #{scan_index} {os.path.basename(path)}: "
            f"{result['indexed']} docs "
            f"(duration={report.get('duration_seconds')}s, "
            f"updates={total_updates})"
        )
        previous_summary = {
            "duration_seconds": report.get("duration_seconds"),
            "total_updates": total_updates,
            "updates_total": total_updates,
        }

    print(f"Done. {len(files)} reports indexed, {total_indexed} total documents")


if __name__ == "__main__":
    main()
