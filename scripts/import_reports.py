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
from elastic_export import (
    export_context_for_report,
    export_report,
    list_report_filenames,
    reset_indices,
    _create_client,
)


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

    files = [os.path.join(args.dir, name) for name in list_report_filenames(args.dir)]
    if not files:
        print(f"No report files found in {args.dir}")
        sys.exit(0)

    if args.reset:
        print("Resetting Elasticsearch indices...")
        reset_indices(_create_client())

    total_indexed = 0

    for path in files:
        with open(path, encoding="utf-8") as handle:
            report = json.load(handle)

        scan_index, report_file, previous_summary = export_context_for_report(
            path,
            output_dir=args.dir,
        )
        summary = report.get("summary") or {}
        total_updates = summary.get("total_updates") or summary.get("updates_total")

        result = export_report(
            report,
            scan_index=scan_index,
            report_file=report_file,
            previous_summary=previous_summary,
        )
        if not result.get("enabled"):
            print("Elasticsearch is disabled. Set ELASTICSEARCH_ENABLED=true in .env")
            sys.exit(1)

        total_indexed += result["indexed"]
        print(
            f"Imported #{scan_index} {report_file}: "
            f"{result['indexed']} docs "
            f"(duration={report.get('duration_seconds')}s, "
            f"updates={total_updates})"
        )

    print(f"Done. {len(files)} reports indexed, {total_indexed} total documents")


if __name__ == "__main__":
    main()
