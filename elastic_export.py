"""Push ProxWatch patch scan reports to Elasticsearch for Kibana dashboards."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from config import (
    ELASTICSEARCH_ENABLED,
    ELASTICSEARCH_INDEX_PREFIX,
    ELASTICSEARCH_PASSWORD,
    ELASTICSEARCH_URL,
    ELASTICSEARCH_USER,
    OUTPUT_DIR,
)

SCAN_INDEX = f"{ELASTICSEARCH_INDEX_PREFIX}-scans"
NODE_INDEX = f"{ELASTICSEARCH_INDEX_PREFIX}-nodes"
PACKAGE_INDEX = f"{ELASTICSEARCH_INDEX_PREFIX}-packages"

INDICES = (SCAN_INDEX, NODE_INDEX, PACKAGE_INDEX)


def list_report_filenames(directory: str | None = None) -> list[str]:
    directory = directory or OUTPUT_DIR
    if not os.path.isdir(directory):
        return []
    return sorted(
        filename
        for filename in os.listdir(directory)
        if filename.startswith("patch_report_") and filename.endswith(".json")
    )


def export_context_for_report(
    report_path: str,
    *,
    output_dir: str | None = None,
) -> tuple[int, str, dict[str, Any] | None]:
    """scan_index, report_file basename, and prior scan summary for delta fields."""
    output_dir = output_dir or OUTPUT_DIR
    report_file = os.path.basename(report_path)
    files = list_report_filenames(output_dir)
    if report_file not in files:
        files = sorted(files + [report_file])

    scan_index = files.index(report_file) + 1
    previous_summary = None
    position = files.index(report_file)
    if position > 0:
        prev_path = os.path.join(output_dir, files[position - 1])
        with open(prev_path, encoding="utf-8") as handle:
            prev_report = json.load(handle)
        prev_summary = prev_report.get("summary") or {}
        total_updates = prev_summary.get("total_updates") or prev_summary.get("updates_total")
        previous_summary = {
            "duration_seconds": prev_report.get("duration_seconds"),
            "total_updates": total_updates,
            "updates_total": total_updates,
        }

    return scan_index, report_file, previous_summary


def export_saved_report(
    report: dict[str, Any],
    report_path: str,
    *,
    output_dir: str | None = None,
) -> dict[str, int]:
    scan_index, report_file, previous_summary = export_context_for_report(
        report_path,
        output_dir=output_dir,
    )
    return export_report(
        report,
        scan_index=scan_index,
        report_file=report_file,
        previous_summary=previous_summary,
    )


def _first(*values: Any, default: Any = None) -> Any:
    for value in values:
        if value is not None:
            return value
    return default


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value or default)
    except (TypeError, ValueError):
        return default


def _scan_id(report: dict[str, Any]) -> str:
    existing_scan_id = report.get("scan_id")
    if existing_scan_id:
        return str(existing_scan_id)

    key = f"{report.get('start_time')}|{report.get('project_name')}|{report.get('proxmox_host')}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _cluster_host_label(cluster_host: str) -> str:
    return (cluster_host or "").replace("https://", "").replace("http://", "").rstrip("/")


def _updates_for_node(node: dict[str, Any]) -> list[dict[str, Any]]:
    return node.get("updates") or node.get("packages") or []


def build_documents(
    report: dict[str, Any],
    *,
    scan_index: int | None = None,
    report_file: str | None = None,
    previous_summary: dict[str, Any] | None = None,
) -> tuple[list[dict], list[dict], list[dict]]:
    scan_time = _first(report.get("generated_at"), report.get("scan_time"), report.get("start_time"))
    scan_id = _scan_id(report)
    summary = report.get("summary") or {}
    scan_label = (scan_time or "").replace("T", " ").split(".")[0]
    duration = _as_float(report.get("duration_seconds"))

    total_updates = _as_int(_first(summary.get("total_updates"), summary.get("updates_total")))
    total_security_updates = _as_int(
        _first(summary.get("total_security_updates"), summary.get("security_updates"))
    )
    total_ordinary_updates = _as_int(
        _first(summary.get("total_ordinary_updates"), summary.get("ordinary_updates"))
    )
    nodes_offline = _as_int(summary.get("nodes_offline"))
    unreachable_nodes = _as_int(_first(summary.get("unreachable_nodes"), summary.get("nodes_failed")))
    nodes_failed = nodes_offline + unreachable_nodes

    prev_duration = _as_float((previous_summary or {}).get("duration_seconds"))
    prev_updates = _as_int(
        _first(
            (previous_summary or {}).get("total_updates"),
            (previous_summary or {}).get("updates_total"),
        )
    )

    node_update_counts = [
        _as_int(_first(node.get("update_count_total"), node.get("updates_total")))
        for node in report.get("nodes") or []
    ]

    security_package_count = sum(
        1
        for node in report.get("nodes") or []
        for package in _updates_for_node(node)
        if _first(package.get("update_type"), package.get("type")) == "security"
    )
    version_changed_count = sum(
        1
        for node in report.get("nodes") or []
        for package in _updates_for_node(node)
        if (
            package.get("current_version")
            and package.get("available_version")
            and package.get("current_version") != package.get("available_version")
        )
    )

    scan_doc = {
        "_index": SCAN_INDEX,
        "_id": scan_id,
        "_source": {
            "@timestamp": scan_time,
            "project_name": report.get("project_name", "ProxWatch"),
            "report_type": report.get("report_type", "patch_level_report"),
            "scan_id": scan_id,
            "scan_index": scan_index,
            "scan_label": scan_label,
            "report_file": report_file,
            "environment": report.get("environment"),
            "scanner_version": report.get("scanner_version"),
            "start_time": report.get("start_time"),
            "end_time": report.get("end_time"),
            "generated_at": scan_time,
            "duration_seconds": duration,
            "duration_delta": round(duration - prev_duration, 2) if previous_summary else 0.0,
            "updates_delta": total_updates - prev_updates if previous_summary else 0,
            "classification_note": _first(
                report.get("classification_note"),
                report.get("security_classification_note"),
            ),
            "proxmox_host": _first(report.get("proxmox_host"), (report.get("proxmox_hosts") or [None])[0]),
            "proxmox_hosts": report.get("proxmox_hosts") or [],
            "nodes_total": _as_int(summary.get("nodes_total")),
            "nodes_online": _as_int(summary.get("nodes_online")),
            "nodes_offline": nodes_offline,
            "unreachable_nodes": unreachable_nodes,
            "nodes_with_updates": _as_int(summary.get("nodes_with_updates")),
            "nodes_fully_updated": _as_int(summary.get("nodes_fully_updated")),
            "total_updates": total_updates,
            "total_security_updates": total_security_updates,
            "total_ordinary_updates": total_ordinary_updates,
            "nodes_failed": nodes_failed,
            "updates_total": total_updates,
            "security_updates": total_security_updates,
            "ordinary_updates": total_ordinary_updates,
            "min_node_updates": min(node_update_counts) if node_update_counts else 0,
            "max_node_updates": max(node_update_counts) if node_update_counts else 0,
            "security_package_count": security_package_count,
            "version_changed_count": version_changed_count,
        },
    }

    node_docs = []
    package_docs = []

    for node in report.get("nodes") or []:
        node_name = _first(node.get("node_name"), node.get("name"), default="unknown")
        cluster_host = node.get("cluster_host") or ""
        host_label = _cluster_host_label(cluster_host)
        node_doc_id = f"{scan_id}-{node_name}-{host_label}"

        update_count_total = _as_int(_first(node.get("update_count_total"), node.get("updates_total")))
        update_count_security = _as_int(
            _first(node.get("update_count_security"), node.get("security_updates"))
        )
        update_count_ordinary = _as_int(
            _first(node.get("update_count_ordinary"), node.get("ordinary_updates"))
        )
        scan_success = bool(_first(node.get("scan_success"), node.get("reachable"), default=False))
        error_message = _first(node.get("error_message"), node.get("error"))

        node_docs.append(
            {
                "_index": NODE_INDEX,
                "_id": node_doc_id,
                "_source": {
                    "@timestamp": scan_time,
                    "project_name": report.get("project_name", "ProxWatch"),
                    "report_type": report.get("report_type", "patch_level_report"),
                    "scan_id": scan_id,
                    "scan_index": scan_index,
                    "scan_label": scan_label,
                    "report_file": report_file,
                    "environment": report.get("environment"),
                    "scanner_version": report.get("scanner_version"),
                    "node_name": node_name,
                    "cluster_host": cluster_host,
                    "cluster_host_label": host_label,
                    "node_host_label": f"{node_name} @ {host_label}",
                    "status": node.get("status", "unknown"),
                    "ip_address": node.get("ip_address"),
                    "proxmox_version": node.get("proxmox_version"),
                    "kernel_version": node.get("kernel_version"),
                    "last_checked": node.get("last_checked"),
                    "scan_success": scan_success,
                    "reachable": scan_success,
                    "update_status": node.get("update_status"),
                    "error_message": error_message,
                    "error": error_message,
                    "update_count_total": update_count_total,
                    "update_count_security": update_count_security,
                    "update_count_ordinary": update_count_ordinary,
                    "updates_total": update_count_total,
                    "security_updates": update_count_security,
                    "ordinary_updates": update_count_ordinary,
                },
            }
        )

        for package_index, package in enumerate(_updates_for_node(node)):
            package_name = _first(
                package.get("package_name"),
                package.get("name"),
                default="unknown",
            )
            package_doc_id = f"{node_doc_id}-{package_index}-{package_name}"
            current_version = package.get("current_version")
            available_version = package.get("available_version")
            update_type = _first(package.get("update_type"), package.get("type"), default="ordinary")
            version_changed = (
                bool(current_version)
                and bool(available_version)
                and current_version != available_version
            )

            package_docs.append(
                {
                    "_index": PACKAGE_INDEX,
                    "_id": package_doc_id,
                    "_source": {
                        "@timestamp": scan_time,
                        "project_name": report.get("project_name", "ProxWatch"),
                        "report_type": report.get("report_type", "patch_level_report"),
                        "scan_id": scan_id,
                        "scan_index": scan_index,
                        "scan_label": scan_label,
                        "report_file": report_file,
                        "environment": report.get("environment"),
                        "scanner_version": report.get("scanner_version"),
                        "node_name": node_name,
                        "cluster_host": cluster_host,
                        "cluster_host_label": host_label,
                        "node_host_label": f"{node_name} @ {host_label}",
                        "package_name": package_name,
                        "current_version": current_version,
                        "available_version": available_version,
                        "version_changed": version_changed,
                        "update_type": update_type,
                        "source": package.get("source"),
                        "description": package.get("description"),
                        "severity": package.get("severity"),
                        "classification_note": package.get("classification_note"),
                    },
                }
            )

    return [scan_doc], node_docs, package_docs


def _index_mappings() -> dict[str, dict]:
    common_scan_fields = {
        "@timestamp": {"type": "date"},
        "project_name": {"type": "keyword"},
        "report_type": {"type": "keyword"},
        "scan_id": {"type": "keyword"},
        "scan_index": {"type": "integer"},
        "scan_label": {"type": "keyword"},
        "report_file": {"type": "keyword"},
        "environment": {"type": "keyword"},
        "scanner_version": {"type": "keyword"},
    }

    return {
        SCAN_INDEX: {
            "mappings": {
                "properties": {
                    **common_scan_fields,
                    "start_time": {"type": "date"},
                    "end_time": {"type": "date"},
                    "generated_at": {"type": "date"},
                    "duration_seconds": {"type": "float"},
                    "duration_delta": {"type": "float"},
                    "updates_delta": {"type": "integer"},
                    "classification_note": {"type": "text"},
                    "proxmox_host": {"type": "keyword"},
                    "proxmox_hosts": {"type": "keyword"},
                    "nodes_total": {"type": "integer"},
                    "nodes_online": {"type": "integer"},
                    "nodes_offline": {"type": "integer"},
                    "unreachable_nodes": {"type": "integer"},
                    "nodes_with_updates": {"type": "integer"},
                    "nodes_fully_updated": {"type": "integer"},
                    "total_updates": {"type": "integer"},
                    "total_security_updates": {"type": "integer"},
                    "total_ordinary_updates": {"type": "integer"},
                    "nodes_failed": {"type": "integer"},
                    "updates_total": {"type": "integer"},
                    "security_updates": {"type": "integer"},
                    "ordinary_updates": {"type": "integer"},
                    "min_node_updates": {"type": "integer"},
                    "max_node_updates": {"type": "integer"},
                    "security_package_count": {"type": "integer"},
                    "version_changed_count": {"type": "integer"},
                }
            }
        },
        NODE_INDEX: {
            "mappings": {
                "properties": {
                    **common_scan_fields,
                    "node_name": {"type": "keyword"},
                    "cluster_host": {"type": "keyword"},
                    "cluster_host_label": {"type": "keyword"},
                    "node_host_label": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "ip_address": {"type": "ip", "ignore_malformed": True},
                    "proxmox_version": {"type": "keyword"},
                    "kernel_version": {"type": "keyword"},
                    "last_checked": {"type": "date"},
                    "scan_success": {"type": "boolean"},
                    "reachable": {"type": "boolean"},
                    "update_status": {"type": "keyword"},
                    "update_count_total": {"type": "integer"},
                    "update_count_security": {"type": "integer"},
                    "update_count_ordinary": {"type": "integer"},
                    "updates_total": {"type": "integer"},
                    "security_updates": {"type": "integer"},
                    "ordinary_updates": {"type": "integer"},
                    "error_message": {"type": "text"},
                    "error": {"type": "text"},
                }
            }
        },
        PACKAGE_INDEX: {
            "mappings": {
                "properties": {
                    **common_scan_fields,
                    "node_name": {"type": "keyword"},
                    "cluster_host": {"type": "keyword"},
                    "cluster_host_label": {"type": "keyword"},
                    "node_host_label": {"type": "keyword"},
                    "package_name": {"type": "keyword"},
                    "current_version": {"type": "keyword"},
                    "available_version": {"type": "keyword"},
                    "version_changed": {"type": "boolean"},
                    "update_type": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "description": {"type": "text"},
                    "severity": {"type": "keyword"},
                    "classification_note": {"type": "text"},
                }
            }
        },
    }


def _create_client():
    from elasticsearch import Elasticsearch

    kwargs: dict[str, Any] = {"hosts": [ELASTICSEARCH_URL]}
    if ELASTICSEARCH_USER and ELASTICSEARCH_PASSWORD:
        kwargs["basic_auth"] = (ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD)

    return Elasticsearch(**kwargs)


def ensure_indices(client) -> None:
    mappings = _index_mappings()
    for index_name, body in mappings.items():
        if not client.indices.exists(index=index_name):
            client.indices.create(index=index_name, mappings=body["mappings"])


def reset_indices(client) -> None:
    for index_name in INDICES:
        if client.indices.exists(index=index_name):
            client.indices.delete(index=index_name)
    ensure_indices(client)


def export_report(
    report: dict[str, Any],
    *,
    scan_index: int | None = None,
    report_file: str | None = None,
    previous_summary: dict[str, Any] | None = None,
) -> dict[str, int]:
    if not ELASTICSEARCH_ENABLED:
        return {"enabled": False, "indexed": 0}

    from elasticsearch import helpers

    client = _create_client()
    ensure_indices(client)

    scan_docs, node_docs, package_docs = build_documents(
        report,
        scan_index=scan_index,
        report_file=report_file,
        previous_summary=previous_summary,
    )
    all_docs = scan_docs + node_docs + package_docs

    success, errors = helpers.bulk(
        client,
        all_docs,
        raise_on_error=False,
        stats_only=True,
    )

    if errors:
        raise RuntimeError(f"Elasticsearch bulk index failed for {errors} documents")

    return {
        "enabled": True,
        "indexed": success,
        "scans": len(scan_docs),
        "nodes": len(node_docs),
        "packages": len(package_docs),
    }
