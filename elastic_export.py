"""Push patch scan reports to Elasticsearch for Kibana dashboards."""

from __future__ import annotations

import hashlib
from typing import Any

from config import (
    ELASTICSEARCH_ENABLED,
    ELASTICSEARCH_INDEX_PREFIX,
    ELASTICSEARCH_PASSWORD,
    ELASTICSEARCH_URL,
    ELASTICSEARCH_USER,
)

SCAN_INDEX = f"{ELASTICSEARCH_INDEX_PREFIX}-scans"
NODE_INDEX = f"{ELASTICSEARCH_INDEX_PREFIX}-nodes"
PACKAGE_INDEX = f"{ELASTICSEARCH_INDEX_PREFIX}-packages"


def _scan_id(report: dict[str, Any]) -> str:
    key = f"{report.get('start_time')}|{report.get('proxmox_host')}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _cluster_host_label(cluster_host: str) -> str:
    return cluster_host.replace("https://", "").replace("http://", "").rstrip("/")


def build_documents(report: dict[str, Any]) -> tuple[list[dict], list[dict], list[dict]]:
    scan_time = report.get("scan_time") or report.get("start_time")
    scan_id = _scan_id(report)
    summary = report.get("summary") or {}

    scan_doc = {
        "_index": SCAN_INDEX,
        "_id": scan_id,
        "_source": {
            "@timestamp": scan_time,
            "scan_id": scan_id,
            "start_time": report.get("start_time"),
            "end_time": report.get("end_time"),
            "duration_seconds": report.get("duration_seconds"),
            "proxmox_host": report.get("proxmox_host"),
            "proxmox_hosts": report.get("proxmox_hosts") or [],
            "nodes_total": summary.get("nodes_total", 0),
            "nodes_online": summary.get("nodes_online", 0),
            "nodes_failed": summary.get("nodes_failed", 0),
            "updates_total": summary.get("updates_total", 0),
            "security_updates": summary.get("security_updates", 0),
            "ordinary_updates": summary.get("ordinary_updates", 0),
        },
    }

    node_docs = []
    package_docs = []

    for node in report.get("nodes") or []:
        node_name = node.get("name") or "unknown"
        cluster_host = node.get("cluster_host") or ""
        node_doc_id = f"{scan_id}-{node_name}-{_cluster_host_label(cluster_host)}"

        node_docs.append(
            {
                "_index": NODE_INDEX,
                "_id": node_doc_id,
                "_source": {
                    "@timestamp": scan_time,
                    "scan_id": scan_id,
                    "node_name": node_name,
                    "cluster_host": cluster_host,
                    "cluster_host_label": _cluster_host_label(cluster_host),
                    "status": node.get("status", "unknown"),
                    "reachable": bool(node.get("reachable")),
                    "updates_total": node.get("updates_total", 0),
                    "security_updates": node.get("security_updates", 0),
                    "ordinary_updates": node.get("ordinary_updates", 0),
                    "error": node.get("error"),
                },
            }
        )

        for package in node.get("packages") or []:
            package_name = package.get("name") or "unknown"
            package_doc_id = f"{node_doc_id}-{package_name}"

            package_docs.append(
                {
                    "_index": PACKAGE_INDEX,
                    "_id": package_doc_id,
                    "_source": {
                        "@timestamp": scan_time,
                        "scan_id": scan_id,
                        "node_name": node_name,
                        "cluster_host": cluster_host,
                        "cluster_host_label": _cluster_host_label(cluster_host),
                        "package_name": package_name,
                        "current_version": package.get("current_version"),
                        "available_version": package.get("available_version"),
                        "update_type": package.get("type", "ordinary"),
                    },
                }
            )

    return [scan_doc], node_docs, package_docs


def _create_client():
    from elasticsearch import Elasticsearch

    kwargs: dict[str, Any] = {"hosts": [ELASTICSEARCH_URL]}
    if ELASTICSEARCH_USER and ELASTICSEARCH_PASSWORD:
        kwargs["basic_auth"] = (ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD)

    return Elasticsearch(**kwargs)


def ensure_indices(client) -> None:
    indices = {
        SCAN_INDEX: {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "scan_id": {"type": "keyword"},
                    "start_time": {"type": "date"},
                    "end_time": {"type": "date"},
                    "duration_seconds": {"type": "float"},
                    "proxmox_host": {"type": "keyword"},
                    "proxmox_hosts": {"type": "keyword"},
                    "nodes_total": {"type": "integer"},
                    "nodes_online": {"type": "integer"},
                    "nodes_failed": {"type": "integer"},
                    "updates_total": {"type": "integer"},
                    "security_updates": {"type": "integer"},
                    "ordinary_updates": {"type": "integer"},
                }
            }
        },
        NODE_INDEX: {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "scan_id": {"type": "keyword"},
                    "node_name": {"type": "keyword"},
                    "cluster_host": {"type": "keyword"},
                    "cluster_host_label": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "reachable": {"type": "boolean"},
                    "updates_total": {"type": "integer"},
                    "security_updates": {"type": "integer"},
                    "ordinary_updates": {"type": "integer"},
                    "error": {"type": "text"},
                }
            }
        },
        PACKAGE_INDEX: {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "scan_id": {"type": "keyword"},
                    "node_name": {"type": "keyword"},
                    "cluster_host": {"type": "keyword"},
                    "cluster_host_label": {"type": "keyword"},
                    "package_name": {"type": "keyword"},
                    "current_version": {"type": "keyword"},
                    "available_version": {"type": "keyword"},
                    "update_type": {"type": "keyword"},
                }
            }
        },
    }

    for index_name, body in indices.items():
        if not client.indices.exists(index=index_name):
            client.indices.create(index=index_name, mappings=body["mappings"])


def export_report(report: dict[str, Any]) -> dict[str, int]:
    if not ELASTICSEARCH_ENABLED:
        return {"enabled": False, "indexed": 0}

    from elasticsearch import helpers

    client = _create_client()
    ensure_indices(client)

    scan_docs, node_docs, package_docs = build_documents(report)
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
