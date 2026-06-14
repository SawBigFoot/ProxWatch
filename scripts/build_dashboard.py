"""Generate kibana/dashboard.ndjson — one row per report, nuance across scans."""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "kibana" / "dashboard.ndjson"

SCANS = "patchscanner-scans-dv"
NODES = "patchscanner-nodes-dv"
PACKAGES = "patchscanner-packages-dv"


def ref_index(name: str, index_id: str):
    return {"name": name, "type": "index-pattern", "id": index_id}


def search_source(index_ref: str, query: str = ""):
    return json.dumps(
        {
            "query": {"query": query, "language": "kuery"},
            "filter": [],
            "indexRefName": index_ref,
        }
    )


def saved_search(search_id: str, title: str, index_id: str, columns: list[str], sort: list):
    return {
        "type": "search",
        "id": search_id,
        "attributes": {
            "title": title,
            "columns": columns,
            "sort": sort,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": search_source(
                    "kibanaSavedObjectMeta.searchSourceJSON.index"
                )
            },
        },
        "references": [ref_index("kibanaSavedObjectMeta.searchSourceJSON.index", index_id)],
    }


def viz(viz_id: str, title: str, description: str, index_id: str, vis_state: dict):
    return {
        "type": "visualization",
        "id": viz_id,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": description,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": search_source(
                    "kibanaSavedObjectMeta.searchSourceJSON.index"
                )
            },
        },
        "references": [ref_index("kibanaSavedObjectMeta.searchSourceJSON.index", index_id)],
    }


def metric_agg(field: str, label: str, agg_id: str = "1", agg_type: str = "max"):
    return {
        "id": agg_id,
        "enabled": True,
        "type": agg_type,
        "schema": "metric",
        "params": {"field": field, "customLabel": label},
    }


def scan_index_buckets(agg_id: str = "2", schema: str = "segment"):
    return {
        "id": agg_id,
        "enabled": True,
        "type": "terms",
        "schema": schema,
        "params": {
            "field": "scan_index",
            "size": 100,
            "order": {"_key": "asc"},
            "min_doc_count": 1,
            "customLabel": "Scan #",
        },
    }


def bar_params(mode: str = "normal", value_title: str = "Value", series_count: int = 1):
    series = []
    for i in range(1, series_count + 1):
        series.append(
            {
                "show": True,
                "type": "histogram",
                "mode": mode,
                "data": {"label": value_title, "id": str(i)},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True,
                "showCircles": True,
            }
        )
    return {
        "addTooltip": True,
        "addLegend": True,
        "legendPosition": "right",
        "scale": "linear",
        "mode": mode,
        "type": "histogram",
        "grid": {"categoryLines": False},
        "categoryAxes": [
            {
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "bottom",
                "show": True,
                "style": {},
                "scale": {"type": "linear"},
                "labels": {"show": True, "truncate": 100, "rotate": 0},
                "title": {"text": "Scan #"},
            }
        ],
        "valueAxes": [
            {
                "id": "ValueAxis-1",
                "name": "LeftAxis-1",
                "type": "value",
                "position": "left",
                "show": True,
                "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": value_title},
            }
        ],
        "seriesParams": series,
        "addTimeMarker": False,
        "defaultYExtents": False,
        "setYExtents": False,
        "yAxis": {},
    }


def bar_per_scan(viz_id, title, description, field, label, *, mode="normal", metrics=None, value_title="Value"):
    metric_defs = metrics or [(field, label, "1")]
    aggs = [metric_agg(f, lbl, aid) for f, lbl, aid in metric_defs]
    aggs.append(scan_index_buckets(str(len(metric_defs) + 1)))
    return viz(
        viz_id,
        title,
        description,
        SCANS,
        {
            "title": title,
            "type": "histogram",
            "params": bar_params(mode=mode, value_title=value_title, series_count=len(metric_defs)),
            "aggs": aggs,
        },
    )


def build_objects():
    items = []

    # Document-level tables — one row per report/node (no aggregation collapse)
    items.append(
        saved_search(
            "ps-search-all-scans",
            "Scan History — Compare All Reports",
            SCANS,
            [
                "scan_index",
                "scan_label",
                "report_file",
                "duration_seconds",
                "duration_delta",
                "updates_total",
                "updates_delta",
                "nodes_online",
                "nodes_failed",
                "security_updates",
                "ordinary_updates",
                "version_changed_count",
            ],
            [["scan_index", "asc"]],
        )
    )

    items.append(
        saved_search(
            "ps-search-all-nodes",
            "Node Detail — Every Report",
            NODES,
            [
                "scan_index",
                "scan_label",
                "node_host_label",
                "status",
                "updates_total",
                "security_updates",
                "ordinary_updates",
            ],
            [["scan_index", "asc"], ["node_host_label", "asc"]],
        )
    )

    items.append(
        viz(
            "ps-vis-scan-count",
            "Total Reports Indexed",
            "Count of scan documents in Elasticsearch",
            SCANS,
            {
                "title": "Total Reports Indexed",
                "type": "metric",
                "params": {
                    "addTooltip": True,
                    "addLegend": False,
                    "type": "metric",
                    "metric": {
                        "percentageMode": False,
                        "useRanges": False,
                        "colorSchema": "Green to Red",
                        "metricColorMode": "Labels",
                        "labels": {"show": True},
                        "style": {"fontSize": 48, "subText": "reports in reports/"},
                    },
                },
                "aggs": [
                    {
                        "id": "1",
                        "enabled": True,
                        "type": "count",
                        "schema": "metric",
                        "params": {"customLabel": "Reports"},
                    }
                ],
            },
        )
    )

    # Charts with real nuance between scans
    items.append(
        bar_per_scan(
            "ps-vis-duration-bars",
            "Scan Duration per Report (seconds)",
            "Each bar is one report — values differ between runs",
            "duration_seconds",
            "Seconds",
            value_title="Seconds",
        )
    )

    items.append(
        bar_per_scan(
            "ps-vis-duration-delta-bars",
            "Duration Change vs Previous Scan",
            "How much faster/slower each scan was compared to the prior report",
            "duration_delta",
            "Delta (s)",
            value_title="Delta (s)",
        )
    )

    items.append(
        bar_per_scan(
            "ps-vis-version-changed-bars",
            "Packages With Version Changes",
            "Count of packages where current != available version, per report",
            "version_changed_count",
            "Changed",
            value_title="Packages",
        )
    )

    items.append(
        bar_per_scan(
            "ps-vis-updates-bars",
            "Total Updates per Report",
            "One bar per indexed report",
            "updates_total",
            "Updates",
            value_title="Updates",
        )
    )

    items.append(
        bar_per_scan(
            "ps-vis-health-bars",
            "Node Health per Report",
            "Online vs failed nodes for each report",
            "nodes_online",
            "Online",
            mode="grouped",
            metrics=[
                ("nodes_online", "Online", "1"),
                ("nodes_failed", "Failed", "2"),
            ],
            value_title="Nodes",
        )
    )

    # Per-node nuance: 2 bars per scan (one per Proxmox host)
    items.append(
        viz(
            "ps-vis-node-updates-bars",
            "Updates per Node — Every Report",
            "Grouped bars per scan #, split by node @ host",
            NODES,
            {
                "title": "Updates per Node — Every Report",
                "type": "histogram",
                "params": bar_params(mode="grouped", value_title="Updates", series_count=1),
                "aggs": [
                    metric_agg("updates_total", "Updates", "1"),
                    scan_index_buckets("2"),
                    {
                        "id": "3",
                        "enabled": True,
                        "type": "terms",
                        "schema": "group",
                        "params": {
                            "field": "node_host_label",
                            "size": 20,
                            "customLabel": "Node @ host",
                        },
                    },
                ],
            },
        )
    )

    items.append(
        viz(
            "ps-vis-host-bars",
            "Updates per Proxmox Host — Every Report",
            "Grouped bars per scan #, split by cluster_host",
            NODES,
            {
                "title": "Updates per Proxmox Host — Every Report",
                "type": "histogram",
                "params": bar_params(mode="grouped", value_title="Updates", series_count=1),
                "aggs": [
                    metric_agg("updates_total", "Updates", "1", "sum"),
                    scan_index_buckets("2"),
                    {
                        "id": "3",
                        "enabled": True,
                        "type": "terms",
                        "schema": "group",
                        "params": {
                            "field": "cluster_host_label",
                            "size": 10,
                            "customLabel": "Host",
                        },
                    },
                ],
            },
        )
    )

    items.append(
        viz(
            "ps-vis-top-packages",
            "Top Packages Across All Reports",
            "Most listed packages across full scan history",
            PACKAGES,
            {
                "title": "Top Packages Across All Reports",
                "type": "histogram",
                "params": bar_params(mode="normal", value_title="Count", series_count=1),
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                    {
                        "id": "2",
                        "enabled": True,
                        "type": "terms",
                        "schema": "segment",
                        "params": {"field": "package_name", "size": 15, "orderBy": "1"},
                    },
                ],
            },
        )
    )

    items.append(
        viz(
            "ps-vis-update-types",
            "Security vs Ordinary (all packages)",
            "Package type distribution across all indexed data",
            PACKAGES,
            {
                "title": "Security vs Ordinary (all packages)",
                "type": "pie",
                "params": {
                    "addTooltip": True,
                    "addLegend": True,
                    "legendPosition": "right",
                    "isDonut": True,
                },
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                    {
                        "id": "2",
                        "enabled": True,
                        "type": "terms",
                        "schema": "segment",
                        "params": {"field": "update_type", "size": 5},
                    },
                ],
            },
        )
    )

    return items


def build_dashboard():
    layout = [
        ("search", "ps-search-all-scans", 0, 0, 48, 24),
        ("visualization", "ps-vis-scan-count", 0, 24, 8, 10),
        ("visualization", "ps-vis-duration-bars", 8, 24, 20, 18),
        ("visualization", "ps-vis-duration-delta-bars", 28, 24, 20, 18),
        ("visualization", "ps-vis-version-changed-bars", 0, 42, 24, 16),
        ("visualization", "ps-vis-updates-bars", 24, 42, 24, 16),
        ("visualization", "ps-vis-health-bars", 0, 58, 48, 16),
        ("search", "ps-search-all-nodes", 0, 74, 48, 22),
        ("visualization", "ps-vis-node-updates-bars", 0, 96, 48, 20),
        ("visualization", "ps-vis-host-bars", 0, 116, 48, 20),
        ("visualization", "ps-vis-top-packages", 0, 136, 24, 16),
        ("visualization", "ps-vis-update-types", 24, 136, 16, 16),
    ]

    panels = []
    refs = []
    for index, (panel_type, obj_id, x, y, w, h) in enumerate(layout, start=1):
        panels.append(
            {
                "version": "8.15.3",
                "type": panel_type,
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(index)},
                "panelIndex": str(index),
                "embeddableConfig": {"enhancements": {}},
                "panelRefName": f"panel_{index}",
            }
        )
        refs.append({"name": f"panel_{index}", "type": panel_type, "id": obj_id})

    return {
        "type": "dashboard",
        "id": "ps-dashboard-main",
        "attributes": {
            "title": "Proxmox Patch Scanner",
            "description": "One row per report from reports/ — duration, deltas, and per-node breakdown",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps(
                {
                    "useMargins": True,
                    "syncColors": False,
                    "syncCursor": True,
                    "syncTooltips": False,
                    "hidePanelTitles": False,
                }
            ),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []}
                )
            },
        },
        "references": refs,
    }


def main():
    objects = build_objects()
    dashboard = build_dashboard()
    lines = [json.dumps(item, separators=(",", ":")) for item in objects]
    lines.append(json.dumps(dashboard, separators=(",", ":")))
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {OUT} ({len(objects)} objects + dashboard)")


if __name__ == "__main__":
    main()
