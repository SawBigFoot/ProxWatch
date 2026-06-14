import json
import os
import sys
from datetime import datetime

import requests

from config import (
    load_clusters,
    VERIFY_SSL,
    OUTPUT_DIR,
    TIMEOUT_SECONDS,
)
from elastic_export import export_report

SECURITY_CLASSIFICATION_NOTE = (
    "Security classification is best-effort based on package metadata/source text."
)


def cluster_headers(cluster):
    return {
        "Authorization": (
            f"PVEAPIToken={cluster['token_id']}={cluster['token_secret']}"
        )
    }


def api_get(cluster, path, timeout=TIMEOUT_SECONDS):
    url = f"{cluster['host']}/api2/json{path}"
    response = requests.get(
        url,
        headers=cluster_headers(cluster),
        verify=VERIFY_SSL,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()["data"]


def classify_update(package):
    """Best-effort security vs ordinary; not guaranteed to match Debian security tracking."""
    origin = (package.get("Origin") or "").lower()
    if "debian-security" in origin or origin.endswith("-security"):
        return "security"

    raw_text = json.dumps(package).lower()
    if "debian-security" in raw_text or '"origin": "debian-security' in raw_text:
        return "security"

    return "ordinary"


def normalize_package(package):
    return {
        "name": package.get("Package") or package.get("package") or package.get("name"),
        "current_version": package.get("OldVersion")
        or package.get("old-version")
        or package.get("current_version"),
        "available_version": package.get("Version")
        or package.get("version")
        or package.get("available_version"),
        "type": classify_update(package),
        "raw": package,
    }


def scan_node(cluster, node):
    node_name = node["node"]

    result = {
        "name": node_name,
        "cluster_host": cluster["host"],
        "status": node.get("status", "unknown"),
        "reachable": node.get("status") == "online",
        "updates_total": 0,
        "security_updates": 0,
        "ordinary_updates": 0,
        "packages": [],
        "error": None,
    }

    try:
        updates = api_get(cluster, f"/nodes/{node_name}/apt/versions", timeout=30)

        for package in updates:
            normalized = normalize_package(package)
            result["packages"].append(normalized)

            if normalized["type"] == "security":
                result["security_updates"] += 1
            else:
                result["ordinary_updates"] += 1

        result["updates_total"] = len(result["packages"])

    except Exception as error:
        result["reachable"] = False
        result["status"] = "error"
        result["error"] = str(error)

    return result


def scan_cluster(cluster):
    nodes = []
    try:
        for node in api_get(cluster, "/nodes"):
            nodes.append(scan_node(cluster, node))
    except Exception as error:
        nodes.append(
            {
                "name": "unknown",
                "cluster_host": cluster["host"],
                "status": "error",
                "reachable": False,
                "updates_total": 0,
                "security_updates": 0,
                "ordinary_updates": 0,
                "packages": [],
                "error": str(error),
            }
        )
    return nodes


def build_summary(nodes):
    return {
        "nodes_total": len(nodes),
        "nodes_online": sum(1 for node in nodes if node["reachable"]),
        "nodes_failed": sum(1 for node in nodes if not node["reachable"]),
        "updates_total": sum(node["updates_total"] for node in nodes),
        "security_updates": sum(node["security_updates"] for node in nodes),
        "ordinary_updates": sum(node["ordinary_updates"] for node in nodes),
    }


def is_node_healthy(node):
    return (
        node.get("reachable")
        and node.get("status") == "online"
        and not node.get("error")
    )


def print_node_health(nodes, expected_nodes=None):
    print("\nNode health:")
    all_healthy = True

    for node in nodes:
        healthy = is_node_healthy(node)
        label = "OK" if healthy else "FAIL"
        host = node.get("cluster_host", "unknown")
        print(
            f"  [{label}] {node['name']} @ {host} "
            f"— status={node.get('status')}, "
            f"updates={node.get('updates_total', 0)}"
        )
        if not healthy:
            all_healthy = False
            if node.get("error"):
                print(f"         error: {node['error']}")

    if expected_nodes is not None and len(nodes) != expected_nodes:
        all_healthy = False
        print(
            f"\nExpected {expected_nodes} node(s), found {len(nodes)}."
        )
    elif all_healthy:
        print(f"\nAll {len(nodes)} node(s) are online and reachable.")
    else:
        print("\nOne or more nodes are not healthy.")

    return all_healthy


def save_report(report):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(OUTPUT_DIR, f"patch_report_{timestamp}.json")

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    return filename


def main():
    expected_nodes = os.getenv("EXPECTED_NODES")
    if expected_nodes:
        expected_nodes = int(expected_nodes)

    start_time = datetime.now()
    clusters = load_clusters()

    report = {
        "scan_time": start_time.isoformat(),
        "start_time": start_time.isoformat(),
        "end_time": None,
        "proxmox_host": clusters[0]["host"],
        "proxmox_hosts": [cluster["host"] for cluster in clusters],
        "duration_seconds": None,
        "security_classification_note": SECURITY_CLASSIFICATION_NOTE,
        "summary": {},
        "nodes": [],
    }

    for cluster in clusters:
        report["nodes"].extend(scan_cluster(cluster))

    end_time = datetime.now()
    report["end_time"] = end_time.isoformat()
    report["summary"] = build_summary(report["nodes"])
    report["duration_seconds"] = round((end_time - start_time).total_seconds(), 2)

    filename = save_report(report)

    print(f"Report saved: {filename}")
    print(f"Duration: {report['duration_seconds']} seconds")
    print(f"Hosts scanned: {len(clusters)}")
    print(json.dumps(report["summary"], indent=4))

    healthy = print_node_health(report["nodes"], expected_nodes)

    try:
        es_result = export_report(report)
        if es_result.get("enabled"):
            print(
                "Elasticsearch: indexed "
                f"{es_result['indexed']} documents "
                f"({es_result['scans']} scans, "
                f"{es_result['nodes']} nodes, "
                f"{es_result['packages']} packages)"
            )
        else:
            print(
                "Elasticsearch export skipped. "
                "Set ELASTICSEARCH_ENABLED=true in .env to populate Kibana."
            )
    except Exception as error:
        print(f"Elasticsearch export failed: {error}")

    if not healthy:
        sys.exit(1)


if __name__ == "__main__":
    main()
