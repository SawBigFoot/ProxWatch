import json
import os
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

import requests

from config import (
    load_clusters,
    VERIFY_SSL,
    OUTPUT_DIR,
    TIMEOUT_SECONDS,
)
from elastic_export import export_saved_report

if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROJECT_NAME = os.getenv("PROJECT_NAME", "ProxWatch")
REPORT_TYPE = os.getenv("REPORT_TYPE", "patch_level_report")
SCANNER_VERSION = os.getenv("SCANNER_VERSION", "1.0.0")
ENVIRONMENT = os.getenv("ENVIRONMENT", "test_lab")

SECURITY_CLASSIFICATION_NOTE = (
    "Security classification is best-effort based on package metadata/source text."
)


def now_iso():
    return datetime.now().isoformat(timespec="microseconds")


def make_scan_id(start_time):
    return f"proxwatch_{start_time.replace(':', '-').replace('T', '_')}"


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


def host_to_ip_or_name(host_url):
    parsed = urlparse(host_url)
    return parsed.hostname or host_url.replace("https://", "").replace("http://", "").split(":")[0]


def classify_update(package):
    """Best-effort security vs ordinary; not guaranteed to match Debian security tracking."""
    origin = (package.get("Origin") or package.get("origin") or "").lower()
    archive = (package.get("Archive") or package.get("archive") or "").lower()
    raw_text = json.dumps(package).lower()

    if "debian-security" in origin or origin.endswith("-security"):
        return "security"
    if "security" in archive:
        return "security"
    if "debian-security" in raw_text or '"origin": "debian-security' in raw_text:
        return "security"

    return "ordinary"


def normalize_package(package):
    update_type = classify_update(package)
    source = (
        package.get("Origin")
        or package.get("origin")
        or package.get("Archive")
        or package.get("archive")
        or package.get("Component")
        or package.get("component")
    )

    return {
        "package_name": package.get("Package") or package.get("package") or package.get("name"),
        "current_version": package.get("OldVersion")
        or package.get("old-version")
        or package.get("current_version"),
        "available_version": package.get("Version")
        or package.get("version")
        or package.get("available_version"),
        "update_type": update_type,
        "source": source,
        "description": (
            "Security-related package update detected."
            if update_type == "security"
            else "Ordinary package update detected."
        ),
        "severity": package.get("Severity") or package.get("severity") or None,
        "classification_note": SECURITY_CLASSIFICATION_NOTE,
    }


def get_node_metadata(cluster, node_name):
    metadata = {
        "proxmox_version": None,
        "kernel_version": None,
    }

    try:
        version_data = api_get(cluster, f"/nodes/{node_name}/version", timeout=10)
        version = version_data.get("version")
        release = version_data.get("release")
        if version and release:
            metadata["proxmox_version"] = f"{version}-{release}"
        else:
            metadata["proxmox_version"] = version or release
    except Exception:
        pass

    try:
        status_data = api_get(cluster, f"/nodes/{node_name}/status", timeout=10)
        metadata["kernel_version"] = status_data.get("kversion") or status_data.get("kernel")
    except Exception:
        pass

    return metadata


def empty_node(cluster, node_name="unknown", status="unreachable", error_message=None):
    checked = now_iso()
    return {
        "node_name": node_name,
        "status": status,
        "ip_address": host_to_ip_or_name(cluster["host"]),
        "cluster_host": cluster["host"],
        "proxmox_version": None,
        "kernel_version": None,
        "last_checked": checked,
        "update_count_total": 0,
        "update_count_security": 0,
        "update_count_ordinary": 0,
        "update_status": "unreachable",
        "scan_success": False,
        "error_message": error_message,
        "updates": [],
    }


def scan_node(cluster, node):
    node_name = node["node"]
    node_status = node.get("status", "unknown")

    result = empty_node(
        cluster,
        node_name=node_name,
        status="online" if node_status == "online" else "offline",
        error_message=None,
    )

    if node_status != "online":
        result["scan_success"] = False
        result["update_status"] = "unreachable"
        result["error_message"] = "Node reported as offline by Proxmox API."
        return result

    metadata = get_node_metadata(cluster, node_name)
    result.update(metadata)

    try:
        updates = api_get(cluster, f"/nodes/{node_name}/apt/versions", timeout=30)

        for package in updates:
            normalized = normalize_package(package)
            result["updates"].append(normalized)

            if normalized["update_type"] == "security":
                result["update_count_security"] += 1
            else:
                result["update_count_ordinary"] += 1

        result["update_count_total"] = len(result["updates"])
        result["scan_success"] = True
        result["error_message"] = None
        result["update_status"] = (
            "updates_available" if result["update_count_total"] > 0 else "up_to_date"
        )

    except Exception as error:
        result["status"] = "unreachable"
        result["scan_success"] = False
        result["update_status"] = "unreachable"
        result["error_message"] = str(error)

    return result


def scan_cluster(cluster):
    nodes = []
    try:
        for node in api_get(cluster, "/nodes"):
            nodes.append(scan_node(cluster, node))
    except Exception as error:
        nodes.append(empty_node(cluster, error_message=str(error)))
    return nodes


def build_summary(nodes):
    return {
        "nodes_total": len(nodes),
        "nodes_online": sum(1 for node in nodes if node.get("status") == "online"),
        "nodes_offline": sum(1 for node in nodes if node.get("status") == "offline"),
        "unreachable_nodes": sum(1 for node in nodes if node.get("status") == "unreachable"),
        "nodes_with_updates": sum(1 for node in nodes if node.get("update_count_total", 0) > 0),
        "nodes_fully_updated": sum(
            1
            for node in nodes
            if node.get("scan_success") and node.get("update_count_total", 0) == 0
        ),
        "total_updates": sum(node.get("update_count_total", 0) for node in nodes),
        "total_security_updates": sum(node.get("update_count_security", 0) for node in nodes),
        "total_ordinary_updates": sum(node.get("update_count_ordinary", 0) for node in nodes),
    }


def is_node_healthy(node):
    return (
        node.get("scan_success")
        and node.get("status") == "online"
        and not node.get("error_message")
    )


def print_node_health(nodes, expected_nodes=None):
    print("\nNode health:")
    all_healthy = True

    for node in nodes:
        healthy = is_node_healthy(node)
        label = "OK" if healthy else "FAIL"
        host = node.get("cluster_host", "unknown")
        print(
            f"  [{label}] {node['node_name']} @ {host} "
            f"— status={node.get('status')}, "
            f"updates={node.get('update_count_total', 0)}"
        )
        if not healthy:
            all_healthy = False
            if node.get("error_message"):
                print(f"         error: {node['error_message']}")

    if expected_nodes is not None and len(nodes) != expected_nodes:
        all_healthy = False
        print(f"\nExpected {expected_nodes} node(s), found {len(nodes)}.")
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
    expected_raw = os.getenv("EXPECTED_NODES", "").strip()
    expected_nodes = int(expected_raw) if expected_raw else None

    start_clock = time.perf_counter()
    start_time_dt = datetime.now()
    start_time = start_time_dt.isoformat(timespec="microseconds")
    clusters = load_clusters()

    report = {
        "project_name": PROJECT_NAME,
        "report_type": REPORT_TYPE,
        "scan_id": make_scan_id(start_time),
        "environment": ENVIRONMENT,
        "scanner_version": SCANNER_VERSION,
        "start_time": start_time,
        "end_time": None,
        "duration_seconds": None,
        "generated_at": None,
        "classification_note": SECURITY_CLASSIFICATION_NOTE,
        "proxmox_hosts": [cluster["host"] for cluster in clusters],
        "summary": {},
        "nodes": [],
    }

    for cluster in clusters:
        report["nodes"].extend(scan_cluster(cluster))

    end_time_dt = datetime.now()
    report["end_time"] = end_time_dt.isoformat(timespec="microseconds")
    report["generated_at"] = report["end_time"]
    report["summary"] = build_summary(report["nodes"])
    report["duration_seconds"] = round(time.perf_counter() - start_clock, 2)

    filename = save_report(report)

    print(f"Report saved: {filename}")
    print(f"Duration: {report['duration_seconds']} seconds")
    print(f"Hosts scanned: {len(clusters)} ({len(report['nodes'])} node(s) total)")
    print(json.dumps(report["summary"], indent=4))

    healthy = print_node_health(report["nodes"], expected_nodes)

    try:
        es_result = export_saved_report(report, filename)
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
