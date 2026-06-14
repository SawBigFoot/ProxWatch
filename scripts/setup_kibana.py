
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import requests

KIBANA_DIR = Path(__file__).resolve().parent.parent / "kibana"
DASHBOARD_FILE = KIBANA_DIR / "dashboard.ndjson"

DATA_VIEWS = [
    {
        "id": "patchscanner-scans-dv",
        "title": "patchscanner-scans",
        "name": "Patch Scanner — Scans",
        "timeFieldName": "@timestamp",
    },
    {
        "id": "patchscanner-nodes-dv",
        "title": "patchscanner-nodes",
        "name": "Patch Scanner — Nodes",
        "timeFieldName": "@timestamp",
    },
    {
        "id": "patchscanner-packages-dv",
        "title": "patchscanner-packages",
        "name": "Patch Scanner — Packages",
        "timeFieldName": "@timestamp",
    },
]


def wait_for_kibana(base_url: str, timeout_seconds: int = 180) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            response = requests.get(f"{base_url}/api/status", timeout=5)
            if response.status_code == 200:
                status = response.json().get("status", {}).get("overall", {}).get("level")
                if status in ("available", "green"):
                    return
        except requests.RequestException:
            pass
        time.sleep(3)

    raise TimeoutError(f"Kibana did not become ready within {timeout_seconds} seconds")


def kibana_headers() -> dict[str, str]:
    return {
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
    }


def create_data_view(base_url: str, data_view: dict) -> None:
    existing = requests.get(
        f"{base_url}/api/data_views/data_view/{data_view['id']}",
        headers=kibana_headers(),
        timeout=10,
    )
    if existing.status_code == 200:
        requests.delete(
            f"{base_url}/api/data_views/data_view/{data_view['id']}",
            headers=kibana_headers(),
            timeout=10,
        )
        print(f"Recreating data view: {data_view['name']}")

    response = requests.post(
        f"{base_url}/api/data_views/data_view",
        headers=kibana_headers(),
        json={"data_view": data_view},
        timeout=10,
    )
    if response.status_code not in (200, 201):
        raise RuntimeError(
            f"Failed to create data view {data_view['title']}: "
            f"{response.status_code} {response.text}"
        )
    print(f"Created data view: {data_view['name']}")

    refresh = requests.post(
        f"{base_url}/api/data_views/data_view/{data_view['id']}/fields/_refresh",
        headers=kibana_headers(),
        timeout=30,
    )
    if refresh.status_code in (200, 201):
        print(f"Refreshed fields: {data_view['name']}")


def import_dashboard(base_url: str) -> None:
    if not DASHBOARD_FILE.exists():
        raise FileNotFoundError(f"Dashboard file not found: {DASHBOARD_FILE}")

    with DASHBOARD_FILE.open("rb") as handle:
        response = requests.post(
            f"{base_url}/api/saved_objects/_import?overwrite=true",
            headers={"kbn-xsrf": "true"},
            files={"file": ("dashboard.ndjson", handle, "application/ndjson")},
            timeout=30,
        )

    if response.status_code not in (200, 201):
        raise RuntimeError(
            f"Dashboard import failed: {response.status_code} {response.text}"
        )

    result = response.json()
    print(
        "Imported dashboard objects: "
        f"{result.get('successCount', 0)} success, "
        f"{result.get('errors', []) and len(result['errors'])} errors"
    )
    if result.get("errors"):
        for error in result["errors"]:
            print(f"  - {error}")


def main():
    parser = argparse.ArgumentParser(description="Set up Kibana for patch scanner data")
    parser.add_argument(
        "--kibana-url",
        default="http://localhost:5601",
        help="Kibana base URL (default: http://localhost:5601)",
    )
    parser.add_argument(
        "--skip-wait",
        action="store_true",
        help="Do not wait for Kibana to become ready",
    )
    args = parser.parse_args()

    base_url = args.kibana_url.rstrip("/")

    try:
        if not args.skip_wait:
            print("Waiting for Kibana...")
            wait_for_kibana(base_url)

        for data_view in DATA_VIEWS:
            create_data_view(base_url, data_view)

        import_dashboard(base_url)
        print(f"Kibana setup complete. Open {base_url}/app/dashboards")
    except Exception as error:
        print(f"Kibana setup failed: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
