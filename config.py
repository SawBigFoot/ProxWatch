import os

from dotenv import load_dotenv

# Secrets (API tokens) are loaded from environment variables only — never hardcoded.
load_dotenv()
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true"
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "reports")
TIMEOUT_SECONDS = int(os.getenv("TIMEOUT_SECONDS", "20"))

ELASTICSEARCH_ENABLED = os.getenv("ELASTICSEARCH_ENABLED", "false").lower() == "true"
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ELASTICSEARCH_USER = os.getenv("ELASTICSEARCH_USER", "")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "")
ELASTICSEARCH_INDEX_PREFIX = os.getenv("ELASTICSEARCH_INDEX_PREFIX", "patchscanner")


def _cluster_from_env(suffix=""):
    host = os.getenv(f"PROXMOX_HOST{suffix}")
    token_id = os.getenv(f"PROXMOX_TOKEN_ID{suffix}")
    token_secret = os.getenv(f"PROXMOX_TOKEN_SECRET{suffix}")

    if not host:
        return None

    if not token_id or not token_secret:
        label = suffix or " (primary)"
        raise ValueError(f"Missing token variables for PROXMOX_HOST{suffix}{label}.")

    return {
        "host": host.rstrip("/"),
        "token_id": token_id,
        "token_secret": token_secret,
    }


def load_clusters():
    """Load one or more Proxmox API endpoints from environment variables.

    Primary: PROXMOX_HOST, PROXMOX_TOKEN_ID, PROXMOX_TOKEN_SECRET
    Additional hosts use the same names with a numeric suffix: _2, _3, _4, ...
    Each host is scanned independently; every node returned by its /nodes API
    is included in the report.
    """
    clusters = []

    primary = _cluster_from_env("")
    if not primary:
        raise ValueError("Missing required environment variable PROXMOX_HOST.")

    clusters.append(primary)

    index = 2
    while True:
        cluster = _cluster_from_env(f"_{index}")
        if not cluster:
            break
        clusters.append(cluster)
        index += 1

    return clusters
