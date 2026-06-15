#!/usr/bin/env bash
# Start ES/Kibana if needed, run scan, optionally open dashboard.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

for candidate in "${PYTHON:-}" python py python3; do
  [[ -z "$candidate" ]] && continue
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" --version >/dev/null 2>&1; then
    PYTHON="$candidate"
    break
  fi
done
: "${PYTHON:?No working Python found}"

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
KIBANA_URL="${KIBANA_URL#https://}"
KIBANA_URL="${KIBANA_URL#http://}"
KIBANA_URL="http://${KIBANA_URL}"

ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://localhost:9200}"
ELASTICSEARCH_URL="${ELASTICSEARCH_URL#https://}"
ELASTICSEARCH_URL="${ELASTICSEARCH_URL#http://}"
ELASTICSEARCH_URL="http://${ELASTICSEARCH_URL}"

DASHBOARD_URL="${KIBANA_URL}/app/dashboards#/view/${KIBANA_DASHBOARD_ID:-ps-dashboard-main}"

if [[ "${SKIP_DOCKER:-false}" != "true" ]]; then
  command -v docker >/dev/null 2>&1 || { echo "Docker required (or set SKIP_DOCKER=true)" >&2; exit 1; }
  curl -fs "${ELASTICSEARCH_URL}" >/dev/null 2>&1 || docker compose up -d
  until curl -fs "${ELASTICSEARCH_URL}" >/dev/null 2>&1; do sleep 3; done
  until curl -fs "${KIBANA_URL}/api/status" >/dev/null 2>&1; do sleep 3; done
fi

export ELASTICSEARCH_ENABLED="${ELASTICSEARCH_ENABLED:-true}"
"$PYTHON" scanner.py
"$PYTHON" scripts/import_reports.py

if [[ "${OPEN_BROWSER:-true}" == "true" ]]; then
  if command -v cmd.exe >/dev/null 2>&1; then
    cmd.exe /c start "" "$DASHBOARD_URL" >/dev/null 2>&1 &
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$DASHBOARD_URL" >/dev/null 2>&1 &
  elif command -v open >/dev/null 2>&1; then
    open "$DASHBOARD_URL" >/dev/null 2>&1 &
  fi
fi
