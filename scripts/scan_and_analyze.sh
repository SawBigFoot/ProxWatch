#!/usr/bin/env bash
# Run a patch scan, verify node health, push to Elasticsearch, and open Kibana.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOG_DIR="${LOG_DIR:-logs}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/scan_and_analyze.log}"
mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

detect_python() {
  if [[ -n "${PYTHON:-}" ]]; then
    if "$PYTHON" --version >/dev/null 2>&1; then
      printf '%s' "$PYTHON"
      return 0
    fi
    echo "PYTHON=${PYTHON} is set but does not run. unset PYTHON or fix the path." >&2
    return 1
  fi

  # On Windows Git Bash, python3 is often a broken Microsoft Store alias.
  for candidate in python py python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" --version >/dev/null 2>&1; then
      printf '%s' "$candidate"
      return 0
    fi
  done

  echo "No working Python found. Tried: python, py, python3" >&2
  return 1
}

PYTHON="$(detect_python)"

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
KIBANA_DASHBOARD_ID="${KIBANA_DASHBOARD_ID:-ps-dashboard-main}"
ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://localhost:9200}"
# EXPECTED_NODES is optional — leave unset to accept any number of discovered nodes
OPEN_BROWSER="${OPEN_BROWSER:-true}"
SKIP_DOCKER="${SKIP_DOCKER:-false}"

normalize_http_url() {
  local url="$1"
  url="${url#https://}"
  url="${url#http://}"
  printf 'http://%s' "$url"
}

KIBANA_URL="$(normalize_http_url "$KIBANA_URL")"
ELASTICSEARCH_URL="$(normalize_http_url "$ELASTICSEARCH_URL")"
DASHBOARD_URL="${KIBANA_URL}/app/dashboards#/view/${KIBANA_DASHBOARD_ID}"

log() {
  printf '==> %s\n' "$*"
}

wait_for_url() {
  local name="$1"
  local url="$2"
  local timeout="${3:-120}"
  local elapsed=0

  log "Waiting for ${name} at ${url} ..."
  until curl -fs "$url" >/dev/null 2>&1; do
    if (( elapsed >= timeout )); then
      echo "Timed out waiting for ${name} (${url})" >&2
      return 1
    fi
    sleep 3
    elapsed=$((elapsed + 3))
  done
  log "${name} is ready"
}

open_dashboard() {
  local url
  url="$(normalize_http_url "$1")"
  if [[ "$OPEN_BROWSER" != "true" ]]; then
    log "Browser open disabled. Dashboard: ${url}"
    return 0
  fi

  log "Opening dashboard (HTTP): ${url}"

  # Windows first — use cmd start with an explicit http:// URL so the browser
  # does not upgrade localhost to https.
  if command -v cmd.exe >/dev/null 2>&1; then
    cmd.exe /c start "" "$url" >/dev/null 2>&1 &
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 &
  elif command -v open >/dev/null 2>&1; then
    open "$url" >/dev/null 2>&1 &
  else
    log "Could not detect a browser opener. Open manually: ${url}"
    return 0
  fi

  log "Opened dashboard in browser"
}

ensure_stack() {
  if [[ "$SKIP_DOCKER" == "true" ]]; then
    log "Skipping Docker startup (SKIP_DOCKER=true)"
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required unless SKIP_DOCKER=true" >&2
    exit 1
  fi

  if ! curl -fs "${ELASTICSEARCH_URL}" >/dev/null 2>&1; then
    log "Starting Elasticsearch and Kibana"
    docker compose up -d
  else
    log "Elasticsearch already running"
  fi

  wait_for_url "Elasticsearch" "${ELASTICSEARCH_URL}" 180
  wait_for_url "Kibana" "${KIBANA_URL}/api/status" 240
}

ensure_kibana_dashboard() {
  log "Rebuilding and refreshing Kibana dashboard"
  log "Using Python: $("$PYTHON" --version 2>&1)"
  "$PYTHON" scripts/build_dashboard.py
  "$PYTHON" scripts/setup_kibana.py --kibana-url "$KIBANA_URL" --skip-wait
}

sync_reports_to_es() {
  log "Resetting indices and syncing all reports/ JSON files to Elasticsearch"
  export ELASTICSEARCH_ENABLED="${ELASTICSEARCH_ENABLED:-true}"
  "$PYTHON" scripts/import_reports.py --reset
}

run_scan() {
  if [[ -n "${EXPECTED_NODES:-}" ]]; then
    log "Running patch scan (expected nodes: ${EXPECTED_NODES})"
  else
    log "Running patch scan (any number of nodes)"
  fi
  log "Using Python: $("$PYTHON" --version 2>&1)"
  export ELASTICSEARCH_ENABLED="${ELASTICSEARCH_ENABLED:-true}"

  if ! "$PYTHON" scanner.py; then
    echo "Scan finished with node health failures. See output above." >&2
    return 1
  fi
}

verify_es_data() {
  local count
  count="$(curl -fs "${ELASTICSEARCH_URL}/patchscanner-scans/_count" 2>/dev/null | "$PYTHON" -c "import json,sys; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)"

  if [[ "$count" -gt 0 ]]; then
    log "Elasticsearch has ${count} scan record(s)"
    return 0
  fi

  log "No data in Elasticsearch yet — importing reports from ${OUTPUT_DIR:-reports}"
  export ELASTICSEARCH_ENABLED="${ELASTICSEARCH_ENABLED:-true}"
  "$PYTHON" scripts/import_reports.py
}

pause_at_end() {
  if [[ "${NO_PAUSE:-false}" == "true" ]]; then
    return 0
  fi
  echo ""
  log "Full log saved to: ${LOG_FILE}"
  read -r -p "Press Enter to close..."
}

main() {
  log "Logging to: ${LOG_FILE}"
  ensure_stack
  ensure_kibana_dashboard
  run_scan
  sync_reports_to_es
  verify_es_data
  open_dashboard "$DASHBOARD_URL"
  log "Done — scan completed and dashboard opened"
}

trap pause_at_end EXIT
main "$@"
