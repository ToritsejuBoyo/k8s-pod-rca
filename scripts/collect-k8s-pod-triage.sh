#!/usr/bin/env bash
# ==============================================================================
# Script: collect-k8s-pod-triage.sh
# Skill:  k8s-pod-rca (Day 9 / OP-08)
# Purpose: Read-only Kubernetes pod diagnostic collector for CrashLoopBackOff,
#          OOMKilled, Pending, and Probe failure root-cause analysis.
#          Uses ONLY read-only kubectl commands (get, logs, top) and outputs
#          a single sanitized JSON bundle.
# ==============================================================================

set -euo pipefail

NAMESPACE="default"
POD_NAME=""
LOG_LINES=150
SANITIZE="false"
OUTPUT_FILE="./k8s-pod-snapshot.json"

usage() {
  cat <<EOF
Usage: $(basename "$0") --pod <pod-name> [options]

Required:
  -p, --pod <name>          Name of the Kubernetes Pod to inspect

Options:
  -n, --namespace <ns>      Kubernetes namespace (default: default)
  -l, --lines <number>      Number of log tail lines per container (default: 150)
  -s, --sanitize            Mask IP addresses, registry hosts, and sensitive env values
  -o, --output <path>       Output JSON file path (default: ./k8s-pod-snapshot.json)
  -h, --help                Show this help message and exit

Example:
  $(basename "$0") --namespace prod --pod checkout-api-6b8f9d-x2k4 --sanitize --output ./triage.json
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--pod)
      POD_NAME="$2"
      shift 2
      ;;
    -n|--namespace)
      NAMESPACE="$2"
      shift 2
      ;;
    -l|--lines)
      LOG_LINES="$2"
      shift 2
      ;;
    -s|--sanitize)
      SANITIZE="true"
      shift 1
      ;;
    -o|--output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: Unknown argument '$1'" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$POD_NAME" ]]; then
  echo "Error: --pod <pod-name> is required." >&2
  usage
  exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
  echo "Error: 'kubectl' is not installed or not in PATH." >&2
  exit 1
fi

sanitize_stream() {
  if [[ "$SANITIZE" == "true" ]]; then
    sed -E \
      -e 's/(password|passwd|secret|token|apikey|api_key|authorization|connectionstring)(["'\'':= ]+)[^"'\''[:space:],}]+/\1\2[REDACTED_SECRET]/Ig' \
      -e 's/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[REDACTED_IP]/g' \
      -e 's/[a-zA-Z0-9._-]+(\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com|\.azurecr\.io|\.gcr\.io|\.pkg\.dev)/[REDACTED_REGISTRY]/g'
  else
    cat
  fi
}

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null || \
  awk 'BEGIN {RS=""; ORS=""} {gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); gsub(/\r/,"\\r"); gsub(/\t/,"\\t"); gsub(/\n/,"\\n"); print "\"" $0 "\""}'
}

echo "[*] Collecting read-only pod specification and status for ${NAMESPACE}/${POD_NAME}..." >&2
POD_JSON_RAW=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o json 2>&1 || true)

if echo "$POD_JSON_RAW" | grep -q '"kind": "Pod"'; then
  POD_JSON=$(echo "$POD_JSON_RAW" | sanitize_stream)
else
  echo "Error: Unable to fetch pod '${POD_NAME}' in namespace '${NAMESPACE}'." >&2
  echo "$POD_JSON_RAW" >&2
  exit 1
fi

echo "[*] Collecting involvedObject events in namespace ${NAMESPACE}..." >&2
EVENTS_JSON=$(kubectl get events -n "$NAMESPACE" \
  --field-selector "involvedObject.name=${POD_NAME}" \
  --sort-by='.lastTimestamp' -o json 2>/dev/null | sanitize_stream || echo '{"items":[]}')

echo "[*] Checking kubectl top metrics (if metrics-server is available)..." >&2
TOP_OUTPUT=$(kubectl top pod "$POD_NAME" -n "$NAMESPACE" --containers 2>/dev/null | sanitize_stream | json_escape || echo '"metrics-server unavailable"')

# Discover all containers (initContainers + standard containers)
CONTAINERS=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" \
  -o jsonpath='{range .spec.initContainers[*]}{.name}{"\n"}{end}{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null || true)

LOGS_JSON_ENTRIES=""
FIRST_ENTRY=true

while IFS= read -r cname; do
  [[ -z "$cname" ]] && continue
  echo "[*] Collecting current and --previous logs for container: ${cname}..." >&2

  CURR_LOG=$(kubectl logs "$POD_NAME" -n "$NAMESPACE" -c "$cname" --tail="$LOG_LINES" --timestamps=true 2>&1 | sanitize_stream | json_escape || echo '""')
  PREV_LOG=$(kubectl logs "$POD_NAME" -n "$NAMESPACE" -c "$cname" --previous --tail="$LOG_LINES" --timestamps=true 2>&1 | sanitize_stream | json_escape || echo '""')

  if [[ "$FIRST_ENTRY" == "true" ]]; then
    FIRST_ENTRY=false
  else
    LOGS_JSON_ENTRIES="${LOGS_JSON_ENTRIES},"
  fi

  LOGS_JSON_ENTRIES="${LOGS_JSON_ENTRIES}
    {
      \"containerName\": \"${cname}\",
      \"currentLogs\": ${CURR_LOG},
      \"previousTerminatedLogs\": ${PREV_LOG}
    }"
done <<< "$CONTAINERS"

TIMESTAMP_UTC=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat <<EOF > "$OUTPUT_FILE"
{
  "schemaVersion": "1.0",
  "skill": "k8s-pod-rca",
  "collectedAtUtc": "${TIMESTAMP_UTC}",
  "namespace": "${NAMESPACE}",
  "podName": "${POD_NAME}",
  "sanitized": ${SANITIZE},
  "topMetrics": ${TOP_OUTPUT},
  "podObject": ${POD_JSON},
  "events": ${EVENTS_JSON},
  "containerLogs": [${LOGS_JSON_ENTRIES}
  ]
}
EOF

echo "[+] Snapshot saved to ${OUTPUT_FILE}" >&2
