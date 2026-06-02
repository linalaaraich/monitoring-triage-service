#!/usr/bin/env bash
# =============================================================================
# phase2-deploy.sh — bring the triage stack up on the dedicated GPU host.
#
# Prereqs (handled by sibling agents — see /root/GPU_MIGRATION_PLAN_2026-05-21.md):
#   - Instance is up, Tailscale connected, /opt/triage/{config,state,models} exist.
#   - Docker + nvidia-container-runtime installed; triage-stack.service and
#     drain-queue.service installed via userdata (NOT enabled yet).
#   - Ollama running on the host as systemd at 127.0.0.1:11434 with
#     qwen2.5:14b + qwen2.5:7b-instruct already pulled.
#   - /opt/triage/triage-data-2026-05-21.tar.gz exists on the host
#     (rca_history.db, drain3_state/, .env-stripped, drain3.ini).
#
# What this script does:
#   1. ship the updated compose file + drain_queue.py + drain-queue.env
#   2. unpack data tarball, install .env, place rca_history.db and drain3_state/
#      into the triage_data docker volume's host bind path
#   3. enable + start triage-stack.service and drain-queue.service
#   4. wait for /health, fire a synthetic Grafana webhook, print the response
#
# Idempotent: safe to run twice. systemctl enable --now is a no-op when active.
# tar -xzf overwrites; .env install uses cp -f; volume seeding skips if files
# already present and newer than the tarball.
#
# Usage:
#   ./phase2-deploy.sh                              # defaults to observability-gpu-uswest2
#   ./phase2-deploy.sh observability-gpu-uswest2
# =============================================================================

set -euxo pipefail

# --- args / config -----------------------------------------------------------
GPU_HOST="${1:-observability-gpu-uswest2}"
SSH_TARGET="ubuntu@${GPU_HOST}"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)

# Repo paths (this script lives at /root/monitoring-triage-service/phase2-deploy.sh)
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_SRC="${REPO_ROOT}/docker-compose.gpu.yml"
DRAIN3_INI_SRC="${REPO_ROOT}/drain3.ini"
TERRAFORM_DIR="/root/provisioning-monitoring-infra/us-west-2"
DRAIN_QUEUE_SRC="${TERRAFORM_DIR}/lambda/drain_queue.py"

# Remote paths
REMOTE_ROOT="/opt/triage"
REMOTE_COMPOSE="${REMOTE_ROOT}/docker-compose.gpu.yml"
REMOTE_DRAIN3_INI="${REMOTE_ROOT}/drain3.ini"
REMOTE_DRAIN_QUEUE="${REMOTE_ROOT}/drain_queue.py"
REMOTE_DRAIN_ENV="${REMOTE_ROOT}/drain-queue.env"
REMOTE_ENV="${REMOTE_ROOT}/.env"
REMOTE_TARBALL="${REMOTE_ROOT}/triage-data-2026-05-21.tar.gz"
REMOTE_UNPACK_DIR="${REMOTE_ROOT}/_data_unpack"

# The compose file declares a NAMED volume `triage_data` (name: ai-stack_triage_data)
# mounted at /data inside containers. Docker resolves it to the host path
#   /var/lib/docker/volumes/ai-stack_triage_data/_data/
# We seed rca_history.db and drain3_state/ INTO that host path BEFORE first
# `docker compose up`. After containers run once the volume exists; if not,
# `docker volume create` creates it idempotently.
DOCKER_VOLUME_NAME="ai-stack_triage_data"
# Resolved server-side via `docker volume inspect` to avoid hardcoding the path
# in case Docker is configured with a non-default data-root.

sanity_check_local() {
  [[ -f "${COMPOSE_SRC}"     ]] || { echo "missing ${COMPOSE_SRC}";     exit 2; }
  [[ -f "${DRAIN_QUEUE_SRC}" ]] || { echo "missing ${DRAIN_QUEUE_SRC}"; exit 2; }
  [[ -f "${DRAIN3_INI_SRC}"  ]] || { echo "missing ${DRAIN3_INI_SRC}";  exit 2; }
  [[ -d "${TERRAFORM_DIR}"   ]] || { echo "missing ${TERRAFORM_DIR}";   exit 2; }
}

fetch_sqs_url() {
  # Pull from terraform output; trim any trailing whitespace.
  (cd "${TERRAFORM_DIR}" && terraform output -raw sqs_cold_start_queue_url) | tr -d '[:space:]'
}

fetch_api_url() {
  (cd "${TERRAFORM_DIR}" && terraform output -raw api_gateway_invoke_url) | tr -d '[:space:]'
}

main() {
  sanity_check_local

  echo "==> [1/7] resolving terraform outputs"
  SQS_URL="$(fetch_sqs_url)"
  API_URL="$(fetch_api_url)"
  [[ -n "${SQS_URL}" ]] || { echo "sqs_cold_start_queue_url empty"; exit 3; }

  echo "==> [2/7] writing drain-queue.env to a tmpfile"
  TMP_DRAIN_ENV="$(mktemp)"
  trap 'rm -f "${TMP_DRAIN_ENV}"' EXIT
  cat > "${TMP_DRAIN_ENV}" <<EOF
SQS_QUEUE_URL=${SQS_URL}
AWS_DEFAULT_REGION=us-west-2
EOF

  echo "==> [3/7] scp compose, drain_queue, drain3.ini, drain-queue.env to ${GPU_HOST}"
  scp "${SSH_OPTS[@]}" "${COMPOSE_SRC}"     "${SSH_TARGET}:${REMOTE_COMPOSE}"
  scp "${SSH_OPTS[@]}" "${DRAIN_QUEUE_SRC}" "${SSH_TARGET}:${REMOTE_DRAIN_QUEUE}"
  scp "${SSH_OPTS[@]}" "${DRAIN3_INI_SRC}"  "${SSH_TARGET}:${REMOTE_DRAIN3_INI}"
  scp "${SSH_OPTS[@]}" "${TMP_DRAIN_ENV}"   "${SSH_TARGET}:${REMOTE_DRAIN_ENV}"

  echo "==> [4/7] unpack tarball, install .env, seed docker volume with rca_history + drain3 state"
  # Heredoc runs on the GPU host. We:
  #   - mkdir + tar -xzf into a staging dir
  #   - cp -f .env-stripped -> /opt/triage/.env
  #   - resolve docker volume mountpoint (creating the volume if missing)
  #   - cp -an rca_history.db + drain3_state/ INTO the volume's _data dir
  #     (cp -a preserves perms; -n avoids clobbering an existing DB on re-run)
  ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" 'bash -s' <<REMOTE
set -euxo pipefail

REMOTE_ROOT="${REMOTE_ROOT}"
TARBALL="${REMOTE_TARBALL}"
UNPACK="${REMOTE_UNPACK_DIR}"
VOL="${DOCKER_VOLUME_NAME}"

if [[ ! -f "\${TARBALL}" ]]; then
  echo "ERROR: data tarball missing: \${TARBALL}" >&2
  echo "       sibling 'copy adolin data' agent must run first" >&2
  exit 10
fi

sudo mkdir -p "\${UNPACK}"
sudo tar -xzf "\${TARBALL}" -C "\${UNPACK}"

# Install .env (the stripped variant — secrets are loaded from systemd EnvFile elsewhere)
if [[ -f "\${UNPACK}/.env-stripped" ]]; then
  sudo cp -f "\${UNPACK}/.env-stripped" "${REMOTE_ENV}"
  sudo chmod 600 "${REMOTE_ENV}"
fi

# drain3.ini in the tarball wins over the one we shipped if both exist
# (tarball reflects the actual adolin-wsl runtime state).
if [[ -f "\${UNPACK}/drain3.ini" ]]; then
  sudo cp -f "\${UNPACK}/drain3.ini" "${REMOTE_DRAIN3_INI}"
fi

# Resolve / create the named docker volume so we know its host mountpoint.
sudo docker volume create "\${VOL}" >/dev/null
VOL_MOUNT="\$(sudo docker volume inspect -f '{{ .Mountpoint }}' "\${VOL}")"
echo "docker volume \${VOL} -> \${VOL_MOUNT}"

# Seed the volume. -n = no-clobber so re-runs preserve any newer state
# the triage container has already written.
if [[ -f "\${UNPACK}/rca_history.db" ]]; then
  sudo cp -an "\${UNPACK}/rca_history.db" "\${VOL_MOUNT}/rca_history.db"
fi
if [[ -d "\${UNPACK}/drain3_state" ]]; then
  sudo mkdir -p "\${VOL_MOUNT}/drain3_state"
  sudo cp -an "\${UNPACK}/drain3_state/." "\${VOL_MOUNT}/drain3_state/"
fi

sudo chown -R root:root "\${VOL_MOUNT}"
sudo ls -la "\${VOL_MOUNT}"
REMOTE

  echo "==> [5/7] enable + start triage-stack.service and drain-queue.service"
  ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" 'bash -s' <<'REMOTE'
set -euxo pipefail
sudo systemctl daemon-reload
sudo systemctl enable --now triage-stack.service
sudo systemctl enable --now drain-queue.service
sudo systemctl --no-pager --full status triage-stack.service || true
sudo systemctl --no-pager --full status drain-queue.service  || true
REMOTE

  echo "==> [6/7] wait up to 90s for triage /health to return 200"
  HEALTH_URL="http://${GPU_HOST}:8090/health"
  deadline=$(( $(date +%s) + 90 ))
  while (( $(date +%s) < deadline )); do
    if curl -fsS --max-time 5 "${HEALTH_URL}" >/dev/null 2>&1; then
      echo "triage /health: OK"
      break
    fi
    sleep 3
  done
  curl -fsS --max-time 5 "${HEALTH_URL}" || { echo "ERROR: /health never came up"; exit 4; }

  echo "==> [7/7] smoke-test: synthetic Grafana webhook"
  # Shape matches Grafana Alerting (matches test_api.py fixture). The fingerprint
  # is unique-per-run so dedup doesn't suppress the synthetic on re-runs.
  FP="smoke-$(date +%s)"
  STARTS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  PAYLOAD=$(cat <<JSON
{
  "receiver": "triage-webhook",
  "status": "firing",
  "alerts": [
    {
      "status": "firing",
      "labels": {"alertname": "SmokeTest", "severity": "info"},
      "annotations": {"summary": "phase 2 deploy smoke test"},
      "startsAt": "${STARTS}",
      "fingerprint": "${FP}"
    }
  ]
}
JSON
)
  echo "POST ${PAYLOAD}"
  curl -sS -w '\nHTTP %{http_code}\n' \
    -H 'Content-Type: application/json' \
    -X POST --data "${PAYLOAD}" \
    "http://${GPU_HOST}:8090/webhook/grafana" || true

  echo
  echo "==============================================================="
  echo "Phase 2 deploy: triage stack is UP on ${GPU_HOST}."
  echo "Next (Phase 4 — needs explicit go from Lina):"
  echo "  point Grafana's webhook contact point at the API Gateway:"
  echo "    ${API_URL}"
  echo "  see /root/monitoring-project/phase4-grafana-webhook-update.md"
  echo "==============================================================="
}

main "$@"
