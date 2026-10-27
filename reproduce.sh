#!/usr/bin/env bash
#
# Reproduces the single-host validation of the bounded-cache replay threshold.
#
# Brings up Keycloak and a single Spring Security resource server at default
# settings, runs the correctness suite, sweeps request rate across R*, and writes
# results to single-host-validation/results/.
#
# Runtime is roughly one minute per rate point. The default sweep is ten rates
# with two repeats, so about twenty-five minutes, plus the first image build.

set -euo pipefail

cd "$(dirname "$0")"
STACK_DIR="single-host-validation"
RESULTS_DIR="${STACK_DIR}/results"
KEYCLOAK_URL="http://localhost:8080"
RS_URL="http://localhost:8081"

RATES="${RATES:-5,10,15,16,17,18,19,20,25,40}"
REPLAY_AT="${REPLAY_AT:-58}"
REPEATS="${REPEATS:-2}"

log() { printf '\n=== %s ===\n' "$1"; }

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}

require docker
require python3

python3 -c 'import httpx, cryptography' 2>/dev/null || {
  echo "missing Python dependencies. Install with:" >&2
  echo "  python3 -m pip install httpx cryptography" >&2
  exit 1
}

log "Starting stack"
docker compose -f "${STACK_DIR}/docker-compose.yml" up -d --build

log "Waiting for Keycloak"
for i in $(seq 1 60); do
  if curl -sf -o /dev/null -m 3 \
      "${KEYCLOAK_URL}/realms/dpop-demo/.well-known/openid-configuration"; then
    echo "ready after ~$((i * 3))s"
    break
  fi
  [ "$i" = 60 ] && { echo "Keycloak did not become ready" >&2; exit 1; }
  sleep 3
done

log "Waiting for resource server"
for i in $(seq 1 40); do
  if curl -sf -o /dev/null -m 3 "${RS_URL}/actuator/health"; then
    echo "ready after ~$((i * 3))s"
    break
  fi
  [ "$i" = 40 ] && { echo "resource server did not become ready" >&2; exit 1; }
  sleep 3
done

mkdir -p "${RESULTS_DIR}"

log "Correctness suite"
python3 "${STACK_DIR}/correctness/correctness.py" | tee "${RESULTS_DIR}/correctness.txt"

log "R* sweep"
( cd "${STACK_DIR}/load" && python3 sweep.py \
    --rates "${RATES}" \
    --replay-at "${REPLAY_AT}" \
    --repeats "${REPEATS}" \
    --out ../results/sweep.json ) | tee "${RESULTS_DIR}/sweep.txt"

log "Threshold plot"
python3 "${STACK_DIR}/load/plot_threshold.py" \
  --in "${RESULTS_DIR}/sweep.json" \
  --out "${RESULTS_DIR}/fig_threshold.pdf" || \
  echo "plot skipped (matplotlib not installed)"

log "Environment capture"
# Record the host and toolchain the run happened on. Never allowed to abort the
# run, hence the guards and the trailing || true.
{
  echo "# captured by reproduce.sh at end of run"
  echo "date_utc: $(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true)"
  echo
  echo "## uname (kernel and arch; node name omitted for privacy)"
  # Deliberately not `uname -a`: the node-name field leaks the operator's hostname.
  echo "$(uname -s) $(uname -r) $(uname -m)" 2>&1 || true
  echo
  echo "## logical CPUs (nproc)"
  if command -v nproc >/dev/null 2>&1; then
    nproc 2>&1 || true
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu 2>&1 || true
  else
    echo "unknown"
  fi
  echo
  echo "## docker version"
  docker version 2>&1 || true
} > "${RESULTS_DIR}/environment.txt" 2>&1 || true
echo "wrote ${RESULTS_DIR}/environment.txt"

log "Done"
echo "Results in ${RESULTS_DIR}/"
echo "Stop the stack with: docker compose -f ${STACK_DIR}/docker-compose.yml down -v"
