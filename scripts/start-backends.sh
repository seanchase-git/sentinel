#!/usr/bin/env bash
# Start/stop the llama-server model backends defined in config/models.yaml.
#
# Usage:
#   start-backends.sh up [alias ...]     # default: all models
#   start-backends.sh down [alias ...]
#   start-backends.sh status
#
# Pid files land in .run/, logs in .run/logs/. Provenance (Section 1532)
# is enforced by sentinel.models.registry before any backend starts.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$REPO_ROOT/.run"
LOG_DIR="$RUN_DIR/logs"
HEALTH_TIMEOUT="${SENTINEL_BACKEND_HEALTH_TIMEOUT:-300}"

mkdir -p "$LOG_DIR"
cd "$REPO_ROOT"

cmd="${1:-up}"
shift || true

pid_alive() {
    local pid_file="$1"
    [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null
}

wait_healthy() {
    local alias="$1" port="$2" deadline=$((SECONDS + HEALTH_TIMEOUT))
    until curl -sf "http://127.0.0.1:${port}/health" >/dev/null 2>&1; do
        if ((SECONDS >= deadline)); then
            echo "error: $alias on :$port not healthy after ${HEALTH_TIMEOUT}s (see $LOG_DIR/$alias.log)" >&2
            return 1
        fi
        if ! pid_alive "$RUN_DIR/$alias.pid"; then
            echo "error: $alias exited during startup (see $LOG_DIR/$alias.log)" >&2
            return 1
        fi
        sleep 2
    done
    echo "healthy: $alias (:$port)"
}

registry_aliases() {
    # backend aliases only — never the proxy/redis pid files that
    # start-proxy.sh writes into the same .run/ directory
    uv run python -c "from sentinel.models.registry import load_registry; \
print('\n'.join(load_registry().models))"
}

case "$cmd" in
up)
    # Materialize the full launch plan BEFORE starting anything: launch-plan
    # validates provenance, aliases, and GGUF presence, so a bad alias can't
    # leave a partial fleet running.
    plan="$(uv run python -m sentinel.models.registry launch-plan "$@")"
    while IFS=$'\t' read -r alias port launch; do
        pid_file="$RUN_DIR/$alias.pid"
        if pid_alive "$pid_file"; then
            echo "already running: $alias (:$port)"
            continue
        fi
        if curl -sf "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
            echo "error: port :$port is already serving /health but $alias has no live pidfile" >&2
            echo "       refusing to start on an occupied port" >&2
            exit 1
        fi
        echo "starting $alias on :$port"
        # shellcheck disable=SC2086
        nohup $launch >"$LOG_DIR/$alias.log" 2>&1 &
        echo $! >"$pid_file"
    done <<<"$plan"
    while IFS=$'\t' read -r alias port _; do
        wait_healthy "$alias" "$port"
        if ! pid_alive "$RUN_DIR/$alias.pid"; then
            echo "error: $alias reported healthy but its process is gone" >&2
            exit 1
        fi
    done <<<"$plan"
    ;;
down)
    aliases=("$@")
    if [[ ${#aliases[@]} -eq 0 ]]; then
        aliases=($(registry_aliases))
    fi
    for alias in "${aliases[@]:-}"; do
        [[ -z "$alias" ]] && continue
        pid_file="$RUN_DIR/$alias.pid"
        if pid_alive "$pid_file"; then
            kill "$(cat "$pid_file")" && echo "stopped: $alias"
        fi
        rm -f "$pid_file"
    done
    ;;
status)
    for alias in $(registry_aliases); do
        pid_file="$RUN_DIR/$alias.pid"
        if pid_alive "$pid_file"; then
            echo "running: $alias (pid $(cat "$pid_file"))"
        elif [[ -f "$pid_file" ]]; then
            echo "stale pidfile: $alias"
        else
            echo "not running: $alias"
        fi
    done
    ;;
*)
    echo "usage: $0 {up|down|status} [alias ...]" >&2
    exit 2
    ;;
esac
