#!/usr/bin/env bash
# Start/stop the Sentinel gateway pair: dedicated Redis cache (:6390) and
# LiteLLM proxy (:8100). Pid files in .run/, logs in .run/logs/.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$REPO_ROOT/.run"
LOG_DIR="$RUN_DIR/logs"
mkdir -p "$LOG_DIR"
cd "$REPO_ROOT"

cmd="${1:-up}"

pid_alive() {
    [[ -f "$1" ]] && kill -0 "$(cat "$1")" 2>/dev/null
}

wait_for() {
    local name="$1" check_cmd="$2" pid_file="$3" deadline=$((SECONDS + 120))
    until eval "$check_cmd" >/dev/null 2>&1; do
        if ((SECONDS >= deadline)); then
            echo "error: $name not healthy after 120s (see $LOG_DIR/$name.log)" >&2
            return 1
        fi
        if ! pid_alive "$pid_file"; then
            echo "error: $name exited during startup (see $LOG_DIR/$name.log)" >&2
            return 1
        fi
        sleep 1
    done
    # The port answering is not proof that OUR process is answering. On a
    # restart the previous instance can still be draining and reply to the
    # health check while the replacement has already aborted on "Failed
    # listening on port ... (tcp)". Observed: this function printed
    # "healthy: redis-cache" in the same second Redis died, and the cache
    # stayed down for hours behind a green status line while LiteLLM
    # silently degraded to an in-memory fallback.
    if ! pid_alive "$pid_file"; then
        echo "error: $name answered the health check but its process is gone;" >&2
        echo "       most likely the previous instance was still holding the port" >&2
        echo "       (see $LOG_DIR/$name.log)" >&2
        return 1
    fi
    echo "healthy: $name"
}

port_free() {
    # Give a stopped service time to release its port before rebinding.
    local port="$1" deadline=$((SECONDS + 30))
    while lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; do
        if ((SECONDS >= deadline)); then
            echo "error: port $port still held after 30s" >&2
            return 1
        fi
        sleep 1
    done
}

case "$cmd" in
up)
    if ! pid_alive "$RUN_DIR/redis-cache.pid"; then
        # Wait out a previous instance still releasing 6390, or the new
        # redis-server aborts on bind while the old one still answers PING.
        port_free 6390 || exit 1
        nohup redis-server "$REPO_ROOT/config/redis-cache.conf" \
            >"$LOG_DIR/redis-cache.log" 2>&1 &
        echo $! >"$RUN_DIR/redis-cache.pid"
    fi
    wait_for redis-cache "redis-cli -p 6390 ping" "$RUN_DIR/redis-cache.pid"

    if ! pid_alive "$RUN_DIR/litellm.pid"; then
        nohup uv run litellm --config "$REPO_ROOT/config/litellm.yaml" \
            --host 127.0.0.1 --port 8100 \
            >"$LOG_DIR/litellm.log" 2>&1 &
        echo $! >"$RUN_DIR/litellm.pid"
    fi
    wait_for litellm "curl -sf http://127.0.0.1:8100/health/liveliness" "$RUN_DIR/litellm.pid"
    ;;
down)
    for name in litellm redis-cache; do
        pid_file="$RUN_DIR/$name.pid"
        if pid_alive "$pid_file"; then
            kill "$(cat "$pid_file")" && echo "stopped: $name"
        fi
        rm -f "$pid_file"
    done
    ;;
*)
    echo "usage: $0 {up|down}" >&2
    exit 2
    ;;
esac
