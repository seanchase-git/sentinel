"""Local observability dashboard: one page for status, metrics, and logs.

Deliberately built on the standard library. A security tool that advertises a
small, auditable surface should not grow a web framework to draw six status
rows, and the review path must never depend on this module.

Loopback only, and not by convention: `serve` refuses any other bind address
through the same `netguard` check the model clients use. This endpoint exposes
backend logs, so binding it to 0.0.0.0 would hand a reader the contents of a
machine that reviews code which cannot leave the building.

Read-only by construction. There is no route that starts, stops, or reconfigures
anything, and the only file it will read is a log belonging to an alias that
appears in the model registry — an unknown alias is rejected rather than joined
onto a path.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from sentinel.netguard import AirGapViolation, is_loopback

REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_DIR = REPO_ROOT / ".run"
LOG_DIR = RUN_DIR / "logs"

GATEWAY_PORT = 8100
DEFAULT_PORT = 8200
_LOG_TAIL_BYTES = 256_000


def _require_dashboard_loopback(host: str) -> None:
    """Loopback for the dashboard is not negotiable, unlike the model endpoints.

    SENTINEL_ALLOW_REMOTE_MODELS exists so somebody can deliberately point the
    REVIEWER at a remote model and accept the consequences. It must not double as
    permission to publish this page, which serves backend logs off a machine that
    reviews code that cannot leave the building. So this checks the address
    directly instead of going through require_loopback, whose escape hatch would
    otherwise apply here by accident.
    """
    if not is_loopback(host):
        raise AirGapViolation(
            f"the dashboard may only bind loopback, refusing {host!r}. It serves "
            "backend logs; SENTINEL_ALLOW_REMOTE_MODELS does not apply."
        )


@dataclass(frozen=True)
class ProcessSample:
    pid: int
    rss_bytes: int
    cpu_percent: float


def _process_table() -> dict[int, ProcessSample]:
    """One `ps` call for every pid we might care about.

    Sampling per backend would mean six forks per poll; the dashboard refreshes
    on a timer, so that cost recurs forever.
    """
    try:
        out = subprocess.run(
            ["ps", "-Ao", "pid=,rss=,pcpu="],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    table: dict[int, ProcessSample] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        try:
            pid, rss_kb, cpu = int(parts[0]), int(parts[1]), float(parts[2])
        except ValueError:
            continue
        table[pid] = ProcessSample(pid=pid, rss_bytes=rss_kb * 1024, cpu_percent=cpu)
    return table


def _read_pid(alias: str) -> int | None:
    path = RUN_DIR / f"{alias}.pid"
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def _probe(url: str, timeout: float = 3.0) -> bool:
    import httpx

    try:
        httpx.get(url, timeout=timeout).raise_for_status()
        return True
    except Exception:
        return False


def _corpus_size() -> int | None:
    try:
        from sentinel.retrieval.rules_store import RulesStore

        store = RulesStore()
        return store.count()
    except Exception:
        return None


def collect_status() -> dict[str, Any]:
    """Health, provenance, and resource use for every served model."""
    from sentinel.models.registry import load_registry

    processes = _process_table()
    backends: list[dict[str, Any]] = []
    try:
        registry = load_registry()
        models = registry.models.items()
    except Exception:
        models = []

    for alias, model in models:
        pid = _read_pid(alias)
        sample = processes.get(pid) if pid else None
        backends.append(
            {
                "alias": alias,
                "role": model.role,
                "port": model.port,
                "model_id": getattr(model, "model_id", None) or getattr(model, "repo", None),
                "publisher": getattr(model, "publisher", None),
                "healthy": _probe(f"http://127.0.0.1:{model.port}/health"),
                "pid": pid,
                "rss_bytes": sample.rss_bytes if sample else None,
                "cpu_percent": sample.cpu_percent if sample else None,
            }
        )

    gateway_pid = _read_pid("litellm")
    redis_pid = _read_pid("redis-cache")
    return {
        "generated_at": time.time(),
        "backends": backends,
        "services": [
            {
                "name": "litellm gateway",
                "port": GATEWAY_PORT,
                "healthy": _probe(f"http://127.0.0.1:{GATEWAY_PORT}/health/liveliness"),
                "pid": gateway_pid,
                "rss_bytes": (
                    processes[gateway_pid].rss_bytes
                    if gateway_pid and gateway_pid in processes
                    else None
                ),
            },
            {
                "name": "redis cache",
                "port": 6390,
                "healthy": redis_pid is not None and redis_pid in processes,
                "pid": redis_pid,
                "rss_bytes": (
                    processes[redis_pid].rss_bytes
                    if redis_pid and redis_pid in processes
                    else None
                ),
            },
        ],
        "corpus_rules": _corpus_size(),
        "active_reviews": _active_reviews(),
        "totals": {
            "resident_bytes": sum(
                b["rss_bytes"] or 0 for b in backends
            ),
            "healthy": sum(1 for b in backends if b["healthy"]),
            "count": len(backends),
        },
    }


def _active_reviews() -> list[dict[str, Any]]:
    """Reviews running right now, with the target they were pointed at."""
    try:
        out = subprocess.run(
            ["ps", "-Ao", "pid=,etime=,command="],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    found: list[dict[str, Any]] = []
    for line in out.splitlines():
        if "sentinel review" not in line or " grep " in line:
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, etime, command = parts
        # argv boundaries are gone by the time ps prints a command line, so a
        # path with spaces cannot be recovered exactly. Take everything after
        # "review " up to the next option and strip it; that keeps
        # "/tmp/My Project" intact instead of showing "/tmp/My".
        target = ""
        marker = " review "
        if marker in command:
            rest = command.split(marker, 1)[1]
            target = rest.split(" -", 1)[0].strip().strip("'\"")
        found.append({"pid": int(pid), "elapsed": etime, "target": target})
    return found


# llama-server prints one of these per slot as it generates:
#   slot print_timing: id  1 | task 51282 | n_decoded = 3222, tg = 8.64 t/s, ...
# It is the only live view of the pipeline that costs nothing to collect: the
# review path stays untouched, and a dashboard that had to be fed by the runner
# would be a dependency from the reviewer onto its own telemetry.
_TIMING_RE = __import__("re").compile(
    r"slot\s+print_timing:\s*id\s+(?P<slot>\d+)\s*\|\s*task\s+(?P<task>\d+)\s*\|"
    r"\s*n_decoded\s*=\s*(?P<decoded>\d+).*?tg\s*=\s*(?P<tps>[\d.]+)\s*t/s"
)
_SAFE_ALIAS_RE = __import__("re").compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_ACTIVITY_TAIL_BYTES = 24_000
_ACTIVE_WINDOW_SECONDS = 20.0


def _backend_activity(alias: str) -> dict[str, Any]:
    """Live generation state for one backend, read from its own log.

    Freshness comes from the file's mtime rather than the log's own clock: those
    timestamps are process-relative, and converting them would mean trusting an
    offset that changes every restart.
    """
    path = LOG_DIR / f"{alias}.log"
    idle = {"active": False, "slots": 0, "tokens_per_second": None, "decoded": None}
    try:
        stat = path.stat()
    except OSError:
        return idle
    age = time.time() - stat.st_mtime
    if age > _ACTIVE_WINDOW_SECONDS:
        return idle
    try:
        with path.open("rb") as handle:
            if stat.st_size > _ACTIVITY_TAIL_BYTES:
                handle.seek(stat.st_size - _ACTIVITY_TAIL_BYTES)
            blob = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return idle

    latest: dict[str, dict[str, float]] = {}
    for match in _TIMING_RE.finditer(blob):
        # The regex is permissive about digits and dots, so "1.2.3" reaches
        # float() and raises. One malformed log line must not take the page down.
        try:
            latest[match.group("slot")] = {
                "tps": float(match.group("tps")),
                "decoded": float(match.group("decoded")),
            }
        except ValueError:
            continue
    if not latest:
        return idle
    return {
        "active": True,
        "slots": len(latest),
        "tokens_per_second": round(sum(v["tps"] for v in latest.values()), 1),
        "decoded": int(sum(v["decoded"] for v in latest.values())),
    }


# The review graph, in order, with what each stage actually trusts. `kind` is
# not decoration: "pure" stages never take a model's word for anything, and that
# split is the product's central claim, so the dashboard states it.
PIPELINE_STAGES: list[dict[str, Any]] = [
    {"node": "guardrail", "backend": "input-guard", "kind": "model",
     "note": "whole file scanned in segments"},
    {"node": "classify", "backend": "classify", "kind": "model",
     "note": "language, framework, risk"},
    {"node": "retrieve", "backend": "nomic-embed", "kind": "hybrid",
     "note": "embed, then pgvector top-K"},
    {"node": "triage", "backend": "triage", "kind": "model",
     "note": "worth a deep read?"},
    {"node": "deep_review", "backend": "deep-review", "kind": "model",
     "note": "candidates, per window"},
    {"node": "validate", "backend": None, "kind": "pure",
     "note": "grounding gate, no model"},
    {"node": "judge", "backend": "judge", "kind": "model",
     "note": "argues the finding is wrong"},
    {"node": "emit", "backend": None, "kind": "pure",
     "note": "assemble the record"},
]


def collect_pipeline(reports_dir: Path) -> dict[str, Any]:
    """Stage-by-stage view: live activity now, latency from the last finished run."""
    runs = collect_runs(reports_dir, limit=1)
    last = runs[0] if runs else None
    latency = (last or {}).get("node_latency", {}) or {}
    usage = (last or {}).get("model_usage", {}) or {}

    stages = []
    for stage in PIPELINE_STAGES:
        alias = stage["backend"]
        activity = _backend_activity(alias) if alias else {"active": False, "slots": 0}
        node_latency = latency.get(stage["node"], {})
        stages.append(
            {
                **stage,
                "live": activity,
                "p50_ms": node_latency.get("p50_ms"),
                "max_ms": node_latency.get("max_ms"),
                "calls": node_latency.get("count"),
                "tokens": (usage.get(alias) or {}).get("completion_tokens") if alias else None,
            }
        )
    return {
        "stages": stages,
        "last_run": {
            "target": (last or {}).get("target"),
            "wall_seconds": (last or {}).get("wall_seconds"),
            "summary": (last or {}).get("summary", {}),
        }
        if last
        else None,
    }


def tail_log(alias: str, lines: int = 200) -> dict[str, Any]:
    """Tail one backend log.

    `alias` is checked against the registry rather than sanitized. A filtered
    string still has to be trusted; a name that must already exist as a served
    backend cannot address a file outside the log directory at all.
    """
    from sentinel.models.registry import load_registry

    try:
        known = set(load_registry().models) | {"litellm", "redis-cache"}
    except Exception:
        known = {"litellm", "redis-cache"}
    # The registry is our own config, but "trusted input" is how directory
    # traversal usually arrives. An alias is a backend name, so require it to
    # look like one before it is ever joined onto a path.
    if alias not in known or not _SAFE_ALIAS_RE.fullmatch(alias):
        return {"alias": alias, "error": "unknown alias", "lines": []}

    path = LOG_DIR / f"{alias}.log"
    # Resolve before reading: is_file() and open() both follow symlinks, so a
    # link at .run/logs/deep-review.log pointing at /etc/passwd would otherwise
    # be served to anyone who can reach the page.
    try:
        resolved = path.resolve()
        log_root = LOG_DIR.resolve()
    except OSError:
        return {"alias": alias, "error": "no log file", "lines": []}
    if not resolved.is_relative_to(log_root):
        return {"alias": alias, "error": "log path escapes the log directory", "lines": []}
    path = resolved
    if not path.is_file():
        return {"alias": alias, "error": "no log file", "lines": []}
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > _LOG_TAIL_BYTES:
                handle.seek(size - _LOG_TAIL_BYTES)
            blob = handle.read().decode("utf-8", errors="replace")
    except OSError as exc:
        return {"alias": alias, "error": str(exc), "lines": []}
    return {"alias": alias, "lines": blob.splitlines()[-lines:], "bytes": size}


def collect_runs(reports_dir: Path, limit: int = 10) -> list[dict[str, Any]]:
    """Summaries of finished reviews found under a reports directory."""
    if not reports_dir.exists():
        return []
    candidates = sorted(
        reports_dir.glob("**/report.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:limit]
    runs: list[dict[str, Any]] = []
    for path in candidates:
        try:
            report = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        summary = report.get("summary", {})
        run = report.get("run", {})
        metrics_path = path.with_name("metrics.json")
        metrics: dict[str, Any] = {}
        if metrics_path.is_file():
            try:
                metrics = json.loads(metrics_path.read_text())
            except (OSError, json.JSONDecodeError):
                metrics = {}
        # Where candidates died, by gate. The summary only carries a total, but
        # "the deterministic gate rejected it" and "the judge refuted it" are
        # different claims about the reviewer, and the funnel is the one view
        # that makes the difference legible.
        drops: dict[str, int] = {}
        for item in report.get("suppressed_candidates", []) or []:
            stage = item.get("stage") or "unknown"
            drops[stage] = drops.get(stage, 0) + 1
        emitted = len(report.get("findings", []) or [])
        unadjudicated = len(report.get("unadjudicated_candidates", []) or [])
        # `findings` is severity-filtered but the suppressed lists are not, so
        # under a filter the funnel is counting two different populations and its
        # "candidates proposed" total is an undercount. Say so rather than
        # printing a number that quietly means something else.
        severity_filter = (report.get("run") or {}).get("severity_filter")

        runs.append(
            {
                "path": str(path.parent),
                "severity_filter": severity_filter,
                "gate_drops": drops,
                "candidates": emitted + unadjudicated + sum(drops.values()),
                "emitted": emitted,
                "unadjudicated": unadjudicated,
                "target": run.get("target"),
                "timestamp": run.get("timestamp"),
                "wall_seconds": metrics.get("wall_seconds") or run.get("wall_seconds"),
                "summary": summary,
                "node_latency": metrics.get("node_latency", {}),
                "model_usage": metrics.get("model_usage", {}),
                "cache_hit_rate": metrics.get("cache_hit_rate"),
            }
        )
    return runs


# The page lives beside this module rather than inside a string literal: it is
# markup, it should be edited and highlighted as markup, and a lint rule written
# for Python has no business reflowing it.
INDEX_HTML = (Path(__file__).with_name("dashboard.html")).read_text(encoding="utf-8")


class _Handler(BaseHTTPRequestHandler):
    server_version = "sentinel-dashboard"
    reports_dir: Path = REPO_ROOT / "sentinel-report"

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # No embedding, no external fetches: this page is self-contained and
        # renders log text from a machine that reviews confidential source.
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: Any, code: int = 200) -> None:
        self._send(code, json.dumps(payload).encode(), "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802 - stdlib interface
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        try:
            if parsed.path in ("/", "/index.html"):
                self._send(200, INDEX_HTML.encode(), "text/html; charset=utf-8")
            elif parsed.path == "/api/status":
                self._json(collect_status())
            elif parsed.path == "/api/runs":
                self._json(collect_runs(self.reports_dir))
            elif parsed.path == "/api/pipeline":
                self._json(collect_pipeline(self.reports_dir))
            elif parsed.path == "/api/logs":
                alias = (query.get("alias") or [""])[0]
                try:
                    count = min(int((query.get("n") or ["200"])[0]), 2000)
                except ValueError:
                    count = 200
                self._json(tail_log(alias, count))
            elif parsed.path == "/healthz":
                self._json({"ok": True})
            else:
                self._json({"error": "not found"}, 404)
        except Exception as exc:  # never take the dashboard down over one panel
            self._json({"error": str(exc)}, 500)

    def log_message(self, *_args: Any) -> None:
        """Silence per-request stderr chatter; this runs beside a review."""


def _already_serving(port: int, host: str = "127.0.0.1") -> bool:
    """Is one of ours already on this port?

    Checked before binding so a review launched while the user has a dashboard
    open reuses it instead of failing on an address collision — and so we never
    take over a port some unrelated service is holding.
    """
    import httpx

    try:
        response = httpx.get(f"http://{host}:{port}/healthz", timeout=1.0)
        return response.status_code == 200 and response.json().get("ok") is True
    except Exception:
        return False


def ensure_running(
    port: int = DEFAULT_PORT,
    host: str = "127.0.0.1",
    reports_dir: Path | None = None,
) -> str | None:
    """Start the dashboard in a background thread if it isn't already up.

    A daemon thread rather than a detached process: the dashboard exists to show
    a review in flight, and a process outliving the run would leave the user an
    orphan listener to notice and kill later. Returns the URL, or None if the
    port could not be used — a dashboard is a convenience and must never be the
    reason a review fails to start.
    """
    import threading

    url = f"http://{host}:{port}"
    if _already_serving(port, host):
        return url
    try:
        _require_dashboard_loopback(host)
        _Handler.reports_dir = reports_dir or (REPO_ROOT / "sentinel-report")
        server = ThreadingHTTPServer((host, port), _Handler)
        # Thread creation belongs inside the guard: a failure to spawn (thread
        # exhaustion, for one) must not surface as a traceback from a review the
        # user asked for. The dashboard is the optional part.
        threading.Thread(target=server.serve_forever, daemon=True, name="dashboard").start()
    except AirGapViolation:
        raise
    except Exception:
        return None
    return url


def open_browser(url: str) -> bool:
    """Best-effort browser open. A failure here is never worth a traceback."""
    import webbrowser

    try:
        return webbrowser.open(url)
    except Exception:
        return False


def serve(
    port: int = DEFAULT_PORT,
    host: str = "127.0.0.1",
    reports_dir: Path | None = None,
) -> None:
    """Serve the dashboard until interrupted. Loopback enforced, not assumed."""
    _require_dashboard_loopback(host)
    _Handler.reports_dir = reports_dir or (REPO_ROOT / "sentinel-report")
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"sentinel dashboard → http://{host}:{port}  (ctrl-c to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
