"""Run-wide metrics collection: per-node latency, per-model tokens, cache hits."""

import statistics
import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass
class ModelUsage:
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cache_hits: int = 0


@dataclass
class MetricsCollector:
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    node_latencies_ms: dict[str, list[float]] = field(
        default_factory=lambda: defaultdict(list)
    )
    model_usage: dict[str, ModelUsage] = field(
        default_factory=lambda: defaultdict(ModelUsage)
    )
    counters: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    @contextmanager
    def time_node(self, node: str):
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            with self._lock:
                self.node_latencies_ms[node].append(elapsed_ms)

    def record_model_call(
        self,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        cache_hit: bool,
    ) -> None:
        with self._lock:
            usage = self.model_usage[model]
            usage.calls += 1
            usage.prompt_tokens += prompt_tokens
            usage.completion_tokens += completion_tokens
            if cache_hit:
                usage.cache_hits += 1

    def increment(self, counter: str, by: int = 1) -> None:
        with self._lock:
            self.counters[counter] += by

    def summary(self) -> dict:
        import math

        def stats(values: list[float]) -> dict:
            ordered = sorted(values)
            # nearest-rank percentile: ceil(p * n) - 1
            p95_idx = max(0, math.ceil(0.95 * len(ordered)) - 1)
            return {
                "count": len(ordered),
                "min_ms": round(ordered[0], 1),
                "p50_ms": round(statistics.median(ordered), 1),
                "p95_ms": round(ordered[p95_idx], 1),
                "max_ms": round(ordered[-1], 1),
            }

        # snapshot under the lock; aggregate outside it
        with self._lock:
            latencies = {n: list(v) for n, v in self.node_latencies_ms.items()}
            usage = {
                m: ModelUsage(u.calls, u.prompt_tokens, u.completion_tokens, u.cache_hits)
                for m, u in self.model_usage.items()
            }
            counters = dict(self.counters)

        total_calls = sum(u.calls for u in usage.values())
        total_hits = sum(u.cache_hits for u in usage.values())
        return {
            "node_latency": {n: stats(v) for n, v in latencies.items() if v},
            "model_usage": {
                m: {
                    "calls": u.calls,
                    "prompt_tokens": u.prompt_tokens,
                    "completion_tokens": u.completion_tokens,
                    "cache_hits": u.cache_hits,
                }
                for m, u in usage.items()
            },
            "cache_hit_rate": round(total_hits / total_calls, 4) if total_calls else None,
            "counters": counters,
        }
