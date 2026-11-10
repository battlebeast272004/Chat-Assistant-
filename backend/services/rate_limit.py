"""Minimal in-memory sliding-window rate limiter (per client IP, per process).

Good enough for a single-instance internal tool. For multi-instance
deployments use a shared store (Redis) or the reverse proxy's limiter.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, limit: int, window_s: float = 60.0):
        self.limit, self.window_s = limit, window_s
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        if self.limit <= 0:
            return True  # disabled
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window_s:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            if len(self._hits) > 10_000:  # bound memory: drop idle keys
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


#: Applies to endpoints that trigger outbound requests (/start, /analyse, and the stage endpoints).
assessment_limiter = RateLimiter(int(os.environ.get("ASSESSMENTS_PER_MINUTE", "10")))
