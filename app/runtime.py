from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass

from app.audit import AuditLog
from app.config import Settings
from app.harness import BASE_URL, Harness, KonsoleHarness, MockHarness
from app.pipeline import Pipeline
from app.store import Store


class OrgRateLimiter:
    """Fixed-window org limiter with bounded tenant cardinality."""

    def __init__(
        self,
        limit: int = 20,
        window_seconds: int = 60,
        max_orgs: int = 10_000,
    ):
        self.limit = limit
        self.window = window_seconds
        self.max_orgs = max_orgs
        self._events: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, org_id: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._events.pop(org_id, deque())
            while bucket and now - bucket[0] >= self.window:
                bucket.popleft()
            allowed = len(bucket) < self.limit
            if allowed:
                bucket.append(now)
            self._events[org_id] = bucket
            while len(self._events) > self.max_orgs:
                self._events.popitem(last=False)
            return allowed

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    @property
    def tracked_orgs(self) -> int:
        with self._lock:
            return len(self._events)


@dataclass(frozen=True)
class ApplicationServices:
    settings: Settings
    store: Store
    audit: AuditLog
    harness: Harness
    pipeline: Pipeline
    limiter: OrgRateLimiter
    started_at: float


def build_services(
    settings: Settings,
    harness: Harness | None = None,
) -> ApplicationServices:
    store = Store(settings.database_path, settings.token_map_key)
    audit = AuditLog(store)
    selected_harness = harness or (
        MockHarness()
        if settings.harness_backend == "mock"
        else KonsoleHarness(
            api_key=settings.harness_api_key,
            base_url=settings.harness_base_url or BASE_URL,
            fallback_model=settings.harness_fallback_model,
        )
    )
    pipeline = Pipeline(store, audit, selected_harness)
    return ApplicationServices(
        settings=settings,
        store=store,
        audit=audit,
        harness=selected_harness,
        pipeline=pipeline,
        limiter=OrgRateLimiter(),
        started_at=time.monotonic(),
    )

