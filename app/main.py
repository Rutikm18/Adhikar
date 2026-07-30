from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import ValidationError

from app.audit import AuditLog
from app.config import ROOT, settings
from app.harness import BASE_URL, KonsoleHarness, MockHarness, Policy
from app.pipeline import Pipeline
from app.sanitize import EmptyInput
from app.schemas import AnalystAction, DPRRecord, RequestCreate
from app.store import Store
from app.tokenizer import rehydrate

STARTED_AT = time.monotonic()
CORPUS_PATH = ROOT / "data" / "corpus.json"
UI_PATH = ROOT / "ui" / "index.html"
FAVICON_PATH = ROOT / "ui" / "favicon.png"

store = Store(settings.database_path, settings.token_map_key)
audit = AuditLog(store)
harness = (
    MockHarness()
    if settings.harness_backend == "mock"
    else KonsoleHarness(
        api_key=settings.harness_api_key,
        base_url=settings.harness_base_url or BASE_URL,
        fallback_model=settings.harness_fallback_model,
    )
)
pipeline = Pipeline(store, audit, harness)

app = FastAPI(
    title="Adhikar DPR Triage Console",
    version="1.0.0",
    description="Human-approved triage controls aligned to DPDP obligations.",
)


class OrgRateLimiter:
    def __init__(self, limit: int = 20, window_seconds: int = 60):
        self.limit = limit
        self.window = window_seconds
        self.events: defaultdict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, org_id: str) -> bool:
        now = time.monotonic()
        with self.lock:
            bucket = self.events[org_id]
            while bucket and now - bucket[0] >= self.window:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True

    def clear(self) -> None:
        with self.lock:
            self.events.clear()


limiter = OrgRateLimiter()


def request_policy(overrides: dict) -> Policy:
    permitted = {
        "region",
        "redact_pii",
        "injection_check",
        "model",
        "fallback_model",
        "temperature",
        "max_tokens",
        "max_cost_usd",
        "tokenization_mode",
    }
    unknown = set(overrides) - permitted
    if unknown:
        raise HTTPException(
            status_code=422,
            detail={"code": "UNKNOWN_POLICY_FIELD", "fields": sorted(unknown)},
        )
    defaults = {
        "region": settings.default_region,
        "model": settings.harness_model,
        "fallback_model": settings.harness_fallback_model or None,
    }
    try:
        return Policy.model_validate({**defaults, **overrides})
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_POLICY", "errors": exc.errors()},
        ) from exc



@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(UI_PATH)


@app.get("/favicon.png", include_in_schema=False)
def favicon() -> FileResponse:
    return FileResponse(FAVICON_PATH, media_type="image/png")


@app.post("/api/requests", response_model=DPRRecord)
def create_request(payload: RequestCreate, response: Response) -> DPRRecord:
    if not limiter.allow(payload.org_id):
        raise HTTPException(
            status_code=429,
            detail={"code": "ORG_RATE_LIMIT", "message": "20 requests/minute exceeded."},
            headers={"Retry-After": "60"},
        )
    try:
        record, deduplicated = pipeline.intake(
            payload.text, payload.org_id, request_policy(payload.policy_overrides)
        )
    except EmptyInput as exc:
        raise HTTPException(
            status_code=400, detail={"code": "EMPTY_INPUT", "message": str(exc)}
        ) from exc
    response.headers["X-Adhikar-Deduplicated"] = str(deduplicated).lower()
    return record


@app.get("/api/requests", response_model=list[DPRRecord])
def list_requests(status: str | None = Query(default=None)) -> list[DPRRecord]:
    allowed = {"TRIAGED", "NEEDS_HUMAN_REVIEW", "APPROVED", "REJECTED", "BLOCKED"}
    if status and status not in allowed:
        raise HTTPException(status_code=422, detail={"code": "INVALID_STATUS"})
    return store.list_requests(status)


@app.get("/api/requests/{request_id}", response_model=DPRRecord)
def get_request(request_id: str) -> DPRRecord:
    record = store.get_request(request_id)
    if not record:
        raise HTTPException(status_code=404, detail={"code": "REQUEST_NOT_FOUND"})
    return record


@app.get("/api/requests/{request_id}/trace")
def get_trace(
    request_id: str,
    x_analyst_id: str | None = Header(default=None, max_length=80),
) -> dict:
    trace = store.get_trace(request_id)
    if trace is None:
        raise HTTPException(status_code=404, detail={"code": "REQUEST_NOT_FOUND"})
    if x_analyst_id:
        trace["analyst_input"] = rehydrate(
            trace["protected_input"], store.decrypt_map(request_id)
        )
    return trace


@app.post("/api/requests/{request_id}/approve", response_model=DPRRecord)
def approve_request(request_id: str, action: AnalystAction) -> DPRRecord:
    record = store.get_request(request_id)
    if not record:
        raise HTTPException(status_code=404, detail={"code": "REQUEST_NOT_FOUND"})
    if record.status == "APPROVED":
        return record
    if record.status != "TRIAGED":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "APPROVAL_NOT_ALLOWED",
                "message": "Only a non-escalated TRIAGED request can be approved.",
            },
        )
    if not record.verdict or not record.verdict.draft_response:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "DRAFT_WITHHELD",
                "message": "Escalated or blocked requests cannot be approved here.",
            },
        )
    updated = store.update_status(request_id, "APPROVED")
    assert updated is not None
    audit.append(
        record.org_id,
        request_id,
        "APPROVE",
        action.analyst_id,
        record.harness_meta,
        record.policy_version,
    )
    return updated


@app.post("/api/requests/{request_id}/reject", response_model=DPRRecord)
def reject_request(request_id: str, action: AnalystAction) -> DPRRecord:
    record = store.get_request(request_id)
    if not record:
        raise HTTPException(status_code=404, detail={"code": "REQUEST_NOT_FOUND"})
    if record.status == "REJECTED":
        return record
    if not action.reason.strip():
        raise HTTPException(
            status_code=422,
            detail={"code": "REJECTION_REASON_REQUIRED"},
        )
    updated = store.update_status(request_id, "REJECTED")
    assert updated is not None
    audit.append(
        record.org_id,
        request_id,
        "REJECT",
        action.analyst_id,
        record.harness_meta,
        record.policy_version,
    )
    return updated


@app.get("/api/audit/export")
def export_audit() -> StreamingResponse:
    audit.append(
        "system",
        "audit_export",
        "EXPORT",
        "system",
        {},
        "sla_policy@1",
    )

    def generate():
        for event in audit.events():
            yield json.dumps(event, sort_keys=True) + "\n"

    return StreamingResponse(
        generate(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=adhikar-audit.ndjson"},
    )


@app.get("/api/audit/verify")
def verify_audit() -> dict:
    return audit.verify_chain()


@app.get("/api/demo/corpus")
def demo_corpus() -> list[dict]:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


@app.post("/api/demo/load-corpus")
def load_corpus(request: Request) -> dict:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    loaded = []
    policy = request_policy({})
    for case in corpus:
        record, _ = pipeline.intake(
            case["text"], "demo-org", policy, allow_dedupe=False
        )
        loaded.append({"case": case["id"], "request_id": record.id, "status": record.status})
    return {"loaded": len(loaded), "requests": loaded}


@app.post("/api/demo/reset", status_code=204)
def reset_demo() -> Response:
    store.reset()
    limiter.clear()
    return Response(status_code=204)


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "harness_backend": settings.harness_backend,
        "region": settings.default_region,
        "model": settings.harness_model,
        "uptime_seconds": round(time.monotonic() - STARTED_AT, 1),
        "audit": audit.verify_chain(),
    }
