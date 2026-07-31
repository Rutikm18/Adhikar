from __future__ import annotations

import hmac
import json
import time

from fastapi import APIRouter, Header, HTTPException, Query, Response
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import ValidationError

from app.config import ROOT
from app.harness import Policy
from app.runtime import ApplicationServices
from app.sanitize import EmptyInput
from app.schemas import AnalystAction, DPRRecord, RequestCreate
from app.tokenizer import rehydrate

CORPUS_PATH = ROOT / "data" / "corpus.json"
UI_PATH = ROOT / "ui" / "index.html"
FAVICON_PATH = ROOT / "ui" / "favicon.png"
_STATUSES = {"TRIAGED", "NEEDS_HUMAN_REVIEW", "APPROVED", "REJECTED", "BLOCKED"}


def _request_policy(overrides: dict, services: ApplicationServices) -> Policy:
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
    settings = services.settings
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
            detail={
                "code": "INVALID_POLICY",
                "errors": [
                    {
                        "location": list(error["loc"]),
                        "message": error["msg"],
                        "type": error["type"],
                    }
                    for error in exc.errors()
                ],
            },
        ) from exc


def _require_demo(services: ApplicationServices) -> None:
    if not services.settings.enable_demo_endpoints:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})


def create_api_router(services: ApplicationServices) -> APIRouter:
    router = APIRouter()
    store = services.store
    audit = services.audit

    @router.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(UI_PATH)

    @router.get("/favicon.png", include_in_schema=False)
    def favicon() -> FileResponse:
        return FileResponse(FAVICON_PATH, media_type="image/png")

    @router.post("/api/requests", response_model=DPRRecord)
    def create_request(payload: RequestCreate, response: Response) -> DPRRecord:
        if not services.limiter.allow(payload.org_id):
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "ORG_RATE_LIMIT",
                    "message": "20 requests/minute exceeded.",
                },
                headers={"Retry-After": "60"},
            )
        try:
            record, deduplicated = services.pipeline.intake(
                payload.text,
                payload.org_id,
                _request_policy(payload.policy_overrides, services),
            )
        except EmptyInput as exc:
            raise HTTPException(
                status_code=400,
                detail={"code": "EMPTY_INPUT", "message": str(exc)},
            ) from exc
        response.headers["X-Adhikar-Deduplicated"] = str(deduplicated).lower()
        return record

    @router.get("/api/requests", response_model=list[DPRRecord])
    def list_requests(
        status: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ) -> list[DPRRecord]:
        if status and status not in _STATUSES:
            raise HTTPException(status_code=422, detail={"code": "INVALID_STATUS"})
        return store.list_requests(status, limit=limit, offset=offset)

    @router.get("/api/requests/{request_id}", response_model=DPRRecord)
    def get_request(request_id: str) -> DPRRecord:
        record = store.get_request(request_id)
        if not record:
            raise HTTPException(status_code=404, detail={"code": "REQUEST_NOT_FOUND"})
        return record

    @router.get("/api/requests/{request_id}/trace")
    def get_trace(
        request_id: str,
        x_analyst_id: str | None = Header(default=None, max_length=80),
        x_analyst_key: str | None = Header(default=None, max_length=512),
    ) -> dict:
        trace = store.get_trace(request_id)
        if trace is None:
            raise HTTPException(status_code=404, detail={"code": "REQUEST_NOT_FOUND"})
        if x_analyst_id is not None or x_analyst_key is not None:
            configured_key = services.settings.analyst_api_key
            if not configured_key:
                raise HTTPException(
                    status_code=403,
                    detail={"code": "TRACE_REHYDRATION_DISABLED"},
                )
            if (
                not x_analyst_id
                or not x_analyst_key
                or not hmac.compare_digest(x_analyst_key, configured_key)
            ):
                raise HTTPException(
                    status_code=403,
                    detail={"code": "ANALYST_AUTHENTICATION_FAILED"},
                )
            trace["analyst_input"] = rehydrate(
                trace["protected_input"], store.decrypt_map(request_id)
            )
        return trace

    @router.post("/api/requests/{request_id}/approve", response_model=DPRRecord)
    def approve_request(request_id: str, action: AnalystAction) -> DPRRecord:
        record = store.get_request(request_id)
        if not record:
            raise HTTPException(status_code=404, detail={"code": "REQUEST_NOT_FOUND"})
        if record.status == "APPROVED":
            return record
        if (
            record.status != "TRIAGED"
            or not record.verdict
            or not record.verdict.draft_response
        ):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "APPROVAL_NOT_ALLOWED",
                    "message": "Only a non-escalated TRIAGED request can be approved.",
                },
            )
        with store.transaction() as connection:
            transitioned = store.transition_status(
                connection,
                request_id,
                ("TRIAGED",),
                "APPROVED",
            )
            if transitioned:
                audit.append(
                    record.org_id,
                    request_id,
                    "APPROVE",
                    action.analyst_id,
                    record.harness_meta,
                    record.policy_version,
                    connection=connection,
                )
        updated = store.get_request(request_id)
        if not transitioned or updated is None:
            raise HTTPException(
                status_code=409,
                detail={"code": "CONCURRENT_STATUS_CHANGE"},
            )
        return updated

    @router.post("/api/requests/{request_id}/reject", response_model=DPRRecord)
    def reject_request(request_id: str, action: AnalystAction) -> DPRRecord:
        record = store.get_request(request_id)
        if not record:
            raise HTTPException(status_code=404, detail={"code": "REQUEST_NOT_FOUND"})
        if record.status == "REJECTED":
            return record
        if record.status == "APPROVED":
            raise HTTPException(
                status_code=409,
                detail={"code": "TERMINAL_STATUS"},
            )
        if not action.reason.strip():
            raise HTTPException(
                status_code=422,
                detail={"code": "REJECTION_REASON_REQUIRED"},
            )
        with store.transaction() as connection:
            transitioned = store.transition_status(
                connection,
                request_id,
                ("TRIAGED", "NEEDS_HUMAN_REVIEW", "BLOCKED"),
                "REJECTED",
            )
            if transitioned:
                audit.append(
                    record.org_id,
                    request_id,
                    "REJECT",
                    action.analyst_id,
                    record.harness_meta,
                    record.policy_version,
                    connection=connection,
                )
        updated = store.get_request(request_id)
        if not transitioned or updated is None:
            raise HTTPException(
                status_code=409,
                detail={"code": "CONCURRENT_STATUS_CHANGE"},
            )
        return updated

    @router.get("/api/audit/export")
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

    @router.get("/api/audit/verify")
    def verify_audit() -> dict:
        return audit.verify_chain()

    @router.get("/api/demo/corpus")
    def demo_corpus() -> list[dict]:
        _require_demo(services)
        return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))

    @router.post("/api/demo/load-corpus")
    def load_corpus() -> dict:
        _require_demo(services)
        corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
        loaded = []
        policy = _request_policy({}, services)
        for case in corpus:
            record, _ = services.pipeline.intake(
                case["text"],
                "demo-org",
                policy,
                allow_dedupe=False,
            )
            loaded.append(
                {
                    "case": case["id"],
                    "request_id": record.id,
                    "status": record.status,
                }
            )
        return {"loaded": len(loaded), "requests": loaded}

    @router.post("/api/demo/reset", status_code=204)
    def reset_demo() -> Response:
        _require_demo(services)
        store.reset()
        services.limiter.clear()
        return Response(status_code=204)

    @router.get("/api/health")
    def health(response: Response) -> dict:
        database_ok = store.healthcheck()
        chain = audit.verify_chain()
        healthy = database_ok and chain["intact"]
        if not healthy:
            response.status_code = 503
        return {
            "status": "ok" if healthy else "degraded",
            "harness_backend": services.settings.harness_backend,
            "region": services.settings.default_region,
            "model": services.settings.harness_model,
            "uptime_seconds": round(time.monotonic() - services.started_at, 1),
            "database": "ok" if database_ok else "unavailable",
            "audit": chain,
        }

    return router

