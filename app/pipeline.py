from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone

from pydantic import ValidationError

from app.audit import AuditLog
from app.clock import compute_sla
from app.harness import (
    Harness,
    HarnessError,
    HarnessResponse,
    Policy,
)
from app.prompts import build_messages, repair_message
from app.sanitize import sanitize_input
from app.schemas import (
    ClaimedIdentity,
    DPRRecord,
    Escalation,
    EscalationReason,
    TriageVerdict,
)
from app.store import Store
from app.tokenizer import token_counts, tokenize, verify_output


def fail_closed(reason: EscalationReason) -> TriageVerdict:
    return TriageVerdict(
        right_claimed="UNCLEAR",
        confidence=0.0,
        claimed_identity=ClaimedIdentity(),
        escalation=Escalation(
            required=True,
            reasons=[reason],
            analyst_note="Automated triage did not complete. Manual review required.",
        ),
        draft_response="",
    )


def _parse_json(text: str) -> dict:
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.I)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    return json.loads(cleaned)


def _add_reason(verdict: TriageVerdict, reason: EscalationReason, note: str = "") -> None:
    if reason not in verdict.escalation.reasons:
        verdict.escalation.reasons.append(reason)
    verdict.escalation.required = True
    if note:
        verdict.escalation.analyst_note = note


class Pipeline:
    def __init__(self, store: Store, audit: AuditLog, harness: Harness):
        self.store = store
        self.audit = audit
        self.harness = harness

    def intake(
        self, raw_text: str, org_id: str, policy: Policy, allow_dedupe: bool = True
    ) -> tuple[DPRRecord, bool]:
        sanitized = sanitize_input(raw_text)
        if allow_dedupe:
            duplicate = self.store.find_duplicate(org_id, sanitized.content_hash)
            if duplicate:
                return duplicate, True

        tokenized_text, token_map = tokenize(sanitized.scanned_text)
        outbound_text = (
            sanitized.scanned_text
            if policy.tokenization_mode == "harness_only"
            else tokenized_text
        )
        effective_policy = policy.model_copy(deep=True)
        if policy.tokenization_mode == "local_only":
            effective_policy.redact_pii = False
        elif policy.tokenization_mode == "defence_in_depth":
            effective_policy.redact_pii = True
        fingerprint = hashlib.sha256(
            effective_policy.model_dump_json().encode("utf-8")
        ).hexdigest()
        cached = self.store.get_cache(org_id, sanitized.content_hash, fingerprint)
        messages, nonce = build_messages(outbound_text)
        response: HarnessResponse | None = None
        from_cache = cached is not None

        if cached:
            verdict, harness_meta = cached
            verdict = verdict.model_copy(deep=True)
        else:
            try:
                response = self.harness.complete(messages, effective_policy)
                try:
                    verdict = TriageVerdict.model_validate(_parse_json(response.text))
                except (json.JSONDecodeError, ValidationError):
                    repaired = self.harness.complete(
                        repair_message(messages, response.text), effective_policy
                    )
                    response = repaired
                    verdict = TriageVerdict.model_validate(_parse_json(response.text))
                harness_meta = {
                    "region_served": response.region_served,
                    "provider": response.provider,
                    "model": response.model,
                    "redactions": [item.model_dump() for item in response.redactions],
                    "injection_flagged": response.injection_flagged,
                    "injection_detail": (
                        "Harness reported adversarial content."
                        if response.injection_flagged
                        else None
                    ),
                    "latency_ms": response.latency_ms,
                    "cost_usd": response.cost_usd,
                    "cached": False,
                }
            except HarnessError:
                verdict = fail_closed("HARNESS_ERROR")
                harness_meta = {
                    "region_served": None,
                    "provider": None,
                    "model": effective_policy.model,
                    "redactions": [],
                    "injection_flagged": False,
                    "latency_ms": 0,
                    "cost_usd": 0.0,
                    "error": "HARNESS_ERROR",
                    "cached": False,
                }
            except (json.JSONDecodeError, ValidationError, ValueError):
                verdict = fail_closed("SCHEMA_FAILURE")
                harness_meta = {
                    "region_served": getattr(response, "region_served", None),
                    "provider": getattr(response, "provider", None),
                    "model": getattr(response, "model", effective_policy.model),
                    "redactions": [],
                    "injection_flagged": bool(
                        getattr(response, "injection_flagged", False)
                    ),
                    "latency_ms": int(getattr(response, "latency_ms", 0)),
                    "cost_usd": float(getattr(response, "cost_usd", 0.0)),
                    "error": "SCHEMA_FAILURE",
                    "cached": False,
                }

        if from_cache:
            harness_meta = dict(harness_meta)
            harness_meta["cached"] = True
        if sanitized.oversized:
            _add_reason(verdict, "OVERSIZED_INPUT")
        if sanitized.homoglyph_flagged:
            _add_reason(
                verdict,
                "ADVERSARIAL_CONTENT",
                "Mixed-script homoglyph pattern requires manual review.",
            )
        if harness_meta.get("injection_flagged"):
            _add_reason(
                verdict,
                "ADVERSARIAL_CONTENT",
                "Harness detected untrusted instructions; they were ignored.",
            )
        if len(sanitized.text.strip()) < 30 and verdict.confidence == 1.0:
            verdict.confidence = 0.74
            _add_reason(verdict, "LOW_CONFIDENCE")
        if verdict.right_claimed == "UNCLEAR" and not verdict.escalation.required:
            _add_reason(verdict, "AMBIGUOUS_RIGHT")
        if verdict.confidence < 0.75 and "LOW_CONFIDENCE" not in verdict.escalation.reasons:
            _add_reason(verdict, "LOW_CONFIDENCE")
        if verdict.escalation.required:
            verdict.draft_response = ""

        foreign_tokens = verify_output(verdict.draft_response, token_map)
        blocked = False
        if foreign_tokens:
            verdict.draft_response = ""
            _add_reason(
                verdict,
                "THIRD_PARTY_DATA",
                "Draft contained an identifier token not present in this request.",
            )
            blocked = True
        if harness_meta.get("injection_flagged"):
            blocked = True
        if verdict.third_party_data_requested:
            blocked = True
            _add_reason(verdict, "THIRD_PARTY_DATA")

        received_at = datetime.now(timezone.utc)
        due_at, policy_version, sla_rule = compute_sla(
            received_at, verdict.right_claimed
        )
        status = (
            "BLOCKED"
            if blocked
            else ("NEEDS_HUMAN_REVIEW" if verdict.escalation.required else "TRIAGED")
        )
        harness_meta.update(
            {
                "local_protected": len(token_map),
                "tokenization_mode": policy.tokenization_mode,
                "policy_region": policy.region,
                "decoded_blobs_inspected": sanitized.decoded_blobs,
                "sla_rule": sla_rule,
            }
        )
        record = DPRRecord(
            id=f"dpr_{uuid.uuid4().hex[:12]}",
            org_id=org_id,
            received_at=received_at,
            raw_text_hash=sanitized.content_hash,
            status=status,
            verdict=verdict,
            sla_due_at=due_at,
            harness_meta=harness_meta,
            policy_version=policy_version,
        )
        safe_messages = []
        for message in messages:
            content = message["content"]
            for token, value in sorted(
                token_map.items(), key=lambda item: len(item[1]), reverse=True
            ):
                content = content.replace(value, token)
            safe_messages.append({**message, "content": content})
        response_for_trace = (
            response.text if response else verdict.model_dump_json()
        )
        response_for_trace, _ = tokenize(response_for_trace)
        trace = {
            "nonce": nonce,
            "outbound_messages": safe_messages,
            "response_text": response_for_trace,
            "redaction_report": harness_meta.get("redactions", []),
            "local_redactions": token_counts(token_map),
            "region_served": harness_meta.get("region_served"),
            "provider": harness_meta.get("provider"),
            "model": harness_meta.get("model"),
            "latency_ms": harness_meta.get("latency_ms"),
            "cost_usd": harness_meta.get("cost_usd"),
            "injection_flagged": harness_meta.get("injection_flagged", False),
            "note": "Matched identifier values are token-protected before trace persistence.",
        }
        self.store.save(
            record, trace, tokenized_text, token_map, fingerprint
        )
        self.audit.append(
            org_id,
            record.id,
            "BLOCK" if status == "BLOCKED" else (
                "ESCALATE" if status == "NEEDS_HUMAN_REVIEW" else "TRIAGE"
            ),
            "system",
            harness_meta,
            policy_version,
        )
        return record, False
