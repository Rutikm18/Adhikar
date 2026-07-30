from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Literal, Protocol

import httpx
from pydantic import BaseModel, Field


class Policy(BaseModel):
    region: Literal["in", "eu", "us", "apac"] = "in"
    redact_pii: bool = True
    injection_check: bool = True
    model: str = "mock-dpr-v1"
    fallback_model: str | None = None
    temperature: float = 0.0
    max_tokens: int = 1200
    max_cost_usd: float = 0.05
    tokenization_mode: Literal[
        "harness_only", "local_only", "defence_in_depth"
    ] = "defence_in_depth"


class Redaction(BaseModel):
    kind: str
    count: int


class HarnessResponse(BaseModel):
    text: str
    redactions: list[Redaction] = Field(default_factory=list)
    injection_flagged: bool = False
    injection_detail: str | None = None
    region_served: str | None = None
    provider: str | None = None
    model: str | None = None
    latency_ms: int = 0
    cost_usd: float = 0.0
    raw: dict = Field(default_factory=dict)


class Harness(Protocol):
    def complete(self, messages: list[dict], policy: Policy) -> HarnessResponse: ...


class HarnessError(RuntimeError):
    pass


class HarnessUnavailable(HarnessError):
    pass


class HarnessTimeout(HarnessError):
    pass


class HarnessBudgetExceeded(HarnessError):
    pass


_INJECTION_TRIGGERS = (
    "ignore previous",
    "ignore all previous",
    "disregard the privacy",
    "mark this identity verified",
    "identity has been verified",
    "reveal every customer",
    "export all customer",
    "system note:",
    "assistant,",
)


class MockHarness:
    """Deterministic local simulator. It makes no network calls."""

    def complete(self, messages: list[dict], policy: Policy) -> HarnessResponse:
        started = time.perf_counter()
        data = messages[-1]["content"]
        lower = data.lower()
        injection = policy.injection_check and any(
            trigger in lower for trigger in _INJECTION_TRIGGERS
        )
        is_hindi = bool(re.search(r"[\u0900-\u097f]", data))

        if any(word in lower for word in ("erase", "delete", "मिटा", "remove my details")):
            right = "ERASURE"
        elif (
            any(word in lower for word in ("correct", "wrong date", "correction"))
            and not any(word in lower for word in ("copy", "access", "send me"))
        ):
            right = "CORRECTION"
        elif "grievance" in lower or "no response" in lower:
            right = "GRIEVANCE"
        elif "nominate" in lower:
            right = "NOMINATION"
        elif any(
            word in lower
            for word in ("copy", "access", "provide", "send my personal data", "dekhna", "देख")
        ):
            right = "ACCESS"
        else:
            right = "UNCLEAR"

        reasons: list[str] = []
        third_party = any(
            phrase in lower
            for phrase in (
                "my spouse",
                "account holder",
                "every customer",
                "all customer",
            )
        )
        minor = "child" in lower or "parent of" in lower
        multiple = (
            any(word in lower for word in ("copy", "access", "send me"))
            and "correct" in lower
        )
        ambiguous = "remove my details" in lower
        legal_hold = any(
            phrase in lower
            for phrase in ("active dispute", "pending proceedings", "complaint evidence")
        )
        nominee = right == "NOMINATION"
        if injection:
            reasons.append("ADVERSARIAL_CONTENT")
        if third_party:
            reasons.append("THIRD_PARTY_DATA")
        if minor:
            reasons.append("MINOR_DATA")
        if multiple:
            reasons.append("MULTIPLE_RIGHTS")
        if ambiguous:
            reasons.append("AMBIGUOUS_RIGHT")
        if legal_hold:
            reasons.append("LEGAL_HOLD_CONFLICT")
        if nominee:
            reasons.append("DECEASED_OR_NOMINEE")
        if right == "UNCLEAR":
            reasons.append("AMBIGUOUS_RIGHT")

        tokens = re.findall(r"<[A-Z][A-Z0-9_]*_\d+>", data)
        identity = {
            "name_token": None,
            "email_token": next((t for t in tokens if t.startswith("<EMAIL_")), None),
            "phone_token": next((t for t in tokens if t.startswith("<PHONE_")), None),
            "account_ref_token": next(
                (t for t in tokens if t.startswith("<ACCOUNT_REF_")), None
            ),
        }
        secondary = ["CORRECTION"] if multiple else []
        escalation = bool(reasons)
        draft = "" if escalation else (
            "We acknowledge your data principal request"
            + (f" regarding {identity['account_ref_token']}" if identity["account_ref_token"] else "")
            + ". An analyst will review the claim and contact you through the registered channel."
        )
        verdict = {
            "right_claimed": right,
            "secondary_rights": secondary,
            "confidence": 0.92 if right != "UNCLEAR" else 0.55,
            "claimed_identity": identity,
            "requested_scope": "Personal data described in the submitted request.",
            "third_party_data_requested": third_party,
            "concerns_minor": minor,
            "language_detected": "hi" if is_hindi and not re.search(r"[A-Za-z]", data) else ("hi-en" if is_hindi else "en"),
            "draft_response": draft,
            "escalation": {
                "required": escalation,
                "reasons": reasons,
                "analyst_note": "Manual review required for the flagged condition." if escalation else "",
            },
            "model_notes": "Deterministic mock classification.",
        }
        redactions = []
        if policy.redact_pii:
            raw_patterns = {
                "EMAIL": r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
                "PHONE": r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)",
                "PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
                "AADHAAR": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
                "ACCOUNT_REF": r"\b[A-Z]{2,4}[-/]?\d{6,12}\b",
            }
            for kind, raw_pattern in raw_patterns.items():
                count = len(re.findall(fr"<{kind}(?:_SHAPED)?_\d+>", data))
                if not count:
                    count = len(re.findall(raw_pattern, data, flags=re.I))
                if count:
                    redactions.append(Redaction(kind=kind, count=count))
        latency = max(1, int((time.perf_counter() - started) * 1000))
        return HarnessResponse(
            text=json.dumps(verdict, ensure_ascii=False),
            redactions=redactions,
            injection_flagged=injection,
            injection_detail="Untrusted instructions detected and ignored." if injection else None,
            region_served=policy.region,
            provider="mock-local",
            model=policy.model,
            latency_ms=latency,
            cost_usd=0.0,
            raw={
                "simulated": True,
                "deterministic": True,
                "fixture_key": hashlib.sha256(data.encode("utf-8")).hexdigest()[:12],
            },
        )


class KonsoleHarness:
    """Event adapter. Only this module is allowed to know provider details."""

    def __init__(self, base_url: str, api_key: str, fallback_model: str = ""):
        self.base_url = base_url
        self.api_key = api_key
        self.fallback_model = fallback_model

    def _call(self, messages: list[dict], policy: Policy, model: str) -> httpx.Response:
        # TODO(event) 1: confirm base URL and authentication header shape
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {
            "messages": messages,
            "model": model,
            "region": policy.region,  # TODO(event) 2: region placement
            "redact_pii": policy.redact_pii,  # TODO(event) 3: redaction switch/report
            "injection_check": policy.injection_check,  # TODO(event) 4: signal shape
            "temperature": policy.temperature,
            "max_tokens": policy.max_tokens,
            "fallback_model": policy.fallback_model,  # TODO(event) 5: routing names
        }
        return httpx.post(self.base_url, headers=headers, json=payload, timeout=15.0)

    def complete(self, messages: list[dict], policy: Policy) -> HarnessResponse:
        estimated_cost = sum(len(str(item)) for item in messages) * 0.000002
        if estimated_cost > policy.max_cost_usd:
            raise HarnessBudgetExceeded("Estimated request cost exceeds the policy cap.")
        if not self.base_url or not self.api_key:
            raise HarnessUnavailable("Konsole harness is not configured.")
        started = time.perf_counter()
        delays = iter((0.5, 1.5))
        response: httpx.Response | None = None
        try:
            for attempt in range(3):
                response = self._call(messages, policy, policy.model)
                if response.status_code != 429 or attempt == 2:
                    break
                time.sleep(next(delays))
        except httpx.TimeoutException as exc:
            raise HarnessTimeout("Harness request exceeded 15 seconds.") from exc
        except httpx.HTTPError as exc:
            raise HarnessUnavailable("Harness network request failed.") from exc
        assert response is not None
        if response.status_code == 429:
            raise HarnessUnavailable("Harness rate limit persisted after retries.")
        if response.status_code >= 500:
            fallback = policy.fallback_model or self.fallback_model
            if not fallback:
                raise HarnessUnavailable("Harness server error and no fallback configured.")
            try:
                response = self._call(messages, policy, fallback)
            except httpx.TimeoutException as exc:
                raise HarnessTimeout("Fallback harness request timed out.") from exc
            if response.status_code >= 400:
                raise HarnessUnavailable("Fallback harness request failed.")
        if response.status_code >= 400:
            raise HarnessUnavailable(f"Harness returned HTTP {response.status_code}.")
        body = response.json()
        return HarnessResponse(
            text=body.get("text", body.get("content", "")),
            redactions=body.get("redactions", []),
            injection_flagged=body.get("injection_flagged", False),
            injection_detail=body.get("injection_detail"),
            region_served=body.get("region_served", policy.region),
            provider=body.get("provider"),
            model=body.get("model", policy.model),
            latency_ms=int((time.perf_counter() - started) * 1000),
            cost_usd=float(body.get("cost_usd", 0.0)),
            raw=body,
        )
