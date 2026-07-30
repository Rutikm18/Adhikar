"""
app/harness.py — the ONLY module permitted to talk to Konsole.

Invariant C1 from the build spec: no other file in this project may import an
LLM SDK or reference a provider URL. evals/test_no_direct_sdk.py enforces this.

Fill the CAPABILITIES block below from your probe_konsole.py results before use.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Literal, Protocol

import httpx
from pydantic import BaseModel

# =============================================================================
# CAPABILITIES — set from probe_konsole.py results (see docs/CAPABILITY_FINDINGS.md)
# =============================================================================
# PII: Konsole ALWAYS masks PII in model input by default (__PII_TYPE_N__ tokens).
# pii_detection=True adds session_pii_map to the response (our redaction evidence).
# WARNING: do NOT send pii_masking=True — it reveals masked values back to the model.
SUPPORTS_PII_DETECTION = True      # confirmed: pii_detected field + session_pii_map
SUPPORTS_PII_MASKING = True        # confirmed: input masking is always active by default
SUPPORTS_JSON_MODE = True          # confirmed: response_format json_object parses cleanly
SUPPORTS_INJECTION_FLAG = False    # confirmed: prompt_injection_detected always False; app-layer required
REGION_PARAM_NAME: str | None = "region"   # confirmed: accepted by API (probe [7])

# Model IDs confirmed working by probe [1]/[2].
# gemini-3.1-flash-lite HTTP 400 from Google, falls back to deepseek with empty content field.
# sarvam-m is deprecated — use sarvam-105b.
MODEL_PRIMARY = "qwen-max"
MODEL_FALLBACK = "deepseek-chat"
MODEL_SOVEREIGN = "sarvam-105b"  # Indian provider — data-sovereignty routing

BASE_URL = os.getenv("KONSOLE_BASE_URL", "https://api.konsole.one/v1")


# =============================================================================
# Errors — every one of these becomes NEEDS_HUMAN_REVIEW upstream. Never fail open.
# =============================================================================
class HarnessError(Exception): ...
class HarnessUnavailable(HarnessError): ...
class HarnessTimeout(HarnessError): ...
class HarnessBudgetExceeded(HarnessError): ...
class HarnessAuthError(HarnessError): ...


# =============================================================================
# Contract
# =============================================================================
class Policy(BaseModel):
    model: str = MODEL_PRIMARY
    fallback_model: str | None = MODEL_FALLBACK
    redact_pii: bool = True
    injection_check: bool = True     # app-layer if SUPPORTS_INJECTION_FLAG is False
    json_mode: bool = True
    temperature: float = 0.0
    max_tokens: int = 1200
    timeout_s: float = 20.0
    sovereign_routing: bool = False  # route to MODEL_SOVEREIGN
    region: Literal["in", "eu", "us", "apac"] = "in"
    # Pipeline compatibility fields — kept so pipeline.py/main.py don't need changes yet
    tokenization_mode: Literal["harness_only", "local_only", "defence_in_depth"] = "defence_in_depth"
    max_cost_usd: float = 0.05

    def fingerprint(self) -> str:
        """Cache key component. Change of policy must invalidate cached verdicts."""
        return json.dumps(self.model_dump(), sort_keys=True)


class Redaction(BaseModel):
    kind: str
    count: int


class HarnessResponse(BaseModel):
    text: str
    redactions: list[Redaction] = []
    injection_flagged: bool = False
    injection_detail: str | None = None
    region_served: str | None = None
    provider: str | None = None
    model: str | None = None
    latency_ms: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0  # kept for pipeline.py compatibility
    raw: dict = {}


class Harness(Protocol):
    def complete(self, messages: list[dict], policy: Policy) -> HarnessResponse: ...


# =============================================================================
# Real implementation
# =============================================================================
class KonsoleHarness:
    def __init__(self, api_key: str | None = None, base_url: str = BASE_URL,
                 fallback_model: str = ""):
        self.api_key = api_key or os.getenv("KONSOLE_API_KEY")
        if not self.api_key:
            raise HarnessAuthError("KONSOLE_API_KEY is not set")
        self.base_url = base_url.rstrip("/") if base_url else BASE_URL
        self.fallback_model = fallback_model
        self._client = httpx.Client(timeout=30.0)

    # -- payload construction -------------------------------------------------
    def _build_payload(self, messages: list[dict], policy: Policy, model: str) -> dict:
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": policy.temperature,
            "max_tokens": policy.max_tokens,
        }
        if policy.redact_pii and SUPPORTS_PII_DETECTION:
            payload["pii_detection"] = True
        # pii_masking=True is intentionally omitted: it tells the model what was masked,
        # causing more PII to appear in the model response. The default Konsole behaviour
        # (no param) already masks PII in model input via __PII_TYPE_N__ tokens.
        if policy.json_mode and SUPPORTS_JSON_MODE:
            payload["response_format"] = {"type": "json_object"}
        if REGION_PARAM_NAME:
            payload[REGION_PARAM_NAME] = policy.region
        return payload

    # -- response parsing -----------------------------------------------------
    @staticmethod
    def _parse(body: dict, elapsed_ms: float, model: str) -> HarnessResponse:
        import re as _re
        try:
            text = body["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            raise HarnessUnavailable(f"Unexpected response shape: {list(body)[:8]}")

        # Redaction evidence from session_pii_map (present when pii_detection=True).
        # Format: {"__PII_TYPE_hash__": "original_value", ...}
        # We count by type and never store original values.
        redactions: list[Redaction] = []
        session_pii_map = body.get("session_pii_map")
        if session_pii_map and isinstance(session_pii_map, dict):
            counts: dict[str, int] = {}
            for token in session_pii_map.keys():
                m = _re.match(r"__PII_(?:IN_)?([A-Z_]+?)_[0-9a-f]+__", token)
                kind = m.group(1) if m else "UNKNOWN"
                counts[kind] = counts.get(kind, 0) + 1
            redactions = [Redaction(kind=k, count=v) for k, v in counts.items()]

        # Injection signal. SUPPORTS_INJECTION_FLAG=False (confirmed by probe): the
        # prompt_injection_detected field exists but was always False in testing.
        # App-layer detection in pipeline.py is the real control.
        injection_flagged = False
        injection_detail = None
        if SUPPORTS_INJECTION_FLAG:
            injection_flagged = bool(body.get("prompt_injection_detected"))
            if injection_flagged:
                injection_detail = f"blocked={body.get('prompt_injection_blocked')}"

        # x_fallback tells us the actual model used when Konsole auto-rerouted.
        actual_model = body.get("model") or model
        fallback_info = body.get("x_fallback")
        if isinstance(fallback_info, dict) and fallback_info.get("used_model"):
            actual_model = fallback_info["used_model"]

        usage = body.get("usage") or {}
        return HarnessResponse(
            text=text,
            redactions=redactions,
            injection_flagged=injection_flagged,
            injection_detail=injection_detail,
            region_served=body.get("region") or body.get("region_served"),
            provider=(fallback_info or {}).get("used_provider") or body.get("provider"),
            model=actual_model,
            latency_ms=int(elapsed_ms),
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            cost_usd=0.0,
            raw=body,
        )

    # -- the one public method ------------------------------------------------
    def complete(self, messages: list[dict], policy: Policy) -> HarnessResponse:
        model = MODEL_SOVEREIGN if policy.sovereign_routing else policy.model
        attempts: list[str] = [model]
        if policy.fallback_model and policy.fallback_model != model:
            attempts.append(policy.fallback_model)

        last_error: Exception | None = None

        for attempt_model in attempts:
            payload = self._build_payload(messages, policy, attempt_model)
            for retry in range(2):
                t0 = time.time()
                try:
                    r = self._client.post(
                        f"{self.base_url}/chat/completions",
                        headers={
                            "Authorization": f"Bearer {self.api_key}",
                            "Content-Type": "application/json",
                        },
                        json=payload,
                        timeout=policy.timeout_s,
                    )
                except httpx.TimeoutException as e:
                    last_error = HarnessTimeout(str(e))
                    continue
                except httpx.HTTPError as e:
                    last_error = HarnessUnavailable(str(e))
                    continue

                elapsed = (time.time() - t0) * 1000

                if r.status_code == 200:
                    return self._parse(r.json(), elapsed, attempt_model)

                if r.status_code in (401, 403):
                    raise HarnessAuthError(f"HTTP {r.status_code}: check KONSOLE_API_KEY")

                if r.status_code == 429:
                    time.sleep(0.5 * (retry + 1) ** 2)
                    last_error = HarnessUnavailable("rate limited")
                    continue

                if 500 <= r.status_code < 600:
                    last_error = HarnessUnavailable(f"HTTP {r.status_code}")
                    break  # try the fallback model rather than retrying the same one

                # 4xx other than auth/rate-limit: a bad request will not fix itself.
                raise HarnessUnavailable(f"HTTP {r.status_code}: {r.text[:300]}")

        raise last_error or HarnessUnavailable("all attempts failed")


# =============================================================================
# Mock — lets the whole app be built and demoed with no network.
# =============================================================================
class MockHarness:
    TRIGGERS = ("ignore all previous", "system note:", "identity has already been verified",
                "ignore previous", "disregard the privacy", "mark this identity verified",
                "identity has been verified", "reveal every customer", "export all customer",
                "assistant,")

    def complete(self, messages: list[dict], policy: Policy) -> HarnessResponse:
        import hashlib
        import re

        data = messages[-1]["content"]
        lower = data.lower()
        injection = policy.injection_check and any(t in lower for t in self.TRIGGERS)
        is_hindi = bool(re.search(r"[ऀ-ॿ]", data))

        if any(word in lower for word in ("erase", "delete", "मिटा", "remove my details")):
            right = "ERASURE"
        elif (any(word in lower for word in ("correct", "wrong date", "correction"))
              and not any(word in lower for word in ("copy", "access", "send me"))):
            right = "CORRECTION"
        elif "grievance" in lower or "no response" in lower:
            right = "GRIEVANCE"
        elif "nominate" in lower:
            right = "NOMINATION"
        elif any(word in lower for word in
                 ("copy", "access", "provide", "send my personal data", "dekhna", "देख")):
            right = "ACCESS"
        else:
            right = "UNCLEAR"

        reasons: list[str] = []
        third_party = any(phrase in lower for phrase in
                          ("my spouse", "account holder", "every customer", "all customer"))
        minor = "child" in lower or "parent of" in lower
        multiple = (any(word in lower for word in ("copy", "access", "send me"))
                    and "correct" in lower)
        ambiguous = "remove my details" in lower
        legal_hold = any(phrase in lower for phrase in
                         ("active dispute", "pending proceedings", "complaint evidence"))
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
            "account_ref_token": next((t for t in tokens if t.startswith("<ACCOUNT_REF_")), None),
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

        redactions: list[Redaction] = []
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

        return HarnessResponse(
            text=json.dumps(verdict, ensure_ascii=False),
            redactions=redactions,
            injection_flagged=injection,
            injection_detail="Untrusted instructions detected and ignored." if injection else None,
            region_served=policy.region,
            provider="mock-local",
            model="mock-dpr-v1",
            latency_ms=max(1, 5),
            cost_usd=0.0,
            raw={
                "simulated": True,
                "deterministic": True,
                "fixture_key": hashlib.sha256(data.encode("utf-8")).hexdigest()[:12],
            },
        )


def get_harness() -> Harness:
    backend = os.getenv("HARNESS_BACKEND", "mock").lower()
    if backend == "konsole":
        return KonsoleHarness(
            api_key=os.getenv("KONSOLE_API_KEY") or os.getenv("HARNESS_API_KEY"),
            base_url=os.getenv("KONSOLE_BASE_URL") or os.getenv("HARNESS_BASE_URL") or BASE_URL,
        )
    return MockHarness()
