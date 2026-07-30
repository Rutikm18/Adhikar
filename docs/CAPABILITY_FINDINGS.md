# Phase 2 — Konsole API Capability Findings

> Generated: 2026-07-30  
> Probe script: `tools/probe_konsole.py`  
> Raw evidence: `konsole_raw.json` (gitignored)  
> Base URL: `https://api.konsole.one/v1`

These findings update `app/harness.py` CAPABILITIES block and SPEC.md Section 2.
Every constant in the CAPABILITIES block is backed by probe output in `konsole_raw.json`.

---

## Confirmed CAPABILITIES constants

| Constant | Value | Evidence |
|---|---|---|
| `SUPPORTS_PII_DETECTION` | `True` | `pii_detected` field present in every response; `session_pii_map` returned when `pii_detection=True` (probe [3]) |
| `SUPPORTS_PII_MASKING` | `True` | Konsole replaces PII with `__PII_TYPE_N__` tokens in model input by default — even without any params. Model response content shows placeholders, not raw values (probe [3] `pii_off` variant) |
| `SUPPORTS_JSON_MODE` | `True` | `response_format: {type: json_object}` returns cleanly parseable JSON (probe [5]) |
| `SUPPORTS_INJECTION_FLAG` | `False` | `prompt_injection_detected` and `prompt_injection_blocked` fields are always `false` — even for payload with explicit system-override injection text (probe [4]) |
| `REGION_PARAM_NAME` | `"region"` | Accepted by API without error (probe [7]) |

---

## Working models

| Model name | Result | Note |
|---|---|---|
| `qwen-max` | **WORKS** | Returns `content`, `finish_reason=stop` |
| `deepseek-chat` | **WORKS** | Alias resolves to `deepseek-v4-flash` internally |
| `gemini-3.1-flash-lite` | FAILS for content | HTTP 200 but `choices[0].message.content = ""`; response goes to `reasoning_content`. `x_fallback` shows Google provider returned HTTP 400 |
| `minimax-text` | FAILS | Unknow model name; `x_fallback` to deepseek with empty content |
| `sarvam-m` | **DEPRECATED** | `"Model 'sarvam-m' has been deprecated. Please use sarvam-105b."` |

**Updated model constants:**
- `MODEL_PRIMARY = "qwen-max"` (was `gemini-3.1-flash-lite`)
- `MODEL_FALLBACK = "deepseek-chat"` (was `qwen-max`)
- `MODEL_SOVEREIGN = "sarvam-105b"` (was `sarvam-m` — deprecated)

Available models via `/models`: 39 total including `gemini-2.5-flash`, `deepseek-v4-flash`, `deepseek-v4-pro`, `qwen3-max`, `qwen3.7-max`, `sarvam-105b`, `sarvam-30b`, `gpt-4.1`, `gpt-5.4`, `o3-mini`.

---

## PII masking — critical finding

The Konsole API applies PII masking to model input **by default and without any parameters**. The probe payload (probe [3], `pii_off` variant) received this model response:

```
"I can see the following details: email: __PII_EMAIL_1__,
phone: __PII_PHONE_NUMBER_2__, PAN: __PII_ID_NUMBER_3__,
Aadhaar: __PII_ID_NUMBER_4__, account: ACC-99887766"
```

The model saw placeholder tokens, not raw PII. The `pii_detected` and `pii_masked` fields were `false` (reporting was off, but masking was active).

### Warning: `pii_masking=True` is counterproductive

Setting `pii_masking=True` caused the model to respond with **original values**:

```
"Your email is represented by the placeholder: priya.sharma@example.in."
```

4–5 identifiers leaked back (vs. 1 without the param). The parameter appears to instruct the model to explain what was detected, which reveals the original values in the output. **`pii_masking=True` must not be used.** It has been removed from `_build_payload`.

### Correct approach

- Use `pii_detection=True` when `policy.redact_pii = True`: adds `session_pii_map` to the response, which gives a count-by-kind redaction report without persisting raw values.
- Default (no params): input masking already active. `session_pii_map` not available.
- Do NOT use `pii_masking=True`.

### `session_pii_map` format

```json
{
  "__PII_EMAIL_63fef025eb__":   "priya.sharma@example.in",
  "__PII_IN_PAN_5e0a16306b__":  "ABCDE1234F",
  "__PII_IN_PAN_cee72a6154__":  "98765 43210",
  "__PII_PERSON_7eb7f83b30__":  "Priya Sharma",
  "__PII_US_SSN_fe70acec47__":  "0000 1111 2222"
}
```

The harness `_parse` method extracts kind from the token key using `__PII_(?:IN_)?([A-Z_]+?)_hash__` and counts by kind. Original values are never stored. The `IN_PAN` prefix is the Indian-specific type tag.

**Classification note:** the Konsole API classified phone `98765 43210` as `IN_PAN` and Aadhaar `0000 1111 2222` as `US_SSN`. The Indian-format local tokeniser in `app/tokenizer.py` catches these correctly using the appropriate patterns; the harness detection is supplementary evidence, not the primary control.

---

## Prompt-injection handling — confirmed finding

Both injection probe variants (`injection_plain` and `injection_with_pii`) returned:
- `prompt_injection_detected: false`
- `prompt_injection_blocked: false`
- Model response: `"Data Access Request"` (model correctly classified, did not obey injection)

The model resisted the injection without the platform flagging it. However, since the field is always `false`, the app cannot rely on it as a detection signal. `SUPPORTS_INJECTION_FLAG = False` is confirmed. The pipeline's nonce-delimited prompt, Unicode inspection, and keyword-based escalation are the real controls.

---

## JSON mode

`response_format: {type: json_object}` returned `{"right": "ACCESS", "confidence": 0.9}` — parses cleanly. `SUPPORTS_JSON_MODE = True` confirmed.

---

## Determinism

Three calls at `temperature=0` all returned `"ERASURE"`. `T7_deterministic_at_temperature_0` will pass against the live backend.

---

## Auto-fallback (`x_fallback`)

The Konsole API includes an `x_fallback` field when it reroutes a request:

```json
{
  "requested_model": "gemini-3.1-flash-lite",
  "used_model": "deepseek-v4-flash",
  "reason": "provider_error",
  "message": "google/gemini-3.1-flash-lite failed: HTTP 400"
}
```

The `_parse` method now reads `x_fallback.used_model` and `x_fallback.used_provider` to report the actual model used, so trace metadata reflects real routing decisions.

---

## README update requirements

The following README claims are now evidence-backed:

| Claim | Evidence source |
|---|---|
| "Request-scoped reversible local tokens plus configurable harness redaction" | `session_pii_map` in probe [3]; `__PII_TYPE_N__` tokens in model input |
| "Before/after diff and category counts" | `session_pii_map` provides kind+count; `_parse` converts to `Redaction` list |
| "Prompt-injection resistance — nonce data boundaries, harness signal, forced escalation" | Injection field exists but always False; app-layer described as the real control |
| "Per-request `in/eu/us/apac` policy passed only through the harness adapter" | `region` param accepted (probe [7]) |
| "`sarvam-m` as Indian-provider sovereign routing option" | NEEDS UPDATE: use `sarvam-105b` |
