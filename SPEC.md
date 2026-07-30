# Adhikar — Build Specification

> **Status:** Reconstructed for audit traceability.  
> This document was produced after code was written and captures the design
> invariants that the implementation must satisfy. Every invariant was verified
> mechanically during Phase 0 audit (see `docs/AUDIT_PHASE0.md`).  
> Before the final submission, confirm with a Konsole mentor that Section 2
> (security pillars) accurately reflects the live API capabilities discovered
> in Phase 2.

---

## Section 0 — Invariants

Eight invariants, labelled C1 through C8, are the primary audit criteria.
All must hold at submission time.

**C1 — Provider isolation**  
No Python file in this project other than `app/harness.py` may import an LLM
SDK, reference a provider URL (`api.openai.com`, `api.anthropic.com`,
`generativeai`, etc.), or call an AI API directly. The harness is the only
network boundary to the model provider.  
*Mechanical check:*  
```
grep -rniE "openai|anthropic|generativeai|api\.openai\.com|api\.anthropic\.com" app/ | grep -v app/harness.py
```
Expected: empty output.

**C2 — No automated identity verification**  
The `ClaimedIdentity` model in `app/schemas.py` must contain no field that can
express a verified state (`verified`, `is_verified`, `identity_verified`,
`verified: bool`, etc.). Identity verification is an out-of-band human and
organisational control and must not be implied by the data model.  
*Mechanical check:*  
```
grep -rniE "identity_verified|is_verified|verified\s*[:=]\s*bool|verified\s*:\s*bool" app/schemas.py
```
Expected: empty output.

**C3 — No real PII in the repository**  
All identifier-shaped values in `data/` must be structurally invalid:
- Aadhaar numbers must not begin with 0 or 1 (real numbers never do)
- PAN must use a known dummy pattern (`ABCDE1234F`, etc.)
- Email domains must be `example.in` (IANA reserved for documentation)
- Account references must use clearly fictional prefixes (`ZX-`, `QZ-`)  

Nothing in the repository may be a plausible real person's data.  
*Mechanical check:*  
```
grep -rniE "aadhaar|[0-9]{4}\s?[0-9]{4}\s?[0-9]{4}|[A-Z]{5}[0-9]{4}[A-Z]" data/
```
Expected: empty output, or only structurally invalid synthetic values.

**C4 — Submission artefacts present**  
`LICENSE` must exist at the repository root and contain the string
`MIT License`. `README.md` must contain all four mandated sections:
1. Hackathon attribution (explicit statement of Konsole by Cleartrust Hackathon 2026)
2. Project overview naming the security pillars
3. Build instructions (clone → venv → install → run)
4. Usage guide with worked examples

**C5 — No personal data in logs**  
No `logger.*` call in `app/` may interpolate raw request text or an
un-tokenised identifier as an argument. The audit log (NDJSON export) may
record identifier categories and counts but never matched values.

**C6 — UI result panel completeness**  
`ui/index.html` must render all eight result-panel elements (Section 15):
1. Status badge (TRIAGED / NEEDS_HUMAN_REVIEW / BLOCKED)
2. Adversarial content alert (shown only when flagged)
3. Identifier protection diff (submitted vs. protected side-by-side)
4. Classification display (right claimed, confidence bar, escalation reasons)
5. Organisation SLA countdown (days remaining, basis, policy version)
6. Draft response (withheld on escalation)
7. Approval / rejection action buttons (approve disabled on escalation)
8. Decision trace panel (protected payload, response, harness metadata)

**C7 — No statutory deadline claim**  
The SLA countdown is an Organisation SLA based on configurable policy. It is
not a statutory deadline. Any use of the phrase "statutory deadline" applied
to the countdown is a failure. The README must explicitly disclaim universal
statutory period claims.

**C8 — No compliance overclaim**  
No sentence in `README.md`, `app/`, or `ui/` may state or imply that this
system is "DPDP-compliant", "fully compliant", or "ensures compliance".
The permitted phrasing is "controls aligned to DPDP obligations".  
*Mechanical check:*  
```
grep -rniE "dpdp.?compliant|fully compliant|ensures compliance" README.md app/ ui/
```
Expected: empty output.

---

## Section 1 — Project overview

Adhikar is a Data Principal Request (DPR) triage console for privacy
operations teams. It turns an untrusted free-text request into:
- A schema-validated classification with confidence
- An Organisation SLA and policy version
- A human-gated draft response (withheld on escalation)
- A tamper-evident audit event

The requestor text is treated as hostile input throughout. A language model
is used only for classification; it never sees un-tokenised identifiers unless
the harness itself provides PII masking.

---

## Section 2 — Security pillars

The four pillars below describe the security properties this project
demonstrates. Pillars marked (HARNESS) are implemented in `app/harness.py`
using Konsole API capabilities. Pillars marked (APP) are application-layer
controls independent of the harness.

| Pillar | Owner | Control | Observable evidence |
|---|---|---|---|
| PII protection | APP + HARNESS | Local reversible tokenisation (8 Indian-format patterns) + configurable harness PII masking | Before/after diff, category count badge, redaction report |
| Prompt-injection resistance | APP | Unicode/encoding inspection, nonce data boundaries, ABSOLUTE RULES in system prompt, forced escalation on adversarial signal | Red adversarial banner, `BLOCKED` status, audit event |
| Data residency | APP | Per-request `region` field passed only through the harness adapter; `sarvam-m` as Indian-provider sovereign routing option | Region badge in trace metadata |
| Auditability | APP | Canonical append-only events SHA-256 hash-chained to the previous event | Chain-integrity badge, NDJSON export |

> **Note (confirmed by Phase 2 probe):** Prompt-injection detection is an
> application-layer control. The Konsole API response always includes a
> `prompt_injection_detected` field, but it was False for every injection probe
> payload (`SUPPORTS_INJECTION_FLAG = False`). The `prompt_injection_blocked`
> field was likewise always False. Do not describe injection detection as a
> Konsole harness feature; the pipeline's nonce-delimited prompt, Unicode
> inspection, and keyword scan are the real controls.

---

## Section 3 — Required file paths

```
adhikar/
├── app/
│   ├── __init__.py
│   ├── audit.py
│   ├── clock.py
│   ├── config.py
│   ├── harness.py          ← ONLY file permitted to call Konsole
│   ├── main.py
│   ├── pipeline.py
│   ├── prompts.py
│   ├── sanitize.py
│   ├── schemas.py
│   ├── store.py
│   └── tokenizer.py
├── data/
│   ├── corpus.json         ← 15 synthetic cases, 5 adversarial
│   ├── records_mock.json
│   └── sla_policy.json
├── docs/
│   ├── AUDIT_PHASE0.md
│   ├── architecture.md
│   └── demo_script.md
├── evals/
│   ├── cases.json
│   ├── run_evals.py
│   ├── test_harness_contract.py
│   └── test_no_direct_sdk.py
├── tests/
│   └── test_security_controls.py
├── tools/
│   └── probe_konsole.py
├── ui/
│   └── index.html
├── .env.example
├── .gitignore
├── LICENSE
├── Makefile
├── README.md
├── SPEC.md                 ← this file
└── requirements.txt
```

---

## Section 11 — Pipeline stages

Requests pass through twelve stages in `app/pipeline.py`. The pipeline must
fail **closed** on every error path — no error may produce a non-escalated
verdict reaching the user.

| Stage | Module | Fail-closed behaviour |
|---|---|---|
| 1. Empty check | `sanitize.py` | Raises `EmptyInput` → HTTP 400 |
| 2. Deduplication | `store.py` | Returns existing record; no new verdict |
| 3. Sanitisation | `sanitize.py` | NFKC, zero-width strip, BiDi strip, base64 decode, oversized truncate |
| 4. Local tokenisation | `tokenizer.py` | 8 Indian-format patterns replaced with `<KIND_N>` tokens; original values stored encrypted |
| 5. Cache lookup | `store.py` | Hit → skip harness; policy fingerprint change invalidates cache |
| 6. Nonce-delimited prompt | `prompts.py` | `<<<DATA-{nonce}>>>` wrapper; system prompt contains ABSOLUTE RULES |
| 7. Harness call | `harness.py` | `HarnessError` → `fail_closed("HARNESS_ERROR")` |
| 8. JSON parse | `pipeline.py` | `json.JSONDecodeError` → repair attempt |
| 9. Schema validation | `schemas.py` | `ValidationError` → repair attempt |
| 10. One repair attempt | `pipeline.py` | Second harness call; if that fails → `fail_closed("SCHEMA_FAILURE")` |
| 11. Post-validation checks | `pipeline.py` | Confidence, UNCLEAR, homoglyph, injection signal, third-party flag — each adds escalation reason |
| 12. Output token allowlist | `tokenizer.py` | Foreign token in draft → draft cleared, `THIRD_PARTY_DATA` added, `BLOCKED` |
| 13. Storage + audit | `store.py`, `audit.py` | Trace re-tokenised before write; SHA-256 hash-chained event appended |

---

## Section 13 — Required adversarial corpus cases

The corpus in `data/corpus.json` must include at least five adversarial cases
covering all five attack types:

| Attack type | Required behaviour | Case ID |
|---|---|---|
| Direct injection | Instructions embedded inline in the request body | 11 |
| Indirect injection | Instructions embedded in quoted/forwarded content | 12 |
| Encoded injection | Instructions hidden in base64 or other encoding | 13 |
| Third-party data harvest | Request for another person's data | 14 |
| Adverse erasure | Erasure request designed to destroy legal-hold evidence | 15 |

All five must produce `escalation.required = true` and `status` of `BLOCKED`
or `NEEDS_HUMAN_REVIEW`. None may produce a draft response.

---

## Section 15 — Required UI result-panel elements

The result panel in `ui/index.html` must render all eight elements below.
Elements 2 and 7 are conditional (shown/enabled only under specific states).

| Element | HTML ID | Condition |
|---|---|---|
| 1. Status badge | `#status` | Always visible after triage |
| 2. Adversarial alert banner | `#alert` | Visible when `injection_flagged` or `ADVERSARIAL_CONTENT` in reasons |
| 3. Identifier protection diff | `#before` / `#after` | Always visible; shows submitted vs. protected text |
| 4. Classification display | `#right`, `#reasons`, `#confidence`, `#confidenceBar` | Always visible |
| 5. Organisation SLA countdown | `#sla`, `#slaSub` | Always visible |
| 6. Draft response | `#draft` | Withheld text shown on escalation; draft shown otherwise |
| 7. Approval / rejection buttons | `#approve`, `#reject` | Approve disabled on escalation |
| 8. Decision trace panel | `#trace`, `#traceMeta` | Collapsible; shows protected payload, response, harness metadata |
