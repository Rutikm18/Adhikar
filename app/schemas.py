from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RightType = Literal[
    "ACCESS", "CORRECTION", "ERASURE", "GRIEVANCE", "NOMINATION", "UNCLEAR"
]
EscalationReason = Literal[
    "LOW_CONFIDENCE",
    "THIRD_PARTY_DATA",
    "ADVERSARIAL_CONTENT",
    "MINOR_DATA",
    "AMBIGUOUS_RIGHT",
    "MULTIPLE_RIGHTS",
    "SCHEMA_FAILURE",
    "HARNESS_ERROR",
    "LEGAL_HOLD_CONFLICT",
    "OVERSIZED_INPUT",
    "DECEASED_OR_NOMINEE",
]
RecordStatus = Literal[
    "TRIAGED", "NEEDS_HUMAN_REVIEW", "APPROVED", "REJECTED", "BLOCKED"
]


class ClaimedIdentity(BaseModel):
    """Untrusted token references only; identity is never verified here."""

    name_token: str | None = None
    email_token: str | None = None
    phone_token: str | None = None
    account_ref_token: str | None = None
    # Deliberately no `verified` field. Verification is an out-of-band control.


class Escalation(BaseModel):
    required: bool = False
    reasons: list[EscalationReason] = Field(default_factory=list)
    analyst_note: str = ""


class TriageVerdict(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    right_claimed: RightType
    secondary_rights: list[RightType] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    claimed_identity: ClaimedIdentity
    requested_scope: str = ""
    third_party_data_requested: bool = False
    concerns_minor: bool = False
    language_detected: str = "en"
    draft_response: str = ""
    escalation: Escalation
    model_notes: str = ""


class DPRRecord(BaseModel):
    id: str
    org_id: str
    received_at: datetime
    raw_text_hash: str
    status: RecordStatus
    verdict: TriageVerdict | None
    sla_due_at: datetime | None
    harness_meta: dict = Field(default_factory=dict)
    policy_version: str = "sla_policy@1"


class RequestCreate(BaseModel):
    text: str
    org_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    policy_overrides: dict = Field(default_factory=dict)


class AnalystAction(BaseModel):
    analyst_id: str = Field(min_length=1, max_length=80)
    reason: str = Field(default="", max_length=1000)


class SanitizedInput(BaseModel):
    text: str
    scanned_text: str
    content_hash: str
    homoglyph_flagged: bool = False
    oversized: bool = False
    decoded_blobs: int = 0
