from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.schemas import RightType

_POLICY_PATH = Path(__file__).resolve().parent.parent / "data" / "sla_policy.json"


def load_sla_policy() -> dict:
    return json.loads(_POLICY_PATH.read_text(encoding="utf-8"))


def compute_sla(received_at: datetime, right: RightType) -> tuple[datetime, str, dict]:
    policy = load_sla_policy()
    rule = policy["rights"][right]
    if received_at.tzinfo is None:
        received_at = received_at.replace(tzinfo=timezone.utc)
    return received_at + timedelta(days=rule["days"]), policy["version"], rule

