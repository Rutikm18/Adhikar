from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Iterator

from app.store import Store


def _canonical(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class AuditLog:
    def __init__(self, store: Store):
        self.store = store

    def append(
        self,
        org_id: str,
        request_id: str,
        action: str,
        actor: str,
        harness: dict,
        policy_version: str,
    ) -> dict:
        safe_harness = {
            key: harness.get(key)
            for key in (
                "region_served",
                "provider",
                "model",
                "redactions",
                "injection_flagged",
                "latency_ms",
                "cost_usd",
            )
        }
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            last = conn.execute(
                "SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            seq = (last["seq"] + 1) if last else 1
            prev_hash = last["hash"] if last else "0" * 64
            event = {
                "seq": seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "org_id": org_id,
                "request_id": request_id,
                "action": action,
                "actor": actor,
                "harness": safe_harness,
                "policy_version": policy_version,
                "prev_hash": prev_hash,
            }
            event_hash = hashlib.sha256(_canonical(event).encode("utf-8")).hexdigest()
            event["hash"] = event_hash
            conn.execute(
                """
                INSERT INTO audit_events
                    (seq, ts, org_id, request_id, action, actor, event_json, prev_hash, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    seq,
                    event["ts"],
                    org_id,
                    request_id,
                    action,
                    actor,
                    _canonical(event),
                    prev_hash,
                    event_hash,
                ),
            )
        return event

    def events(self) -> Iterator[dict]:
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT event_json FROM audit_events ORDER BY seq"
            ).fetchall()
        for row in rows:
            yield json.loads(row["event_json"])

    def verify_chain(self) -> dict:
        expected_prev = "0" * 64
        count = 0
        for event in self.events():
            count += 1
            claimed_hash = event.pop("hash", "")
            if event.get("prev_hash") != expected_prev:
                return {"intact": False, "events": count, "broken_at": count}
            computed = hashlib.sha256(_canonical(event).encode("utf-8")).hexdigest()
            if not hmac.compare_digest(computed, claimed_hash):
                return {"intact": False, "events": count, "broken_at": count}
            expected_prev = claimed_hash
        return {"intact": True, "events": count, "broken_at": None}
