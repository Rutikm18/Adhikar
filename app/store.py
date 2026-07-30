from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from app.schemas import DPRRecord, TriageVerdict


class Store:
    def __init__(self, path: Path, token_map_key: str):
        self.path = path
        master = hashlib.sha256(token_map_key.encode("utf-8")).digest()
        self._enc_key = hmac.new(master, b"adhikar-token-map-enc", hashlib.sha256).digest()
        self._mac_key = hmac.new(master, b"adhikar-token-map-mac", hashlib.sha256).digest()
        self.init_db()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def init_db(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    raw_text_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    verdict_json TEXT,
                    sla_due_at TEXT,
                    harness_meta_json TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    trace_json TEXT NOT NULL,
                    tokenized_text TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_requests_org_hash_time
                    ON requests(org_id, raw_text_hash, received_at);
                CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
                CREATE TABLE IF NOT EXISTS token_maps (
                    request_id TEXT PRIMARY KEY REFERENCES requests(id) ON DELETE CASCADE,
                    encrypted_map TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS verdict_cache (
                    org_id TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    policy_fingerprint TEXT NOT NULL,
                    verdict_json TEXT NOT NULL,
                    harness_meta_json TEXT NOT NULL,
                    PRIMARY KEY(org_id, content_hash, policy_fingerprint)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    hash TEXT NOT NULL
                );
                """
            )

    def _crypt(self, data: bytes, nonce: bytes) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < len(data):
            block = hmac.new(
                self._enc_key, nonce + counter.to_bytes(4, "big"), hashlib.sha256
            ).digest()
            output.extend(block)
            counter += 1
        return bytes(a ^ b for a, b in zip(data, output))

    def _encrypt_map(self, token_map: dict[str, str]) -> str:
        nonce = secrets.token_bytes(16)
        plaintext = json.dumps(token_map, sort_keys=True).encode("utf-8")
        ciphertext = self._crypt(plaintext, nonce)
        tag = hmac.new(self._mac_key, nonce + ciphertext, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(nonce + tag + ciphertext).decode("ascii")

    def decrypt_map(self, request_id: str) -> dict[str, str]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT encrypted_map FROM token_maps WHERE request_id=?", (request_id,)
            ).fetchone()
        if not row:
            return {}
        envelope = base64.urlsafe_b64decode(row["encrypted_map"])
        nonce, tag, ciphertext = envelope[:16], envelope[16:48], envelope[48:]
        expected = hmac.new(self._mac_key, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("Token map integrity check failed.")
        return json.loads(self._crypt(ciphertext, nonce).decode("utf-8"))

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> DPRRecord:
        return DPRRecord(
            id=row["id"],
            org_id=row["org_id"],
            received_at=row["received_at"],
            raw_text_hash=row["raw_text_hash"],
            status=row["status"],
            verdict=json.loads(row["verdict_json"]) if row["verdict_json"] else None,
            sla_due_at=row["sla_due_at"],
            harness_meta=json.loads(row["harness_meta_json"]),
            policy_version=row["policy_version"],
        )

    def find_duplicate(self, org_id: str, content_hash: str) -> DPRRecord | None:
        threshold = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM requests
                WHERE org_id=? AND raw_text_hash=? AND received_at>=?
                ORDER BY received_at DESC LIMIT 1
                """,
                (org_id, content_hash, threshold),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def get_cache(
        self, org_id: str, content_hash: str, fingerprint: str
    ) -> tuple[TriageVerdict, dict] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT verdict_json, harness_meta_json FROM verdict_cache
                WHERE org_id=? AND content_hash=? AND policy_fingerprint=?
                """,
                (org_id, content_hash, fingerprint),
            ).fetchone()
        if not row:
            return None
        return (
            TriageVerdict.model_validate_json(row["verdict_json"]),
            json.loads(row["harness_meta_json"]),
        )

    def save(
        self,
        record: DPRRecord,
        trace: dict,
        tokenized_text: str,
        token_map: dict[str, str],
        policy_fingerprint: str,
    ) -> None:
        verdict_json = record.verdict.model_dump_json() if record.verdict else None
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.id,
                    record.org_id,
                    record.received_at.isoformat(),
                    record.raw_text_hash,
                    record.status,
                    verdict_json,
                    record.sla_due_at.isoformat() if record.sla_due_at else None,
                    json.dumps(record.harness_meta, sort_keys=True),
                    record.policy_version,
                    json.dumps(trace, sort_keys=True),
                    tokenized_text,
                ),
            )
            conn.execute(
                "INSERT INTO token_maps(request_id, encrypted_map) VALUES (?, ?)",
                (record.id, self._encrypt_map(token_map)),
            )
            if record.verdict:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO verdict_cache VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        record.org_id,
                        record.raw_text_hash,
                        policy_fingerprint,
                        verdict_json,
                        json.dumps(record.harness_meta, sort_keys=True),
                    ),
                )

    def list_requests(self, status: str | None = None) -> list[DPRRecord]:
        query = "SELECT * FROM requests"
        args: tuple[Any, ...] = ()
        if status:
            query += " WHERE status=?"
            args = (status,)
        query += " ORDER BY received_at DESC LIMIT 200"
        with self.connect() as conn:
            rows = conn.execute(query, args).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_request(self, request_id: str) -> DPRRecord | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM requests WHERE id=?", (request_id,)
            ).fetchone()
        return self._row_to_record(row) if row else None

    def get_trace(self, request_id: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT trace_json, tokenized_text FROM requests WHERE id=?", (request_id,)
            ).fetchone()
        if not row:
            return None
        trace = json.loads(row["trace_json"])
        trace["protected_input"] = row["tokenized_text"]
        return trace

    def update_status(self, request_id: str, status: str) -> DPRRecord | None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE requests SET status=? WHERE id=?", (status, request_id)
            )
        return self.get_request(request_id)

    def reset(self) -> None:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM audit_events")
            conn.execute("DELETE FROM token_maps")
            conn.execute("DELETE FROM requests")
            conn.execute("DELETE FROM verdict_cache")
            conn.execute("DELETE FROM sqlite_sequence WHERE name='audit_events'")
