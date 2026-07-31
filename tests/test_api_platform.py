from __future__ import annotations

import hashlib
import re
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.factory import create_app
from app.harness import MockHarness
from app.runtime import OrgRateLimiter


class PlatformApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="adhikar-api-")
        self.settings = Settings(
            environment="test",
            database_path=Path(self.temp.name) / "api.db",
            token_map_key="api-test-token-map-key",
            analyst_api_key="analyst-test-key",
            enable_demo_endpoints=True,
        )
        self.client = TestClient(create_app(self.settings, harness=MockHarness()))

    def tearDown(self) -> None:
        self.client.close()
        self.temp.cleanup()

    def create_request(self, suffix: str = "01") -> dict:
        response = self.client.post(
            "/api/requests",
            json={
                "text": (
                    f"Please provide access to synthetic account ZX-000000{suffix} "
                    f"and contact nova{suffix}.quill@example.in."
                ),
                "org_id": "test-org",
                "policy_overrides": {"tokenization_mode": "defence_in_depth"},
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_api_documentation_is_not_exposed(self) -> None:
        for path in ("/docs", "/redoc", "/openapi.json"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)

    def test_security_headers_and_request_id_are_added(self) -> None:
        response = self.client.get("/", headers={"X-Request-ID": "test-request-1"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Request-ID"], "test-request-1")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertNotIn("unpkg.com", response.text)
        self.assertNotIn("text/babel", response.text)
        self.assertNotIn("babel-7.26.4.min.js", response.text)

        asset = self.client.get(
            "/assets/app.min.js",
            headers={"Accept-Encoding": "gzip"},
        )
        self.assertEqual(asset.status_code, 200)
        self.assertEqual(
            asset.headers["Cache-Control"],
            "public, max-age=31536000, immutable",
        )
        self.assertEqual(asset.headers.get("Content-Encoding"), "gzip")

    def test_validation_response_does_not_echo_request_text(self) -> None:
        secret_text = "synthetic-sensitive-value@example.in"
        response = self.client.post(
            "/api/requests",
            json={"text": secret_text, "org_id": "invalid org id"},
        )
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(secret_text, response.text)
        self.assertEqual(response.json()["detail"]["code"], "VALIDATION_ERROR")

    def test_large_http_body_is_rejected_before_model_validation(self) -> None:
        response = self.client.post(
            "/api/requests",
            content=b"x" * (257 * 1024),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["detail"]["code"], "REQUEST_TOO_LARGE")

    def test_trace_rehydration_fails_closed_and_requires_both_headers(self) -> None:
        record = self.create_request()
        path = f"/api/requests/{record['id']}/trace"

        protected = self.client.get(path)
        self.assertEqual(protected.status_code, 200)
        self.assertNotIn("analyst_input", protected.json())
        self.assertNotIn("nova01.quill@example.in", protected.text)

        missing_key = self.client.get(path, headers={"X-Analyst-ID": "analyst-1"})
        self.assertEqual(missing_key.status_code, 403)

        wrong_key = self.client.get(
            path,
            headers={"X-Analyst-ID": "analyst-1", "X-Analyst-Key": "wrong"},
        )
        self.assertEqual(wrong_key.status_code, 403)

        authorised = self.client.get(
            path,
            headers={
                "X-Analyst-ID": "analyst-1",
                "X-Analyst-Key": "analyst-test-key",
            },
        )
        self.assertEqual(authorised.status_code, 200)
        self.assertIn("nova01.quill@example.in", authorised.json()["analyst_input"])

    def test_status_transitions_are_atomic_and_terminal(self) -> None:
        record = self.create_request("02")
        request_id = record["id"]
        approved = self.client.post(
            f"/api/requests/{request_id}/approve",
            json={"analyst_id": "analyst-1"},
        )
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved.json()["status"], "APPROVED")

        repeated = self.client.post(
            f"/api/requests/{request_id}/approve",
            json={"analyst_id": "analyst-1"},
        )
        self.assertEqual(repeated.status_code, 200)

        rejected = self.client.post(
            f"/api/requests/{request_id}/reject",
            json={"analyst_id": "analyst-1", "reason": "Synthetic test reason."},
        )
        self.assertEqual(rejected.status_code, 409)
        self.assertEqual(rejected.json()["detail"]["code"], "TERMINAL_STATUS")

    def test_request_listing_is_bounded_and_paginated(self) -> None:
        self.create_request("03")
        self.create_request("04")
        first = self.client.get("/api/requests?limit=1&offset=0")
        second = self.client.get("/api/requests?limit=1&offset=1")
        self.assertEqual(len(first.json()), 1)
        self.assertEqual(len(second.json()), 1)
        self.assertNotEqual(first.json()[0]["id"], second.json()[0]["id"])
        self.assertEqual(self.client.get("/api/requests?limit=101").status_code, 422)

    def test_health_includes_database_and_audit_readiness(self) -> None:
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["database"], "ok")
        self.assertTrue(response.json()["audit"]["intact"])


class PlatformConfigurationTests(unittest.TestCase):
    def test_compiled_ui_matches_canonical_jsx_source(self) -> None:
        root = Path(__file__).resolve().parent.parent
        html = (root / "ui" / "index.html").read_text(encoding="utf-8")
        match = re.search(
            r'<script type="text/x-adhikar-jsx" id="adhikar-ui-source">'
            r"([\s\S]*?)</script>",
            html,
        )
        self.assertIsNotNone(match)
        source_hash = hashlib.sha256(match.group(1).strip().encode()).hexdigest()
        compiled = (root / "ui" / "vendor" / "app.min.js").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"source-sha256={source_hash}", compiled.splitlines()[0])

    def test_production_rejects_insecure_defaults(self) -> None:
        with self.assertRaises(ValidationError):
            Settings(environment="production")

    def test_demo_endpoints_can_be_removed_from_runtime_surface(self) -> None:
        with tempfile.TemporaryDirectory(prefix="adhikar-no-demo-") as temp:
            settings = Settings(
                environment="test",
                database_path=Path(temp) / "api.db",
                token_map_key="test-key",
                enable_demo_endpoints=False,
            )
            with TestClient(create_app(settings, harness=MockHarness())) as client:
                self.assertEqual(client.get("/api/demo/corpus").status_code, 404)
                self.assertEqual(client.post("/api/demo/reset").status_code, 404)

    def test_rate_limiter_has_bounded_tenant_memory(self) -> None:
        limiter = OrgRateLimiter(limit=1, max_orgs=2)
        self.assertTrue(limiter.allow("org-1"))
        self.assertFalse(limiter.allow("org-1"))
        self.assertTrue(limiter.allow("org-2"))
        self.assertTrue(limiter.allow("org-3"))
        self.assertEqual(limiter.tracked_orgs, 2)


if __name__ == "__main__":
    unittest.main()
