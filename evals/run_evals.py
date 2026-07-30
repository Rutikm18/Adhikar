#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.audit import AuditLog
from app.harness import MockHarness, Policy
from app.pipeline import Pipeline
from app.store import Store


def main() -> int:
    corpus = {
        case["id"]: case
        for case in json.loads((ROOT / "data" / "corpus.json").read_text(encoding="utf-8"))
    }
    cases = json.loads((ROOT / "evals" / "cases.json").read_text(encoding="utf-8"))
    results = []
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="adhikar-evals-") as temp_dir:
        store = Store(Path(temp_dir) / "evals.db", "eval-only-key")
        pipeline = Pipeline(store, AuditLog(store), MockHarness())
        policy = Policy(region="in", tokenization_mode="defence_in_depth")
        for expected in cases:
            case = corpus[expected["id"]]
            case_start = time.perf_counter()
            record, _ = pipeline.intake(
                case["text"], "eval-org", policy, allow_dedupe=False
            )
            verdict = record.verdict
            assert verdict is not None
            reasons = set(verdict.escalation.reasons)
            passed = (
                verdict.right_claimed == expected["expected_right"]
                and verdict.escalation.required == expected["expected_escalation"]
                and set(expected["must_include_reasons"]).issubset(reasons)
            )
            guarded = record.status in {"BLOCKED", "NEEDS_HUMAN_REVIEW"}
            if int(case["id"]) >= 11:
                passed = passed and guarded
            results.append(
                {
                    "id": case["id"],
                    "description": case["description"],
                    "expected": expected["expected_right"],
                    "got": verdict.right_claimed,
                    "esc": verdict.escalation.required,
                    "passed": passed,
                    "guarded": guarded,
                    "elapsed": time.perf_counter() - case_start,
                    "cost": float(record.harness_meta.get("cost_usd", 0.0)),
                }
            )

    print("DPR TRIAGE EVALS — backend=mock  policy=in/defence_in_depth")
    print("─" * 78)
    print(f"{'ID':<4}{'DESCRIPTION':<34}{'EXPECTED':<12}{'GOT':<12}{'ESC':<5}RESULT")
    for result in results:
        print(
            f"{result['id']:<4}{result['description'][:31]:<34}"
            f"{result['expected']:<12}{result['got']:<12}"
            f"{'Y' if result['esc'] else '-':<5}"
            f"{'PASS' if result['passed'] else 'FAIL'}"
        )
    print("─" * 78)
    passed = sum(item["passed"] for item in results)
    adversarial = [item for item in results if int(item["id"]) >= 11]
    guarded = sum(item["guarded"] for item in adversarial)
    mean = sum(item["elapsed"] for item in results) / len(results)
    cost = sum(item["cost"] for item in results)
    print(
        f"{passed}/{len(results)} passed · adversarial {guarded}/{len(adversarial)} guarded "
        f"· mean {mean:.3f}s · ${cost:.3f}"
    )
    print(f"Total runtime: {time.perf_counter() - started:.3f}s")
    return 0 if passed == len(results) and guarded == len(adversarial) else 1


if __name__ == "__main__":
    raise SystemExit(main())

