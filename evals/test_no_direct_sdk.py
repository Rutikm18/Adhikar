#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = re.compile(
    r"openai|anthropic|google\.generativeai|api\.openai\.com|api\.anthropic\.com",
    re.IGNORECASE,
)


def main() -> int:
    failures = []
    for path in (ROOT / "app").rglob("*.py"):
        if path.name == "harness.py":
            continue
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if FORBIDDEN.search(line):
                failures.append(f"{path.relative_to(ROOT)}:{line_number}")
    if failures:
        print("FAIL: direct provider reference outside app/harness.py")
        print("\n".join(failures))
        return 1
    print("PASS: provider boundary is isolated to app/harness.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

