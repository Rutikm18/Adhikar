from __future__ import annotations

import re
from collections import defaultdict

TokenMap = dict[str, str]

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    ("AADHAAR_SHAPED", re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")),
    ("PAN", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),
    (
        "PHONE",
        re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"),
    ),
    ("VEHICLE", re.compile(r"\b[A-Z]{2}[\s-]?\d{1,2}[\s-]?[A-Z]{1,3}[\s-]?\d{4}\b")),
    ("IFSC", re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")),
    ("UPI_VPA", re.compile(r"\b[A-Z0-9._-]{2,}@[A-Z][A-Z0-9.-]{1,}\b", re.I)),
    ("ACCOUNT_REF", re.compile(r"\b[A-Z]{2,4}[-/]?\d{6,12}\b")),
]
_TOKEN = re.compile(r"<[A-Z][A-Z0-9_]*_\d+>")


def tokenize(text: str) -> tuple[str, TokenMap]:
    counters: defaultdict[str, int] = defaultdict(int)
    token_map: TokenMap = {}
    transformed = text
    for kind, pattern in _PATTERNS:
        def replace(match: re.Match[str]) -> str:
            value = match.group(0)
            for token, known in token_map.items():
                if known == value:
                    return token
            counters[kind] += 1
            token = f"<{kind}_{counters[kind]}>"
            token_map[token] = value
            return token

        transformed = pattern.sub(replace, transformed)
    return transformed, token_map


def rehydrate(text: str, token_map: TokenMap) -> str:
    output = text
    for token, value in token_map.items():
        output = output.replace(token, value)
    return output


def verify_output(draft: str, token_map: TokenMap) -> list[str]:
    return sorted({token for token in _TOKEN.findall(draft) if token not in token_map})


def token_counts(token_map: TokenMap) -> list[dict[str, int | str]]:
    counts: defaultdict[str, int] = defaultdict(int)
    for token in token_map:
        kind = token[1: token.rfind("_")]
        counts[kind] += 1
    return [{"kind": kind, "count": count} for kind, count in sorted(counts.items())]

