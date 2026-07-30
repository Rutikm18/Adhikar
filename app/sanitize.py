from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata

from app.schemas import SanitizedInput

MAX_INPUT_CHARS = 20_000
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff"), None)
_BIDI = dict.fromkeys(
    list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)), None
)
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{200,}={0,2})(?![A-Za-z0-9+/])")


class EmptyInput(ValueError):
    pass


def _decoded_ascii_blobs(text: str) -> list[str]:
    decoded: list[str] = []
    for candidate in _BASE64.findall(text):
        try:
            raw = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
        if raw and sum(byte in b"\n\r\t" or 32 <= byte <= 126 for byte in raw) / len(raw) > 0.95:
            decoded.append(raw.decode("ascii", errors="ignore"))
    return decoded


def _homoglyph_heavy(text: str) -> bool:
    runs = re.findall(r"[^\W\d_]{6,}", text, flags=re.UNICODE)
    for run in runs:
        latin = sum("LATIN" in unicodedata.name(char, "") for char in run)
        non_latin = sum(char.isalpha() for char in run) - latin
        if latin and non_latin / len(run) > 0.15:
            return True
    return False


def sanitize_input(raw_text: str) -> SanitizedInput:
    if not raw_text or not raw_text.strip():
        raise EmptyInput("Request text must not be empty.")
    normalized = unicodedata.normalize("NFKC", raw_text)
    normalized = normalized.translate(_ZERO_WIDTH).translate(_BIDI)
    oversized = len(normalized) > MAX_INPUT_CHARS
    if oversized:
        normalized = normalized[:10_000] + "\n[...TRUNCATED...]\n" + normalized[-10_000:]
    decoded = _decoded_ascii_blobs(normalized)
    scanned = normalized
    if decoded:
        scanned += "\n\n[DECODED CONTENT FOR SECURITY INSPECTION]\n" + "\n".join(decoded)
    return SanitizedInput(
        text=normalized,
        scanned_text=scanned,
        content_hash=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        homoglyph_flagged=_homoglyph_heavy(normalized),
        oversized=oversized,
        decoded_blobs=len(decoded),
    )

