"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store.

Interface:
    detect(text: str) -> list[dict]
    redact(text: str) -> str
"""
from __future__ import annotations

import re

# Regex patterns
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_BANK_RE = re.compile(r"(?i)(?:STK|số tài khoản|so tai khoan)\s*[:\s]?\s*(\d{8,20})")
_CCCD_CONTEXT_RE = re.compile(r"(?i)(?:CCCD|căn cước|can cuoc)\s*(?:của\s+[^:\n]+?:\s*|[:\s]\s*)?(\d{12})\b")
_CCCD_RAW_RE = re.compile(r"\b\d{12}\b")
_PHONE_CONTEXT_RE = re.compile(r"(?i)(?:SĐT|SDT|số điện thoại|so dien thoai|là|la)\s*[:\s]?\s*(0\d{9})\b")
_PHONE_RAW_RE = re.compile(r"\b0\d{9}\b")


def _is_overlapping(span: tuple[int, int], existing_spans: list[tuple[int, int]]) -> bool:
    start, end = span
    for ex_start, ex_end in existing_spans:
        if start < ex_end and ex_start < end:
            return True
    return False


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII (CCCD, PHONE, BANK_ACCOUNT, EMAIL)."""
    entities: list[dict] = []
    occupied_spans: list[tuple[int, int]] = []

    # 1. EMAIL
    for m in _EMAIL_RE.finditer(text):
        span = m.span()
        if not _is_overlapping(span, occupied_spans):
            occupied_spans.append(span)
            entities.append({"type": "EMAIL", "start": span[0], "end": span[1]})

    # 2. VN_BANK_ACCOUNT (thường có tiền tố STK/số tài khoản)
    for m in _BANK_RE.finditer(text):
        span = m.span(1)
        if not _is_overlapping(span, occupied_spans):
            occupied_spans.append(span)
            entities.append({"type": "VN_BANK_ACCOUNT", "start": span[0], "end": span[1]})

    # 3. VN_CCCD (có ngữ cảnh CCCD hoặc chuỗi 12 chữ số)
    for m in _CCCD_CONTEXT_RE.finditer(text):
        span = m.span(1)
        if not _is_overlapping(span, occupied_spans):
            occupied_spans.append(span)
            entities.append({"type": "VN_CCCD", "start": span[0], "end": span[1]})

    for m in _CCCD_RAW_RE.finditer(text):
        span = m.span()
        if not _is_overlapping(span, occupied_spans):
            occupied_spans.append(span)
            entities.append({"type": "VN_CCCD", "start": span[0], "end": span[1]})

    # 4. VN_PHONE (có ngữ cảnh SĐT hoặc 10 chữ số bắt đầu bằng 0)
    for m in _PHONE_CONTEXT_RE.finditer(text):
        span = m.span(1)
        if not _is_overlapping(span, occupied_spans):
            occupied_spans.append(span)
            entities.append({"type": "VN_PHONE", "start": span[0], "end": span[1]})

    for m in _PHONE_RAW_RE.finditer(text):
        span = m.span()
        if not _is_overlapping(span, occupied_spans):
            occupied_spans.append(span)
            entities.append({"type": "VN_PHONE", "start": span[0], "end": span[1]})

    entities.sort(key=lambda e: e["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế các thực thể PII bằng [REDACTED_<TYPE>], thay từ cuối về đầu."""
    detected = detect(text)
    # Thay từ cuối văn bản về đầu để offset không bị lệch
    for ent in reversed(detected):
        placeholder = f"[REDACTED_{ent['type']}]"
        text = text[:ent["start"]] + placeholder + text[ent["end"]:]
    return text
