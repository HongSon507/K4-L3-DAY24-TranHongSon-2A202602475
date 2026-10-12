"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call.

Cổng chặn TRƯỚC KHI tool thật sự execute.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PRINCIPALS_FILE = DATA_DIR / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict[str, dict]:
    if PRINCIPALS_FILE.exists():
        return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách bảo mật trước khi cho phép gọi tool.
    
    Luôn trả về (allow: bool, reason: str) với reason không bao giờ rỗng.
    """
    # 1. Rule tối thiểu bắt buộc: restricted data + egress -> DENY
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Egress with restricted data is prohibited"

    # 2. Kiểm tra hạn sử dụng token (TTL / expires_at)
    if context.expires_at:
        try:
            exp_time = datetime.fromisoformat(context.expires_at)
            if exp_time.tzinfo is None:
                exp_time = exp_time.replace(tzinfo=timezone.utc)
            if exp_time < datetime.now(timezone.utc):
                return False, f"Token expired at {context.expires_at}"
        except Exception as e:
            return False, f"Invalid expiration timestamp format: {e}"

    # 3. Kiểm tra định danh và phân quyền On-Behalf-Of (OBO)
    if context.principal_id:
        principals = _load_principals()
        if context.principal_id not in principals:
            return False, f"Unknown principal: {context.principal_id}"

        principal_info = principals[context.principal_id]

        # Kiểm tra mục đích (purpose) nếu có khai báo
        if context.request_purpose and principal_info.get("purposes"):
            if context.request_purpose not in principal_info["purposes"]:
                return (
                    False,
                    f"Purpose '{context.request_purpose}' not permitted for principal '{context.principal_id}'",
                )

        # Tính toán tập quyền hiệu lực (effective allowed tools)
        effective_tools = set(principal_info.get("allowed_tools", []))

        if context.agent_scopes:
            effective_tools &= set(context.agent_scopes)

        if context.delegation_depth > 0 and context.parent_scopes:
            effective_tools &= set(context.parent_scopes)

        # Kiểm tra tool được yêu cầu
        if context.requested_tool:
            if context.requested_tool not in effective_tools:
                return (
                    False,
                    f"Tool '{context.requested_tool}' not permitted for principal '{context.principal_id}' with effective tools: {sorted(effective_tools)}",
                )

    return True, f"Policy check passed for {context.requested_tool or 'action'} under principal '{context.principal_id or 'default'}'"
