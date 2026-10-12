"""BƯỚC 3c/3d — Trifecta split + Egress allowlist + On-Behalf-Of (OBO) PEP.

Run A: Gọi search_docs (untrusted content). Trích xuất typed ticket IDs từ tên file.
Run B: Tra cứu customer_id từ data/customers.json (nguồn tin cậy qua related_tickets).
       Kiểm tra Policy trước mọi tool call, ghi toàn bộ allow và deny vào ledger.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CUSTOMERS_FILE = DATA_DIR / "customers.json"
PRINCIPALS_FILE = DATA_DIR / "principals.json"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _load_customers() -> list[dict]:
    if CUSTOMERS_FILE.exists():
        return json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    return []


def _load_principals() -> dict[str, dict]:
    if PRINCIPALS_FILE.exists():
        return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    return {}


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Xử lý yêu cầu người dùng qua kiến trúc Trifecta Split và Policy Enforcement."""
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    expires_at = "2099-01-01T00:00:00+00:00"

    principals = _load_principals()
    principal_info = principals.get(principal_id, {"allowed_tools": [], "purposes": []})
    agent_scopes = tuple(principal_info.get("allowed_tools", []))

    # ==========================================
    # RUN A: Đọc untrusted content (search_docs)
    # ==========================================
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=agent_scopes,
        parent_scopes=(),
        expires_at=expires_at,
    )
    allow_search, reason_search = policy.check(ctx_search)

    search_args_hash = hashlib.sha256(
        json.dumps({"query": message}, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()

    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-agent/run-a",
            "run_id": run_id,
            "tool": "search_docs",
            "args_hash": search_args_hash,
            "classification": "internal",
            "decision": "allow" if allow_search else "deny",
            "reason": reason_search,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        },
        ledger_path,
    )

    docs = []
    if allow_search:
        docs = tools.search_docs(message)

    # Trích xuất typed ticket IDs dạng số từ TÊN FILE (không dùng text của attacker)
    ticket_ids: list[int] = []
    for d in docs:
        m = re.search(r"ticket-(\d+)", d["id"])
        if m:
            ticket_ids.append(int(m.group(1)))

    combined_text = "\n\n".join(d["text"] for d in docs)
    # PII Redaction trước khi text vượt qua ranh giới sang Run B
    redacted_text = pii.redact(combined_text)
    injected = llm.find_injection(combined_text)

    # ==========================================
    # RUN B: Private Data Access & Egress PEP
    # ==========================================
    customers = _load_customers()

    # Ánh xạ từ ticket_ids sang customer_ids thông qua nguồn tin cậy related_tickets
    target_customer_ids: list[str] = []
    for tid in ticket_ids:
        for c in customers:
            if tid in c.get("related_tickets", []):
                cid = c["customer_id"]
                if cid not in target_customer_ids:
                    target_customer_ids.append(cid)

    collected_customers: list[dict] = []

    # Đọc thông tin khách hàng với kiểm tra PEP nghiêm ngặt
    for cust_id in target_customer_ids:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=agent_scopes,
            parent_scopes=agent_scopes,
            expires_at=expires_at,
        )
        allow_read, reason_read = policy.check(ctx_read)

        read_args_hash = hashlib.sha256(
            json.dumps({"customer_id": cust_id}, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent/run-b",
                "run_id": run_id,
                "tool": "read_customer",
                "args_hash": read_args_hash,
                "classification": "restricted",
                "decision": "allow" if allow_read else "deny",
                "reason": reason_read,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if allow_read:
            try:
                record = tools.read_customer(cust_id)
                collected_customers.append(record)
            except tools.ToolError:
                pass

    # Xử lý chỉ thị injection (chặn exfiltration tại PEP)
    if injected is not None:
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=agent_scopes,
            parent_scopes=agent_scopes,
            expires_at=expires_at,
        )
        allow_post, reason_post = policy.check(ctx_post)

        post_args_hash = hashlib.sha256(
            json.dumps({"target_url": injected.target_url}, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent/run-b",
                "run_id": run_id,
                "tool": "http_post",
                "args_hash": post_args_hash,
                "classification": "restricted",
                "decision": "allow" if allow_post else "deny",
                "reason": reason_post,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if allow_post:
            tools.http_post(injected.target_url, {"records": collected_customers})

    return llm.summarize(docs)
