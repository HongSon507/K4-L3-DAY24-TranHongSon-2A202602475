"""BƯỚC 3d/3e — Audit ledger append-only, tamper-evident hash chain."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _compute_hash(entry_without_hash: dict) -> str:
    serialized = json.dumps(entry_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Thêm một entry vào ledger với liên kết prev_hash và hash sha256."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists():
        content = path.read_text(encoding="utf-8").strip()
        if content:
            lines = content.splitlines()
            if lines:
                try:
                    last_record = json.loads(lines[-1])
                    if "hash" in last_record:
                        prev_hash = last_record["hash"]
                except Exception:
                    pass

    record = dict(entry)
    record["prev_hash"] = prev_hash
    # Xoá hash nếu đã có trong dict đầu vào trước khi tính toán
    record.pop("hash", None)

    computed_hash = _compute_hash(record)
    record["hash"] = computed_hash

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def verify(path: Path) -> bool:
    """Xác thực toàn bộ hash chain trong file ledger."""
    path = Path(path)
    if not path.exists():
        return True

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return True

    lines = content.splitlines()
    expected_prev = "0" * 64

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # Kiểm tra reason không được rỗng
        reason = entry.get("reason")
        if not reason or not str(reason).strip():
            return False

        # Kiểm tra prev_hash
        if entry.get("prev_hash") != expected_prev:
            return False

        # Kiểm tra hash tính lại
        stored_hash = entry.get("hash")
        if not stored_hash:
            return False

        copy_entry = dict(entry)
        copy_entry.pop("hash", None)
        recalculated_hash = _compute_hash(copy_entry)

        if recalculated_hash != stored_hash:
            return False

        expected_prev = stored_hash

    return True
