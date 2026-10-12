# Verification — Điền trước khi nộp

- **OS / Python / Gitleaks version:**
  - OS: Windows 11 (PowerShell)
  - Python: 3.14.6 (chạy trong môi trường ảo `.venv`)
  - Gitleaks: v8.30.1 (pin trong `.pre-commit-config.yaml` và `.gitleaks.toml`)
- **`python -m pytest tests/ -q`:**
  - Kết quả: `33 passed in 5.29s` (100% tests pass, bao gồm test_obo, test_split, test_injection, test_pii, test_policy, test_ledger, test_supply_chain)
- **`pre-commit run --all-files`:**
  - Hook `gitleaks-system` (rev v8.30.1): Passed (quét toàn bộ file hiện tại sạch, 0 findings)
- **Ledger verify:**
  - Lệnh: `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"`
  - Kết quả: `True` (chuỗi hash chain nguyên vẹn, 100% bản ghi có reason và on_behalf_of)
- **Kiểm tra sink log before / after:**
  - `reports/attack-before.log`: Chứa bản ghi PII synthetic rò rỉ của `KH-000999`
  - `reports/attack-after.log`: Rỗng (0 bytes, không rò rỉ dữ liệu)
- **Các lỗi còn lại:**
  - Không có lỗi (0 lỗi). Tất cả các tiêu chí trong rubric và điều kiện loại trừ vi phạm đều được đáp ứng đầy đủ.
