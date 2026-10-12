# Secret giả trong lịch sử Git — Điền trong Checkpoint 4

- **Scanner và phiên bản:** Gitleaks v8.30.1 (chạy qua lệnh `gitleaks git --config .gitleaks.toml --redact --verbose .`).
- **Commit chứa token giả:** `1bdd849` (commit đã commit token mẫu và sau đó file bị xóa ở commit tiếp theo).
- **File, rule và kết quả quét lịch sử:**
  - Quy tắc phát hiện: Rule ID `lab24-synthetic-token` cấu hình trong `.gitleaks.toml`.
  - Pattern: `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}`.
  - Kết quả quét lịch sử: Gitleaks tìm thấy 1 finding tại commit `1bdd849`, trả về exit code 1 như dự kiến (đây là token giả cài sẵn để làm bài thực hành, không phải lỗi bảo mật thật).
- **Kết quả quét file hiện tại:**
  - Chạy `gitleaks dir --config .gitleaks.toml .` hoặc `pre-commit run --all-files`.
  - Kết quả: Sạch hoàn toàn (0 findings, exit code 0).
- **Nếu đây là credential thật, cần xử lý thế nào:**
  - Cần lập tức **thu hồi (revoke) và đảo quyền / thay thế (rotate)** secret trên hệ thống cung cấp dịch vụ (IdP, Cloud provider, API gateway).
  - Kiểm tra audit log của token xem đã có hành vi truy cập trái phép hoặc exfiltration nào xảy ra trong khoảng thời gian lộ lọt hay chưa.
  - Vô hiệu hóa mọi phiên làm việc hoặc quyền hạn liên kết với token cũ.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:**
  - Việc xóa file khỏi HEAD chỉ làm file biến mất ở commit mới nhất, nhưng toàn bộ nội dung và chuỗi secret vẫn tồn tại vĩnh viễn trong lịch sử Git (`git log`, commit objects, reflog). Bất kỳ ai clone repo đều có thể khôi phục lại secret.
  - Pin dependency và pre-commit hook chỉ có tác dụng phòng ngừa các lỗ hổng supply chain và ngăn chặn việc vô tình commit secret trong tương lai, nhưng hoàn toàn **không thể làm vô hiệu hóa** một secret đã bị lộ ra bên ngoài. Do đó, bước **thu hồi và rotate** tại nguồn là bắt buộc và không thể thay thế.
