# DPIA-lite — Điền trong Checkpoint 5

1. **Loại dữ liệu và phân loại:**
   - **Internal / Public:** Nội dung các ticket hỗ trợ trong `corpus/`, câu hỏi của người dùng, tài liệu hướng dẫn kỹ thuật.
   - **Restricted (Dữ liệu cá nhân nhạy cảm - PII):** Thông tin khách hàng trong `data/customers.json` bao gồm: Họ và tên, CCCD (12 chữ số), Số điện thoại (10 chữ số), Số tài khoản ngân hàng (STK), Địa chỉ Email.

2. **Mục đích xử lý và principal:**
   - **Mục đích hợp lệ:** `summarize-tickets` (tóm tắt yêu cầu của khách), `support-reply` (soạn phản hồi hỗ trợ kỹ thuật), `privacy-audit` (kiểm toán bảo mật).
   - **Principal ủy quyền (OBO):**
     - `support_l1`: Nhân viên hỗ trợ tầng 1 — chỉ được phép tra cứu tài liệu (`search_docs`), **bị cấm tuyệt đối** truy cập hồ sơ khách hàng (`read_customer`).
     - `dpo`: Cán bộ bảo vệ dữ liệu — được phép tra cứu tài liệu và đọc hồ sơ khách hàng cho mục đích hợp lệ (`support-reply`, `privacy-audit`).

3. **Dữ liệu đi qua những run/tool nào, endpoint nào:**
   - **Run A (Untrusted Context):** Nhận truy vấn, gọi `search_docs` để đọc nội dung `corpus/*.md`. Áp dụng PII redaction và chỉ trích xuất danh sách số nguyên `ticket_id` từ **tên file** đưa qua ranh giới sang Run B.
   - **Run B (Trusted Context):** Nhận `ticket_id`, tra cứu nguồn tin cậy `data/customers.json` (thông qua `related_tickets`) để lấy `customer_id`. Gọi PEP kiểm tra quyền trước khi thực thi `read_customer`.
   - **Endpoint ngoại vi (Egress):** `http://127.0.0.1:10024/reconcile` (sink giả lập). Mọi yêu cầu gọi `http_post` khi ngữ cảnh chứa dữ liệu `restricted` đều bị PEP chặn đứng tại chỗ.

4. **Bằng chứng deny/allow và giới hạn của mock:**
   - **Bằng chứng Allow:** `search_docs` được allow cho cả hai principal; `read_customer` được allow cho `dpo` khi có ticket hợp lệ liên kết (ghi nhận trong [reports/ledger.jsonl](file:///d:/VINUNI/K4-L3-DAY24-TranHongSon-2A202602475/reports/ledger.jsonl)).
   - **Bằng chứng Deny:** Quyết định `deny` ghi nhận rõ ràng khi `support_l1` yêu cầu `read_customer`, và khi bất kỳ agent nào cố gắng `http_post` dữ liệu `restricted` ra sink. File [reports/attack-after.log](file:///d:/VINUNI/K4-L3-DAY24-TranHongSon-2A202602475/reports/attack-after.log) rỗng chứng minh dữ liệu không còn bị rò rỉ.
   - **Giới hạn của môi trường Mock:** Hệ thống kiểm thử dựa trên Fake LLM deterministic và sink loopback cục bộ. Quá trình xác thực danh tính principal mang tính mô phỏng qua fixture, cần được tích hợp với hệ thống OAuth2/OIDC và Vault/KMS thực tế trong môi trường sản xuất.
