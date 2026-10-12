# Baseline — Điền trong Checkpoint 1

1. **Agent có identity mỗi run chưa? Dẫn file/hàm:**
   - **Chưa có.** Agent trong baseline không có cơ chế định danh phiên (`run_id`), định danh agent (`agent_id`) hay danh tính người dùng/ủy quyền (`principal_id`, `on_behalf_of`).
   - **Dẫn chứng:** [agent/loop.py:L27-54](file:///d:/VINUNI/K4-L3-DAY24-TranHongSon-2A202602475/agent/loop.py#L27-L54) trong hàm `_naive_loop(message, llm)` chỉ nhận hai tham số là chuỗi truy vấn và instance LLM, hoàn toàn không khởi tạo ngữ cảnh định danh hay gán quyền hạn.

2. **Ai cho phép `http_post`? Dẫn file/hàm:**
   - **Không có bất kỳ Policy Enforcement Point (PEP) hay cơ chế kiểm soát truy cập nào cho phép.** Quyết định gọi `http_post` hoàn toàn do chỉ thị injection bị kẻ tấn công cài cắm trong nội dung tài liệu không tin cậy ép buộc LLM thực thi.
   - **Dẫn chứng:** [agent/loop.py:L34-45](file:///d:/VINUNI/K4-L3-DAY24-TranHongSon-2A202602475/agent/loop.py#L34-L45) trong hàm `_naive_loop()`: khi `injected = llm.find_injection(combined_text)` phát hiện chỉ thị, agent trực tiếp gọi `tools.http_post(injected.target_url, {"records": collected})` mà không qua bất kỳ hàm kiểm tra policy hay phân quyền nào.

3. **Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:**
   - **Phía agent không lưu lại bất kỳ bằng chứng kiểm toán (audit log/ledger) nào.** Bằng chứng duy nhất chứng minh dữ liệu cá nhân bị exfiltrate nằm ở phía server nhận (sink), được ghi vào tệp `reports/sink.log`.
   - **Dẫn chứng:** [sink/sink.py:L56-78](file:///d:/VINUNI/K4-L3-DAY24-TranHongSon-2A202602475/sink/sink.py#L56-L78) trong method `SinkHandler.do_POST()`, server sink ghi nhận toàn bộ payload nhận được vào tệp log [reports/sink.log](file:///d:/VINUNI/K4-L3-DAY24-TranHongSon-2A202602475/reports/sink.log).
