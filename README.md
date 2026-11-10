# FRSec - Fun Reminder Security (detection-as-code)

Rule Sigma nằm trong Git, được lint và test trong CI, rồi đẩy vào Elastic Security trên VM Azure.

```
Lambda (JSON ECS)  ->  CloudWatch  ->  pull_logs.py  ->  Elasticsearch (VM)
                                                              ^
Git: rules/*.yml -> CI (sigma check, pytest, ES tạm) -> deploy_rules.py (chạy trên VM) -> Kibana
```

## Rule hiện có (9)
| Rule | Khi nào bắn | Mức | MITRE |
|---|---|---|---|
| fr_prompt_injection_flagged | prompt bị gắn cờ injection | medium | ghi chú ATLAS AML.T0051 trong mô tả |
| fr_user_banned | tài khoản bị ban | high | attack.initial_access |
| fr_ip_banned | IP guest bị ban (đổi ID né ban) | high | attack.defense_evasion |
| fr_banned_access_attempt | đã ban vẫn gửi tiếp | medium | attack.defense_evasion |
| fr_token_limit_global | hết hạn mức token cả ngày | high | attack.impact, T1496 |
| fr_token_limit_user_or_ip | một user hoặc IP hết hạn mức ngày | medium | attack.impact, T1496 |
| fr_auth_failed | token đăng nhập sai/hết hạn | low | attack.credential_access |
| fr_sweeper_late_reminder | sweeper phải báo nhắc việc trễ | low | không (vận hành) |
| fr_sweeper_run_failed | lần quét sweeper có lỗi | medium | không (vận hành) |

Các mã MITRE là gán gần đúng, hãy tự đối chiếu trên attack.mitre.org và atlas.mitre.org trước khi đưa lên CV.

## Chạy local
```bash
pip install -r requirements.txt
python -m pytest tests -q            # test rule bằng log mẫu
sigma check rules                    # cần internet (tải dữ liệu MITRE)
python tools/deploy_rules.py --dry-run
```

## Đẩy rule lên Kibana (chạy trên VM, sau khi `git pull` repo FRSec)
```bash
export KIBANA_PASSWORD_ELASTIC='...'   # nhập bằng read -s, đừng gõ thẳng vào lệnh
python3 tools/deploy_rules.py
```
Rule chạy mỗi 5 phút và nhìn lại 24 giờ (`LOOKBACK=now-24h`), vì VM tắt phần lớn thời gian và log về theo lô. Rule chỉ chạy khi VM bật, nên đây là lab, không phải cảnh báo realtime.

## Giới hạn
- Chỉ có rule khớp một sự kiện. Ngưỡng theo thời gian (ví dụ 3 injection trong 10 phút) chưa làm: cần rule threshold của Elastic hoặc Sigma correlation, backend hiện tại hỗ trợ hạn chế.
- Matcher trong `tests/test_rules.py` chỉ hỗ trợ tập con Sigma (field: giá trị, AND giữa các field, `condition: selection`). Rule phức tạp hơn sẽ làm test báo lỗi.
- Lint đầy đủ (`sigma check`) và test với Elasticsearch thật chỉ chạy trong CI.
