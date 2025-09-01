## LLM-base-HoneyPot-in-NGFW
## Mục Lục
- [Sơ đồ mạng](#Sơ-đồ-mạng)
- [Application Architecture](#Application-Architecture)
- [Cơ chế hoạt động của Honeypot](#Cơ-chế-hoạt-động-của-Honeypot)
- [Hướng dẫn sử dụng](#Hướng-dẫn-sử-dụng)
- [Kết Quả](#Kết-Quả)
# Sơ đồ mạng
![Sơ đồ mạng](https://github.com/LeTrieuPhu/LLM-base-HoneyPot-in-NGFW/blob/main/Report/Network.png)
# Application Architecture
Sơ đồ tổng quát về sự tương tác giữa các host và luồng dữ liệu bên trong hệ thống
![Application Architecture](https://github.com/LeTrieuPhu/LLM-base-HoneyPot-in-NGFW/blob/main/Report/app_data.png)
# Cơ chế hoạt động của Honeypot
![Honeypot](https://github.com/LeTrieuPhu/LLM-base-HoneyPot-in-NGFW/blob/main/Report/Honeypot.png)
# Hướng dẫn sử dụng
1. Clone git
```bash
git clone https://github.com/LeTrieuPhu/LLM-base-HoneyPot-in-NGFW.git
```
2. Giải nén và Duy chuyển đến thư mục **app**
```bash
cd LLM-base-HoneyPot-in-NGFW/HoneyPot/VelLMes-honeypot-v2
/app/
```
3. Build và Run
```bash
sudo docker compose build
sudo doker compose up
```
4. Kiểm tra
- Kết nối SSH
```bash
ssh admin@192.168.100.10 -p 22

- Thay IP bằng IP của máy Honeypot
- '-p 22': là kết nối tới Port 22
```
- Truy cập web bằng IP của máy Honeypot
```bash
http://192.168.100.10
```
# Kết Quả
1. Ba CVE về SSH
- CVE-2025-32728
![CVE-2025-32728](https://github.com/LeTrieuPhu/LLM-base-HoneyPot-in-NGFW/blob/main/Report/CVE-2025-32728.jpg)
- CVE-2025-32754
![CVE-2025-32754](https://github.com/LeTrieuPhu/LLM-base-HoneyPot-in-NGFW/blob/main/Report/CVE-2025-32754.jpg)
- CVE-2025-32755
![CVE-2025-32755](https://github.com/LeTrieuPhu/LLM-base-HoneyPot-in-NGFW/blob/main/Report/CVE-2025-32755.jpg)
- 
2. Một CVE về HTTP
- CVE-2025-32013
![CVE-2025-32013](https://github.com/LeTrieuPhu/LLM-base-HoneyPot-in-NGFW/blob/main/Report/CVE-2025-32013.jpg)
3. Tổng Hợp
![ALL](https://github.com/LeTrieuPhu/LLM-base-HoneyPot-in-NGFW/blob/main/Report/ALL_CVE.jpg)
> ℹ️ **Chú thích:** Kết quả phân tích chi tiết của đồ án trong [Báo Cáo](https://github.com/LeTrieuPhu/LLM-base-HoneyPot-in-NGFW/blob/main/LeTrieuPhu_TranThienManh_DACN.pdf)
