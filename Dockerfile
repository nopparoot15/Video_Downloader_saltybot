# ใช้ Python 3.11 ที่เล็กและไว
FROM python:3.11-slim

# ติดตั้ง ffmpeg สำหรับรวม/แปลงไฟล์ และ dependencies ขั้นต่ำ
RUN apt-get update && \
    apt-get install -y --no-install-recommends ffmpeg && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ติดตั้งไลบรารีก่อนเพื่อลด layer cache bust
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# คัดลอกซอร์สโค้ด
COPY bot.py .
# ถ้ามีไฟล์ allowlist แยก ให้คัดลอกด้วย
# COPY channel_allowlist.py .

# ให้ log ไหลแบบ realtime
ENV PYTHONUNBUFFERED=1

# โฟลเดอร์เก็บไฟล์ชั่วคราว/ผลลัพธ์
RUN mkdir -p /app/downloads

# รันบอท
CMD ["python", "-u", "bot.py"]
