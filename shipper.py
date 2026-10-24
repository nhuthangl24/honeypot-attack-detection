#!/usr/bin/env python3
"""
Beelzebub Log Shipper (VM 1 -> VM 2)
-----------------------------------
Chạy trên VM 1 (Honeypot VM).
Tự động theo dõi file log `beelzebub.json` (hoặc Docker container) 
và stream sự kiện theo thời gian thực sang VM 2 (ML + Dashboard VM).

Cách dùng:
    python3 shipper.py --vm2-url http://192.168.1.100:8080/api/ingest
hoặc thông qua biến môi trường:
    VM2_URL=http://<IP_VM2>:8080/api/ingest python3 shipper.py
"""

import os
import sys
import time
import json
import argparse
import urllib.request
import urllib.error
import subprocess
from pathlib import Path

def post_event(url: str, event_data: dict, timeout: int = 5) -> bool:
    try:
        data = json.dumps(event_data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "Beelzebub-Shipper/1.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 201)
    except Exception as exc:
        print(f"[Shipper Error] Gửi event sang VM2 thất bại: {exc}", flush=True)
        return False

def tail_file(file_path: Path, vm2_url: str):
    print(f"[Shipper] Bắt đầu theo dõi file log: {file_path}", flush=True)
    print(f"[Shipper] Đích truyền dữ liệu (VM2): {vm2_url}", flush=True)

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        # Nhảy tới cuối file
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            
            line_str = line.strip()
            if not line_str:
                continue
            
            # Gửi sang VM2
            payload = {"raw_line": line_str}
            try:
                parsed = json.loads(line_str)
                payload["parsed"] = parsed
            except Exception:
                pass

            post_event(vm2_url, payload)

def tail_docker(container_name: str, vm2_url: str):
    print(f"[Shipper] Bắt đầu theo dõi Docker logs của container: '{container_name}'", flush=True)
    print(f"[Shipper] Đích truyền dữ liệu (VM2): {vm2_url}", flush=True)

    cmd = ["docker", "logs", "--follow", "--tail", "50", container_name]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    try:
        for line in proc.stdout:
            line_str = line.strip()
            if not line_str:
                continue
            payload = {"raw_line": line_str}
            try:
                parsed = json.loads(line_str)
                payload["parsed"] = parsed
            except Exception:
                pass
            post_event(vm2_url, payload)
    except KeyboardInterrupt:
        proc.terminate()

def main():
    parser = argparse.ArgumentParser(description="Chuyển tiếp log từ Honeypot VM1 sang ML VM2")
    parser.add_argument("--vm2-url", default=os.getenv("VM2_URL", "http://127.0.0.1:8080/api/ingest"),
                        help="Địa chỉ API ingest trên VM2 (VD: http://192.168.1.50:8080/api/ingest)")
    parser.add_argument("--log-file", default=os.getenv("BEELZEBUB_LOG", "beelzebub.json"),
                        help="Đường dẫn file beelzebub.json")
    parser.add_argument("--container", default=os.getenv("BEELZEBUB_CONTAINER", ""),
                        help="Tên container Docker Beelzebub nếu lấy trực tiếp từ Docker")

    args = parser.parse_args()

    # Kiểm tra phương thức đọc
    if args.container:
        tail_docker(args.container, args.vm2_url)
    else:
        log_path = Path(args.log_file)
        if not log_path.exists():
            # Thử các đường dẫn mặc định
            candidates = [
                Path("beelzebub.json"),
                Path("/var/log/beelzebub.json"),
                Path("/var/log/beelzebub/beelzebub.json"),
                Path("logs/beelzebub.json")
            ]
            for c in candidates:
                if c.exists():
                    log_path = c
                    break
        
        if log_path.exists():
            tail_file(log_path, args.vm2_url)
        else:
            print(f"[Shipper] Không tìm thấy file log tại '{args.log_file}'. Đang fallback sang Docker logs container 'beelzebub'...")
            tail_docker("beelzebub", args.vm2_url)

if __name__ == "__main__":
    main()
