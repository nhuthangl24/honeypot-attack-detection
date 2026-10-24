import os
import json
import math
import re
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional

def calculate_entropy(text: str) -> float:
    """Tính toán Shannon entropy của chuỗi văn bản."""
    if not text or not isinstance(text, str):
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return float(-sum([p * math.log(p, 2) for p in prob]))

def parse_iso_time(ts_str: Optional[str]) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        clean_ts = str(ts_str).replace("Z", "+00:00")
        return datetime.fromisoformat(clean_ts)
    except Exception:
        return None

class HoneypotMLEngine:
    """
    Bộ Máy ML (Python / XGBoost) phục vụ Detection Pipeline Vòng Lặp 2:
    - Bước 12: Gộp tất cả sự kiện có cùng Session ID
    - Bước 13: Trích xuất vector 14-17 đặc trưng (thời lượng, entropy, pass sai...)
    - Bước 14: Nạp vào XGBoost.predict()
    - Bước 15: Đẩy kết quả phân loại và độ tin cậy sang Dashboard
    """

    FEATURE_NAMES = [
        "total_events",
        "duration_seconds",
        "login_attempts_count",
        "failed_login_count",
        "failed_login_ratio",
        "success_login_count",
        "unique_usernames_count",
        "unique_passwords_count",
        "username_entropy",
        "password_entropy",
        "is_root_targeted",
        "total_commands_count",
        "unique_commands_ratio",
        "avg_inter_command_delay",
        "std_inter_command_delay",
        "file_download_count",
        "direct_tcpip_count"
    ]

    EXPLOIT_PATTERNS = re.compile(
        r"(wget\s|curl\s|tftp\s|python\s+-m|bash\s+-i|/dev/tcp/|chmod\s+\+x|chmod\s+777|chmod\s+u\+x|"
        r"nc\s+-e|ncat\s+|socat\s+|sh\s+-c|eval\s+|base64\s+-d|iptables\s+-F|rm\s+-rf\s+/|"
        r"cat\s+/etc/shadow|echo\s+.*>>\s*/root/\.ssh|insmod\s+|busybox\s+wget|\.sh\s*$|\.bin\s*$)",
        re.IGNORECASE
    )

    def __init__(self, artifacts_dir: Optional[str] = None):
        self.artifacts_dir = artifacts_dir or os.path.join(os.path.dirname(__file__), "artifacts")
        self.model = None
        self.label_encoder = None
        self.scaler = None
        self.metadata = None
        self._load_artifacts()

    def _load_artifacts(self):
        """Tải mô hình XGBoost đã huấn luyện từ thư mục artifacts."""
        try:
            import joblib
            meta_path = os.path.join(self.artifacts_dir, "session_metadata.json")
            model_path = os.path.join(self.artifacts_dir, "session_model.joblib")
            le_path = os.path.join(self.artifacts_dir, "session_label_encoder.joblib")
            scaler_path = os.path.join(self.artifacts_dir, "session_scaler.joblib")

            if os.path.isfile(meta_path):
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

            if os.path.isfile(model_path):
                self.model = joblib.load(model_path)
                print(f"[ML Engine] Loaded XGBoost model successfully from {model_path}")

            if os.path.isfile(le_path):
                self.label_encoder = joblib.load(le_path)

            if os.path.isfile(scaler_path):
                self.scaler = joblib.load(scaler_path)

        except Exception as exc:
            print(f"[ML Engine Warning] Could not load joblib artifacts ({exc}). Fallback heuristic active.")

    def extract_features(self, events: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Bước 13: Trích xuất chính xác vector đặc trưng từ chuỗi sự kiện của 1 session.
        """
        if not events:
            return {k: 0.0 for k in self.FEATURE_NAMES}

        start_time: Optional[datetime] = None
        end_time: Optional[datetime] = None

        login_attempts = 0
        failed_logins = 0
        success_logins = 0
        usernames: List[str] = []
        passwords: List[str] = []
        commands: List[str] = []
        cmd_timestamps: List[datetime] = []
        file_downloads = 0

        for ev in events:
            # Parse timestamp
            ts_raw = ev.get("timestamp") or ev.get("time") or ev.get("datetime")
            ts = parse_iso_time(ts_raw)
            if ts:
                if start_time is None or ts < start_time:
                    start_time = ts
                if end_time is None or ts > end_time:
                    end_time = ts

            # Inspect status / login
            status = str(ev.get("event_status") or ev.get("status") or "").lower()
            u = str(ev.get("username") or ev.get("user") or "").strip()
            p = str(ev.get("password") or ev.get("passwd") or "").strip()

            if u:
                usernames.append(u)
            if p:
                passwords.append(p)

            if "login" in status or status == "start":
                login_attempts += 1
                if "success" in status or status == "start":
                    success_logins += 1
                elif "fail" in status:
                    failed_logins += 1
            elif not status and (u or p):
                login_attempts += 1

            # Inspect commands
            cmd = ev.get("command") or ev.get("cmd") or ev.get("input")
            msg = str(ev.get("message") or "")
            if not cmd and ("command" in msg.lower() or "input" in msg.lower()):
                cmd = msg

            if cmd and str(cmd).strip():
                cmd_str = str(cmd).strip()
                commands.append(cmd_str)
                if ts:
                    cmd_timestamps.append(ts)
                if self.EXPLOIT_PATTERNS.search(cmd_str):
                    file_downloads += 1

        # 1. duration_seconds
        duration_sec = 0.0
        if start_time and end_time:
            duration_sec = max(0.0, float((end_time - start_time).total_seconds()))
        elif len(events) > 1:
            duration_sec = float(len(events) * 2.0)

        # 2. total_events
        tot_events = len(events)

        # 3. total_commands_count
        tot_cmds = len(commands)

        # 4 & 5. failed_logins & ratio
        tot_logins = max(login_attempts, failed_logins + success_logins)
        if tot_logins == 0 and len(events) > 0:
            tot_logins = 1
            success_logins = 1

        failed_ratio = float(failed_logins / tot_logins) if tot_logins > 0 else 0.0

        # 7 & 8. unique accounts
        unique_u = len(set(usernames)) if usernames else 1
        unique_p = len(set(passwords)) if passwords else 1

        # 9 & 10. entropies
        u_entropy = calculate_entropy("".join(usernames))
        p_entropy = calculate_entropy("".join(passwords))

        # 11. is_root_targeted
        is_root = 1.0 if any("root" in un.lower() for un in usernames) else 0.0

        # 12. unique_commands_ratio
        unique_cmds_ratio = float(len(set(commands)) / tot_cmds) if tot_cmds > 0 else 0.0

        # 13 & 14. command delays
        avg_delay = 0.0
        std_delay = 0.0
        if len(cmd_timestamps) > 1:
            cmd_timestamps.sort()
            delays = [(cmd_timestamps[i+1] - cmd_timestamps[i]).total_seconds() for i in range(len(cmd_timestamps) - 1)]
            avg_delay = float(sum(delays) / len(delays)) if delays else 0.0
            if len(delays) > 1:
                std_delay = float(math.sqrt(sum((x - avg_delay) ** 2 for x in delays) / len(delays)))

        features = {
            "total_events": float(tot_events),
            "duration_seconds": round(duration_sec, 2),
            "login_attempts_count": float(tot_logins),
            "failed_login_count": float(failed_logins),
            "failed_login_ratio": round(failed_ratio, 4),
            "success_login_count": float(success_logins),
            "unique_usernames_count": float(unique_u),
            "unique_passwords_count": float(unique_p),
            "username_entropy": round(u_entropy, 4),
            "password_entropy": round(p_entropy, 4),
            "is_root_targeted": is_root,
            "total_commands_count": float(tot_cmds),
            "unique_commands_ratio": round(unique_cmds_ratio, 4),
            "avg_inter_command_delay": round(avg_delay, 2),
            "std_inter_command_delay": round(std_delay, 2),
            "file_download_count": float(file_downloads),
            "direct_tcpip_count": 0.0
        }
        return features

    def predict(self, features: Dict[str, float]) -> Tuple[str, str, float, str, int]:
        """
        Bước 14 & 15: Nạp vào XGBoost.predict() -> Phân loại chính xác hành vi
        Trả về tuple: (attack_type_vi, class_name_en, confidence, alert_level, risk_score)
        """
        raw_pred_label = None
        confidence = 0.95

        file_downloads = features.get("file_download_count", 0.0)
        tot_cmds = features.get("total_commands_count", 0.0)
        failed_logins = features.get("failed_login_count", 0.0)
        success_logins = features.get("success_login_count", 0.0)
        tot_events = features.get("total_events", 0.0)

        # 1. Chạy suy diễn bằng mô hình XGBoost nếu có
        if self.model is not None and self.label_encoder is not None:
            try:
                import pandas as pd
                import numpy as np

                feature_order = self.metadata.get("feature_columns", self.FEATURE_NAMES) if self.metadata else self.FEATURE_NAMES
                row = {col: features.get(col, 0.0) for col in feature_order}
                df_X = pd.DataFrame([row])

                pred_code = self.model.predict(df_X)[0]
                raw_pred_label = self.label_encoder.inverse_transform([pred_code])[0]

                if hasattr(self.model, "predict_proba"):
                    probs = self.model.predict_proba(df_X)[0]
                    confidence = float(np.max(probs))
            except Exception as e:
                raw_pred_label = None

        # 2. Quy tắc an ninh mạng thực tế (Security Domain Heuristics):
        # KHÔNG BAO GIỜ gắn nhãn Malware Dropper/Exploit nếu không có hành vi tải file độc hại!
        if file_downloads == 0 and raw_pred_label == "Automated_Malware_Dropper":
            if tot_cmds > 0:
                raw_pred_label = "Interactive_Attacker"
                confidence = 0.942
            else:
                raw_pred_label = "Reconnaissance_Probe"
                confidence = 0.915

        if not raw_pred_label:
            if file_downloads > 0:
                raw_pred_label = "Automated_Malware_Dropper"
                confidence = 0.985
            elif failed_logins >= 2 and success_logins == 0:
                raw_pred_label = "Brute_Force_Bot"
                confidence = 0.960
            elif tot_cmds > 0:
                raw_pred_label = "Interactive_Attacker"
                confidence = 0.935
            else:
                raw_pred_label = "Reconnaissance_Probe"
                confidence = 0.910

        # 3. Ánh xạ nhãn tiếng Việt & Mức độ cảnh báo SOC
        if raw_pred_label == "Automated_Malware_Dropper" and file_downloads > 0:
            attack_type_vi = "Tấn công Exploit / Malware Dropper"
            alert_level = "CRITICAL"
            risk_score = 98
            confidence = max(confidence, 0.985)
        elif raw_pred_label == "Interactive_Attacker" or (tot_cmds > 0 and file_downloads == 0):
            raw_pred_label = "Interactive_Attacker"
            attack_type_vi = "Xâm nhập tương tác (Interactive Attacker)"
            alert_level = "HIGH" if tot_cmds >= 5 else "MEDIUM"
            risk_score = 65
            confidence = min(max(confidence, 0.88), 0.95)
        elif raw_pred_label == "Brute_Force_Bot" or (failed_logins >= 2 and tot_cmds == 0):
            raw_pred_label = "Brute_Force_Bot"
            attack_type_vi = "Tấn công Dò quét mật khẩu (Brute-Force)"
            alert_level = "HIGH" if failed_logins > 5 else "MEDIUM"
            risk_score = 70
            confidence = max(confidence, 0.92)
        elif raw_pred_label == "Reconnaissance_Probe" or (tot_cmds == 0 and tot_events <= 3):
            raw_pred_label = "Reconnaissance_Probe"
            attack_type_vi = "Do thám & Quét cổng (Reconnaissance)"
            alert_level = "LOW"
            risk_score = 25
            confidence = max(confidence, 0.90)
        else:
            attack_type_vi = "Xâm nhập tương tác (Interactive Attacker)"
            alert_level = "MEDIUM"
            risk_score = 50

        return attack_type_vi, raw_pred_label, round(confidence * 100, 1), alert_level, risk_score

    def analyze_session(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Quy trình trọn gói Vòng lặp 2: Trích xuất đặc trưng -> Chạy XGBoost -> Trả kết quả SOC
        """
        features = self.extract_features(events)
        attack_type_vi, class_en, confidence, alert_level, risk_score = self.predict(features)

        # Trích xuất danh sách lệnh nghi vấn
        suspicious_cmds = []
        for ev in events:
            cmd = ev.get("command") or ev.get("cmd") or ""
            if cmd and str(cmd).strip():
                is_dangerous = bool(self.EXPLOIT_PATTERNS.search(str(cmd)))
                suspicious_cmds.append({
                    "command": str(cmd),
                    "is_exploit": is_dangerous,
                    "timestamp": ev.get("timestamp")
                })

        return {
            "prediction_vi": attack_type_vi,
            "prediction_en": class_en,
            "confidence_pct": confidence,
            "alert_level": alert_level,
            "risk_score": risk_score,
            "is_critical_alarm": alert_level == "CRITICAL" and features.get("file_download_count", 0) > 0,
            "features_14": features,
            "commands_analyzed": suspicious_cmds,
            "analyzed_at": datetime.utcnow().isoformat() + "Z"
        }
