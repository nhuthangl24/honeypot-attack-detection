import asyncio
import json
import os
import re
import sqlite3
import subprocess
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DB_PATH", str(APP_DIR / "data" / "events.db")))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "2"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

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
    conn = sqlite3.connect(DB_PATH, timeout=10)
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

def get_candidate_log_files():
    candidates = []
    env_file = os.getenv("BEELZEBUB_LOG_FILE") or os.getenv("LOG_FILE")
    if env_file:
        candidates.append(Path(env_file))
    candidates.extend([
        APP_DIR / "logs" / "beelzebub.json",
        APP_DIR.parent / "logs" / "beelzebub.json",
        APP_DIR / "deploy" / "beelzebub" / "logs" / "beelzebub.json",
        Path("/var/log/beelzebub/beelzebub.json"),
        Path("/var/log/beelzebub.json"),
        APP_DIR / "data" / "raw" / "beelzebub_sample.json",
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

def insert_event(item: dict) -> bool:
    columns = list(item.keys())
    placeholders = ",".join("?" for _ in columns)
    with db_connect() as conn:
        cur = conn.execute(
            f"INSERT OR IGNORE INTO events ({','.join(columns)}) VALUES ({placeholders})",
            [item[c] for c in columns]
        )
        return cur.rowcount > 0

def docker_parser_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        container = get_target_container()
        since_val = os.getenv("LOG_SINCE")
        if since_val:
            cmd = ["docker", "logs", "--follow", "--since", since_val, container]
        else:
            cmd = ["docker", "logs", "--follow", "--tail", "2000", container]

        print(f"[parser] Starting Docker log monitor for '{container}' ({' '.join(cmd[2:])})...", flush=True)

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
                            print(f"[parser] + Ingested Docker event: [{parsed['protocol']}] IP: {parsed['source_ip']} | Status: {parsed['event_status']} | Cmd: {parsed['command'] or parsed['message'] or '-'}", flush=True)
                    except sqlite3.Error as exc:
                        print(f"[parser] Database error: {exc}", flush=True)

            proc.terminate()
            try:
                stderr_data = proc.stderr.read() if proc.stderr else ""
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                stderr_data = ""

            if proc.returncode not in (0, None, -15):
                print(f"[parser] Docker exited with code {proc.returncode}: {stderr_data.strip()}", flush=True)

        except FileNotFoundError:
            print("[parser] 'docker' command not found in PATH. Make sure Docker is installed on this host.", flush=True)
        except Exception as exc:
            print(f"[parser] Docker error: {exc}", flush=True)

        stop_event.wait(POLL_INTERVAL)

def file_parser_loop(stop_event: threading.Event):
    """Monitors any local Beelzebub JSON log files and ingests new records."""
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
                                        print(f"[parser] + Ingested file event ({fpath.name}): [{parsed['protocol']}] IP: {parsed['source_ip']} | Cmd: {parsed['command'] or parsed['event_status']}", flush=True)
                                except sqlite3.Error as exc:
                                    print(f"[parser] Database error: {exc}", flush=True)
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
    t_docker.start()
    t_file.start()
    app.state.stop_event = stop_event
    app.state.workers = [t_docker, t_file]
    yield
    stop_event.set()
    t_docker.join(timeout=3)
    t_file.join(timeout=3)

app = FastAPI(title="Beelzebub SOC Dashboard", version="0.1.0", lifespan=lifespan)
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

    found_files = [str(p) for p in get_candidate_log_files()]

    return {
        "status": "ok",
        "database": str(DB_PATH),
        "container_name": container,
        "docker_container_found": docker_ok,
        "log_files_found": found_files,
        "events_total": count
    }

@app.post("/api/events/test")
def test_event():
    """Generates a sample honeypot event for testing dashboard reception."""
    now_iso = datetime.now(timezone.utc).isoformat()
    test_record = {
        "event_key": f"test:{datetime.now(timezone.utc).timestamp()}",
        "timestamp": now_iso,
        "source_ip": "192.168.1.99",
        "source_port": 49152,
        "protocol": "ssh",
        "session_id": "test-session-01",
        "event_status": "login_success",
        "message": "Manual test connection",
        "command": "uname -a",
        "command_output": "Linux beelzebub-vm 5.15.0-generic",
        "username": "root",
        "service_description": "Test Injection",
        "http_method": None,
        "request_uri": None,
        "user_agent": None,
        "body": None,
        "raw_level": "info",
        "raw_json": json.dumps({"test": True, "created_at": now_iso}),
        "ingested_at": now_iso
    }
    inserted = insert_event(test_record)
    return {"inserted": inserted, "event": test_record}

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
    return {"total_events": total, "events_24h": last_24h, "unique_ips": unique_ips,
            "sessions": sessions, "protocols": protocols, "statuses": statuses,
            "top_ips": top_ips, "timeline": timeline}

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
        clauses.append("(source_ip LIKE ? OR message LIKE ? OR command LIKE ? OR username LIKE ? OR request_uri LIKE ?)")
        pattern = f"%{q}%"
        args.extend([pattern] * 5)
    if protocol:
        clauses.append("protocol = ?"); args.append(protocol)
    if status:
        clauses.append("event_status = ?"); args.append(status)
    if ip:
        clauses.append("source_ip LIKE ?"); args.append(f"%{ip}%")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    with db_connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM events" + where, args).fetchone()[0]
        rows = conn.execute(
            "SELECT id, timestamp, source_ip, source_port, protocol, session_id, event_status, message, command, command_output, username, service_description, http_method, request_uri, user_agent FROM events"
            + where + " ORDER BY id DESC LIMIT ? OFFSET ?", args + [limit, offset]
        ).fetchall()
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
    return item

@app.get("/api/sessions/{session_id}")
def session_detail(session_id: str):
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, source_ip, source_port, protocol, session_id, event_status, message, command, command_output, username, service_description, raw_json FROM events WHERE session_id = ? ORDER BY id ASC",
            (session_id,)
        ).fetchall()
    items = []
    for r in rows:
        it = dict(r)
        try:
            it["raw_json"] = json.loads(it["raw_json"])
        except Exception:
            pass
        items.append(it)
    return {"session_id": session_id, "total": len(items), "events": items}

@app.get("/api/filters")
def filters():
    with db_connect() as conn:
        protocols = [r[0] for r in conn.execute("SELECT DISTINCT protocol FROM events WHERE protocol IS NOT NULL ORDER BY protocol")]
        statuses = [r[0] for r in conn.execute("SELECT DISTINCT event_status FROM events WHERE event_status IS NOT NULL ORDER BY event_status")]
    return {"protocols": protocols, "statuses": statuses}
