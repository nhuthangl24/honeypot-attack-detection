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
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DB_PATH", str(APP_DIR / "data" / "events.db")))
CONTAINER_NAME = os.getenv("BEELZEBUB_CONTAINER", "beelzebub")
LOG_SINCE = os.getenv("LOG_SINCE", "5m")
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

def first_value(event: dict, *keys):
    for key in keys:
        val = event.get(key)
        if val not in (None, ""):
            return val
    return None

def parse_record(line: str) -> Optional[dict]:
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    event = record.get("event")
    if not isinstance(event, dict):
        return None  # operational log, not a honeypot event

    event = redact(event)
    source_ip = first_value(event, "SourceIp")
    source_port = first_value(event, "SourcePort")
    remote_addr = first_value(event, "RemoteAddr")
    if (source_ip is None or source_port is None) and isinstance(remote_addr, str) and ":" in remote_addr:
        host, port = remote_addr.rsplit(":", 1)
        source_ip = source_ip or host.strip("[]")
        if source_port is None:
            source_port = port

    try:
        source_port = int(source_port) if source_port not in (None, "") else None
    except (ValueError, TypeError):
        source_port = None

    # A stable key prevents duplicate insertion when the parser restarts.
    event_id = first_value(event, "ID")
    timestamp = first_value(event, "DateTime")
    stable_material = event_id or json.dumps(event, sort_keys=True, ensure_ascii=False)
    event_key = f"{timestamp or ''}:{stable_material}:{first_value(event, 'Status') or ''}"

    return {
        "event_key": event_key,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_port": source_port,
        "protocol": first_value(event, "Protocol"),
        "session_id": event_id,
        "event_status": first_value(event, "Status") or record.get("status"),
        "message": first_value(event, "Msg") or record.get("msg"),
        "command": first_value(event, "Command"),
        "command_output": first_value(event, "CommandOutput"),
        "username": first_value(event, "User"),
        "service_description": first_value(event, "Description"),
        "http_method": first_value(event, "HTTPMethod"),
        "request_uri": first_value(event, "RequestURI"),
        "user_agent": first_value(event, "UserAgent"),
        "body": first_value(event, "Body"),
        "raw_level": record.get("level"),
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

def parser_loop(stop_event: threading.Event):
    """Follow Docker logs on the VM host and ingest only JSON records containing an event object."""
    cmd = ["docker", "logs", "--follow", "--since", LOG_SINCE, CONTAINER_NAME]
    while not stop_event.is_set():
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                if stop_event.is_set():
                    break
                parsed = parse_record(line.strip())
                if parsed:
                    try:
                        insert_event(parsed)
                    except sqlite3.Error as exc:
                        print(f"[parser] database error: {exc}", flush=True)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        except FileNotFoundError:
            print("[parser] Docker CLI not found. Install Docker or run this service on the Honeypot VM host.", flush=True)
        except Exception as exc:
            print(f"[parser] {type(exc).__name__}: {exc}", flush=True)
        stop_event.wait(POLL_INTERVAL)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    stop_event = threading.Event()
    worker = threading.Thread(target=parser_loop, args=(stop_event,), daemon=True)
    worker.start()
    app.state.stop_event = stop_event
    app.state.worker = worker
    yield
    stop_event.set()
    worker.join(timeout=4)

app = FastAPI(title="Beelzebub SOC Dashboard", version="0.1.0", lifespan=lifespan)
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
    docker_ok = subprocess.run(["docker", "inspect", CONTAINER_NAME], capture_output=True, text=True).returncode == 0
    with db_connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return {"status": "ok", "database": str(DB_PATH), "docker_container_found": docker_ok, "events_total": count}

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
            "SELECT id, timestamp, source_ip, source_port, protocol, session_id, event_status, message, command, username, service_description, http_method, request_uri, user_agent FROM events"
            + where + " ORDER BY id DESC LIMIT ? OFFSET ?", args + [limit, offset]
        ).fetchall()
    return {"total": total, "limit": limit, "offset": offset, "items": [dict(r) for r in rows]}

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

@app.get("/api/filters")
def filters():
    with db_connect() as conn:
        protocols = [r[0] for r in conn.execute("SELECT DISTINCT protocol FROM events WHERE protocol IS NOT NULL ORDER BY protocol")]
        statuses = [r[0] for r in conn.execute("SELECT DISTINCT event_status FROM events WHERE event_status IS NOT NULL ORDER BY event_status")]
    return {"protocols": protocols, "statuses": statuses}
