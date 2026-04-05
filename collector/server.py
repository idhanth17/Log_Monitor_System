from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import datetime
import time
import asyncio
import uuid
import hashlib
import secrets
import sqlite3
import subprocess
import os
import sys

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_PG = True
except ImportError:
    HAS_PG = False

app = FastAPI(title="Access-Controlled Log Monitor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv("DATABASE_URL")
DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs.db"))
DB_PATH = os.path.normpath(DB_PATH)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "dc_secret_2026")

def _get_conn():
    if DATABASE_URL:
        if not HAS_PG:
            raise ImportError("psycopg2-binary is required for PostgreSQL support. Install it via pip.")
        return psycopg2.connect(DATABASE_URL)
    else:
        import sqlite3
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA cache_size=-10000')
        conn.row_factory = sqlite3.Row
        return conn

def init_db():
    conn = _get_conn()
    is_pg = DATABASE_URL is not None
    cursor = conn.cursor()

    if not is_pg:
        cursor.execute('PRAGMA journal_mode=WAL')
        cursor.execute('PRAGMA synchronous=NORMAL')
    
    # helper for dialect-specific syntax
    id_type = "SERIAL PRIMARY KEY" if is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"
    text_type = "TEXT"
    
    # Logs table
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS logs (
            id {id_type},
            timestamp {text_type},
            service_name {text_type},
            host_id {text_type},
            severity {text_type},
            message {text_type},
            request_id {text_type},
            user_tag {text_type}
        )
    ''')
    
    # failure_detectors table
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS failure_detectors (
            service_name {text_type} PRIMARY KEY,
            status {text_type},
            last_heartbeat {text_type}
        )
    ''')

    # Users table
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS users (
            id {id_type},
            name {text_type} UNIQUE NOT NULL,
            role {text_type} DEFAULT 'user',
            password_hash {text_type}
        )
    ''')

    # Sessions table
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS sessions (
            id {text_type} PRIMARY KEY,
            user_name {text_type} NOT NULL,
            service_name {text_type} NOT NULL,
            start_time {text_type} NOT NULL,
            end_time {text_type},
            is_active INTEGER DEFAULT 1
        )
    ''')

    # Service registry
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS services_registry (
            id {id_type},
            name {text_type} UNIQUE NOT NULL,
            is_active INTEGER DEFAULT 1,
            mode {text_type} DEFAULT 'public'
        )
    ''')

    # Service access users
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS service_access_users (
            service_name {text_type},
            user_name {text_type},
            PRIMARY KEY (service_name, user_name)
        )
    ''')

    # Tokens table
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS tokens (
            token {text_type} PRIMARY KEY,
            user_name {text_type},
            role {text_type},
            expires DOUBLE PRECISION
        )
    ''')

    # Access requests table
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS access_requests (
            id {text_type} PRIMARY KEY,
            user_name {text_type},
            service_name {text_type},
            status {text_type},
            timestamp {text_type}
        )
    ''')

    # Leader election table
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS leader_election (
            id INTEGER PRIMARY KEY,
            leader_id {text_type},
            expires DOUBLE PRECISION,
            force_crash INTEGER DEFAULT 0
        )
    ''')
    
    if is_pg:
        cursor.execute('INSERT INTO leader_election (id, leader_id, expires, force_crash) VALUES (1, NULL, 0, 0) ON CONFLICT (id) DO NOTHING')
    else:
        cursor.execute('INSERT OR IGNORE INTO leader_election (id, leader_id, expires, force_crash) VALUES (1, NULL, 0, 0)')

    # Performance indexes
    idx_sql = [
        'CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(timestamp DESC)',
        'CREATE INDEX IF NOT EXISTS idx_logs_sev ON logs(severity)',
        'CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active)',
        'CREATE INDEX IF NOT EXISTS idx_tokens_exp ON tokens(expires)',
        'CREATE INDEX IF NOT EXISTS idx_access_req_status ON access_requests(status)'
    ]
    for sql in idx_sql: cursor.execute(sql)

    # Node Registry
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS node_registry (
            node_id {text_type} PRIMARY KEY,
            priority INTEGER DEFAULT 0,
            created_at DOUBLE PRECISION,
            last_seen DOUBLE PRECISION,
            node_status {text_type} DEFAULT 'enabled'
        )
    ''')

    # Seed admin user
    pw_hash = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    if is_pg:
        cursor.execute('INSERT INTO users (name, role, password_hash) VALUES (%s, %s, %s) ON CONFLICT (name) DO NOTHING', ("admin", "admin", pw_hash))
    else:
        cursor.execute('INSERT OR IGNORE INTO users (name, role, password_hash) VALUES (?, ?, ?)', ("admin", "admin", pw_hash))

    # Seed default services
    cursor.execute('SELECT COUNT(*) FROM services_registry')
    if cursor.fetchone()[0] == 0:
        default_services = [
            ("file-server", "public"), ("data-vault", "private"), ("ml-pipeline", "protected"),
            ("auth-service", "public"), ("payment-service", "protected"),
        ]
        for svc_name, mode in default_services:
            placeholder = "%s" if is_pg else "?"
            cursor.execute(f'INSERT INTO services_registry (name, is_active, mode) VALUES ({placeholder}, 1, {placeholder})', (svc_name, mode))

    conn.commit()
    conn.close()

init_db()

# -----------------------------------------------------------------
# HELPERS (Async Thread-Safe Wrappers)
# -----------------------------------------------------------------
def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

async def run_query(query: str, params: tuple = (), commit: bool = False, fetch_one: bool = False, fetch_all: bool = False):
    is_pg = DATABASE_URL is not None
    # Auto-translate SQL placeholders if using Postgres
    if is_pg:
        query = query.replace('?', '%s')
        # Handle 'INSERT OR REPLACE' -> Postgres 'ON CONFLICT'
        if 'INSERT OR REPLACE' in query.upper():
            if 'TOKENS' in query.upper():
                query = "INSERT INTO tokens (token, user_name, role, expires) VALUES (%s, %s, %s, %s) ON CONFLICT (token) DO UPDATE SET user_name=EXCLUDED.user_name, role=EXCLUDED.role, expires=EXCLUDED.expires"
            elif 'FAILURE_DETECTORS' in query.upper():
                query = "INSERT INTO failure_detectors (service_name, status, last_heartbeat) VALUES (%s, %s, %s) ON CONFLICT (service_name) DO UPDATE SET status=EXCLUDED.status, last_heartbeat=EXCLUDED.last_heartbeat"
        # Handle 'INSERT OR IGNORE'
        if 'INSERT OR IGNORE' in query.upper():
            query = query.upper().replace('INSERT OR IGNORE INTO', 'INSERT INTO') + ' ON CONFLICT DO NOTHING'

    def _execute():
        conn = _get_conn()
        try:
            if is_pg:
                cursor = conn.cursor(cursor_factory=RealDictCursor)
            else:
                cursor = conn.cursor()
            
            cursor.execute(query, params)
            res = None
            if fetch_one:
                res = cursor.fetchone()
                if res: res = dict(res)
            elif fetch_all:
                res = [dict(r) for r in cursor.fetchall()]
            
            if commit:
                conn.commit()
            return res
        finally:
            conn.close()
            
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _execute)

async def write_log_async(service_name: str, user_name: str, severity: str, message: str):
    query = '''
        INSERT INTO logs (timestamp, service_name, host_id, severity, message, request_id, user_tag)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    '''
    params = (
        datetime.datetime.now(datetime.timezone.utc).isoformat(),
        service_name, "system", severity, message,
        f"req-{uuid.uuid4().hex[:8]}", user_name
    )
    await run_query(query, params, commit=True)

async def get_token_user_async(token: str):
    row = await run_query('SELECT * FROM tokens WHERE token=?', (token,), fetch_one=True)
    if not row: return None
    if row['expires'] < time.time():
        await run_query('DELETE FROM tokens WHERE token=?', (token,), commit=True)
        return None
    return {"name": row["user_name"], "role": row["role"], "expires": row["expires"]}

async def save_token_async(token: str, name: str, role: str, expires: float):
    await run_query('INSERT OR REPLACE INTO tokens (token, user_name, role, expires) VALUES (?,?,?,?)',
                    (token, name, role, expires), commit=True)

async def delete_token_async(token: str):
    await run_query('DELETE FROM tokens WHERE token=?', (token,), commit=True)

async def require_auth(request: Request):
    token = request.headers.get("X-Auth-Token")
    if not token: raise HTTPException(status_code=401, detail="Missing auth token")
    user = await get_token_user_async(token)
    if not user: raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user

async def require_admin(request: Request):
    user = await require_auth(request)
    if user["role"] != "admin": raise HTTPException(status_code=403, detail="Admin access required")
    return user

# -----------------------------------------------------------------
# PYDANTIC MODELS
# -----------------------------------------------------------------
class LoginRequest(BaseModel):
    name: str
    password: Optional[str] = None

class CreateUserRequest(BaseModel):
    name: str
    role: str = "user"

class CreateServiceRequest(BaseModel):
    name: str
    mode: str = "public"
    allowed_users: List[str] = []

class ElectRequest(BaseModel):
    node_id: str
    priority: int = 0

class RegisterNodeRequest(BaseModel):
    node_id: str
    priority: int = 0

class PriorityUpdateRequest(BaseModel):
    priority: int

class SessionStartRequest(BaseModel):
    service_name: str

class SessionStopRequest(BaseModel):
    session_id: str

class RequestAccessRequest(BaseModel):
    service_name: str

# -----------------------------------------------------------------
# ENDPOINTS
# -----------------------------------------------------------------
@app.post("/api/auth/login")
async def login(body: LoginRequest):
    user = await run_query('SELECT * FROM users WHERE name = ?', (body.name,), fetch_one=True)
    if not user: raise HTTPException(status_code=404, detail="User not found")
    if user["role"] == "admin":
        if not body.password or hash_password(body.password) != user["password_hash"]:
            raise HTTPException(status_code=401, detail="Invalid admin credentials")
    token = secrets.token_hex(24)
    expires = time.time() + 8 * 3600
    await save_token_async(token, body.name, user["role"], expires)
    await write_log_async("auth-service", body.name, "INFO", f"User logged in")
    return {"token": token, "name": body.name, "role": user["role"]}

@app.get("/api/dashboard/summary")
async def get_dashboard_summary(request: Request):
    await require_admin(request)
    now = time.time()
    last_min = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)).isoformat()
    
    s_rows = await run_query('SELECT * FROM sessions WHERE is_active = 1', fetch_all=True)
    sessions = []
    for r in s_rows:
        d = dict(r)
        start = datetime.datetime.fromisoformat(d["start_time"])
        d["duration_seconds"] = int((datetime.datetime.now(datetime.timezone.utc) - start).total_seconds())
        sessions.append(d)

    req_rows = await run_query('SELECT * FROM access_requests WHERE status = "pending"', fetch_all=True)
    svc_rows = await run_query('SELECT * FROM services_registry', fetch_all=True)
    user_rows = await run_query('SELECT id, name, role FROM users ORDER BY role, name', fetch_all=True)
    
    l_row = await run_query('SELECT COUNT(*) as count FROM logs WHERE timestamp > ?', (last_min,), fetch_one=True)
    e_row = await run_query('SELECT COUNT(*) as count FROM logs WHERE timestamp > ? AND severity = "ERROR"', (last_min,), fetch_one=True)
    metrics = {"logs_per_second": round(l_row['count'] / 60.0, 2), "error_count_60s": e_row['count']}
    
    log_rows = await run_query('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 60', fetch_all=True)
    n_rows = await run_query('SELECT * FROM node_registry ORDER BY priority DESC, created_at ASC', fetch_all=True)
    nodes = []
    for r in n_rows:
        nd = dict(r)
        nd["is_active"] = (now - nd["last_seen"]) < 15 if nd["last_seen"] else False
        nodes.append(nd)

    leader_row = await run_query('SELECT * FROM leader_election WHERE id = 1', fetch_one=True)
    leader_info = None
    if leader_row and leader_row['leader_id']:
        is_alive = (now < leader_row['expires'])
        leader_info = {
            "leader_id": leader_row['leader_id'],
            "is_alive": is_alive,
            "expires_in": max(0, int(leader_row['expires'] - now))
        }

    return {
        "sessions": sessions, "requests": [dict(r) for r in req_rows],
        "registry": [dict(r) for r in svc_rows], "users": [dict(r) for r in user_rows],
        "metrics": metrics, "logs": [dict(r) for r in log_rows],
        "nodes": nodes, "leader": leader_info
    }

@app.post("/api/leader/elect")
async def leader_elect(body: ElectRequest):
    now = time.time()
    row = await run_query('SELECT created_at, node_status FROM node_registry WHERE node_id = ?', (body.node_id,), fetch_one=True)
    
    if not row:
        await run_query('INSERT INTO node_registry (node_id, priority, created_at, last_seen, node_status) VALUES (?,?,?,?,?)',
                        (body.node_id, body.priority, now, now, 'enabled'), commit=True)
    else:
        if row['node_status'] == 'disabled': return {"status": "disabled"}
        await run_query('UPDATE node_registry SET priority = ?, last_seen = ? WHERE node_id = ?',
                        (body.priority, now, body.node_id), commit=True)
    
    l_elect = await run_query('SELECT * FROM leader_election WHERE id = 1', fetch_one=True)
    
    # Check for force crash
    if l_elect and l_elect['leader_id'] == body.node_id and l_elect['force_crash']:
        await run_query("UPDATE node_registry SET node_status = 'disabled' WHERE node_id = ?", (body.node_id,), commit=True)
        await run_query('UPDATE leader_election SET leader_id = NULL, force_crash = 0 WHERE id = 1', commit=True)
        await write_log_async("platform", body.node_id, "CRITICAL", "Node crashed by admin")
        return {"status": "crashed"}

    # Renew lease
    if l_elect and l_elect['leader_id'] == body.node_id:
        new_exp = now + 12
        await run_query('UPDATE leader_election SET expires = ? WHERE id = 1', (new_exp,), commit=True)
        return {"status": "renewed", "expires": new_exp}

    # If someone else is leader and still active
    if l_elect and l_elect['leader_id'] and now < l_elect['expires']:
        return {"status": "standby", "leader_id": l_elect['leader_id']}

    # Perform election
    candidates = await run_query("SELECT * FROM node_registry WHERE node_status = 'enabled' AND last_seen > ? ORDER BY priority DESC, created_at ASC",
                                (now - 15,), fetch_all=True)
    if not candidates: return {"status": "standby", "leader_id": None}
    
    best = candidates[0]['node_id']
    if best == body.node_id:
        new_exp = now + 12
        await run_query('UPDATE leader_election SET leader_id = ?, expires = ? WHERE id = 1', (best, new_exp), commit=True)
        return {"status": "acquired", "expires": new_exp}
    
    return {"status": "standby", "leader_id": best}

@app.post("/api/leader/crash")
async def leader_crash(request: Request):
    await require_admin(request)
    await run_query('UPDATE leader_election SET force_crash = 1 WHERE id = 1', commit=True)
    await write_log_async("admin", "admin", "WARNING", "Leader crash signal sent")
    return {"status": "crash_signal_set"}

@app.post("/api/nodes/{node_id}/enable")
async def enable_node(node_id: str, request: Request):
    await require_admin(request)
    await run_query("UPDATE node_registry SET node_status = 'enabled' WHERE node_id = ?", (node_id,), commit=True)
    return {"status": "enabled"}

@app.post("/api/nodes/{node_id}/disable")
async def disable_node(node_id: str, request: Request):
    await require_admin(request)
    await run_query("UPDATE node_registry SET node_status = 'disabled' WHERE node_id = ?", (node_id,), commit=True)
    
    # Instantly trigger failover if the disabled node was the leader
    l_elect = await run_query('SELECT leader_id FROM leader_election WHERE id = 1', fetch_one=True)
    if l_elect and l_elect['leader_id'] == node_id:
        await run_query('UPDATE leader_election SET leader_id = NULL, expires = 0 WHERE id = 1', commit=True)
        
    return {"status": "disabled"}

@app.patch("/api/nodes/{node_id}/priority")
async def update_priority(node_id: str, body: PriorityUpdateRequest, request: Request):
    await require_admin(request)
    await run_query("UPDATE node_registry SET priority = ? WHERE node_id = ?", (body.priority, node_id), commit=True)
    return {"status": "updated"}

@app.delete("/api/nodes/{node_id}")
async def delete_node(node_id: str, request: Request):
    await require_admin(request)
    await run_query("DELETE FROM node_registry WHERE node_id = ?", (node_id,), commit=True)
    return {"status": "removed"}

@app.post("/api/heartbeat")
async def heartbeat(request: Request):
    data = await request.json()
    svc = data.get("service_name")
    if not svc: return {"status": "error"}
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    await run_query('INSERT OR REPLACE INTO failure_detectors (service_name, status, last_heartbeat) VALUES (?,?,?)',
                    (svc, "active", ts), commit=True)
    return {"status": "ok"}

@app.post("/api/registry/{name}/toggle")
async def toggle_svc(name: str, request: Request):
    await require_admin(request)
    await run_query('UPDATE services_registry SET is_active = 1 - is_active WHERE name = ?', (name,), commit=True)
    return {"status": "toggled"}

@app.post("/api/sessions/kick/{id}")
async def kick_session(id: str, request: Request):
    await require_admin(request)
    end = datetime.datetime.now().isoformat()
    await run_query('UPDATE sessions SET end_time = ?, is_active = 0 WHERE id = ?', (end, id), commit=True)
    return {"status": "kicked"}

@app.post("/api/requests/{id}/{action}")
async def resolve_request(id: str, action: str, request: Request):
    await require_admin(request)
    status = "approved" if action == "approve" else "denied"
    req = await run_query('SELECT * FROM access_requests WHERE id = ?', (id,), fetch_one=True)
    if not req: raise HTTPException(status_code=404)
    await run_query('UPDATE access_requests SET status = ? WHERE id = ?', (status, id), commit=True)
    if status == "approved":
        await run_query('INSERT OR IGNORE INTO service_access_users (service_name, user_name) VALUES (?,?)',
                        (req["service_name"], req["user_name"]), commit=True)
    return {"status": status}

@app.post("/api/auth/users")
async def create_user(body: CreateUserRequest, request: Request):
    await require_admin(request)
    await run_query('INSERT INTO users (name, role) VALUES (?, ?)', (body.name, body.role), commit=True)
    return {"status": "created"}

@app.delete("/api/auth/users/{name}")
async def delete_user(name: str, request: Request):
    await require_admin(request)
    if name == "admin": raise HTTPException(status_code=400)
    await run_query('DELETE FROM users WHERE name = ?', (name,), commit=True)
    return {"status": "deleted"}

# ── GET service registry (used by user index.html) ──────────────────────────
@app.get("/api/registry")
async def get_registry(request: Request):
    token = request.headers.get("X-Auth-Token")
    user = await get_token_user_async(token) if token else None
    rows = await run_query('SELECT * FROM services_registry WHERE is_active = 1', fetch_all=True)
    result = []
    for svc in rows:
        svc = dict(svc)
        if user:
            if user["role"] == "admin":
                svc["user_access"] = "admin"
            elif svc["mode"] == "public":
                svc["user_access"] = "allowed"
            elif svc["mode"] == "private":
                access = await run_query(
                    'SELECT 1 FROM service_access_users WHERE service_name=? AND user_name=?',
                    (svc["name"], user["name"]), fetch_one=True)
                svc["user_access"] = "allowed" if access else "denied"
            elif svc["mode"] == "protected":
                access = await run_query(
                    'SELECT 1 FROM service_access_users WHERE service_name=? AND user_name=?',
                    (svc["name"], user["name"]), fetch_one=True)
                if access:
                    svc["user_access"] = "allowed"
                else:
                    pending = await run_query(
                        'SELECT 1 FROM access_requests WHERE service_name=? AND user_name=? AND status="pending"',
                        (svc["name"], user["name"]), fetch_one=True)
                    svc["user_access"] = "pending" if pending else "denied"
            else:
                svc["user_access"] = "denied"
        else:
            svc["user_access"] = "denied" if svc["mode"] != "public" else "allowed"
        result.append(svc)
    return result

# ── POST provision new service (admin) ──────────────────────────────────────
@app.post("/api/services")
async def create_service(body: CreateServiceRequest, request: Request):
    await require_admin(request)
    existing = await run_query('SELECT 1 FROM services_registry WHERE name=?', (body.name,), fetch_one=True)
    if existing:
        raise HTTPException(status_code=409, detail="Service already exists")
    await run_query(
        'INSERT INTO services_registry (name, is_active, mode) VALUES (?, 1, ?)',
        (body.name, body.mode), commit=True)
    if body.mode == "private" and body.allowed_users:
        for uname in body.allowed_users:
            await run_query(
                'INSERT OR IGNORE INTO service_access_users (service_name, user_name) VALUES (?,?)',
                (body.name, uname), commit=True)
    await write_log_async("admin", "admin", "INFO", f"Service provisioned: {body.name} ({body.mode})")
    return {"status": "created"}

import subprocess
import os
import sys

# ── POST register node manually (admin) ─────────────────────────────────────
@app.post("/api/nodes/register")
async def register_node_manual(body: RegisterNodeRequest, request: Request):
    await require_admin(request)
    now = time.time()
    existing = await run_query('SELECT 1 FROM node_registry WHERE node_id=?', (body.node_id,), fetch_one=True)
    if existing:
        raise HTTPException(status_code=409, detail="Node already registered")
    
    # Register the node slot
    await run_query(
        'INSERT INTO node_registry (node_id, priority, created_at, last_seen, node_status) VALUES (?,?,?,?,?)',
        (body.node_id, body.priority, now, now, 'enabled'), commit=True)
    
    # Actually launch the process in the background so it comes online instantly!
    try:
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agents", "simulator.py")
        subprocess.Popen([sys.executable, script_path, body.node_id, str(body.priority)])
    except Exception as e:
        print(f"Failed to launch simulator process: {e}")
        
    return {"status": "registered"}

# ── POST start session (user) ────────────────────────────────────────────────
@app.post("/api/sessions/start")
async def start_session(body: SessionStartRequest, request: Request):
    user = await require_auth(request)
    svc = await run_query('SELECT * FROM services_registry WHERE name=? AND is_active=1', (body.service_name,), fetch_one=True)
    if not svc:
        raise HTTPException(status_code=404, detail="Service not found or offline")
    # Check access
    svc = dict(svc)
    if svc["mode"] == "private" or svc["mode"] == "protected":
        if user["role"] != "admin":
            access = await run_query(
                'SELECT 1 FROM service_access_users WHERE service_name=? AND user_name=?',
                (body.service_name, user["name"]), fetch_one=True)
            if not access:
                raise HTTPException(status_code=403, detail="Access not granted")
    session_id = str(uuid.uuid4())
    start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    await run_query(
        'INSERT INTO sessions (id, user_name, service_name, start_time, is_active) VALUES (?,?,?,?,1)',
        (session_id, user["name"], body.service_name, start_time), commit=True)
    await write_log_async(body.service_name, user["name"], "INFO", f"Session started")
    return {"session_id": session_id, "service_name": body.service_name}

# ── POST stop session (user) ─────────────────────────────────────────────────
@app.post("/api/sessions/stop")
async def stop_session(body: SessionStopRequest, request: Request):
    user = await require_auth(request)
    row = await run_query('SELECT * FROM sessions WHERE id=? AND is_active=1', (body.session_id,), fetch_one=True)
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    row = dict(row)
    if row["user_name"] != user["name"] and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not your session")
    end = datetime.datetime.now(datetime.timezone.utc).isoformat()
    await run_query('UPDATE sessions SET end_time=?, is_active=0 WHERE id=?', (end, body.session_id), commit=True)
    await write_log_async(row["service_name"], user["name"], "INFO", f"Session terminated")
    return {"status": "stopped"}

# ── POST request access to protected/private service (user) ──────────────────
@app.post("/api/requests")
async def request_access(body: RequestAccessRequest, request: Request):
    user = await require_auth(request)
    svc = await run_query('SELECT 1 FROM services_registry WHERE name=?', (body.service_name,), fetch_one=True)
    if not svc:
        raise HTTPException(status_code=404, detail="Service not found")
    # Avoid duplicate pending requests
    existing = await run_query(
        'SELECT 1 FROM access_requests WHERE user_name=? AND service_name=? AND status="pending"',
        (user["name"], body.service_name), fetch_one=True)
    if existing:
        return {"status": "already_pending"}
    req_id = str(uuid.uuid4())
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    await run_query(
        'INSERT INTO access_requests (id, user_name, service_name, status, timestamp) VALUES (?,?,?,?,?)',
        (req_id, user["name"], body.service_name, "pending", ts), commit=True)
    await write_log_async(body.service_name, user["name"], "INFO", f"Access requested")
    return {"status": "pending", "id": req_id}

@app.on_event("startup")
async def node_rehydration():
    """
    On server boot, re-spawn simulator processes for all nodes 
    that were previously marked as 'enabled' in the database.
    """
    print("🚀 [System] Initializing distributed node rehydration...")
    enabled_nodes = await run_query("SELECT node_id, priority FROM node_registry WHERE node_status = 'enabled'", fetch_all=True)
    
    if not enabled_nodes:
        print("ℹ️ [System] No enabled nodes found in registry. Skipping rehydration.")
        return

    script_path = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agents", "simulator.py"))
    
    spawn_count = 0
    for node in enabled_nodes:
        try:
            # Re-spawn the process safely
            subprocess.Popen([sys.executable, script_path, node["node_id"], str(node["priority"])])
            spawn_count += 1
        except Exception as e:
            print(f"❌ [System] Failed to rehydrate node {node['node_id']}: {e}")

    print(f"✅ [System] Rehydrated {spawn_count} nodes into the cluster cluster.")

app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dashboard", "static"), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
