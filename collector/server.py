from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import sqlite3
import datetime
import os
import time
import asyncio
import uuid
import hashlib
import secrets
from typing import Optional, List

app = FastAPI(title="Access-Controlled Log Monitor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.getenv("DB_PATH", "logs.db")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    cursor = conn.cursor()

    # Logs table (preserved)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            service_name TEXT,
            host_id TEXT,
            severity TEXT,
            message TEXT,
            request_id TEXT,
            user_tag TEXT
        )
    ''')
    
    # Existing tables from monitoring
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS failure_detectors (
            service_name TEXT PRIMARY KEY,
            status TEXT,
            last_heartbeat TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alert_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT,
            service_name TEXT,
            status TEXT,
            message TEXT
        )
    ''')

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'user',
            password_hash TEXT
        )
    ''')

    # Sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_name TEXT NOT NULL,
            service_name TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT,
            is_active INTEGER DEFAULT 1
        )
    ''')

    # Service registry with access mode
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS services_registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            is_active INTEGER DEFAULT 1,
            mode TEXT DEFAULT 'public'
        )
    ''')

    # ── MIGRATIONS ──
    try:
        cursor.execute("ALTER TABLE services_registry ADD COLUMN mode TEXT DEFAULT 'public'")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Private service allowed users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS service_access_users (
            service_name TEXT NOT NULL,
            user_name TEXT NOT NULL,
            PRIMARY KEY (service_name, user_name)
        )
    ''')

    # Access requests (for protected services)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_requests (
            id TEXT PRIMARY KEY,
            user_name TEXT NOT NULL,
            service_name TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            timestamp TEXT NOT NULL
        )
    ''')

    # Persistent auth tokens (survive server restarts)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            user_name TEXT NOT NULL,
            role TEXT NOT NULL,
            expires REAL NOT NULL
        )
    ''')
    # Clean up expired tokens on startup
    cursor.execute('DELETE FROM tokens WHERE expires < ?', (time.time(),))

    # Distributed Leader Election Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS leader_election (
            id INTEGER PRIMARY KEY,
            leader_id TEXT,
            expires REAL,
            force_crash INTEGER DEFAULT 0
        )
    ''')
    try:
        cursor.execute("ALTER TABLE leader_election ADD COLUMN force_crash INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    cursor.execute('SELECT COUNT(*) FROM leader_election')
    if cursor.fetchone()[0] == 0:
        cursor.execute('INSERT INTO leader_election (id, leader_id, expires, force_crash) VALUES (1, NULL, 0, 0)')

    # Node Registry for Priority & Tenure
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS node_registry (
            node_id TEXT PRIMARY KEY,
            priority INTEGER DEFAULT 0,
            created_at REAL,
            last_seen REAL,
            node_status TEXT DEFAULT 'enabled'
        )
    ''')
    # Migration: add node_status if upgrading from older schema
    try:
        cursor.execute("ALTER TABLE node_registry ADD COLUMN node_status TEXT DEFAULT 'enabled'")
        conn.commit()
    except sqlite3.OperationalError:
        pass


    # Seed admin user
    pw_hash = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    cursor.execute('''
        INSERT OR IGNORE INTO users (name, role, password_hash) VALUES (?, ?, ?)
    ''', ("admin", "admin", pw_hash))

    # Seed demo users
    for name in ["Alice", "Bob", "Charlie"]:
        cursor.execute('INSERT OR IGNORE INTO users (name, role) VALUES (?, ?)', (name, "user"))

    # Seed default services if empty
    cursor.execute('SELECT COUNT(*) FROM services_registry')
    if cursor.fetchone()[0] == 0:
        default_services = [
            ("file-server", "public"),
            ("data-vault", "private"),
            ("ml-pipeline", "protected"),
            ("auth-service", "public"),
            ("payment-service", "protected"),
        ]
        for svc_name, mode in default_services:
            cursor.execute('INSERT INTO services_registry (name, is_active, mode) VALUES (?, 1, ?)', (svc_name, mode))
        # Alice gets access to data-vault
        cursor.execute('INSERT OR IGNORE INTO service_access_users (service_name, user_name) VALUES (?, ?)', ("data-vault", "Alice"))

    conn.commit()
    conn.close()

init_db()

# -----------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------
def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def write_log(service_name: str, user_name: str, severity: str, message: str):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (timestamp, service_name, host_id, severity, message, request_id, user_tag)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.datetime.now(datetime.timezone.utc).isoformat(),
        service_name, "browser-client", severity, message,
        f"req-{uuid.uuid4().hex[:8]}", user_name
    ))
    conn.commit()
    conn.close()

def get_token_user(token: str):
    """Look up token in the DB (survives restarts)."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tokens WHERE token=?', (token,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    if row['expires'] < time.time():
        # Clean up expired token
        conn2 = sqlite3.connect(DB_PATH, timeout=10)
        conn2.execute('DELETE FROM tokens WHERE token=?', (token,))
        conn2.commit()
        conn2.close()
        return None
    return {"name": row["user_name"], "role": row["role"], "expires": row["expires"]}

def save_token(token: str, name: str, role: str, expires: float):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute('INSERT OR REPLACE INTO tokens (token, user_name, role, expires) VALUES (?,?,?,?)',
                 (token, name, role, expires))
    conn.commit()
    conn.close()

def delete_token(token: str):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute('DELETE FROM tokens WHERE token=?', (token,))
    conn.commit()
    conn.close()

def require_auth(request: Request):
    token = request.headers.get("X-Auth-Token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing auth token")
    user = get_token_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user

def require_admin(request: Request):
    user = require_auth(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
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

class ElectRequest(BaseModel):
    node_id: str
    priority: int = 0
    mode: str = "public"
    allowed_users: Optional[List[str]] = []

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
# AUTH ENDPOINTS
# -----------------------------------------------------------------
@app.post("/api/auth/login")
async def login(body: LoginRequest):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE name = ?', (body.name,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    role = user["role"]

    if role == "admin":
        if not body.password:
            raise HTTPException(status_code=401, detail="Admin requires password")
        if hash_password(body.password) != user["password_hash"]:
            raise HTTPException(status_code=401, detail="Invalid password")

    token = secrets.token_hex(24)
    expires = time.time() + 8 * 3600
    save_token(token, body.name, role, expires)

    write_log("auth-service", body.name, "INFO", f"User '{body.name}' ({role}) logged in")
    return {"token": token, "name": body.name, "role": role}

@app.post("/api/auth/logout")
async def logout(request: Request):
    token = request.headers.get("X-Auth-Token")
    user = require_auth(request)
    if token:
        delete_token(token)
    write_log("auth-service", user["name"], "INFO", f"User '{user['name']}' logged out")
    return {"status": "logged out"}

@app.get("/api/auth/me")
async def get_me(request: Request):
    user = require_auth(request)
    return {"name": user["name"], "role": user["role"]}

@app.get("/api/auth/users")
async def list_users(request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, role FROM users ORDER BY role, name')
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/auth/users")
async def create_user(body: CreateUserRequest, request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (name, role) VALUES (?, ?)', (body.name, body.role))
        conn.commit()
    except Exception:
        raise HTTPException(status_code=400, detail="User already exists")
    finally:
        conn.close()
    return {"status": "created"}

@app.delete("/api/auth/users/{name}")
async def delete_user(name: str, request: Request):
    require_admin(request)
    if name == "admin": raise HTTPException(status_code=400, detail="Cannot delete admin")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE name = ?', (name,))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

# -----------------------------------------------------------------
# SESSIONS
# -----------------------------------------------------------------
@app.get("/api/sessions/active")
async def get_active_sessions(request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM sessions WHERE is_active = 1')
    rows = cursor.fetchall()
    conn.close()
    
    sessions = []
    for r in rows:
        d = dict(r)
        start = datetime.datetime.fromisoformat(d["start_time"])
        d["duration_seconds"] = int((datetime.datetime.now() - start).total_seconds())
        sessions.append(d)
    return sessions

@app.post("/api/sessions/start")
async def start_session(body: SessionStartRequest, request: Request):
    user = require_auth(request)
    
    # Check access permission
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT mode FROM services_registry WHERE name = ?', (body.service_name,))
    svc = cursor.fetchone()
    
    if not svc:
        conn.close()
        raise HTTPException(status_code=404, detail="Service not found")
        
    mode = svc["mode"]
    if mode == "private":
        cursor.execute('SELECT 1 FROM service_access_users WHERE service_name = ? AND user_name = ?',
                    (body.service_name, user["name"]))
        if not cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=403, detail="Access denied (Private service)")
    elif mode == "protected":
        # Protected services require admin approval
        cursor.execute('SELECT 1 FROM service_access_users WHERE service_name = ? AND user_name = ?',
                    (body.service_name, user["name"]))
        if not cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=403, detail="Access denied (Needs approval)")

    session_id = uuid.uuid4().hex
    start_time = datetime.datetime.now().isoformat()
    cursor.execute('''
        INSERT INTO sessions (id, user_name, service_name, start_time)
        VALUES (?, ?, ?, ?)
    ''', (session_id, user["name"], body.service_name, start_time))
    conn.commit()
    conn.close()
    
    write_log(body.service_name, user["name"], "INFO", f"Access session started")
    return {"session_id": session_id}

@app.post("/api/sessions/stop")
async def stop_session(body: SessionStopRequest, request: Request):
    user = require_auth(request)
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM sessions WHERE id = ?', (body.session_id,))
    session = cursor.fetchone()
    if not session:
        conn.close()
        raise HTTPException(status_code=404, detail="Session not found")
        
    if session["user_name"] != user["name"] and user["role"] != "admin":
        conn.close()
        raise HTTPException(status_code=403, detail="Forbidden")

    end_time = datetime.datetime.now().isoformat()
    cursor.execute('UPDATE sessions SET end_time = ?, is_active = 0 WHERE id = ?', (end_time, body.session_id))
    conn.commit()
    conn.close()
    
    write_log(session["service_name"], session["user_name"], "INFO", f"Access session terminated")
    return {"status": "stopped"}

@app.post("/api/sessions/kick/{session_id}")
async def kick_session(session_id: str, request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM sessions WHERE id = ?', (session_id,))
    session = cursor.fetchone()
    if session:
        end_time = datetime.datetime.now().isoformat()
        cursor.execute('UPDATE sessions SET end_time = ?, is_active = 0 WHERE id = ?', (end_time, session_id))
        conn.commit()
        write_log(session["service_name"], session["user_name"], "WARNING", f"Session terminated by Administrator")
    conn.close()
    return {"status": "kicked"}

# -----------------------------------------------------------------
# SERVICE REGISTRY
# -----------------------------------------------------------------
@app.get("/api/registry")
async def list_registry(request: Request):
    user = require_auth(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM services_registry')
    services = [dict(r) for r in cursor.fetchall()]
    
    # Enrich with allowed users for admin, and check access for user
    for svc in services:
        cursor.execute('SELECT user_name FROM service_access_users WHERE service_name = ?', (svc["name"],))
        svc["allowed_users"] = [r["user_name"] for r in cursor.fetchall()]
        
        # Determine current user access state
        if svc["mode"] == "public": svc["user_access"] = "allowed"
        elif user["role"] == "admin": svc["user_access"] = "admin"
        elif user["name"] in svc["allowed_users"]: svc["user_access"] = "allowed"
        else:
            cursor.execute('SELECT status FROM access_requests WHERE service_name = ? AND user_name = ?',
                        (svc["name"], user["name"]))
            req = cursor.fetchone()
            svc["user_access"] = req["status"] if req else "denied"
            
    conn.close()
    return services

@app.post("/api/registry")
async def create_registry_service(body: CreateServiceRequest, request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO services_registry (name, mode) VALUES (?, ?)', (body.name, body.mode))
        for uname in body.allowed_users:
            cursor.execute('INSERT INTO service_access_users (service_name, user_name) VALUES (?, ?)', (body.name, uname))
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()
    return {"status": "provisioned"}

@app.post("/api/registry/{name}/toggle")
async def toggle_service(name: str, request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE services_registry SET is_active = 1 - is_active WHERE name = ?', (name,))
    conn.commit()
    conn.close()
    return {"status": "toggled"}

@app.delete("/api/registry/{name}")
async def delete_service(name: str, request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM services_registry WHERE name = ?', (name,))
    cursor.execute('DELETE FROM service_access_users WHERE service_name = ?', (name,))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

@app.post("/api/registry/{name}/users/{uname}")
async def add_allowed_user(name: str, uname: str, request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO service_access_users (service_name, user_name) VALUES (?, ?)', (name, uname))
    conn.commit()
    conn.close()
    return {"status": "added"}

@app.delete("/api/registry/{name}/users/{uname}")
async def remove_allowed_user(name: str, uname: str, request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM service_access_users WHERE service_name = ? AND user_name = ?', (name, uname))
    conn.commit()
    conn.close()
    return {"status": "removed"}

# -----------------------------------------------------------------
# ACCESS REQUESTS
# -----------------------------------------------------------------
@app.get("/api/requests")
async def list_requests(request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM access_requests WHERE status = "pending"')
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/requests")
async def request_access(body: RequestAccessRequest, request: Request):
    user = require_auth(request)
    conn = get_db()
    cursor = conn.cursor()
    rid = uuid.uuid4().hex
    ts = datetime.datetime.now().isoformat()
    cursor.execute('''
        INSERT OR REPLACE INTO access_requests (id, user_name, service_name, status, timestamp)
        VALUES (?, ?, ?, "pending", ?)
    ''', (rid, user["name"], body.service_name, ts))
    conn.commit()
    conn.close()
    write_log(body.service_name, user["name"], "WARNING", "System access requested")
    return {"status": "pending", "request_id": rid}

@app.post("/api/requests/{id}/approve")
async def approve_request(id: str, request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM access_requests WHERE id = ?', (id,))
    req = cursor.fetchone()
    if req:
        cursor.execute('UPDATE access_requests SET status = "approved" WHERE id = ?', (id,))
        cursor.execute('INSERT OR IGNORE INTO service_access_users (service_name, user_name) VALUES (?, ?)',
                    (req["service_name"], req["user_name"]))
        conn.commit()
        write_log(req["service_name"], req["user_name"], "INFO", "System access approved by Admin")
    conn.close()
    return {"status": "approved"}

@app.post("/api/requests/{id}/deny")
async def deny_request(id: str, request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM access_requests WHERE id = ?', (id,))
    req = cursor.fetchone()
    if req:
        cursor.execute('UPDATE access_requests SET status = "denied" WHERE id = ?', (id,))
        conn.commit()
        write_log(req["service_name"], req["user_name"], "WARNING", "System access denied by Admin")
    conn.close()
    return {"status": "denied"}

# -----------------------------------------------------------------
# LOGS & METRICS
# -----------------------------------------------------------------
@app.get("/api/logs/recent")
async def get_recent_logs(request: Request, limit: int = 200):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/metrics")
async def get_metrics(request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    last_min = (datetime.datetime.now() - datetime.timedelta(minutes=1)).isoformat()
    cursor.execute('SELECT COUNT(*) FROM logs WHERE timestamp > ?', (last_min,))
    lps = cursor.fetchone()[0] / 60.0
    cursor.execute('SELECT COUNT(*) FROM logs WHERE timestamp > ? AND severity = "ERROR"', (last_min,))
    errs = cursor.fetchone()[0]
    conn.close()
    return {"logs_per_second": round(lps, 2), "error_count_60s": errs}

@app.post("/api/heartbeat")
async def heartbeat(request: Request):
    """Update failure detector with latest service heartbeat."""
    data = await request.json()
    svc = data.get("service_name")
    host = data.get("host_id")
    status = data.get("status", "active")
    
    if not svc:
        return {"status": "error", "message": "Missing service_name"}

    conn = get_db()
    cursor = conn.cursor()
    
    # Check current status in DB
    cursor.execute('SELECT status FROM failure_detectors WHERE service_name = ?', (svc,))
    row = cursor.fetchone()
    
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute('''
        INSERT OR REPLACE INTO failure_detectors (service_name, status, last_heartbeat)
        VALUES (?, ?, ?)
    ''', (svc, status, ts))
    
    # Log if it's a new or changed status
    if not row or row['status'] != status:
        write_log(svc, host, "INFO" if status == "active" else "WARNING", 
                  f"Service status changed to {status} via host {host}")
    
    conn.commit()
    conn.close()
    return {"status": "ok"}

# -----------------------------------------------------------------
# LEADER ELECTION
# -----------------------------------------------------------------
@app.get("/api/nodes")
async def list_nodes(request: Request):
    """Admin-only: list all known nodes and their metrics."""
    require_admin(request)
    now = time.time()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM node_registry ORDER BY priority DESC, created_at ASC')
    rows = cursor.fetchall()
    conn.close()
    
    nodes = []
    for r in rows:
        d = dict(r)
        d["is_active"] = (now - d["last_seen"]) < 15 if d["last_seen"] else False
        d["node_status"] = d.get("node_status", "enabled")
        nodes.append(d)
    return nodes

@app.post("/api/nodes")
async def register_node(body: RegisterNodeRequest, request: Request):
    """Admin-only: pre-register a node in the registry."""
    require_admin(request)
    now = time.time()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT node_id FROM node_registry WHERE node_id = ?', (body.node_id,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Node ID already exists")
    cursor.execute(
        'INSERT INTO node_registry (node_id, priority, created_at, last_seen, node_status) VALUES (?, ?, ?, ?, ?)',
        (body.node_id, body.priority, now, 0, 'enabled')
    )
    conn.commit()
    conn.close()
    write_log("admin-console", "admin", "INFO",
              f"Node [{body.node_id}] pre-registered by admin (priority={body.priority}).")
    return {"status": "registered", "node_id": body.node_id}

@app.post("/api/nodes/{node_id}/enable")
async def enable_node(node_id: str, request: Request):
    """Admin-only: mark a node as enabled so it can participate in elections."""
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT node_id FROM node_registry WHERE node_id = ?', (node_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Node not found")
    cursor.execute("UPDATE node_registry SET node_status = 'enabled' WHERE node_id = ?", (node_id,))
    conn.commit()
    conn.close()
    write_log("admin-console", "admin", "INFO",
              f"Node [{node_id}] re-enabled by admin — eligible for election.")
    return {"status": "enabled", "node_id": node_id}

@app.post("/api/nodes/{node_id}/disable")
async def disable_node(node_id: str, request: Request):
    """Admin-only: mark a node as disabled so it cannot win elections."""
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT node_id FROM node_registry WHERE node_id = ?', (node_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Node not found")
    cursor.execute("UPDATE node_registry SET node_status = 'disabled' WHERE node_id = ?", (node_id,))
    conn.commit()
    conn.close()
    write_log("admin-console", "admin", "WARNING",
              f"Node [{node_id}] disabled by admin — excluded from elections.")
    return {"status": "disabled", "node_id": node_id}

@app.post("/api/leader/elect")
async def leader_elect(body: ElectRequest):
    """Distributed nodes call this to acquire/renew leadership lease with priority/tenure."""
    now = time.time()
    conn = get_db()
    cursor = conn.cursor()
    
    # 0. Register/Update node in node_registry
    cursor.execute('SELECT created_at, node_status FROM node_registry WHERE node_id = ?', (body.node_id,))
    row = cursor.fetchone()
    if not row:
        created_at = now
        cursor.execute(
            'INSERT INTO node_registry (node_id, priority, created_at, last_seen, node_status) VALUES (?, ?, ?, ?, ?)',
            (body.node_id, body.priority, created_at, now, 'enabled')
        )
    else:
        created_at = row['created_at']
        node_status = row['node_status']
        # If the node is disabled (was crashed), do NOT update last_seen so it stays invisible
        # but still allow it to update its priority for when it gets re-enabled
        if node_status == 'disabled':
            # Node was force-crashed — tell it to stay down
            conn.commit()
            conn.close()
            return {"status": "disabled", "message": "Node is disabled by admin. Re-enable via Node Manager to rejoin."}
        cursor.execute('UPDATE node_registry SET priority = ?, last_seen = ? WHERE node_id = ?',
                       (body.priority, now, body.node_id))
    
    # 1. Check for force_crash
    cursor.execute('SELECT leader_id, force_crash FROM leader_election WHERE id = 1')
    row = cursor.fetchone()
    
    if row and row['leader_id'] == body.node_id and row['force_crash'] == 1:
        # Disable the node so it can't immediately re-win the election
        cursor.execute("UPDATE node_registry SET node_status = 'disabled' WHERE node_id = ?", (body.node_id,))
        cursor.execute('UPDATE leader_election SET leader_id = NULL, force_crash = 0 WHERE id = 1')
        conn.commit()
        conn.close()
        write_log("platform-coordinator", body.node_id, "CRITICAL",
                  f"Node [{body.node_id}] force-crashed by admin — marked disabled. Admin must re-enable via Node Manager.")
        return {"status": "crashed"}

    # 2. Check current leader status
    cursor.execute('SELECT leader_id, expires FROM leader_election WHERE id = 1')
    row = cursor.fetchone()
    current_leader = row['leader_id']
    expires = row['expires']
    
    # If there's an active leader who is NOT this node, check if we should even consider election
    if current_leader and expires > now and current_leader != body.node_id:
        # Check if the current leader is still active, enabled, and in node_registry
        cursor.execute("SELECT last_seen, node_status FROM node_registry WHERE node_id = ?", (current_leader,))
        l_row = cursor.fetchone()
        if l_row and (now - l_row['last_seen']) < 15 and l_row['node_status'] == 'enabled':
            conn.commit()
            conn.close()
            return {"status": "standby", "leader_id": current_leader}

    # 3. If we are here, we need an election (old leader expired / crashed / gone)
    # Find the BEST candidate among active nodes that are ENABLED
    cursor.execute(
        "SELECT * FROM node_registry WHERE last_seen > ? AND node_status = 'enabled' ORDER BY priority DESC, created_at ASC",
        (now - 15,)
    )
    candidates = cursor.fetchall()
    
    if not candidates:
        conn.commit()
        conn.close()
        return {"status": "standby", "leader_id": None}
    
    best_candidate = candidates[0]['node_id']
    
    if best_candidate == body.node_id:
        status = "acquired" if current_leader != body.node_id else "renewed"
        new_expires = now + 15
        cursor.execute('UPDATE leader_election SET leader_id = ?, expires = ?, force_crash = 0 WHERE id = 1',
                       (body.node_id, new_expires))
        conn.commit()
        conn.close()
        return {
            "status": status, 
            "leader_id": body.node_id, 
            "expires": new_expires,
            "candidates": [dict(c) for c in candidates]
        }
    else:
        conn.commit()
        conn.close()
        return {
            "status": "standby", 
            "leader_id": best_candidate,
            "candidates": [dict(c) for c in candidates]
        }

@app.post("/api/leader/crash")
async def leader_crash(request: Request):
    """Admin-only: signal current leader to crash upon next renewal."""
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE leader_election SET force_crash = 1 WHERE id = 1')
    conn.commit()
    conn.close()
    write_log("admin-console", "admin", "WARNING", "Sent CRASH signal to current distributed leader.")
    return {"status": "crash_signal_set"}

@app.get("/api/leader/current")
async def get_current_leader():
    """Returns the current elected leader and whether it is still alive."""
    now = time.time()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT leader_id, expires FROM leader_election WHERE id = 1')
    row = cursor.fetchone()
    if not row or not row['leader_id']:
        conn.close()
        return {"leader_id": None, "is_alive": False, "expires": None}

    leader_id = row['leader_id']
    expires = row['expires']

    # Cross-check with node_registry last_seen
    cursor.execute('SELECT last_seen FROM node_registry WHERE node_id = ?', (leader_id,))
    n_row = cursor.fetchone()
    conn.close()

    is_alive = bool(
        n_row and
        (now - n_row['last_seen']) < 15 and
        expires > now
    )
    return {
        "leader_id": leader_id,
        "is_alive": is_alive,
        "expires": expires,
        "expires_in": max(0, round(expires - now, 1))
    }

@app.patch("/api/nodes/{node_id}/priority")
async def update_node_priority(node_id: str, body: PriorityUpdateRequest, request: Request):
    """Admin-only: update a node's election priority. Takes effect on the next heartbeat cycle."""
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT node_id FROM node_registry WHERE node_id = ?', (node_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Node not found")
    cursor.execute('UPDATE node_registry SET priority = ? WHERE node_id = ?', (body.priority, node_id))
    conn.commit()
    conn.close()
    write_log("admin-console", "admin", "INFO",
              f"Node [{node_id}] priority updated to {body.priority} by admin.")
    return {"status": "updated", "node_id": node_id, "priority": body.priority}

@app.delete("/api/nodes/{node_id}")
async def delete_node(node_id: str, request: Request):
    """Admin-only: remove a node from the registry (for stale/offline nodes)."""
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    # Don't allow removing an active node silently — check last_seen
    cursor.execute('SELECT last_seen FROM node_registry WHERE node_id = ?', (node_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Node not found")
    cursor.execute('DELETE FROM node_registry WHERE node_id = ?', (node_id,))
    conn.commit()
    conn.close()
    write_log("admin-console", "admin", "WARNING",
              f"Node [{node_id}] removed from registry by admin.")
    return {"status": "removed", "node_id": node_id}

# -----------------------------------------------------------------
# SERVE DASHBOARDS
# -----------------------------------------------------------------
app.mount("/", StaticFiles(directory="dashboard/static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
