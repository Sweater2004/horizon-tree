import os
import sys
import json
import uuid
import secrets
import threading
import time
from datetime import datetime, timedelta
from typing import List, Optional, Dict

import bcrypt
import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import uvicorn
ACTIVE_MAP_ID = None  # ID карты, которая сейчас открыта в UI


def print_error(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs, flush=True)

def get_base_dir() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_base_dir()
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

from db_conn import DB_PATH, get_db, db_connection, db_write, execute_write


SECRET_KEY = os.getenv("JWT_SECRET", "horizon-tree-v5-dev-secret-key-change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(title="Horizon Tree v5.0")
@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# ============================================================
# БАЗА ДАННЫХ
# ============================================================

def init_db():
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer',
            is_active INTEGER DEFAULT 1, created_at TEXT, updated_at TEXT,
            last_login TEXT, last_ip TEXT, ip_whitelist TEXT
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS network_maps(
            id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT,
            owner_id TEXT NOT NULL, is_public INTEGER DEFAULT 0,
            created_at TEXT, updated_at TEXT, data TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS map_collaborators(
            id INTEGER PRIMARY KEY AUTOINCREMENT, map_id TEXT NOT NULL,
            user_id TEXT NOT NULL, permissions TEXT DEFAULT 'view', added_at TEXT,
            FOREIGN KEY(map_id) REFERENCES network_maps(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(map_id, user_id)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, action TEXT,
            details TEXT, ip_address TEXT, created_at TEXT
        )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_maps_owner ON network_maps(owner_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_collab_user ON map_collaborators(user_id)")

    from db.migrations import migrate_v5, migrate_v6
    with db_write() as conn:
        migrate_v5(conn)
    with db_write() as conn:
        migrate_v6(conn)

init_db()

# ============================================================
# УТИЛИТЫ
# ============================================================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

# ============================================================
# ПОЛЬЗОВАТЕЛИ
# ============================================================

def get_user_from_db(user_id: str):
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, role, is_active, created_at, last_login FROM users WHERE id = ?", (user_id,))
        return cur.fetchone()

def get_user_from_request(request: Request) -> Optional[dict]:
    if hasattr(request.state, 'user') and request.state.user:
        return request.state.user
    token = request.headers.get("Authorization")
    if token and token.startswith("Bearer "):
        try:
            payload = decode_token(token[7:])
            user = get_user_from_db(payload.get('sub'))
            if user and user[3]:
                data = {"sub": user[0], "username": user[1], "role": user[2], "is_active": bool(user[3])}
                request.state.user = data
                return data
        except Exception:
            pass
    return None

def require_admin(request: Request) -> dict:
    user = get_user_from_request(request)
    if not user:
        raise HTTPException(401, "Требуется авторизация")
    if user.get('role') != 'admin':
        raise HTTPException(403, "Только администратор")
    return user

def check_user_permission(user_role: str, required_role: str) -> bool:
    roles = {'admin': 3, 'editor': 2, 'viewer': 1}
    return roles.get(user_role, 0) >= roles.get(required_role, 0)

def log_action(user_id: str, action: str, details: Optional[dict] = None, ip: Optional[str] = None):
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO audit_logs (user_id, action, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?)",
                    (user_id, action, json.dumps(details) if details else None, ip, datetime.now().isoformat()))

def init_admin_user():
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
        exists = cur.fetchone()
    if not exists:
        admin_password = secrets.token_urlsafe(12)
        admin_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        with db_write() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO users (id, username, password_hash, role, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (admin_id, 'admin', hash_password(admin_password), 'admin', 1, now, now))
        with open(os.path.join(BASE_DIR, 'admin_password.txt'), 'w', encoding='utf-8') as f:
            f.write(f"Login: admin\nPassword: {admin_password}\n")
        print("\n" + "=" * 60)
        print("🔑 АДМИНИСТРАТОР СОЗДАН")
        print("=" * 60)
        print(f"Логин: admin")
        print(f"Пароль: {admin_password}")
        print("=" * 60 + "\n")

init_admin_user()

# ============================================================
# MIDDLEWARE
# ============================================================

PUBLIC_PATHS = ["/api/auth/login", "/api/auth/logout", "/api/auth/me", "/health", "/login", "/static", "/favicon.ico", "/"]

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if any(path.startswith(p) for p in PUBLIC_PATHS):
        return await call_next(request)
    token = request.headers.get("Authorization")
    if not token or not token.startswith("Bearer "):
        return JSONResponse(401, {"detail": "Требуется авторизация", "code": "unauthorized"})
    try:
        payload = decode_token(token[7:])
        user = get_user_from_db(payload.get('sub'))
        if not user or not user[3]:
            return JSONResponse(403, {"detail": "Пользователь заблокирован", "code": "blocked"})
        request.state.user = payload
        return await call_next(request)
    except jwt.ExpiredSignatureError:
        return JSONResponse(401, {"detail": "Токен истек", "code": "token_expired"})
    except jwt.InvalidTokenError:
        return JSONResponse(401, {"detail": "Неверный токен", "code": "invalid_token"})

# ============================================================
# МОДЕЛИ
# ============================================================

class LoginRequest(BaseModel):
    username: str
    password: str

class MapCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    is_public: bool = False
    allowed_subnets: Optional[List[str]] = None
    data: Optional[dict] = None
class CompositeMapCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    source_map_ids: List[str]  # ID карт, которые объединяем
    root_map_id: str  # ID карты, которая будет корнем (её корневой узел = общий)

class CompositeLink(BaseModel):
    source_map_id: str
    target_map_id: str
    source_root_node_id: str
    target_root_node_id: str
    link_type: str = "cable"  # cable / fiber / radio
    note: Optional[str] = None

@app.post("/api/maps/composite")
async def create_composite_map(data: CompositeMapCreate, request: Request):
    """Создать карту-композицию (объединение готовых карт)."""
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")
    
    map_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    
    # Загружаем все карты-источники
    source_maps = []
    with db_connection() as conn:
        cur = conn.cursor()
        for sid in data.source_map_ids:
            cur.execute("SELECT id, name, data FROM network_maps WHERE id = ?", (sid,))
            r = cur.fetchone()
            if not r:
                raise HTTPException(404, f"Карта {sid} не найдена")
            source_maps.append({
                "id": r[0],
                "name": r[1],
                "data": json.loads(r[2])
            })
    
    # Строим композицию
    composite_nodes = []
    composite_edges = []
    
    for sm in source_maps:
        sm_id = sm["id"]
        sm_name = sm["name"]
        sm_data = sm["data"]
        nodes = sm_data.get("nodes", [])
        
        if not nodes:
            continue
        
        # Ищем корневой узел (is_root=True) или первый
        root_node = next((n for n in nodes if n.get("is_root")), nodes[0])
        root_id = root_node["id"]
        
        # Считаем устройства (узлы) и коммутаторы (не root, type=switch)
        total_devices = len(nodes)
        switch_count = sum(1 for n in nodes if n.get("type") == "switch")
        
        # Создаём узел-контейнер для карты
        container_id = f"composite-{sm_id}"
        composite_nodes.append({
            "id": container_id,
            "ip": "",
            "name": sm_name,
            "type": "composite",
            "is_composite": True,
            "composite_map_id": sm_id,
            "metadata": {
                "total_devices": total_devices,
                "switch_count": switch_count,
                "root_node_id": root_id,
                "root_node_ip": root_node.get("ip"),
                "root_node_name": root_node.get("name"),
                "access_level": "owner"  # упрощённо
            },
            "parent_id": None,
            "hops_from_root": 0,
            "is_root": (sm_id == data.root_map_id),
            "checks": [],
            "status": {},
            "aggregated_status": "unknown",
            "is_outside_whitelist": False,
            "created_at": now,
            "updated_at": now
        })
    
    # Создаём карту
    graph = {
        "nodes": composite_nodes,
        "edges": composite_edges,
        "settings": {"auto_refresh": False, "is_composite": True},
        "created_at": now,
        "updated_at": now
    }
    
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO network_maps
            (id, name, description, owner_id, is_public, created_at, updated_at,
             data, allowed_subnets, current_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            map_id, data.name, data.description or "", user_data['sub'],
            0, now, now,
            json.dumps(graph, ensure_ascii=False),
            json.dumps([], ensure_ascii=False),
            1
        ))
        cur.execute("""
            INSERT INTO map_versions (map_id, version, data, created_at, created_by, comment)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (map_id, 1, json.dumps(graph, ensure_ascii=False),
              now, user_data['sub'], "Создание композиции"))
    
    log_action(user_data['sub'], f"create_composite_{data.name}",
               {"map_id": map_id, "sources": data.source_map_ids},
               request.client.host if request.client else "unknown")
    
    return {"success": True, "map_id": map_id, "name": data.name}


@app.post("/api/maps/{map_id}/composite-link")
async def composite_link(map_id: str, data: CompositeLink, request: Request):
    """Связать два контейнера композиции (вручную)."""
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")
    
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT data FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        
        graph = json.loads(r[0])
        nodes = graph.get("nodes", [])
        
        source_container = next((n for n in nodes if n.get("composite_map_id") == data.source_map_id), None)
        target_container = next((n for n in nodes if n.get("composite_map_id") == data.target_map_id), None)
        
        if not source_container:
            raise HTTPException(404, "Source карта не найдена в композиции")
        if not target_container:
            raise HTTPException(404, "Target карта не найдена в композиции")
        
        now = datetime.now().isoformat()
        edge_id = f"composite-link-{data.source_map_id}-{data.target_map_id}"
        
        # Удаляем старую связь (если была)
        graph["edges"] = [e for e in graph.get("edges", []) if e.get("id") != edge_id]
        
        graph["edges"].append({
            "id": edge_id,
            "source": source_container["id"],
            "target": target_container["id"],
            "type": "composite-link",
            "link_type": data.link_type,
            "source_root_node_id": data.source_root_node_id,
            "target_root_node_id": data.target_root_node_id,
            "note": data.note or "",
            "created_at": now
        })
        
        # Связываем корни (target становится child source)
        target_container["parent_id"] = source_container["id"]
        target_container["is_root"] = False
        target_container["hops_from_root"] = (source_container.get("hops_from_root", 0) or 0) + 1
        target_container["updated_at"] = now
        
        graph["updated_at"] = now
        
        cur.execute("UPDATE network_maps SET data = ?, updated_at = ? WHERE id = ?",
                    (json.dumps(graph, ensure_ascii=False), now, map_id))
    
    return {"success": True, "edge_id": edge_id}

@app.post("/api/maps/{map_id}/composite-add")
async def add_map_to_composite(map_id: str, data: dict, request: Request):
    """Добавить карту в существующую композицию (вручную)."""
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")

    source_map_id = data.get("source_map_id")
    if not source_map_id:
        raise HTTPException(400, "Не указан source_map_id")

    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT data FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта-композиция не найдена")

        graph = json.loads(r[0])
        if not graph.get("settings", {}).get("is_composite"):
            raise HTTPException(400, "Это не композиция")

        # Проверяем, есть ли уже такая карта в композиции
        for n in graph.get("nodes", []):
            if n.get("composite_map_id") == source_map_id:
                raise HTTPException(400, "Эта карта уже есть в композиции")

        # Загружаем исходную карту, чтобы получить её метаданные
        cur.execute("SELECT id, name, data FROM network_maps WHERE id = ?", (source_map_id,))
        src_row = cur.fetchone()
        if not src_row:
            raise HTTPException(404, "Исходная карта не найдена")

        src_id, src_name, src_data_json = src_row
        src_data = json.loads(src_data_json)
        src_nodes = src_data.get("nodes", [])
        
        if not src_nodes:
            raise HTTPException(400, "Исходная карта пуста")

        root_node = next((n for n in src_nodes if n.get("is_root")), src_nodes[0])
        total_devices = len(src_nodes)
        switch_count = sum(1 for n in src_nodes if n.get("type") == "switch")

        now = datetime.now().isoformat()
        container_id = f"composite-{src_id}"

        # Создаём контейнер
        new_container = {
            "id": container_id,
            "ip": "",
            "name": src_name,
            "type": "composite",
            "is_composite": True,
            "composite_map_id": src_id,
            "metadata": {
                "total_devices": total_devices,
                "switch_count": switch_count,
                "root_node_id": root_node["id"],
                "root_node_ip": root_node.get("ip"),
                "root_node_name": root_node.get("name"),
                "access_level": "owner"
            },
            "parent_id": None,
            "hops_from_root": 0,
            "is_root": False,
            "checks": [],
            "status": {},
            "aggregated_status": "unknown",
            "is_outside_whitelist": False,
            "created_at": now,
            "updated_at": now
        }

        graph["nodes"].append(new_container)
        graph["updated_at"] = now

        cur.execute("UPDATE network_maps SET data = ?, updated_at = ? WHERE id = ?",
                    (json.dumps(graph, ensure_ascii=False), now, map_id))

    return {"success": True, "container_id": container_id}

@app.delete("/api/maps/{map_id}/composite-link/{edge_id}")
async def composite_link_delete(map_id: str, edge_id: str, request: Request):
    """Удалить ручную связь между контейнерами композиции."""
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")

    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT data FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")

        graph = json.loads(r[0])
        original_len = len(graph.get("edges", []))
        removed = None

        new_edges = []
        for e in graph.get("edges", []):
            if e.get("id") == edge_id and e.get("type") == "composite-link":
                removed = e
                continue
            new_edges.append(e)

        if removed is None:
            raise HTTPException(404, "Связь не найдена")

        graph["edges"] = new_edges

        # Разрываем parent_id у target-контейнера (если он был)
        target_container_id = removed.get("target")
        source_container_id = removed.get("source")
        for n in graph.get("nodes", []):
            if n.get("id") == target_container_id and n.get("parent_id") == source_container_id:
                n["parent_id"] = None
                n["is_root"] = True
                n["hops_from_root"] = 0
                n["updated_at"] = datetime.now().isoformat()
                break

        graph["updated_at"] = datetime.now().isoformat()
        cur.execute("UPDATE network_maps SET data = ?, updated_at = ? WHERE id = ?",
                    (json.dumps(graph, ensure_ascii=False), graph["updated_at"], map_id))

    return {"success": True, "edge_id": edge_id}

@app.get("/api/maps/composite-available")
async def list_available_for_composite(request: Request):
    """Список карт, доступных для композиции."""
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    
    user_id = user_data['sub']
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT nm.id, nm.name, nm.description, nm.data, nm.updated_at
            FROM network_maps nm
            WHERE nm.owner_id = ? OR nm.is_public = 1
            ORDER BY nm.updated_at DESC
        """, (user_id,))
        
        maps = []
        for r in cur.fetchall():
            data = json.loads(r[3])
            nodes = data.get("nodes", [])
            # Пропускаем композиции
            if data.get("settings", {}).get("is_composite"):
                continue
            
            total_devices = len(nodes)
            switch_count = sum(1 for n in nodes if n.get("type") == "switch")
            root_node = next((n for n in nodes if n.get("is_root")), None)
            
            maps.append({
                "id": r[0],
                "name": r[1],
                "description": r[2],
                "total_devices": total_devices,
                "switch_count": switch_count,
                "root_ip": root_node.get("ip") if root_node else None,
                "root_name": root_node.get("name") if root_node else None,
                "updated_at": r[4]
            })
    
    return {"maps": maps}

class MapUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_public: Optional[bool] = None
    allowed_subnets: Optional[List[str]] = None
    data: Optional[dict] = None

class ScanRequest(BaseModel):
    root_ip: str
    hops: int = 2
    subnet: Optional[str] = None
    methods: List[str] = ["arp", "traceroute"]

class SettingsUpdate(BaseModel):
    allowed_subnets: Optional[List[str]] = None
    snmp_default_community: Optional[str] = None
    snmp_default_version: Optional[str] = None
    scan_timeout: Optional[int] = None
    max_hops: Optional[int] = None
    max_devices_per_scan: Optional[int] = None

# ============================================================
# АУТЕНТИФИКАЦИЯ
# ============================================================

@app.post("/api/auth/login")
async def login(login_data: LoginRequest, request: Request):
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?", (login_data.username,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(401, "Неверный логин или пароль")
        if not user[4]:
            raise HTTPException(403, "Пользователь заблокирован")
        if not verify_password(login_data.password, user[2]):
            raise HTTPException(401, "Неверный логин или пароль")
        client_ip = request.client.host if request.client else "unknown"
        cur.execute("UPDATE users SET last_login = ?, last_ip = ? WHERE id = ?", (datetime.now().isoformat(), client_ip, user[0]))
    token = create_access_token({"sub": user[0], "username": user[1], "role": user[3]})
    log_action(user[0], "login", {"ip": client_ip}, client_ip)
    return {"access_token": token, "token_type": "bearer", "user": {"id": user[0], "username": user[1], "role": user[3]}}

@app.get("/api/auth/me")
async def get_me(request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    user = get_user_from_db(user_data['sub'])
    if not user:
        raise HTTPException(401, "Пользователь не найден")
    return {"id": user[0], "username": user[1], "role": user[2], "is_active": bool(user[3]), "created_at": user[4], "last_login": user[5]}

@app.post("/api/auth/logout")
async def logout(request: Request):
    user_data = get_user_from_request(request)
    if user_data:
        log_action(user_data['sub'], "logout", {}, request.client.host if request.client else "unknown")
    return {"success": True}

# ============================================================
# КАРТЫ
# ============================================================

def _empty_graph() -> dict:
    now = datetime.now().isoformat()
    return {"nodes": [], "edges": [], "settings": {"auto_refresh": True, "refresh_interval": 30}, "created_at": now, "updated_at": now}

@app.get("/api/maps")
async def list_maps(request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    user_id = user_data['sub']
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT nm.id, nm.name, nm.description, nm.owner_id,
                   nm.is_public, nm.created_at, nm.updated_at,
                   CASE WHEN nm.owner_id = ? THEN 'owner'
                        WHEN mc.permissions IS NOT NULL THEN mc.permissions
                        ELSE 'view' END AS access_level, nm.current_version
            FROM network_maps nm
            LEFT JOIN map_collaborators mc ON nm.id = mc.map_id AND mc.user_id = ?
            WHERE nm.owner_id = ? OR nm.is_public = 1 OR mc.user_id = ?
            ORDER BY nm.updated_at DESC
        """, (user_id, user_id, user_id, user_id))
        maps = [{"id": r[0], "name": r[1], "description": r[2], "owner_id": r[3], "is_public": bool(r[4]),
                 "created_at": r[5], "updated_at": r[6], "access_level": r[7], "current_version": r[8]} for r in cur.fetchall()]
    return {"maps": maps}

@app.post("/api/maps")
async def create_map(data: MapCreate, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")
    map_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    graph = data.data if data.data else _empty_graph()
    if data.allowed_subnets is None:
        with db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT value FROM global_settings WHERE key='allowed_subnets'")
            row = cur.fetchone()
        allowed_subnets = json.loads(row[0]) if row else []
    else:
        allowed_subnets = data.allowed_subnets
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO network_maps (id, name, description, owner_id, is_public, created_at, updated_at, data, allowed_subnets, current_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (map_id, data.name, data.description or "", user_data['sub'], 1 if data.is_public else 0, now, now,
                     json.dumps(graph, ensure_ascii=False), json.dumps(allowed_subnets, ensure_ascii=False), 1))
        cur.execute("INSERT INTO map_versions (map_id, version, data, created_at, created_by, comment) VALUES (?, ?, ?, ?, ?, ?)",
                    (map_id, 1, json.dumps(graph, ensure_ascii=False), now, user_data['sub'], "Создание карты"))
    log_action(user_data['sub'], f"create_map_{data.name}", {"map_id": map_id}, request.client.host if request.client else "unknown")
    return {"success": True, "map_id": map_id, "name": data.name}

@app.get("/api/maps/{map_id}")
async def get_map(map_id: str, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    user_id = user_data['sub']
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT nm.data, nm.owner_id, nm.is_public, nm.name, nm.description,
                   nm.allowed_subnets, nm.current_version, mc.permissions
            FROM network_maps nm
            LEFT JOIN map_collaborators mc ON nm.id = mc.map_id AND mc.user_id = ?
            WHERE nm.id = ?
        """, (user_id, map_id))
        r = cur.fetchone()
    if not r:
        raise HTTPException(404, "Карта не найдена")
    is_owner = r[1] == user_id
    is_public = bool(r[2])
    collaborator_perms = r[7]
    if not (is_owner or is_public or collaborator_perms):
        raise HTTPException(403, "Доступ запрещен")
    
    graph_data = json.loads(r[0])
    
    # === СЧИТАЕМ СТАТУС ДЛЯ КОМПОЗИЦИИ ===
    if graph_data.get("settings", {}).get("is_composite"):
        for container in graph_data.get("nodes", []):
            if container.get("is_composite"):
                src_map_id = container.get("composite_map_id")
                if not src_map_id: continue
                
                # Загружаем исходную карту
                with db_connection() as conn_inner:
                    cur_inner = conn_inner.cursor()
                    cur_inner.execute("SELECT data FROM network_maps WHERE id = ?", (src_map_id,))
                    src_row = cur_inner.fetchone()
                
                if src_row:
                    src_data = json.loads(src_row[0])
                    src_nodes = src_data.get("nodes", [])
                    
                    online_count = sum(1 for n in src_nodes if n.get("aggregated_status") == "online")
                    offline_count = sum(1 for n in src_nodes if n.get("aggregated_status") == "offline")
                    total = len(src_nodes)
                    
                    if total == 0:
                        container["aggregated_status"] = "unknown"
                    elif online_count == total:
                        container["aggregated_status"] = "online"
                    elif offline_count == total:
                        container["aggregated_status"] = "offline"
                    elif online_count > 0:
                        container["aggregated_status"] = "mixed"
                    else:
                        container["aggregated_status"] = "unknown"

    # Заменяем старый return на новый (с graph_data)
    return {"id": map_id, "name": r[3], "description": r[4], "owner_id": r[1], "is_public": is_public,
            "allowed_subnets": json.loads(r[5]) if r[5] else [], "current_version": r[6],
            "access_level": "owner" if is_owner else (collaborator_perms or "view"), "data": graph_data}

@app.post("/api/maps/{map_id}/activate")
async def activate_map(map_id: str, request: Request):
    """Устанавливает карту как активную (для планировщика)."""
    import state
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    state.ACTIVE_MAP_ID = map_id
    print(f"🎯 Активная карта: {map_id}")
    return {"success": True, "active_map_id": map_id}

@app.put("/api/maps/{map_id}")
async def update_map(map_id: str, data: MapUpdate, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")
    user_id = user_data['sub']
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT owner_id, current_version, data FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        owner_id, current_version, old_data_json = r
        if owner_id != user_id and user_data.get('role') != 'admin':
            cur.execute("SELECT permissions FROM map_collaborators WHERE map_id = ? AND user_id = ?", (map_id, user_id))
            collab = cur.fetchone()
            if not collab or collab[0] != 'edit':
                raise HTTPException(403, "Недостаточно прав для редактирования")
        updates = []
        params = []
        if data.name is not None:
            updates.append("name = ?"); params.append(data.name)
        if data.description is not None:
            updates.append("description = ?"); params.append(data.description)
        if data.is_public is not None:
            updates.append("is_public = ?"); params.append(1 if data.is_public else 0)
        if data.allowed_subnets is not None:
            updates.append("allowed_subnets = ?"); params.append(json.dumps(data.allowed_subnets, ensure_ascii=False))
        if data.data is not None:
            updates.append("data = ?"); params.append(json.dumps(data.data, ensure_ascii=False))
        if not updates:
            return {"success": True, "message": "Нет изменений"}
        updates.append("updated_at = ?"); params.append(datetime.now().isoformat()); params.append(map_id)
        cur.execute(f"UPDATE network_maps SET {', '.join(updates)} WHERE id = ?", params)
        new_version = current_version or 1
        if data.data is not None:
            new_version = (current_version or 1) + 1
            cur.execute("INSERT INTO map_versions (map_id, version, data, created_at, created_by, comment) VALUES (?, ?, ?, ?, ?, ?)",
                        (map_id, new_version, json.dumps(data.data, ensure_ascii=False), datetime.now().isoformat(), user_id, "Ручное обновление"))
            cur.execute("UPDATE network_maps SET current_version = ? WHERE id = ?", (new_version, map_id))
    log_action(user_id, f"update_map_{map_id}", {}, None)
    return {"success": True, "new_version": new_version}

@app.delete("/api/maps/{map_id}")
async def delete_map(map_id: str, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT owner_id FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        if r[0] != user_data['sub'] and user_data.get('role') != 'admin':
            raise HTTPException(403, "Только владелец или админ")
        cur.execute("DELETE FROM network_maps WHERE id = ?", (map_id,))
    log_action(user_data['sub'], f"delete_map_{map_id}", {}, None)
    return {"success": True}

# ============================================================
# ВЕРСИИ КАРТ
# ============================================================

@app.get("/api/maps/{map_id}/versions")
async def list_versions(map_id: str, request: Request):
    if not get_user_from_request(request):
        raise HTTPException(401, "Требуется авторизация")
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT version, created_at, created_by, comment FROM map_versions WHERE map_id = ? ORDER BY version DESC LIMIT 100", (map_id,))
        rows = cur.fetchall()
    return {"versions": [{"version": r[0], "created_at": r[1], "created_by": r[2], "comment": r[3]} for r in rows]}

@app.post("/api/maps/{map_id}/versions/{version}/restore")
async def restore_version(map_id: str, version: int, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Недостаточно прав")
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT owner_id FROM network_maps WHERE id = ?", (map_id,))
        _owner = cur.fetchone()
        if not _owner:
            raise HTTPException(404, "Карта не найдена")
        if _owner[0] != user_data['sub'] and user_data.get('role') != 'admin':
            cur.execute("SELECT permissions FROM map_collaborators WHERE map_id = ? AND user_id = ?", (map_id, user_data['sub']))
            _collab = cur.fetchone()
            if not _collab or _collab[0] != 'edit':
                raise HTTPException(403, "Недостаточно прав для этой карты")
        cur.execute("SELECT data FROM map_versions WHERE map_id = ? AND version = ?", (map_id, version))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Версия не найдена")
        now = datetime.now().isoformat()
        cur.execute("UPDATE network_maps SET data = ?, updated_at = ? WHERE id = ?", (r[0], now, map_id))
        cur.execute("SELECT current_version FROM network_maps WHERE id = ?", (map_id,))
        current = cur.fetchone()[0] or 1
        new_version = current + 1
        cur.execute("INSERT INTO map_versions (map_id, version, data, created_at, created_by, comment) VALUES (?, ?, ?, ?, ?, ?)",
                    (map_id, new_version, r[0], now, user_data['sub'], f"Откат к версии {version}"))
        cur.execute("UPDATE network_maps SET current_version = ? WHERE id = ?", (new_version, map_id))
    return {"success": True, "new_version": new_version, "restored_from": version}

# ============================================================
# ГЛОБАЛЬНЫЕ НАСТРОЙКИ
# ============================================================

def _get_global_settings() -> dict:
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM global_settings")
        settings = {}
        for key, value in cur.fetchall():
            try: settings[key] = json.loads(value)
            except Exception: settings[key] = value
    return settings

@app.get("/api/admin/settings")
async def get_settings(request: Request):
    require_admin(request)
    return _get_global_settings()

@app.put("/api/admin/settings")
async def update_settings(data: SettingsUpdate, request: Request):
    admin_data = require_admin(request)
    with db_write() as conn:
        cur = conn.cursor()
        now = datetime.now().isoformat()
        updates = data.model_dump(exclude_none=True)
        for key, value in updates.items():
            cur.execute("INSERT OR REPLACE INTO global_settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                        (key, json.dumps(value), now, admin_data['sub']))
    log_action(admin_data['sub'], "update_settings", updates, request.client.host if request.client else "unknown")
    return {"success": True, "settings": _get_global_settings()}

# ============================================================
# СКАНИРОВАНИЕ (главное)
# ============================================================

def _do_scan(job_id: str, map_id: str, req: ScanRequest, user_id: str):
    from scanner.arp_scan import scan_subnet, scan_with_nmap, ping_with_ttl
    from scanner.traceroute import traceroute
    from scanner.topology_builder import build_topology

    def _update(job_id, **fields):
        keys = ", ".join(f"{k} = ?" for k in fields.keys())
        execute_write(f"UPDATE scan_jobs SET {keys} WHERE id = ?", (*fields.values(), job_id))

    try:
        _update(job_id, status="running", progress=5)
        subnet = req.subnet or ".".join(req.root_ip.split(".")[:3]) + ".0/24"

        with db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT value FROM global_settings WHERE key='allowed_subnets'")
            row = cur.fetchone()
            global_subnets = json.loads(row[0]) if row else []
            cur.execute("SELECT allowed_subnets FROM network_maps WHERE id = ?", (map_id,))
            row = cur.fetchone()
            map_subnets = json.loads(row[0]) if row and row[0] else []
            effective_subnets = map_subnets if map_subnets else global_subnets

        _update(job_id, progress=10)

        # 1. Сканирование
        nmap_devices = scan_with_nmap(subnet, timeout=120)
        arp_devices = scan_subnet(subnet, timeout=120)
        seen_ips = {d["ip"] for d in arp_devices}
        for nd in nmap_devices:
            if nd["ip"] not in seen_ips:
                arp_devices.append(nd)
                seen_ips.add(nd["ip"])

        # 2.СКЛЕЙКА ПО MAC
        mac_groups = {}
        for dev in arp_devices:
            mac = (dev.get("mac") or "").upper()
            if mac and not mac.startswith("FF:FF"):
                mac_groups.setdefault(mac, []).append(dev["ip"])

        # 3.ПРОВЕРКА
        alive_devices = []
        ttl_map = {}
        for dev in arp_devices:
            ip = dev["ip"]
            ping_res = ping_with_ttl(ip, timeout=1)
            if ping_res["alive"]:
                dev["ttl"] = ping_res["ttl"]
                dev["rtt"] = ping_res["rtt"]
                alive_devices.append(dev)
                ttl_map[ip] = ping_res["ttl"]
            else:
                mac = (dev.get("mac") or "").upper()
                if mac in mac_groups and len(mac_groups[mac]) > 1:
                    alive_devices.append(dev)
                    print(f"   🔗 {ip} — мёртв, но есть MAC-братья: {mac_groups[mac]}")
                else:
                    print(f"   ❌ {ip} — мёртв (уникальный MAC)")

        arp_devices = alive_devices
        print(f" Живых устройств: {len(arp_devices)}")

        # 3. SNMP
        if arp_devices:
            from scanner.auto_detect import enrich_with_snmp
            with db_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT value FROM global_settings WHERE key='snmp_default_community'")
                row = cur.fetchone()
            community = json.loads(row[0]) if row else "public"
            arp_devices = enrich_with_snmp(arp_devices, community=community, timeout=1)

        _update(job_id, progress=30)

        # 4. Traceroute
        traceroute_results = {}
        if "traceroute" in req.methods:
            devices_to_trace = [d for d in arp_devices if d["ip"] != req.root_ip][:50]
            total = len(devices_to_trace) or 1
            for i, dev in enumerate(devices_to_trace):
                try:
                    path = traceroute(dev["ip"], max_hops=req.hops + 2, timeout=30)
                    traceroute_results[dev["ip"]] = path
                except Exception as e:
                    print_error(f"⚠️ traceroute {dev['ip']}: {e}")
                    traceroute_results[dev["ip"]] = []
                _update(job_id, progress=30 + int((i + 1) / total * 60))

        # 5. Строим граф
        graph = build_topology(
            root_ip=req.root_ip, hops=req.hops, arp_devices=arp_devices,
            traceroute_results=traceroute_results, allowed_subnets=effective_subnets,
            max_devices=500
        )

        # 6. Склейка по traceroute
        import socket
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = None
        print(f"   [debug] local_ip = {local_ip}")
        
        merge_groups = []
        
        # Собираем путь для каждого IP
        paths = {}
        for ip in ttl_map:
            path = traceroute_results.get(ip, [])
            visible = tuple(h.get("ip") for h in path if h.get("ip"))
            paths[ip] = visible
        
        # Прямые: путь пустой, (ip,), или (root_ip,)
        direct_ips = []
        for ip, path in paths.items():
            if ip == local_ip:
                print_error(f"⚠️ {ip}: это наш сервер, пропускаем")
                continue
            if not path or path == (ip,) or path == (req.root_ip,):
                direct_ips.append(ip)
            else:
                print_error(f"⚠️ {ip}: за промежуточным (путь {path}), не склеиваем")
        
        # Склеиваем все прямые (кроме нашего сервера) в одну группу
        if len(direct_ips) > 1:
            merge_groups.append(direct_ips)
            print(f" Прямые: склеиваем {direct_ips}")

        # 7. Склейка по TTL ОТКЛЮЧЕНА
        if not merge_groups:
            ttl_groups = {}
            for ip, ttl in ttl_map.items():
                if ttl is not None:
                    ttl_groups.setdefault(ttl, []).append(ip)
            for ttl, ips in ttl_groups.items():
                if len(ips) > 1:
                    merge_groups.append(ips)

        # 8. Применяем слияние
        if merge_groups:
            for group in merge_groups:
                node_ids = [f"node-{ip.replace('.', '-')}" for ip in group]
                existing = [n for n in graph["nodes"] if n["id"] in node_ids]
                if len(existing) < 2:
                    continue
                master = existing[0]
                all_ips = [n.get("ip") for n in existing if n.get("ip")]
                master["ip"] = ", ".join(all_ips)
                master["interfaces"] = all_ips
                master["name"] = f"{master.get('name') or master['ip']} ({len(all_ips)} IP)"
                master["type"] = "router"
                master["discovered_by"] = list(set(
                    sum([n.get("discovered_by", []) for n in existing], [])
                )) + ["auto-merge"]
                
                for e in graph["edges"]:
                    if e["source"] in node_ids: e["source"] = master["id"]
                    if e["target"] in node_ids: e["target"] = master["id"]
                
                graph["nodes"] = [n for n in graph["nodes"] if n["id"] == master["id"] or n["id"] not in node_ids]
                
                seen = set()
                new_edges = []
                for e in graph["edges"]:
                    key = (e["source"], e["target"])
                    if key not in seen:
                        seen.add(key)
                        new_edges.append(e)
                graph["edges"] = new_edges
                
                for n in graph["nodes"]:
                    if n.get("parent_id") in node_ids:
                        n["parent_id"] = master["id"]
                
                if master.get("parent_id") in node_ids:
                    master["parent_id"] = None
        
        # 9. Сохраняем
        now = datetime.now().isoformat()
        with db_write() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE network_maps SET data = ?, updated_at = ? WHERE id = ?",
                        (json.dumps(graph, ensure_ascii=False), now, map_id))
            cur.execute("SELECT current_version FROM network_maps WHERE id = ?", (map_id,))
            current = cur.fetchone()[0] or 1
            new_version = current + 1
            cur.execute("INSERT INTO map_versions (map_id, version, data, created_at, created_by, comment) VALUES (?, ?, ?, ?, ?, ?)",
                        (map_id, new_version, json.dumps(graph, ensure_ascii=False), now, user_id, f"Автосканирование {req.root_ip}"))
            cur.execute("UPDATE network_maps SET current_version = ? WHERE id = ?", (new_version, map_id))

        _update(job_id, status="done", progress=100,
                result=json.dumps({"nodes_count": len(graph["nodes"]), "edges_count": len(graph["edges"]), "version": new_version}),
                finished_at=datetime.now().isoformat())
        print(f" Сканирование завершено, версия {new_version}")

    except Exception as e:
        import traceback
        traceback.print_exc()
        _update(job_id, status="error", error=str(e), finished_at=datetime.now().isoformat())

@app.post("/api/maps/{map_id}/scan")
async def start_scan(map_id: str, req: ScanRequest, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")
    job_id = str(uuid.uuid4())
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT owner_id FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        if r[0] != user_data['sub'] and user_data.get('role') != 'admin':
            cur.execute("SELECT permissions FROM map_collaborators WHERE map_id = ? AND user_id = ?", (map_id, user_data['sub']))
            _collab = cur.fetchone()
            if not _collab or _collab[0] != 'edit':
                raise HTTPException(403, "Недостаточно прав для этой карты")
        cur.execute("INSERT INTO scan_jobs (id, map_id, status, progress, created_at, created_by) VALUES (?, ?, 'pending', 0, ?, ?)",
                    (job_id, map_id, datetime.now().isoformat(), user_data['sub']))
    thread = threading.Thread(target=_do_scan, args=(job_id, map_id, req, user_data['sub']), daemon=True)
    thread.start()
    return {"job_id": job_id, "status": "pending"}

@app.get("/api/maps/{map_id}/scan/{job_id}")
async def get_scan_status(map_id: str, job_id: str, request: Request):
    if not get_user_from_request(request):
        raise HTTPException(401, "Требуется авторизация")
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, status, progress, result, error, created_at, finished_at FROM scan_jobs WHERE id = ? AND map_id = ?", (job_id, map_id))
        r = cur.fetchone()
    if not r:
        raise HTTPException(404, "Задача не найдена")
    return {"job_id": r[0], "status": r[1], "progress": r[2], "result": json.loads(r[3]) if r[3] else None,
            "error": r[4], "created_at": r[5], "finished_at": r[6]}

# ============================================================
# СТАТИСТИКА ПО КАРТЕ
# ============================================================

@app.get("/api/maps/{map_id}/stats")
async def get_map_stats(map_id: str, request: Request):
    """Статистика карты: узлы online/offline, uptime, средний latency."""
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT data FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        
        graph = json.loads(r[0])
        nodes = graph.get("nodes", [])
        
        # Статистика по узлам
        total = len(nodes)
        online = sum(1 for n in nodes if n.get("aggregated_status") == "online")
        offline = sum(1 for n in nodes if n.get("aggregated_status") == "offline")
        mixed = sum(1 for n in nodes if n.get("aggregated_status") == "mixed")
        unknown = total - online - offline - mixed
        
        # Статистика по последним проверкам (за 24 часа)
        cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
        cur.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online_count,
                AVG(CASE WHEN status = 'online' AND latency > 0 THEN latency END) as avg_latency
            FROM check_history
            WHERE map_id = ? AND timestamp >= ?
        """, (map_id, cutoff))
        ch = cur.fetchone()
        ch_total = ch[0] or 0
        ch_online = ch[1] or 0
        avg_latency = round(ch[2] or 0, 2)
        
        # Uptime за 24 часа (процент online проверок)
        uptime = round((ch_online / ch_total * 100), 2) if ch_total > 0 else 0
        
        # Кол-во уникальных IP (интерфейсов)
        all_ips = set()
        for n in nodes:
            interfaces = n.get("interfaces") or []
            if not interfaces:
                interfaces = [ip.strip() for ip in (n.get("ip") or "").split(",") if ip.strip()]
            all_ips.update(interfaces)
        
        # Последняя проверка
        cur.execute("""
            SELECT MAX(timestamp) FROM check_history WHERE map_id = ?
        """, (map_id,))
        last_check = cur.fetchone()[0]
        
        return {
            "map_id": map_id,
            "nodes": {
                "total": total,
                "online": online,
                "offline": offline,
                "mixed": mixed,
                "unknown": unknown,
            },
            "interfaces": {
                "total": len(all_ips),
            },
            "checks_24h": {
                "total": ch_total,
                "online": ch_online,
                "uptime_percent": uptime,
                "avg_latency_ms": avg_latency,
            },
            "last_check": last_check,
        }

# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():
    return {"status": "ok", "database": "sqlite", "version": "5.0", "time": datetime.now().isoformat()}

@app.get("/")
async def index():
    index_path = os.path.join(TEMPLATES_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({"message": "Horizon Tree v5.0 API работает."})

@app.get("/login")
async def login_page():
    login_path = os.path.join(TEMPLATES_DIR, "login.html")
    if os.path.exists(login_path):
        return FileResponse(login_path)
    return JSONResponse({"message": "Страница логина"})

@app.get("/admin")
async def admin_page():
    admin_path = os.path.join(TEMPLATES_DIR, "admin.html")
    if os.path.exists(admin_path):
        return FileResponse(admin_path)
    return JSONResponse({"message": "Админка"})

# ============================================================
# ИСТОРИЯ УЗЛА
# ============================================================

@app.get("/api/maps/{map_id}/nodes/{node_id}/history")
async def get_node_history(map_id: str, node_id: str, hours: int = 24, check_type: Optional[str] = None, request: Request = None):
    if not get_user_from_request(request):
        raise HTTPException(401, "Требуется авторизация")
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    with db_connection() as conn:
        cur = conn.cursor()
        if check_type:
            cur.execute("SELECT check_type, status, latency, timestamp FROM check_history WHERE map_id = ? AND node_id = ? AND check_type = ? AND timestamp >= ? ORDER BY timestamp ASC",
                        (map_id, node_id, check_type, cutoff))
        else:
            cur.execute("SELECT check_type, status, latency, timestamp FROM check_history WHERE map_id = ? AND node_id = ? AND timestamp >= ? ORDER BY timestamp ASC",
                        (map_id, node_id, cutoff))
        rows = cur.fetchall()
    history = [{"check_type": r[0], "status": r[1], "latency": r[2] or 0, "timestamp": r[3]} for r in rows]
    total = len(history)
    online = sum(1 for h in history if h["status"] == "online")
    offline = sum(1 for h in history if h["status"] == "offline")
    error = total - online - offline
    latencies = [h["latency"] for h in history if h["status"] == "online" and h["latency"] > 0]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    uptime = (online / total * 100) if total > 0 else 0
    return {"node_id": node_id, "hours": hours, "history": history,
            "stats": {"total": total, "online": online, "offline": offline, "error": error,
                      "uptime_percent": round(uptime, 2), "avg_latency": round(avg_latency, 2),
                      "min_latency": round(min(latencies), 2) if latencies else 0,
                      "max_latency": round(max(latencies), 2) if latencies else 0}}

# ============================================================
# УЗЛЫ
# ============================================================

class NodeCreate(BaseModel):
    ip: str
    name: Optional[str] = None
    type: str = "unknown"
    parent_id: Optional[str] = None
    checks: Optional[List[dict]] = None

@app.post("/api/maps/{map_id}/nodes")
async def add_node(map_id: str, node_data: NodeCreate, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT data, owner_id, allowed_subnets FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        if r[1] != user_data['sub'] and user_data.get('role') != 'admin':
            cur.execute("SELECT permissions FROM map_collaborators WHERE map_id = ? AND user_id = ?", (map_id, user_data['sub']))
            _collab = cur.fetchone()
            if not _collab or _collab[0] != 'edit':
                raise HTTPException(403, "Недостаточно прав для этой карты")
        graph = json.loads(r[0])
        allowed_subnets = json.loads(r[2]) if r[2] else []
        node_id = f"node-{node_data.ip.replace('.', '-')}"
        if any(n["id"] == node_id for n in graph["nodes"]):
            raise HTTPException(400, "Узел с таким IP уже существует")
        in_whitelist = True
        if allowed_subnets:
            try:
                import ipaddress
                addr = ipaddress.ip_address(node_data.ip)
                in_whitelist = any(addr in ipaddress.ip_network(s, strict=False) for s in allowed_subnets)
            except ValueError:
                pass
        now = datetime.now().isoformat()
        checks = node_data.checks or [{"id": f"chk-{uuid.uuid4().hex[:12]}", "type": "icmp", "enabled": True, "timeout": 2}]
        for c in checks:
            if "id" not in c: c["id"] = f"chk-{uuid.uuid4().hex[:12]}"
            if "enabled" not in c: c["enabled"] = True
            if "timeout" not in c: c["timeout"] = 3
        parent_id = node_data.parent_id
        if parent_id and not any(n["id"] == parent_id for n in graph["nodes"]):
            parent_id = None
        hops = 1
        if parent_id:
            parent_node = next((n for n in graph["nodes"] if n["id"] == parent_id), None)
            if parent_node:
                hops = parent_node.get("hops_from_root", 0) + 1
        new_node = {"id": node_id, "ip": node_data.ip, "name": node_data.name or node_data.ip, "type": node_data.type,
                    "discovered_by": ["manual"], "parent_id": parent_id, "hops_from_root": hops, "is_root": False,
                    "metadata": {}, "checks": checks, "status": {}, "aggregated_status": "unknown",
                    "is_outside_whitelist": not in_whitelist, "created_at": now, "updated_at": now}
        graph["nodes"].append(new_node)
        if parent_id:
            graph["edges"].append({"id": f"edge-{parent_id}-{node_id}", "source": parent_id, "target": node_id,
                                   "type": "parent-child", "discovered_by": "manual", "note": "", "created_at": now})
        graph["updated_at"] = now
        cur.execute("UPDATE network_maps SET data = ?, updated_at = ? WHERE id = ?", (json.dumps(graph, ensure_ascii=False), now, map_id))
        cur.execute("SELECT current_version FROM network_maps WHERE id = ?", (map_id,))
        current = cur.fetchone()[0] or 1
        new_version = current + 1
        cur.execute("INSERT INTO map_versions (map_id, version, data, created_at, created_by, comment) VALUES (?, ?, ?, ?, ?, ?)",
                    (map_id, new_version, json.dumps(graph, ensure_ascii=False), now, user_data['sub'], f"Ручное добавление узла {node_data.ip}"))
        cur.execute("UPDATE network_maps SET current_version = ? WHERE id = ?", (new_version, map_id))
    log_action(user_data['sub'], f"add_node_{node_data.ip}", {"map_id": map_id, "ip": node_data.ip, "in_whitelist": in_whitelist},
               request.client.host if request.client else "unknown")
    return {"success": True, "node_id": node_id, "is_outside_whitelist": not in_whitelist, "version": new_version}

@app.delete("/api/maps/{map_id}/nodes/{node_id}")
async def delete_node(map_id: str, node_id: str, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT data, owner_id FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        if r[1] != user_data['sub'] and user_data.get('role') != 'admin':
            cur.execute("SELECT permissions FROM map_collaborators WHERE map_id = ? AND user_id = ?", (map_id, user_data['sub']))
            _collab = cur.fetchone()
            if not _collab or _collab[0] != 'edit':
                raise HTTPException(403, "Недостаточно прав для этой карты")
        graph = json.loads(r[0])
        original_len = len(graph["nodes"])
        graph["nodes"] = [n for n in graph["nodes"] if n["id"] != node_id]
        if len(graph["nodes"]) == original_len:
            raise HTTPException(404, "Узел не найден")
        graph["edges"] = [e for e in graph["edges"] if e["source"] != node_id and e["target"] != node_id]
        for n in graph["nodes"]:
            if n.get("parent_id") == node_id:
                n["parent_id"] = None
        now = datetime.now().isoformat()
        graph["updated_at"] = now
        cur.execute("UPDATE network_maps SET data = ?, updated_at = ? WHERE id = ?", (json.dumps(graph, ensure_ascii=False), now, map_id))
        cur.execute("SELECT current_version FROM network_maps WHERE id = ?", (map_id,))
        current = cur.fetchone()[0] or 1
        new_version = current + 1
        cur.execute("INSERT INTO map_versions (map_id, version, data, created_at, created_by, comment) VALUES (?, ?, ?, ?, ?, ?)",
                    (map_id, new_version, json.dumps(graph, ensure_ascii=False), now, user_data['sub'], f"Удаление узла {node_id}"))
        cur.execute("UPDATE network_maps SET current_version = ? WHERE id = ?", (new_version, map_id))
    return {"success": True, "version": new_version}

class InterfacesUpdate(BaseModel):
    interfaces: List[str]

@app.put("/api/maps/{map_id}/nodes/{node_id}/interfaces")
async def update_node_interfaces(map_id: str, node_id: str, data: InterfacesUpdate, request: Request):
    """Обновить список интерфейсов (IP) узла вручную (editor+)."""
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")
    
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT data, owner_id FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        
        graph = json.loads(r[0])
        node = next((n for n in graph["nodes"] if n["id"] == node_id), None)
        if not node:
            raise HTTPException(404, "Узел не найден")
        
        # Валидация IP
        import ipaddress
        valid_ips = []
        for ip in data.interfaces:
            ip = ip.strip()
            if not ip: continue
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                continue  # пропускаем невалидные
        
        if not valid_ips:
            raise HTTPException(400, "Нужен хотя бы один валидный IP")
        
        # Обновляем
        node["interfaces"] = valid_ips
        node["ip"] = ", ".join(valid_ips)
        node["name"] = f"{node.get('name') or valid_ips[0]} ({len(valid_ips)} IP)"
        node["updated_at"] = datetime.now().isoformat()
        graph["updated_at"] = node["updated_at"]
        
        now = datetime.now().isoformat()
        cur.execute("UPDATE network_maps SET data = ?, updated_at = ? WHERE id = ?",
                    (json.dumps(graph, ensure_ascii=False), now, map_id))
        cur.execute("SELECT current_version FROM network_maps WHERE id = ?", (map_id,))
        current = cur.fetchone()[0] or 1
        new_version = current + 1
        cur.execute("""
            INSERT INTO map_versions (map_id, version, data, created_at, created_by, comment)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (map_id, new_version, json.dumps(graph, ensure_ascii=False),
              now, user_data['sub'], f"Ручное изменение интерфейсов узла {node_id}"))
        cur.execute("UPDATE network_maps SET current_version = ? WHERE id = ?", (new_version, map_id))
    
    return {"success": True, "interfaces": valid_ips, "version": new_version}

class ChecksUpdate(BaseModel):
    checks: List[dict]

@app.put("/api/maps/{map_id}/nodes/{node_id}/checks")
async def update_node_checks(map_id: str, node_id: str, data: ChecksUpdate, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT data, owner_id FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        if r[1] != user_data['sub'] and user_data.get('role') != 'admin':
            cur.execute("SELECT permissions FROM map_collaborators WHERE map_id = ? AND user_id = ?", (map_id, user_data['sub']))
            _collab = cur.fetchone()
            if not _collab or _collab[0] != 'edit':
                raise HTTPException(403, "Недостаточно прав для этой карты")
        graph = json.loads(r[0])
        node = next((n for n in graph["nodes"] if n["id"] == node_id), None)
        if not node:
            raise HTTPException(404, "Узел не найден")
        checks = []
        for c in data.checks:
            ctype = c.get("type")
            if ctype not in ("icmp", "tcp", "udp", "snmp"): continue
            check = {"id": c.get("id") or f"chk-{uuid.uuid4().hex[:12]}", "type": ctype,
                     "enabled": c.get("enabled", True), "timeout": c.get("timeout", 2 if ctype == "icmp" else 3)}
            if ctype in ("tcp", "udp"):
                if "port" not in c: continue
                check["port"] = int(c["port"])
            checks.append(check)
        if not checks:
            raise HTTPException(400, "Нужна хотя бы одна проверка")
        node["checks"] = checks
        node["updated_at"] = datetime.now().isoformat()
        graph["updated_at"] = node["updated_at"]
        now = datetime.now().isoformat()
        cur.execute("UPDATE network_maps SET data = ?, updated_at = ? WHERE id = ?", (json.dumps(graph, ensure_ascii=False), now, map_id))
        cur.execute("SELECT current_version FROM network_maps WHERE id = ?", (map_id,))
        current = cur.fetchone()[0] or 1
        new_version = current + 1
        cur.execute("INSERT INTO map_versions (map_id, version, data, created_at, created_by, comment) VALUES (?, ?, ?, ?, ?, ?)",
                    (map_id, new_version, json.dumps(graph, ensure_ascii=False), now, user_data['sub'], f"Изменение проверок узла {node_id}"))
        cur.execute("UPDATE network_maps SET current_version = ? WHERE id = ?", (new_version, map_id))
    return {"success": True, "checks": checks, "version": new_version}

class NodeUpdate(BaseModel):
    ip: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None
    parent_id: Optional[str] = None
    parent_ip: Optional[str] = None

@app.put("/api/maps/{map_id}/nodes/{node_id}")
async def update_node(map_id: str, node_id: str, data: NodeUpdate, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")
    
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT data, owner_id FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        if r[1] != user_data['sub'] and user_data.get('role') != 'admin':
            cur.execute("SELECT permissions FROM map_collaborators WHERE map_id = ? AND user_id = ?", (map_id, user_data['sub']))
            _collab = cur.fetchone()
            if not _collab or _collab[0] != 'edit':
                raise HTTPException(403, "Недостаточно прав для этой карты")
        
        graph = json.loads(r[0])
        node = next((n for n in graph["nodes"] if n["id"] == node_id), None)
        if not node:
            raise HTTPException(404, "Узел не найден")
        
        now = datetime.now().isoformat()
        old_ip = node["ip"]
        
        # === IP ===
        if data.ip is not None and data.ip != node["ip"]:
            new_id = f"node-{data.ip.replace('.', '-')}"
            if new_id != node_id and any(n["id"] == new_id for n in graph["nodes"]):
                raise HTTPException(400, "Узел с таким IP уже существует")
            node["ip"] = data.ip
            old_id = node["id"]
            node["id"] = new_id
            for e in graph["edges"]:
                if e["source"] == old_id: e["source"] = new_id
                if e["target"] == old_id: e["target"] = new_id
            for n in graph["nodes"]:
                if n.get("parent_id") == old_id: n["parent_id"] = new_id
            node_id = new_id
        
        # === Имя ===
        if data.name is not None:
            node["name"] = data.name
        
        # === Тип ===
        if data.type is not None and data.type in ("router", "switch", "server", "pc", "unknown"):
            node["type"] = data.type
        
        # === Родитель ===
        if "parent_id" in data.model_fields_set:
            new_parent = data.parent_id
            if new_parent:
                if not any(n["id"] == new_parent for n in graph["nodes"]):
                    raise HTTPException(400, "Родительский узел не найден")
                def is_descendant(ancestor_id, nid):
                    for n in graph["nodes"]:
                        if n["id"] == nid and n.get("parent_id") == ancestor_id:
                            return True
                        if n["id"] == nid and n.get("parent_id"):
                            if is_descendant(ancestor_id, n["parent_id"]):
                                return True
                    return False
                if new_parent == node["id"] or is_descendant(node["id"], new_parent):
                    raise HTTPException(400, "Нельзя создать цикл в дереве")
            
            # Удаляем старые рёбра этого узла
            graph["edges"] = [e for e in graph["edges"] if e["source"] != node["id"]]
            node["parent_id"] = new_parent
            
            if new_parent:
                parent = next(n for n in graph["nodes"] if n["id"] == new_parent)
                node["hops_from_root"] = parent.get("hops_from_root", 0) + 1
                graph["edges"].append({
                    "id": f"edge-{new_parent}-{node['id']}",
                    "source": new_parent,
                    "target": node["id"],
                    "from_ip": data.parent_ip,
                    "to_ip": node.get("ip"),
                    "type": "parent-child",
                    "discovered_by": "manual",
                    "note": "Изменено вручную",
                    "created_at": now
                })
            else:
                node["hops_from_root"] = 0
        
        # === Обновление parent_ip (отдельно) ===
        if data.parent_ip is not None:
            node["parent_ip"] = data.parent_ip
            for e in graph["edges"]:
                if e["source"] == node.get("parent_id") and e["target"] == node["id"]:
                    e["from_ip"] = data.parent_ip
                    break
        
        node["updated_at"] = now
        graph["updated_at"] = now
        
        cur.execute("UPDATE network_maps SET data = ?, updated_at = ? WHERE id = ?",
                    (json.dumps(graph, ensure_ascii=False), now, map_id))
        cur.execute("SELECT current_version FROM network_maps WHERE id = ?", (map_id,))
        current = cur.fetchone()[0] or 1
        new_version = current + 1
        cur.execute("""
            INSERT INTO map_versions (map_id, version, data, created_at, created_by, comment)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (map_id, new_version, json.dumps(graph, ensure_ascii=False),
              now, user_data['sub'], f"Изменение узла {old_ip}"))
        cur.execute("UPDATE network_maps SET current_version = ? WHERE id = ?", (new_version, map_id))
    
    return {"success": True, "node_id": node_id, "version": new_version, "node": node}


class NodeIconUpdate(BaseModel):
    icon: Optional[str] = None

@app.put("/api/maps/{map_id}/nodes/{node_id}/icon")
async def set_node_icon(map_id: str, node_id: str, data: NodeIconUpdate, request: Request):
    """Установить иконку узла (editor+)."""
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")
    
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT data, owner_id FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        
        graph = json.loads(r[0])
        node = next((n for n in graph["nodes"] if n["id"] == node_id), None)
        if not node:
            raise HTTPException(404, "Узел не найден")
        
        if "metadata" not in node or node["metadata"] is None:
            node["metadata"] = {}
        
        if data.icon:
            node["metadata"]["icon"] = data.icon
        else:
            node["metadata"].pop("icon", None)
        
        now = datetime.now().isoformat()
        node["updated_at"] = now
        graph["updated_at"] = now
        
        cur.execute("UPDATE network_maps SET data = ?, updated_at = ? WHERE id = ?",
                    (json.dumps(graph, ensure_ascii=False), now, map_id))
    
    return {"success": True, "icon": data.icon}

class PositionsUpdate(BaseModel):
    positions: Dict[str, Dict[str, float]]

@app.put("/api/maps/{map_id}/positions")
async def save_positions(map_id: str, data: PositionsUpdate, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT data, owner_id FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        if r[1] != user_data['sub'] and user_data.get('role') != 'admin':
            cur.execute("SELECT permissions FROM map_collaborators WHERE map_id = ? AND user_id = ?", (map_id, user_data['sub']))
            _collab = cur.fetchone()
            if not _collab or _collab[0] != 'edit':
                raise HTTPException(403, "Недостаточно прав для этой карты")
        graph = json.loads(r[0])
        for node in graph["nodes"]:
            pos = data.positions.get(node["id"])
            if pos:
                if "metadata" not in node: node["metadata"] = {}
                node["metadata"]["x"] = float(pos.get("x", 0))
                node["metadata"]["y"] = float(pos.get("y", 0))
        graph["updated_at"] = datetime.now().isoformat()
        cur.execute("UPDATE network_maps SET data = ? WHERE id = ?", (json.dumps(graph, ensure_ascii=False), map_id))
    return {"success": True}

# ============================================================
# ЭКСПОРТ / ИМПОРТ
# ============================================================

@app.get("/api/maps/{map_id}/export")
async def export_map(map_id: str, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, name, description, owner_id, is_public, allowed_subnets, data, current_version, created_at, updated_at FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        is_owner = r[3] == user_data['sub']
        is_public = bool(r[4])
        if not (is_owner or is_public):
            cur.execute("SELECT permissions FROM map_collaborators WHERE map_id = ? AND user_id = ?", (map_id, user_data['sub']))
            if not cur.fetchone():
                raise HTTPException(403, "Доступ запрещен")
    return {"type": "horizon_tree_map", "version": "5.0", "exported_at": datetime.now().isoformat(), "exported_by": user_data['sub'],
            "map": {"name": r[1], "description": r[2], "is_public": bool(r[4]), "allowed_subnets": json.loads(r[5]) if r[5] else [],
                    "current_version": r[7], "created_at": r[8], "updated_at": r[9], "data": json.loads(r[6])}}

class MapImport(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_public: bool = False
    allowed_subnets: Optional[List[str]] = None
    data: Optional[dict] = None
    type: Optional[str] = None
    version: Optional[str] = None
    map: Optional[dict] = None

@app.post("/api/maps/import")
async def import_map(payload: MapImport, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")
    if payload.map:
        payload.name = payload.name or payload.map.get("name")
        payload.description = payload.description or payload.map.get("description")
        payload.is_public = payload.is_public or payload.map.get("is_public", False)
        payload.allowed_subnets = payload.allowed_subnets or payload.map.get("allowed_subnets")
        payload.data = payload.map.get("data")
    if not payload.data:
        raise HTTPException(400, "Неверный формат: нет data или map.data")
    if "nodes" not in payload.data:
        raise HTTPException(400, "Неверный формат: нет nodes")
    map_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    for node in payload.data.get("nodes", []):
        if "id" not in node:
            node["id"] = f"node-{node.get('ip', uuid.uuid4().hex[:8]).replace('.', '-')}"
    if payload.allowed_subnets is None:
        with db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT value FROM global_settings WHERE key='allowed_subnets'")
            row = cur.fetchone()
        allowed_subnets = json.loads(row[0]) if row else []
    else:
        allowed_subnets = payload.allowed_subnets
    name = payload.name or payload.data.get("name") or "Импортированная карта"
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO network_maps (id, name, description, owner_id, is_public, created_at, updated_at, data, allowed_subnets, current_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (map_id, name, payload.description or "", user_data['sub'], 1 if payload.is_public else 0, now, now,
                     json.dumps(payload.data, ensure_ascii=False), json.dumps(allowed_subnets, ensure_ascii=False), 1))
        cur.execute("INSERT INTO map_versions (map_id, version, data, created_at, created_by, comment) VALUES (?, ?, ?, ?, ?, ?)",
                    (map_id, 1, json.dumps(payload.data, ensure_ascii=False), now, user_data['sub'], "Импорт карты"))
    log_action(user_data['sub'], "import_map", {"map_id": map_id, "name": name}, request.client.host if request.client else "unknown")
    return {"success": True, "map_id": map_id, "name": name, "nodes_count": len(payload.data.get("nodes", []))}

# ============================================================
# ПОЛЬЗОВАТЕЛИ (АДМИН)
# ============================================================

class AdminUserCreate(BaseModel):
    username: str
    password: str
    role: str = "viewer"

class AdminUserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None

@app.get("/api/admin/users")
async def admin_list_users(request: Request):
    require_admin(request)
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, role, is_active, created_at, last_login, last_ip FROM users ORDER BY created_at DESC")
        users = [{"id": r[0], "username": r[1], "role": r[2], "is_active": bool(r[3]), "created_at": r[4], "last_login": r[5], "last_ip": r[6]} for r in cur.fetchall()]
    return {"users": users}

@app.post("/api/admin/users")
async def admin_create_user(data: AdminUserCreate, request: Request):
    admin_data = require_admin(request)
    if data.role not in ("admin", "editor", "viewer"):
        raise HTTPException(400, "Неверная роль")
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = ?", (data.username,))
        if cur.fetchone():
            raise HTTPException(400, "Пользователь уже существует")
        user_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        cur.execute("INSERT INTO users (id, username, password_hash, role, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (user_id, data.username, hash_password(data.password), data.role, 1, now, now))
    log_action(admin_data['sub'], f"create_user_{data.username}", {"username": data.username, "role": data.role},
               request.client.host if request.client else "unknown")
    return {"success": True, "user_id": user_id}

@app.put("/api/admin/users/{user_id}")
async def admin_update_user(user_id: str, data: AdminUserUpdate, request: Request):
    admin_data = require_admin(request)
    if user_id == admin_data['sub']:
        raise HTTPException(400, "Нельзя редактировать самого себя")
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(404, "Пользователь не найден")
        updates = []
        params = []
        if data.username is not None:
            cur.execute("SELECT id FROM users WHERE username = ? AND id != ?", (data.username, user_id))
            if cur.fetchone():
                raise HTTPException(400, "Это имя уже занято")
            updates.append("username = ?"); params.append(data.username)
        if data.password is not None:
            updates.append("password_hash = ?"); params.append(hash_password(data.password))
        if data.role is not None:
            if data.role not in ("admin", "editor", "viewer"):
                raise HTTPException(400, "Неверная роль")
            updates.append("role = ?"); params.append(data.role)
        if data.is_active is not None:
            updates.append("is_active = ?"); params.append(1 if data.is_active else 0)
        if updates:
            updates.append("updated_at = ?"); params.append(datetime.now().isoformat()); params.append(user_id)
            cur.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
            log_action(admin_data['sub'], f"update_user_{user[1]}", {"updates": data.model_dump(exclude_none=True)},
                       request.client.host if request.client else "unknown")
    return {"success": True}

@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(user_id: str, request: Request):
    admin_data = require_admin(request)
    if user_id == admin_data['sub']:
        raise HTTPException(400, "Нельзя удалить самого себя")
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(404, "Пользователь не найден")
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    log_action(admin_data['sub'], f"delete_user_{user[0]}", {}, request.client.host if request.client else "unknown")
    return {"success": True}

# ============================================================
# СВЯЗЫВАНИЕ КОРНЕЙ
# ============================================================

class LinkRootsRequest(BaseModel):
    source_root_id: str
    target_root_id: str
    link_type: str = "vpn"
    note: Optional[str] = None

@app.post("/api/maps/{map_id}/link-roots")
async def link_roots(map_id: str, data: LinkRootsRequest, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    if not check_user_permission(user_data.get('role', 'viewer'), 'editor'):
        raise HTTPException(403, "Требуется роль editor или admin")
    if data.link_type not in ("vpn", "router", "cable", "direct"):
        raise HTTPException(400, "Неверный тип связи")
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT data, owner_id FROM network_maps WHERE id = ?", (map_id,))
        r = cur.fetchone()
        if not r:
            raise HTTPException(404, "Карта не найдена")
        if r[1] != user_data['sub'] and user_data.get('role') != 'admin':
            cur.execute("SELECT permissions FROM map_collaborators WHERE map_id = ? AND user_id = ?", (map_id, user_data['sub']))
            _collab = cur.fetchone()
            if not _collab or _collab[0] != 'edit':
                raise HTTPException(403, "Недостаточно прав для этой карты")
        graph = json.loads(r[0])
        source_node = next((n for n in graph["nodes"] if n["id"] == data.source_root_id), None)
        target_node = next((n for n in graph["nodes"] if n["id"] == data.target_root_id), None)
        if not source_node:
            raise HTTPException(404, "Source root не найден")
        if not target_node:
            raise HTTPException(404, "Target root не найден")
        if not source_node.get("is_root"):
            raise HTTPException(400, "Source должен быть корнем")
        if not target_node.get("is_root"):
            raise HTTPException(400, "Target должен быть корнем")
        if data.source_root_id == data.target_root_id:
            raise HTTPException(400, "Нельзя связать корень с собой")
        now = datetime.now().isoformat()
        target_node["parent_id"] = data.source_root_id
        target_node["is_root"] = False
        target_node["hops_from_root"] = (source_node.get("hops_from_root", 0) or 0) + 1
        target_node["updated_at"] = now
        edge_id = f"edge-{data.source_root_id}-{data.target_root_id}"
        graph["edges"] = [e for e in graph["edges"] if e["target"] != data.target_root_id]
        graph["edges"].append({"id": edge_id, "source": data.source_root_id, "target": data.target_root_id,
                               "type": "parent-child", "discovered_by": "manual-link", "note": data.note or f"Связь: {data.link_type}", "created_at": now})
        graph["updated_at"] = now
        cur.execute("UPDATE network_maps SET data = ?, updated_at = ? WHERE id = ?", (json.dumps(graph, ensure_ascii=False), now, map_id))
        cur.execute("SELECT current_version FROM network_maps WHERE id = ?", (map_id,))
        current = cur.fetchone()[0] or 1
        new_version = current + 1
        cur.execute("INSERT INTO map_versions (map_id, version, data, created_at, created_by, comment) VALUES (?, ?, ?, ?, ?, ?)",
                    (map_id, new_version, json.dumps(graph, ensure_ascii=False), now, user_data['sub'], f"Связь корней {data.source_root_id} -> {data.target_root_id}"))
        cur.execute("UPDATE network_maps SET current_version = ? WHERE id = ?", (new_version, map_id))
    log_action(user_data['sub'], f"link_roots_{data.source_root_id}_{data.target_root_id}", {"link_type": data.link_type, "note": data.note},
               request.client.host if request.client else "unknown")
    return {"success": True, "version": new_version, "link_type": data.link_type}

# ============================================================
# СЛИЯНИЕ УЗЛОВ (MERGE) — для ручного
# ============================================================

class DeviceMergeRequest(BaseModel):
    map_id: str
    node_ids: List[str]
    name: str
    type: str = "router"
    vendor: Optional[str] = None
    model: Optional[str] = None

@app.post("/api/maps/{map_id}/devices/merge")
async def merge_nodes_to_device(map_id: str, data: DeviceMergeRequest, request: Request):
    user_data = get_user_from_request(request)
    if not user_data:
        raise HTTPException(401, "Требуется авторизация")
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute("SELECT data, owner_id FROM network_maps WHERE id=?", (map_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Карта не найдена")
        graph = json.loads(row[0])
        node_map = {n["id"]: n for n in graph["nodes"]}
        missing = [nid for nid in data.node_ids if nid not in node_map]
        if missing:
            raise HTTPException(400, f"Узлы не найдены: {missing}")
        now = datetime.now().isoformat()
        dev_id = f"device-{uuid.uuid4().hex[:12]}"
        cur.execute("INSERT INTO devices (id, map_id, name, type, vendor, model, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (dev_id, map_id, data.name, data.type, data.vendor, data.model, now, now))
        merged_ids = set(data.node_ids)
        for nid in data.node_ids:
            n = node_map[nid]
            iface_id = f"iface-{uuid.uuid4().hex[:12]}"
            cur.execute("INSERT INTO interfaces (id, device_id, name, ip_address, mac, media, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (iface_id, dev_id, n.get("name") or n.get("ip"), n.get("ip"), (n.get("metadata") or {}).get("mac"), "unknown", now))
        new_node = {"id": dev_id, "ip": ", ".join(node_map[nid].get("ip", "") for nid in data.node_ids if node_map[nid].get("ip")),
                    "name": data.name, "type": data.type, "discovered_by": ["manual-merge"], "parent_id": None,
                    "hops_from_root": min(node_map[nid].get("hops_from_root", 0) for nid in data.node_ids),
                    "is_root": any(node_map[nid].get("is_root") for nid in data.node_ids),
                    "metadata": {"vendor": data.vendor, "model": data.model}, "checks": node_map[data.node_ids[0]].get("checks", []),
                    "status": {}, "aggregated_status": "unknown", "is_outside_whitelist": False, "created_at": now, "updated_at": now}
        graph["nodes"] = [n for n in graph["nodes"] if n["id"] not in merged_ids]
        graph["nodes"].append(new_node)
        for e in graph["edges"]:
            if e["source"] in merged_ids: e["source"] = dev_id
            if e["target"] in merged_ids: e["target"] = dev_id
        seen = set()
        new_edges = []
        for e in graph["edges"]:
            key = (e["source"], e["target"])
            if key in seen: continue
            seen.add(key)
            new_edges.append(e)
        graph["edges"] = new_edges
        for n in graph["nodes"]:
            if n.get("parent_id") in merged_ids:
                n["parent_id"] = dev_id
        graph["updated_at"] = now
        cur.execute("UPDATE network_maps SET data=?, updated_at=? WHERE id=?", (json.dumps(graph, ensure_ascii=False), now, map_id))
    return {"success": True, "device_id": dev_id}

# ============================================================
# ЗАПУСК
# ============================================================

if __name__ == "__main__":
    import socket
    from checks import scheduler
    scheduler.start(interval=30)
    print("Планировщик запущен")

    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    local_ip = get_local_ip()
    print("\n" + "=" * 60)
    print("   HORIZON TREE v5.0 — МОНИТОРИНГ ТОПОЛОГИИ")
    print("=" * 60)
    print(f"\n   Сервер: http://{local_ip}:8000")
    print(f"   Локально: http://localhost:8000")
    print(f"   API docs: http://{local_ip}:8000/docs")
    print(f"\n   Логин: admin")
    print(f"   Пароль: admin_password.txt")
    print(f"\n   Планировщик: каждые 30 сек")
    print("\n" + "=" * 60 + "\n")

    host = os.getenv("HORIZON_HOST", "0.0.0.0")
    port = int(os.getenv("HORIZON_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)