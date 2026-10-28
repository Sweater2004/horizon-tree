"""
Миграция БД v5.0: топология, версии карт, история проверок, настройки.
Совместима с существующей схемой v4.0 (не ломает её).
"""
import sqlite3
import json
from datetime import datetime


def migrate_v5(conn: sqlite3.Connection):
    """Миграция v5.0 — добавляет таблицы для топологии."""
    cur = conn.cursor()
    
    # ============================================================
    # 1. ГЛОБАЛЬНЫЕ НАСТРОЙКИ
    # ============================================================
    cur.execute("""
    CREATE TABLE IF NOT EXISTS global_settings(
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT,
        updated_by TEXT
    )
    """)
    
    # Дефолтные настройки (INSERT OR IGNORE — не перезаписываем существующие)
    now = datetime.now().isoformat()
    defaults = [
        ('allowed_subnets', json.dumps(["192.168.178.0/24"])),
        ('snmp_default_community', json.dumps("public")),
        ('snmp_default_version', json.dumps("2c")),
        ('scan_timeout', json.dumps(5)),
        ('max_hops', json.dumps(10)),
        ('max_devices_per_scan', json.dumps(500)),
    ]
    for key, value in defaults:
        cur.execute("""
            INSERT OR IGNORE INTO global_settings (key, value, updated_at)
            VALUES (?, ?, ?)
        """, (key, value, now))
    
    # ============================================================
    # 2. РАСШИРЕНИЕ ТАБЛИЦЫ maps
    # ============================================================
    cur.execute("PRAGMA table_info(network_maps)")
    columns = {row[1] for row in cur.fetchall()}
    
    if 'allowed_subnets' not in columns:
        cur.execute("ALTER TABLE network_maps ADD COLUMN allowed_subnets TEXT")
    if 'current_version' not in columns:
        cur.execute("ALTER TABLE network_maps ADD COLUMN current_version INTEGER DEFAULT 1")
    
    # ============================================================
    # 3. ВЕРСИИ КАРТ (для отката)
    # ============================================================
    cur.execute("""
    CREATE TABLE IF NOT EXISTS map_versions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        map_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        data TEXT NOT NULL,
        created_at TEXT,
        created_by TEXT,
        comment TEXT,
        FOREIGN KEY(map_id) REFERENCES network_maps(id) ON DELETE CASCADE,
        UNIQUE(map_id, version)
    )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_versions_map ON map_versions(map_id, version)")
    
    # ============================================================
    # 4. ИСТОРИЯ ПРОВЕРОК (по каждому методу отдельно)
    # ============================================================
    cur.execute("""
    CREATE TABLE IF NOT EXISTS check_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        map_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        check_type TEXT NOT NULL,
        status TEXT NOT NULL,
        latency REAL,
        details TEXT,
        timestamp TEXT NOT NULL
    )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ch_map_node ON check_history(map_id, node_id, timestamp)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ch_type ON check_history(check_type, timestamp)")
    
    # ============================================================
    # 5. ЗАДАЧИ СКАНИРОВАНИЯ (async jobs)
    # ============================================================
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_jobs(
        id TEXT PRIMARY KEY,
        map_id TEXT NOT NULL,
        status TEXT NOT NULL,
        progress INTEGER DEFAULT 0,
        result TEXT,
        error TEXT,
        created_at TEXT,
        created_by TEXT,
        finished_at TEXT
    )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_jobs_map ON scan_jobs(map_id, created_at)")
    
    conn.commit()
    print("✅ Миграция v5.0 выполнена")
def migrate_v6(conn):
    """v6.0: физические устройства и интерфейсы."""
    cur = conn.cursor()

    # ====== УСТРОЙСТВА (один роутер = много IP) ======
    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        map_id TEXT NOT NULL,
        name TEXT,
        type TEXT DEFAULT 'unknown',
        vendor TEXT,
        model TEXT,
        notes TEXT,
        metadata TEXT,
        created_at TEXT,
        updated_at TEXT,
        FOREIGN KEY(map_id) REFERENCES network_maps(id) ON DELETE CASCADE
    )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_devices_map ON devices(map_id)")

    # ====== ИНТЕРФЕЙСЫ (IP-адреса устройства) ======
    cur.execute("""
    CREATE TABLE IF NOT EXISTS interfaces (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        name TEXT,
        ip_address TEXT,
        mac TEXT,
        media TEXT DEFAULT 'unknown',
        speed TEXT,
        vlan TEXT,
        notes TEXT,
        metadata TEXT,
        created_at TEXT,
        FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ifaces_device ON interfaces(device_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ifaces_ip ON interfaces(ip_address)")

    conn.commit()
    print("✅ Миграция v6.0 выполнена")