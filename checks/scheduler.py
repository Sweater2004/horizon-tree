"""
Фоновый планировщик проверок.
Каждые N секунд проверяет все узлы всех карт и обновляет статусы.
"""
import json
import sys          
import sqlite3
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

from . import run_check


# Интервал по умолчанию (сек)
DEFAULT_INTERVAL = 30

# Глобальный флаг для остановки
_stop_event = threading.Event()


def print_error(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs, flush=True)

def print_info(*args, **kwargs):
    print(*args, **kwargs, flush=True)

def _aggregate_status(statuses: List[str]) -> str:
    """Агрегирует статусы нескольких проверок в один."""
    if not statuses:
        return "unknown"
    online = statuses.count("online")
    offline = statuses.count("offline")
    if online == len(statuses):
        return "online"
    if offline == len(statuses):
        return "offline"
    if online > 0:
        return "mixed"
    return "unknown"



def _check_node(node: dict, map_id: str, conn: sqlite3.Connection) -> dict:
    """Проверяет ВСЕ интерфейсы узла. Статус = online, если хотя бы один IP online."""
    # Получаем список IP для проверки
    interfaces = node.get("interfaces") or []
    if not interfaces:
        ip_raw = node.get("ip", "")
        interfaces = [ip.strip() for ip in ip_raw.split(",") if ip.strip()]
    
    if not interfaces:
        return node
    
    checks = node.get("checks", [])
    if not checks:
        return node

    status_map = {}  # {"icmp:10.1.1.1": {"status": ..., "latency": ...}, ...}
    ip_statuses = []  # статусы по IP (для агрегации)
    now = datetime.now().isoformat()
    cur = conn.cursor()

    print_info(f"🔍 Проверка узла: {node.get('name') or node.get('id')} (IP: {len(interfaces)})")

    for ip in interfaces:
        for check in checks:
            if not check.get("enabled", True):
                continue
            try:
                result = run_check(check, ip)
            except Exception as e:
                result = {"status": "error", "latency": 0, "error": str(e)}

            ctype = check.get("type", "unknown")
            port = check.get("port")
            check_key = f"{ctype}_{port}" if port else ctype
            key = f"{ip}::{check_key}"  # уникальный ключ: "10.1.1.1::icmp"
            
            raw_status = result.get("status", "error")
            
            status_map[key] = {
                "ip": ip,
                "check_type": check_key,
                "status": raw_status,
                "latency": result.get("latency", 0),
                "last_check": now
            }
            ip_statuses.append(raw_status)

            # Логируем
            status_icon = {"online": "🟢", "offline": "🔴", "timeout": "🟡", "error": "❌"}.get(raw_status, "⚪")
            latency = result.get("latency", 0)
            msg = f"   {status_icon} {ip} [{check_key}] → {raw_status} ({latency} ms)"
            
            if raw_status in ("offline", "error", "timeout"):
                print_error(msg)
            else:
                print_info(msg)

            # В историю
            cur.execute("""
                INSERT INTO check_history
                (map_id, node_id, check_type, status, latency, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                map_id, node.get("id"), f"{ip}:{check_key}",
                raw_status, result.get("latency", 0),
                json.dumps(result.get("error")) if result.get("error") else None,
                now
            ))

    conn.commit()

    node["status"] = status_map
    node["aggregated_status"] = _aggregate_status(ip_statuses)
    node["updated_at"] = now

    # Итоговый статус
    agg = node["aggregated_status"]
    agg_icon = {"online": "🟢", "offline": "🔴", "mixed": "🟡", "unknown": "⚪"}.get(agg, "⚪")
    msg = f"   {agg_icon} Итог: {agg} ({ip_statuses.count('online')}/{len(ip_statuses)} online)"
    
    if agg in ("offline", "mixed"):
        print_error(msg)
    else:
        print_info(msg)

    return node

def _process_map(map_row: tuple, conn: sqlite3.Connection, batch_write: list):
    """Обрабатывает одну карту."""
    map_id, data_json = map_row
    try:
        graph = json.loads(data_json)
    except Exception:
        return

    nodes = graph.get("nodes", [])
    if not nodes:
        return

    for node in nodes:
        # Пропускаем отключённые проверки
        if not node.get("checks"):
            continue
        _check_node(node, map_id, conn)

    # Обновляем граф
    graph["updated_at"] = datetime.now().isoformat()
    batch_write.append((json.dumps(graph, ensure_ascii=False), map_id))


def run_once(interval_limit: int = 60):
    """Один проход по всем картам (кроме композиций)."""
    conn = sqlite3.connect(DB_PATH := _get_db_path())
    cur = conn.cursor()
    
    # Берем ВСЕ карты, кроме композиций
    cur.execute("SELECT id, data FROM network_maps")
    all_maps = cur.fetchall()
    
    maps = []
    for map_row in all_maps:
        map_id, data_json = map_row
        try:
            data = json.loads(data_json)
            if data.get("settings", {}).get("is_composite"):
                continue
            maps.append(map_row)
        except Exception:
            pass
    
    print_info(f"🎯 Планировщик: проверяем {len(maps)} карт (композиции пропущены)")

    batch_write = []
    total_nodes = 0
    
    for map_row in maps:
        _process_map(map_row, conn, batch_write)
        try:
            graph = json.loads(map_row[1])
            total_nodes += len(graph.get("nodes", []))
        except Exception:
            pass
    
    for data_json, map_id in batch_write:
        cur.execute(
            "UPDATE network_maps SET data = ?, updated_at = ? WHERE id = ?",
            (data_json, datetime.now().isoformat(), map_id)
        )
    conn.commit()
    conn.close()
    
    print_info(f"✅ Планировщик: проверено {len(maps)} карт, {total_nodes} узлов")
    return {"maps": len(maps), "nodes": total_nodes}

def _get_db_path() -> str:
    """Импортируем DB_PATH из app.py (чтобы не дублировать)."""
    import app
    return app.DB_PATH


def _loop(interval: int):
    """Основной цикл планировщика."""
    print_info(f"⏰ Планировщик проверок запущен (интервал {interval}с)")
    while not _stop_event.is_set():
        try:
            result = run_once()
            print_info(f"🔍 Проверено: {result['maps']} карт, {result['nodes']} узлов")
        except Exception as e:
            print_error(f"❌ Ошибка планировщика: {e}")

        # Ждём interval секунд (но проверяем stop_event каждую секунду)
        for _ in range(interval):
            if _stop_event.is_set():
                break
            time.sleep(1)

    print("⏹️ Планировщик остановлен")


def start(interval: int = DEFAULT_INTERVAL):
    """Запускает планировщик в фоновом потоке."""
    _stop_event.clear()
    thread = threading.Thread(target=_loop, args=(interval,), daemon=True)
    thread.start()
    return thread


def stop():
    """Останавливает планировщик."""
    _stop_event.set()
