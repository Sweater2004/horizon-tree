"""
SNMP-опрос устройств через системную утилиту snmpget (net-snmp).
Работает на Astra Linux: sudo apt install snmp
Не зависит от версии pysnmp (использует subprocess).
"""
import subprocess
import shutil
from typing import Optional, Dict


# Проверка наличия snmpget
SNMPGET_BIN = shutil.which("snmpget") or "/usr/bin/snmpget"


def _run_snmpget(ip: str, oid: str, community: str, version: str, timeout: int) -> Optional[str]:
    """Запускает snmpget для одного OID. Возвращает строку или None."""
    if not shutil.which("snmpget"):
        return None

    version_flag = "-v2c" if version == "2c" else "-v1"
    cmd = [
        SNMPGET_BIN,
        version_flag,
        "-c", community,
        "-t", str(timeout),
        "-r", "1",
        "-Ovq",  # только значение, без OID
        ip,
        oid
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout + 2, encoding='utf-8', errors='ignore'
        )
        if result.returncode != 0:
            return None
        output = result.stdout.strip()
        if not output or output.startswith("No Such"):
            return None
        # Убираем кавычки, если есть
        return output.strip('"')
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def snmp_get(
    ip: str,
    community: str = "public",
    version: str = "2c",
    timeout: int = 2
) -> Optional[Dict]:
    """
    SNMP GET для базовых OID через системный snmpget.
    
    Возвращает:
        {"name": "...", "descr": "...", "uptime": "...", "location": "...", "contact": "..."}
        или None, если устройство не отвечает.
    """
    oids = {
        "name":     "1.3.6.1.2.1.1.5.0",   # sysName
        "descr":    "1.3.6.1.2.1.1.1.0",   # sysDescr
        "uptime":   "1.3.6.1.2.1.1.3.0",   # sysUpTime
        "location": "1.3.6.1.2.1.1.6.0",   # sysLocation
        "contact":  "1.3.6.1.2.1.1.4.0",   # sysContact
    }

    result = {}
    got_any = False

    for key, oid in oids.items():
        value = _run_snmpget(ip, oid, community, version, timeout)
        if value is not None:
            result[key] = value
            got_any = True

    if not got_any:
        return None

    return result


def format_uptime(ticks_str: str) -> str:
    """Преобразует sysUpTime в человеко-читаемый формат.
    Поддерживает форматы:
    - "0:0:57:55.61" (дни:часы:минуты:секунды.сотые) — от snmpget -Ovq
    - "Timeticks: (12345) 0:02:03.45"
    - "12345"
    """
    try:
        s = ticks_str.strip()
        # Убираем "Timeticks: (...) " если есть
        if "(" in s and ")" in s:
            s = s.split(")", 1)[1].strip()
        # Если формат "0:0:57:55.61" (дни:часы:минуты:секунды.сотые)
        if ":" in s:
            parts = s.split(":")
            if len(parts) >= 4:
                days = int(parts[0])
                hours = int(parts[1])
                minutes = int(parts[2])
                result_parts = []
                if days: result_parts.append(f"{days}д")
                if hours: result_parts.append(f"{hours}ч")
                if minutes: result_parts.append(f"{minutes}м")
                return " ".join(result_parts) if result_parts else "только что"
        # Иначе — просто число тиков
        ticks = int(s.split()[0])
        seconds = ticks // 100
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        result_parts = []
        if days: result_parts.append(f"{days}д")
        if hours: result_parts.append(f"{hours}ч")
        if minutes: result_parts.append(f"{minutes}м")
        return " ".join(result_parts) if result_parts else "только что"
    except (ValueError, TypeError, IndexError):
        return ticks_str or "—"

def enrich_node_metadata(node: dict, community: str = "public") -> dict:
    """
    Обогащает узел SNMP-данными, если устройство отвечает.
    Модифицирует node["metadata"] и node["name"].
    """
    ip = node.get("ip")
    if not ip:
        return node

    result = snmp_get(ip, community=community, timeout=2)
    if not result:
        return node

    meta = node.get("metadata", {}) or {}

    if result.get("descr"):
        meta["snmp_descr"] = result["descr"]
        words = result["descr"].split()
        if words:
            meta["vendor"] = words[0]

    if result.get("uptime"):
        meta["snmp_uptime"] = format_uptime(result["uptime"])

    if result.get("location"):
        meta["snmp_location"] = result["location"]

    if result.get("contact"):
        meta["snmp_contact"] = result["contact"]

    if result.get("name"):
        meta["snmp_name"] = result["name"]
        if node.get("name") in (None, "", ip):
            node["name"] = result["name"]

    node["metadata"] = meta
    node["discovered_by"] = list(set(node.get("discovered_by", []) + ["snmp"]))

    return node

def get_lldp_neighbors(ip: str, community: str = "public") -> list:
    """Возвращает список соседей LLDP для устройства по IP."""
    if not shutil.which("snmpwalk"):
        return []
    
    # OID для таблицы соседей LLDP (стандартный)
    # 1.0.8802.1.1.2.1.4.1.1.7 — lldpRemPortId
    # 1.0.8802.1.1.2.1.4.1.1.9 — lldpRemSysName
    # 1.0.8802.1.1.2.1.4.1.1.8 — lldpRemPortDesc
    try:
        cmd = ["snmpwalk", "-v2c", "-c", community, "-t", "2", "-r", "1", "-On", ip, "1.0.8802.1.1.2.1.4.1.1"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return []
        
        neighbors = {}
        for line in result.stdout.splitlines():
            # Формат: .1.0.8802.1.1.2.1.4.1.1.7.0.1.2 = STRING: "Gi0/1"
            parts = line.split(" = ")
            if len(parts) != 2: continue
            oid, val = parts[0], parts[1].replace('STRING: ', '').strip('"')
            
            # Парсим индекс (последние цифры OID)
            # OID: ...1.1.7.<timeMark>.<localPortNum>.<remIndex>
            # Нам нужны localPortNum и remIndex
            oid_parts = oid.split(".")
            if len(oid_parts) < 3: continue
            
            # Берем последние 3 цифры (timeMark, localPort, remIndex)
            try:
                rem_index = int(oid_parts[-1])
                local_port = int(oid_parts[-2])
            except ValueError:
                continue
                
            key = (local_port, rem_index)
            if key not in neighbors:
                neighbors[key] = {"local_port": local_port, "remote_name": "", "remote_port": ""}
            
            # 7 = lldpRemPortId, 9 = lldpRemSysName
            if ".1.7." in oid:
                neighbors[key]["remote_port"] = val
            elif ".1.9." in oid:
                neighbors[key]["remote_name"] = val
        
        return list(neighbors.values())
    except Exception as e:
        print(f"⚠️ LLDP ошибка для {ip}: {e}")
        return []