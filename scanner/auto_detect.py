"""
Автоматическое определение типа устройства и проверка SNMP.
Использует эвристики:
- 172.16-31.x.x — транспортная сеть (обычно роутеры).
- 10.x.x.x — корпоративная сеть.
- Первый хоп traceroute — шлюз.
- Устройства, через которые идёт большинство путей — роутеры.
"""
import re
import ipaddress
from typing import List, Dict, Optional


def guess_device_type(ip: str, is_first_hop: bool = False, path_count: int = 0) -> str:
    """
    Угадывает тип устройства по IP и контексту.
    
    is_first_hop: устройство — первый хоп traceroute (шлюз).
    path_count: сколько путей проходит через это устройство.
    """
    # 1. Приватные диапазоны
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"

    # 172.16.0.0/12 — транспортная сеть (обычно роутеры)
    if addr in ipaddress.ip_network("172.16.0.0/12"):
        return "router"

    # 10.0.0.0/8 — корпоративная сеть (может быть что угодно)
    if addr in ipaddress.ip_network("10.0.0.0/8"):
        # Если это первый хоп или через него идёт много путей — роутер
        if is_first_hop or path_count > 1:
            return "router"
        return "server"

    # 192.168.0.0/16 — домашняя сеть (роутер = .1)
    if addr in ipaddress.ip_network("192.168.0.0/16"):
        if ip.endswith(".1"):
            return "router"
        return "pc"

    # 127.0.0.0/8 — localhost
    if addr in ipaddress.ip_network("127.0.0.0/8"):
        return "server"

    return "unknown"


def enrich_with_snmp(devices: List[Dict], community: str = "public", timeout: int = 1) -> List[Dict]:
    """
    Автоматически проверяет все устройства на SNMP.
    Добавляет поля: snmp_capable, snmp_name, snmp_descr, snmp_uptime, snmp_location.
    """
    try:
        from scanner.snmp_walk import snmp_get
    except ImportError:
        return devices

    for dev in devices:
        try:
            result = snmp_get(dev["ip"], community=community, timeout=timeout)
            if result:
                dev["snmp_capable"] = True
                dev["snmp_name"] = result.get("name")
                dev["snmp_descr"] = result.get("descr")
                dev["snmp_uptime"] = result.get("uptime")
                dev["snmp_location"] = result.get("location")

                # Если SNMP вернул имя — используем его как имя устройства
                if result.get("name") and not dev.get("name"):
                    dev["name"] = result["name"]

                # Если sysDescr содержит "router", "switch", "Cisco" — уточняем тип
                descr = (result.get("descr") or "").lower()
                if any(word in descr for word in ["router", "ios", "routeros", "mikrotik"]):
                    dev["type"] = "router"
                elif any(word in descr for word in ["switch", "catalyst", "nexus"]):
                    dev["type"] = "switch"
                elif any(word in descr for word in ["linux", "windows", "server"]):
                    dev["type"] = "server"
        except Exception:
            dev["snmp_capable"] = False

    return devices


def detect_roles_from_traceroutes(
    devices: List[Dict],
    traceroute_results: Dict[str, List[Dict]]
) -> List[Dict]:
    """
    Определяет роли устройств на основе traceroute:
    - Первый хоп — шлюз (router).
    - Устройства, через которые идёт много путей — router.
    """
    # Считаем, сколько путей проходит через каждое устройство
    path_count = {}
    first_hops = set()

    for target_ip, path in traceroute_results.items():
        for i, hop in enumerate(path):
            hop_ip = hop.get("ip")
            if not hop_ip:
                continue
            path_count[hop_ip] = path_count.get(hop_ip, 0) + 1
            if i == 0:
                first_hops.add(hop_ip)

    # Обновляем типы устройств
    for dev in devices:
        ip = dev["ip"]
        if ip in first_hops:
            dev["type"] = "router"
            dev["role"] = "gateway"
        elif path_count.get(ip, 0) > 2:
            dev["type"] = "router"
            dev["role"] = "core"
        elif path_count.get(ip, 0) > 0:
            dev["type"] = "switch"
            dev["role"] = "transit"

        # Если тип не определён — угадываем по IP
        if dev.get("type") in (None, "unknown", ""):
            dev["type"] = guess_device_type(
                ip,
                is_first_hop=ip in first_hops,
                path_count=path_count.get(ip, 0)
            )

    return devices
def detect_multi_ip_devices(devices: List[Dict], traceroute_results: Dict[str, List[Dict]]) -> List[Dict]:
    """
    Эвристика: определяет, какие IP принадлежат одному устройству.
    1. Совпадение MAC-адреса.
    2. Два IP всегда идут подряд в traceroute (например, вход и выход из роутера).
    """
    groups = []

    # 1. По MAC-адресу
    by_mac = {}
    for d in devices:
        mac = (d.get("mac") or "").upper()
        if mac and not mac.startswith("FF:FF"):
            by_mac.setdefault(mac, []).append(d["ip"])
    
    for mac, ips in by_mac.items():
        if len(ips) > 1:
            groups.append({"reason": f"MAC: {mac}", "ips": ips})

    # 2. По traceroute (идут подряд)
    pair_counts = {}
    for target, path in traceroute_results.items():
        for i in range(len(path) - 1):
            a = path[i].get("ip")
            b = path[i+1].get("ip")
            if a and b and a != b:
                pair = tuple(sorted([a, b]))  # a,b и b,a — это одна пара
                pair_counts[pair] = pair_counts.get(pair, 0) + 1

    # Если два IP встречаются вместе на пути больше 2 раз — это хоп-ту-хоп
    for pair, count in pair_counts.items():
        if count >= 2:
            groups.append({"reason": f"Traceroute (встречаются {count} раз)", "ips": list(pair)})

    # Убираем дубли
    unique_groups = []
    seen = set()
    for g in groups:
        key = tuple(sorted(g["ips"]))
        if key not in seen:
            seen.add(key)
            unique_groups.append(g)

    return unique_groups

def group_by_second_hop(traceroute_results: Dict[str, List[Dict]], root_ip: str) -> List[List[str]]:
    """
    Если LLDP и SSH не помогли, считаем, что все IP, которые идут 
    ВТОРЫМ хопом в traceroute, принадлежат одному устройству (коммутатору).
    Логика: трафик до всех устройств проходит через этот узел, значит, это их общий шлюз.
    """
    second_hop_ips = set()
    targets_behind = {}
    
    for target_ip, path in traceroute_results.items():
        if not path or len(path) < 2:
            continue
        
        # Берем второй хоп (индекс 1)
        hop1 = path[1] if len(path) > 1 else None
        if hop1 and hop1.get("ip") and hop1["ip"] != root_ip:
            hop_ip = hop1["ip"]
            second_hop_ips.add(hop_ip)
            if hop_ip not in targets_behind:
                targets_behind[hop_ip] = []
            targets_behind[hop_ip].append(target_ip)
    
    # Группируем: для каждого второго хопа собираем всех, кто за ним
    groups = []
    for hop_ip, targets in targets_behind.items():
        if len(targets) >= 2:  # Если за ним есть хотя бы 2 устройства
            groups.append([hop_ip] + targets)
    
    return groups
def group_by_gateway(traceroute_results: Dict[str, List[Dict]], root_ip: str) -> List[List[str]]:
    """
    Если traceroute до разных целей идёт через один и тот же первый хоп (шлюз),
    и после него сразу цель (нет других видимых хопов), то эти цели — 
    IP-адреса самого шлюза. Группируем их вместе с шлюзом.
    """
    gateway_groups = {}  # gateway_ip -> [target1, target2, ...]
    
    for target_ip, path in traceroute_results.items():
        if not path or len(path) < 2:
            continue
        
        # Берем только видимые хопы
        visible = [h.get("ip") for h in path if h.get("ip")]
        if len(visible) < 2:
            continue
        
        # Первый видимый хоп — это шлюз (если это не сам root)
        gateway = visible[0]
        if gateway == root_ip:
            # Если root — это первый, то шлюз = root, а цель = visible[1]
            if len(visible) >= 2:
                target = visible[1]
                if target != root_ip:
                    gateway_groups.setdefault(root_ip, []).append(target)
        else:
            # Если шлюз не root, значит root был скрыт, а шлюз — visible[0]
            if len(visible) >= 2:
                target = visible[1]
                if target != gateway:
                    gateway_groups.setdefault(gateway, []).append(target)
    
    # Формируем группы: [шлюз] + [цели]
    groups = []
    for gw, targets in gateway_groups.items():
        if len(targets) >= 2:
            groups.append([gw] + targets)
    
    return groups