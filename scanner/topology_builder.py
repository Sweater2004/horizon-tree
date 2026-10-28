"""
Построение топологии (JSON-граф) на основе ARP + traceroute + LLDP.
Логика:
1. Корень — root_ip.
2. Traceroute строит цепочки (родитель -> ребенок).
3. ARP-устройства без traceroute привязываются к корню.
4. LLDP добавляет достоверные связи между устройствами.
"""
import ipaddress
import uuid
from datetime import datetime
from typing import List, Dict, Optional


def _node_id(ip: str) -> str:
    return f"node-{ip.replace('.', '-')}"


def _edge_id(src_id: str, dst_id: str) -> str:
    return f"edge-{src_id}-{dst_id}"


def _check_id() -> str:
    return f"chk-{uuid.uuid4().hex[:12]}"


def _is_in_whitelist(ip: str, allowed_subnets: List[str]) -> bool:
    if not allowed_subnets:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for subnet in allowed_subnets:
        try:
            if addr in ipaddress.ip_network(subnet, strict=False):
                return True
        except ValueError:
            continue
    return False


def _default_checks() -> List[Dict]:
    return [{"id": _check_id(), "type": "icmp", "enabled": True, "timeout": 2}]


def _new_node(
    ip: str,
    name: Optional[str] = None,
    node_type: str = "unknown",
    parent_id: Optional[str] = None,
    hops: int = 0,
    is_root: bool = False,
    discovered_by: Optional[List[str]] = None,
    metadata: Optional[Dict] = None,
    in_whitelist: bool = True,
    now: Optional[str] = None
) -> Dict:
    now = now or datetime.now().isoformat()
    return {
        "id": _node_id(ip),
        "ip": ip,
        "name": name or ip,
        "type": node_type,
        "interfaces": [ip],  
        "discovered_by": discovered_by or ["arp"],
        "parent_id": parent_id,
        "hops_from_root": hops,
        "is_root": is_root,
        "metadata": metadata or {},
        "checks": _default_checks(),
        "status": {},
        "aggregated_status": "unknown",
        "is_outside_whitelist": not in_whitelist,
        "created_at": now,
        "updated_at": now,
    }


def build_topology(
    root_ip: str,
    hops: int,
    arp_devices: List[Dict],
    traceroute_results: Dict[str, List[Dict]],
    allowed_subnets: List[str],
    lldp_map: Dict[str, List[Dict]] = None,
    max_devices: int = 500
) -> Dict:
    """
    Строит JSON-граф топологии на основе traceroute (цепочки) и ARP.
    """
    now = datetime.now().isoformat()
    nodes: Dict[str, Dict] = {}
    edges: List[Dict] = []

    # ====== КОРЕНЬ ======
    root_in_wl = _is_in_whitelist(root_ip, allowed_subnets)
    root_node = _new_node(
        ip=root_ip,
        name=root_ip,
        node_type="router",
        parent_id=None,
        hops=0,
        is_root=True,
        discovered_by=["icmp"],
        in_whitelist=root_in_wl,
        now=now
    )
    nodes[root_node["id"]] = root_node
    print(f"🌱 Корень: {root_ip} (whitelist: {'да' if root_in_wl else 'НЕТ'})")

    # ============================================================
    # 1. СТРОИМ ЦЕПОЧКИ ИЗ TRACEROUTE
    # ============================================================
    # Сортируем пути: сначала более длинные, чтобы промежуточные узлы
    # (например, 10.187.185.129) создались до конечных.
    sorted_paths = sorted(
        traceroute_results.items(),
        key=lambda x: len(x[1]) if x[1] else 0,
        reverse=True
    )

    for target_ip, path in sorted_paths:
        if target_ip == root_ip:
            continue
        if not path or len(path) < 2:
            continue

        # Берем только видимые хопы (игнорируем "None" / скрытые)
        visible_hops = [h.get("ip") for h in path if h.get("ip")]
        # Убираем root_ip из всех хопов (чтобы не было петли 5→5)
        visible_hops = [h for h in visible_hops if h != root_ip]

        # ВСЕГДА создаём ребро root → первый видимый хоп (если он не root)
        if visible_hops:
            first_hop = visible_hops[0]
            first_id = _node_id(first_hop)
            if first_id not in nodes:
                first_dev = next((d for d in arp_devices if d["ip"] == first_hop), {})
                nodes[first_id] = _new_node(
                    ip=first_hop,
                    name=first_dev.get("vendor") or first_dev.get("name") or first_hop,
                    node_type="switch",
                    parent_id=root_node["id"],
                    hops=1,
                    discovered_by=["traceroute"],
                    metadata={"mac": first_dev.get("mac", ""), "vendor": first_dev.get("vendor", "")},
                    in_whitelist=_is_in_whitelist(first_hop, allowed_subnets),
                    now=now
                )
            edge_exists = any(e["source"] == root_node["id"] and e["target"] == first_id for e in edges)
            if not edge_exists:
                edges.append({
                    "id": _edge_id(root_node["id"], first_id),
                    "source": root_node["id"],
                    "target": first_id,
                    "type": "parent-child",
                    "discovered_by": "traceroute",
                    "note": "",
                    "created_at": now
                })

        # Проходим по цепочке и строим связи родитель -> ребенок
        for i in range(len(visible_hops) - 1):
            src_ip = visible_hops[i]
            dst_ip = visible_hops[i + 1]

            # Пропускаем, если dst — это корень (он уже создан)
            if dst_ip == root_ip:
                continue

            src_id = _node_id(src_ip) if src_ip != root_ip else root_node["id"]
            dst_id = _node_id(dst_ip)

            # Создаем узел-источник, если его нет
            if src_id not in nodes:
                src_dev = next((d for d in arp_devices if d["ip"] == src_ip), {})
                src_parent = root_node["id"]
                src_hops = 1
                
                # Если у src уже есть запись в каком-то пути — берем parent оттуда
                for h in path:
                    if h.get("ip") == src_ip:
                        idx = path.index(h)
                        if idx > 0 and path[idx - 1].get("ip"):
                            prev_ip = path[idx - 1]["ip"]
                            if prev_ip == root_ip:
                                src_parent = root_node["id"]
                            elif _node_id(prev_ip) in nodes:
                                src_parent = _node_id(prev_ip)
                        break

                nodes[src_id] = _new_node(
                    ip=src_ip,
                    name=src_dev.get("vendor") or src_dev.get("name") or src_ip,
                    node_type="switch" if src_ip != root_ip else "router",
                    parent_id=src_parent,
                    hops=nodes[src_parent].get("hops_from_root", 0) + 1 if src_parent in nodes else 1,
                    discovered_by=["traceroute"],
                    metadata={"mac": src_dev.get("mac", ""), "vendor": src_dev.get("vendor", "")},
                    in_whitelist=_is_in_whitelist(src_ip, allowed_subnets),
                    now=now
                )

            # Создаем узел-назначение, если его нет
            if dst_id not in nodes:
                dst_dev = next((d for d in arp_devices if d["ip"] == dst_ip), {})
                nodes[dst_id] = _new_node(
                    ip=dst_ip,
                    name=dst_dev.get("vendor") or dst_dev.get("name") or dst_ip,
                    node_type="unknown",
                    parent_id=src_id,
                    hops=nodes[src_id].get("hops_from_root", 1) + 1,
                    discovered_by=["traceroute", "arp"],
                    metadata={"mac": dst_dev.get("mac", ""), "vendor": dst_dev.get("vendor", "")},
                    in_whitelist=_is_in_whitelist(dst_ip, allowed_subnets),
                    now=now
                )

            # Создаем ребро
            edge_exists = any(e["source"] == src_id and e["target"] == dst_id for e in edges)
            if not edge_exists:
                edges.append({
                    "id": _edge_id(src_id, dst_id),
                    "source": src_id,
                    "target": dst_id,
                    "type": "parent-child",
                    "discovered_by": "traceroute",
                    "note": "",
                    "created_at": now
                })

    # ============================================================
    # 2. ARP-УСТРОЙСТВА БЕЗ TRACEROUTE
    # ============================================================
    for dev in arp_devices:
        ip = dev["ip"]
        if ip == root_ip:
            continue
        node_id = _node_id(ip)
        if node_id in nodes:
            continue  # уже создан в проходе 1

        in_wl = _is_in_whitelist(ip, allowed_subnets)
        nodes[node_id] = _new_node(
            ip=ip,
            name=dev.get("vendor") or ip,
            node_type="unknown",
            parent_id=root_node["id"],
            hops=1,
            discovered_by=["arp"],
            metadata={"mac": dev.get("mac", ""), "vendor": dev.get("vendor", "")},
            in_whitelist=in_wl,
            now=now
        )
        edges.append({
            "id": _edge_id(root_node["id"], node_id),
            "source": root_node["id"],
            "target": node_id,
            "type": "parent-child",
            "discovered_by": "arp",
            "note": "",
            "created_at": now
        })

    # ============================================================
    # 3. LLDP-СВЯЗИ
    # ============================================================
    if lldp_map:
        for src_ip, neighbors in lldp_map.items():
            src_node = nodes.get(_node_id(src_ip))
            if not src_node:
                continue
            for n in neighbors:
                rem_name = n.get("remote_name")
                if not rem_name:
                    continue
                target_ip = None
                for d in arp_devices:
                    if d.get("vendor") == rem_name or d.get("name") == rem_name or d.get("ip") == rem_name:
                        target_ip = d["ip"]
                        break
                if not target_ip and "." in rem_name:
                    target_ip = rem_name
                if target_ip and _node_id(target_ip) in nodes:
                    src_id = _node_id(src_ip)
                    tgt_id = _node_id(target_ip)
                    edge_exists = any(
                        (e["source"] == src_id and e["target"] == tgt_id) or
                        (e["source"] == tgt_id and e["target"] == src_id)
                        for e in edges
                    )
                    if not edge_exists:
                        edges.append({
                            "id": _edge_id(src_id, tgt_id),
                            "source": src_id,
                            "target": tgt_id,
                            "type": "lldp",
                            "discovered_by": "lldp",
                            "note": f"Порт: {n.get('local_port')}",
                            "created_at": now
                        })
                        print(f"  🔗 LLDP-связь: {src_ip} -> {target_ip}")

    # ====== УБИРАЕМ ПЕТЛИ (source == target) ======
    edges = [e for e in edges if e["source"] != e["target"]]

    print(f"🌳 Узлов: {len(nodes)}, рёбер: {len(edges)}")
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "settings": {"auto_refresh": True, "refresh_interval": 30},
        "created_at": now,
        "updated_at": now
    }