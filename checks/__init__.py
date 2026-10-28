"""
Обёртка для запуска проверок по конфигу.
Поддерживает: icmp, tcp, udp, snmp.
"""
from .icmp import check_icmp
from .tcp import check_tcp
from .udp import check_udp


def run_check(check: dict, ip: str) -> dict:
    """
    Запускает проверку по конфигу.
    
    check = {
        "type": "icmp" | "tcp" | "udp" | "snmp",
        "timeout": 3,
        "port": 22  # только для tcp/udp
    }
    """
    ctype = check.get("type")
    timeout = check.get("timeout", 3)
    
    if ctype == "icmp":
        return check_icmp(ip, timeout)
    elif ctype == "tcp":
        return check_tcp(ip, check.get("port", 80), timeout)
    elif ctype == "udp":
        return check_udp(ip, check.get("port", 53), timeout)
    elif ctype == "snmp":
        try:
            from scanner.snmp_walk import snmp_get
            result = snmp_get(ip, timeout=timeout)
            if result:
                return {"status": "online", "latency": 0}
            return {"status": "offline", "latency": 0}
        except Exception as e:
            return {"status": "unknown", "latency": 0, "note": str(e)}
    else:
        return {
            "status": "error",
            "latency": 0,
            "error": f"Unknown check type: {ctype}"
        }
