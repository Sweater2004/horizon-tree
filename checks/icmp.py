"""
ICMP-проверка (ping).
Работает на Astra Linux без sudo (cap_net_raw на /usr/bin/ping).
"""
import subprocess
import platform
import time


def check_icmp(ip: str, timeout: int = 2) -> dict:
    """
    Проверяет доступность хоста через ICMP (ping).
    
    Возвращает:
        {"status": "online"|"offline"|"timeout"|"error", "latency": float}
    """
    system = platform.system().lower()
    
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    else:
        # Astra/Linux: ping в /usr/bin/ping (в PATH), capabilities выданы
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    
    try:
        start = time.time()
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 1
        )
        latency = (time.time() - start) * 1000
        
        if result.returncode == 0:
            return {"status": "online", "latency": round(latency, 2)}
        return {"status": "offline", "latency": 0}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "latency": 0}
    except Exception as e:
        return {"status": "error", "latency": 0, "error": str(e)}
