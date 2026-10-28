"""
Traceroute для определения пути до устройства.
Возвращает список хопов, включая скрытые (ip=None).
"""
import subprocess
import platform
import re
from typing import List, Dict


def _run(cmd: List[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, encoding='utf-8', errors='ignore'
        )
        return result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def traceroute(target: str, max_hops: int = 10, timeout: int = 30) -> List[Dict]:
    """
    Возвращает список хопов, включая скрытые (ip=None).
    Формат: [{"hop": 1, "ip": "10.0.0.1", "latency": None}, {"hop": 2, "ip": None, ...}]
    """
    system = platform.system().lower()
    
    if system == "windows":
        cmd = ["tracert", "-h", str(max_hops), "-w", "1000", "-d", target]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", target]
    
    output = _run(cmd, timeout=timeout)
    if not output:
        return []
    
    hops = []
    
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        
        # Хоп с IP: " 1  10.0.0.1  2.5 ms  2.1 ms"
        m = re.match(r'^(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+', line)
        if m:
            hops.append({
                "hop": int(m.group(1)),
                "ip": m.group(2),
                "latency": None
            })
            continue
        
        # Скрытый хоп: " 2  * * *"
        m = re.match(r'^(\d+)\s+\*\s+\*\s+\*', line)
        if m:
            hops.append({
                "hop": int(m.group(1)),
                "ip": None,
                "latency": None
            })
            continue
    
    return hops