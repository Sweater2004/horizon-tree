"""
Сканирование подсети: ARP + ICMP в двух потоках, плюс Nmap.
"""
import subprocess
import re
import ipaddress
import shutil
import threading
from typing import List, Dict

ARP_BIN = "/usr/sbin/arp"
IP_BIN = "/usr/bin/ip"

def _run(cmd: List[str], timeout: int = 60) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, encoding='utf-8', errors='ignore'
        )
        return result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""

def _scan_arp(subnet: str, timeout: int, result: list):
    devices = {}
    if shutil.which("arp-scan"):
        try:
            iface_out = _run(["ip", "route", "get", subnet.split('/')[0]], timeout=5)
            m = re.search(r'dev (\S+)', iface_out)
            iface = m.group(1) if m else "eno2"
            out = _run(["arp-scan", f"--interface={iface}", subnet, "--quiet"], timeout=timeout)
            for line in out.splitlines():
                mm = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)', line)
                if mm:
                    devices[mm.group(1)] = {
                        "ip": mm.group(1), "mac": mm.group(2).upper(),
                        "vendor": mm.group(3).strip(), "discovered_by": "arp-scan"
                    }
        except Exception:
            pass
    
    out = _run([IP_BIN, "neigh"], timeout=10)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3: continue
        ip = parts[0]
        if ":" in ip: continue
        mac = None
        if "lladdr" in parts:
            idx = parts.index("lladdr")
            if idx + 1 < len(parts): mac = parts[idx + 1].upper()
        if not mac or mac.startswith("FF:FF:FF") or mac.startswith("01:00:5E"): continue
        if ip not in devices:
            devices[ip] = {"ip": ip, "mac": mac, "vendor": "", "discovered_by": "arp"}
    
    if not devices:
        out = _run([ARP_BIN, "-an"], timeout=10)
        for line in out.splitlines():
            mm = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})', line)
            if mm:
                ip, mac = mm.group(1), mm.group(2).upper()
                if mac.startswith("FF:FF:FF") or mac.startswith("01:00:5E"): continue
                devices[ip] = {"ip": ip, "mac": mac, "vendor": "", "discovered_by": "arp"}
    result.extend(devices.values())

def _scan_icmp(subnet: str, timeout: int, result: list):
    devices = {}
    if shutil.which("fping"):
        out = _run(["fping", "-a", "-g", subnet, "-t", "500"], timeout=timeout)
        for line in out.splitlines():
            ip = line.strip()
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                devices[ip] = {"ip": ip, "mac": "", "vendor": "", "discovered_by": "icmp"}
    
    if not devices:
        out = _run(["nmap", "-sn", subnet], timeout=timeout)
        for line in out.splitlines():
            mm = re.search(r'Nmap scan report for (?:\S+ )?\(?(\d+\.\d+\.\d+\.\d+)\)?', line)
            if mm:
                ip = mm.group(1)
                devices[ip] = {"ip": ip, "mac": "", "vendor": "", "discovered_by": "icmp"}
    result.extend(devices.values())

def scan_subnet(subnet: str, timeout: int = 120) -> List[Dict]:
    print(f"🔍 Сканирование {subnet} (ARP + ICMP в параллель)...")
    arp_result, icmp_result = [], []
    
    t_arp = threading.Thread(target=_scan_arp, args=(subnet, timeout, arp_result))
    t_icmp = threading.Thread(target=_scan_icmp, args=(subnet, timeout, icmp_result))
    t_arp.start(); t_icmp.start()
    t_arp.join(); t_icmp.join()
    
    print(f"  ARP: {len(arp_result)} устройств")
    print(f"  ICMP: {len(icmp_result)} устройств")
    
    found: Dict[str, Dict] = {}
    for dev in arp_result + icmp_result:
        ip = dev["ip"]
        if ip not in found: found[ip] = dev
        else:
            if not found[ip].get("mac") and dev.get("mac"): found[ip]["mac"] = dev["mac"]
            if not found[ip].get("vendor") and dev.get("vendor"): found[ip]["vendor"] = dev["vendor"]
    
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return list(found.values())
    
    filtered = [dev for ip, dev in found.items() if ipaddress.ip_address(ip) in network]
    print(f"✅ Итого: {len(filtered)} устройств в {subnet}")
    return filtered

def scan_with_nmap(subnet: str, timeout: int = 120) -> List[Dict]:
    """Использует nmap для поиска хостов и определения топологии через TCP-пинг."""
    print(f"🔍 Nmap-сканирование {subnet}...")
    devices = {}
    try:
        cmd = [ "nmap", "-sn", "-PS22,80,443", "-PA80,443", "--traceroute", "-n", "--max-retries", "1", subnet]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        print("⚠️ nmap timeout")
        return []
    except FileNotFoundError:
        print("⚠️ nmap не установлен (sudo apt install nmap)")
        return []

    lines = output.splitlines()
    for i, line in enumerate(lines):
        m = re.search(r'Nmap scan report for (\S+)', line)
        if m:
            ip = m.group(1)
            devices[ip] = {"ip": ip, "mac": "", "vendor": "", "discovered_by": "nmap"}
        mac_m = re.search(r'MAC Address: ([0-9A-F:]{17}) \((.+?)\)', line)
        if mac_m:
            last_ip = list(devices.keys())[-1] if devices else None
            if last_ip:
                devices[last_ip]["mac"] = mac_m.group(1)
                devices[last_ip]["vendor"] = mac_m.group(2)

    print(f"✅ Nmap нашел {len(devices)} хостов")
    return list(devices.values())

def ping_with_ttl(ip: str, timeout: int = 1) -> dict:
    """Возвращает {'alive': bool, 'ttl': int, 'rtt': float}."""
    import subprocess
    import re
    try:
        # -c 1 (1 пакет), -W timeout (сек)
        res = subprocess.run(["ping", "-c", "1", "-W", str(timeout), ip], 
                             capture_output=True, text=True, timeout=timeout + 2)
        if res.returncode != 0:
            return {"alive": False, "ttl": None, "rtt": None}
        
        # Ищем ttl=64 в выводе
        ttl_match = re.search(r'ttl=(\d+)', res.stdout)
        rtt_match = re.search(r'time=([\d.]+)', res.stdout)
        
        return {
            "alive": True,
            "ttl": int(ttl_match.group(1)) if ttl_match else None,
            "rtt": float(rtt_match.group(1)) if rtt_match else None
        }
    except Exception:
        return {"alive": False, "ttl": None, "rtt": None}