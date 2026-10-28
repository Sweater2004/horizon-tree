"""
Сбор "отпечатков" IP-адресов для склейки в устройства.
Использует только стандартную библиотеку (SSH, TLS).
TCP Timestamp (scapy) — опционально, если сервер запущен от root.
"""
import hashlib
import socket
import ssl
import subprocess


def get_ssh_fingerprint(ip: str, timeout: int = 3) -> str | None:
    """Возвращает отпечаток SSH-ключа или None."""
    try:
        out = subprocess.run(
            ["ssh-keyscan", "-T", str(timeout), "-t", "rsa,ed25519,ecdsa", ip],
            capture_output=True, text=True, timeout=timeout + 2
        ).stdout
        if not out.strip():
            return None
        keys = subprocess.run(
            ["ssh-keygen", "-lf", "-"], input=out,
            capture_output=True, text=True, timeout=5
        ).stdout
        fps = sorted({line.split()[1] for line in keys.splitlines() if len(line.split()) > 1})
        return ",".join(fps) if fps else None
    except Exception:
        return None


def get_tls_fingerprint(ip: str, timeout: int = 3) -> str | None:
    """Возвращает SHA-256 сертификата или None."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                der = tls.getpeercert(binary_form=True)
                if not der:
                    return None
                return hashlib.sha256(der).hexdigest()
    except Exception:
        return None


def fingerprint_ip(ip: str) -> dict:
    """Возвращает отпечатки для одного IP."""
    return {
        "ip": ip,
        "ssh": get_ssh_fingerprint(ip),
        "tls": get_tls_fingerprint(ip),
    }


def group_by_fingerprints(items: list[dict]) -> tuple[list[list[str]], list[tuple]]:
    """
    Группирует IP по совпадению SSH/TLS отпечатков.
    Возвращает (группы_IP, улики).
    """
    n = len(items)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    evidence = []

    for i in range(n):
        for j in range(i + 1, n):
            a, b = items[i], items[j]
            if a["ssh"] and a["ssh"] == b["ssh"]:
                union(i, j)
                evidence.append((a["ip"], b["ip"], f"SSH: {a['ssh']}"))
            if a["tls"] and a["tls"] == b["tls"]:
                union(i, j)
                evidence.append((a["ip"], b["ip"], f"TLS: {a['tls'][:16]}…"))

    groups = {}
    for i, it in enumerate(items):
        groups.setdefault(find(i), []).append(it["ip"])

    return list(groups.values()), evidence
