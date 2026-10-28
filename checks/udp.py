"""
UDP-проверка.
UDP не гарантирует ответ, поэтому используем эвристику:
- ECONNREFUSED (111) — хост жив, порт закрыт → online
- Network unreachable (101) / No route (113) → offline
- Таймаут → unknown (UDP не отвечает)
- Другие ошибки → unknown
"""
import socket
import time


def check_udp(ip: str, port: int, timeout: int = 3) -> dict:
    """
    Проверяет UDP-порт.
    
    Возвращает:
        {"status": "online"|"offline"|"unknown", "latency": float, "note": "..."}
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    
    try:
        start = time.time()
        sock.sendto(b'', (ip, port))
        
        try:
            data, _ = sock.recvfrom(1024)
            latency = (time.time() - start) * 1000
            return {"status": "online", "latency": round(latency, 2), "note": "получен ответ"}
        except socket.timeout:
            latency = (time.time() - start) * 1000
            return {"status": "unknown", "latency": round(latency, 2), "note": "таймаут (UDP не отвечает)"}
        except ConnectionRefusedError:
            latency = (time.time() - start) * 1000
            return {"status": "online", "latency": round(latency, 2), "note": "порт закрыт (ICMP unreachable)"}
        except OSError as e:
            errno = getattr(e, 'errno', None)
            latency = (time.time() - start) * 1000
            if errno == 111:
                return {"status": "online", "latency": round(latency, 2), "note": "порт закрыт"}
            if errno in (101, 113):
                return {"status": "offline", "latency": round(latency, 2), "note": f"сеть недоступна (errno={errno})"}
            return {"status": "unknown", "latency": round(latency, 2), "note": f"UDP ошибка: {e}"}
    except socket.timeout:
        return {"status": "unknown", "latency": 0, "note": "таймаут"}
    except Exception as e:
        return {"status": "unknown", "latency": 0, "note": str(e)}
    finally:
        sock.close()
