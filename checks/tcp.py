"""
TCP-проверка (connect).
Проверяет, открыт ли порт на хосте.
"""
import socket
import time


def check_tcp(ip: str, port: int, timeout: int = 3) -> dict:
    """
    Проверяет TCP-порт через connect.
    
    Возвращает:
        {"status": "online"|"offline"|"timeout"|"error", "latency": float}
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        start = time.time()
        result = sock.connect_ex((ip, port))
        latency = (time.time() - start) * 1000
        
        if result == 0:
            return {"status": "online", "latency": round(latency, 2)}
        return {"status": "offline", "latency": 0, "error": f"connect_ex={result}"}
    except socket.timeout:
        return {"status": "timeout", "latency": 0}
    except Exception as e:
        return {"status": "error", "latency": 0, "error": str(e)}
    finally:
        sock.close()
