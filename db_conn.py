import os
import sys
import sqlite3
import time
import threading
from contextlib import contextmanager


def _get_base_dir() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


DB_PATH = os.path.join(_get_base_dir(), "monitor.db")

MAX_RETRIES = 3
RETRY_DELAY = 1.0
BUSY_TIMEOUT_MS = 30000

_write_lock = threading.RLock()

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(
        DB_PATH,
        timeout=30,
        isolation_level=None,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()
    return conn


def get_db() -> sqlite3.Connection:
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            conn = _connect()
            conn.execute("SELECT 1").fetchone()
            return conn
        except sqlite3.OperationalError as e:
            last_error = e
            if "locked" in str(e).lower() and attempt < MAX_RETRIES:
                print(f"⚠️  [db] database is locked (попытка {attempt}/{MAX_RETRIES}), ждём {RETRY_DELAY}с...")
                time.sleep(RETRY_DELAY)
                continue
            raise
    raise last_error


@contextmanager
def db_connection():
    conn = None
    try:
        conn = get_db()
        yield conn
    finally:
        if conn:
            conn.close()


@contextmanager
def db_write():
    with _write_lock:
        conn = None
        try:
            conn = get_db()
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            # COMMIT может упасть, если внутри уже был conn.commit() (например, migrations.py)
            try:
                conn.execute("COMMIT")
            except sqlite3.OperationalError as e:
                if "no transaction is active" not in str(e).lower():
                    raise
                # уже закоммичено вручную — игнорируем
        except Exception:
            if conn:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
            raise
        finally:
            if conn:
                conn.close()


def execute_write(query: str, params: tuple = ()) -> int:
    with db_write() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        return cur.rowcount


def execute_read(query: str, params: tuple = ()) -> list:
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        return cur.fetchall()


def execute_one(query: str, params: tuple = ()):
    with db_connection() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        return cur.fetchone()
