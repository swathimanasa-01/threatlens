import json
import sqlite3
from datetime import datetime, timezone

DB_PATH = "threatlens.db"


def _conn(path=None):
    c = sqlite3.connect(path or DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db(path=None):
    with _conn(path) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ioc TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            risk TEXT NOT NULL,
            summary TEXT,
            evidence TEXT)""")


def save(ioc, ioc_type, risk, summary, evidence, path=None):
    with _conn(path) as c:
        c.execute(
            "INSERT INTO investigations (timestamp, ioc, ioc_type, risk, summary, evidence)"
            " VALUES (?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"),
             ioc, ioc_type, risk, summary, json.dumps(evidence)))  # parameterised: no SQL injection


def history(limit=100, path=None):
    with _conn(path) as c:
        return c.execute(
            "SELECT * FROM investigations ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def clear(path=None):
    with _conn(path) as c:
        c.execute("DELETE FROM investigations")
