import aiosqlite
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "alerts.db")

async def init_db():
    """Initializes the SQLite database and creates the alerts table."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dest_ip TEXT,
                window_size INTEGER,
                score REAL,
                verdict INTEGER
            )
        """)
        await db.commit()

async def log_alert(src_ip, dest_ip, window_size, score, verdict):
    """Logs a new packet alert into the database."""
    timestamp = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO alerts (timestamp, src_ip, dest_ip, window_size, score, verdict)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, src_ip, dest_ip, window_size, score, verdict))
        await db.commit()

async def get_recent_alerts(limit=50):
    """Fetches recent alerts, ordered by ID descending."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
