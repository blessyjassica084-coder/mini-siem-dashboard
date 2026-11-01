import sqlite3
from pathlib import Path

def init_db(db_file=None):
    if db_file is None:
        db_file = Path(__file__).resolve().parents[1] / "database" / "siem.db"
    db_file = Path(db_file)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_file) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                ip_address TEXT NOT NULL DEFAULT 'Unknown',
                port INTEGER DEFAULT 0,
                timestamp TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                source TEXT DEFAULT 'Windows Security'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'HIGH',
                timestamp TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                details TEXT DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                reason TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT (datetime('now','localtime'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS windows_event_state (
                record_id INTEGER PRIMARY KEY
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_type_time ON logs(event_type, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip_time ON logs(ip_address, timestamp)")
        conn.commit()

if __name__ == "__main__":
    init_db()
    print("SIEM database setup completed successfully.")
