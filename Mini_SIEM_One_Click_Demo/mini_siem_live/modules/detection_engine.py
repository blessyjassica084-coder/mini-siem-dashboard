"""Rule-based detections over collected Windows authentication events."""
import sqlite3
from pathlib import Path

def run_detection(db_file=None):
    if db_file is None:
        db_file = Path(__file__).resolve().parents[1] / "database" / "siem.db"
    conn = sqlite3.connect(db_file)
    try:
        # Five failed logons from the same known remote IP in five minutes.
        rows = conn.execute("""
            SELECT ip_address, COUNT(*) AS attempts
            FROM logs
            WHERE event_type='Failed Login'
              AND ip_address NOT IN ('Unknown', '0.0.0.0', '127.0.0.1')
              AND timestamp >= datetime('now','localtime','-5 minutes')
            GROUP BY ip_address
            HAVING COUNT(*) >= 5
        """).fetchall()
        for ip, attempts in rows:
            recent = conn.execute("""
                SELECT 1 FROM alerts
                WHERE ip_address=? AND alert_type='Brute Force Login Attempt'
                  AND timestamp >= datetime('now','localtime','-5 minutes')
                LIMIT 1
            """, (ip,)).fetchone()
            if not recent:
                conn.execute("""
                    INSERT INTO alerts(ip_address, alert_type, severity, details)
                    VALUES (?, 'Brute Force Login Attempt', 'HIGH', ?)
                """, (ip, f"{attempts} failed logons observed in the last five minutes"))
                print(f"[ALERT] Possible brute-force login activity from {ip}")
        conn.commit()
    finally:
        conn.close()

if __name__ == "__main__":
    run_detection()
