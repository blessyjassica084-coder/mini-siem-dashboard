"""Windows Security Event Log collector.

Reads Windows Security events 4624 (successful logon) and 4625 (failed logon).
It records each Windows Event RecordNumber once. This is a local demonstration
collector, not an enterprise-grade event forwarder.
"""
import re
import sqlite3
from pathlib import Path

AUTH_EVENT_IDS = {4624: "Successful Login", 4625: "Failed Login"}

def _extract_ip(event):
    # Windows Event 4624/4625 StringInserts contain several fields. Their
    # positions vary by event version, so extract an IPv4 address if present.
    try:
        for item in (event.StringInserts or []):
            if item:
                for candidate in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", str(item)):
                    parts = candidate.split(".")
                    if all(0 <= int(p) <= 255 for p in parts) and candidate not in ("0.0.0.0", "127.0.0.1"):
                        return candidate
    except Exception:
        pass
    return "Unknown"

def collect_windows_events_once(db_file=None):
    if db_file is None:
        db_file = Path(__file__).resolve().parents[1] / "database" / "siem.db"
    try:
        import win32evtlog
    except ImportError:
        print("[SIEM] pywin32 is missing. Install it with: py -m pip install pywin32")
        return 0

    conn = sqlite3.connect(db_file)
    inserted = 0
    handle = None
    try:
        # Security log access usually requires an elevated Administrator shell
        # and the local Security Event Log user-right/policy.
        handle = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(handle, flags, 0) or []
        for event in events:
            event_id = event.EventID & 0xFFFF
            if event_id not in AUTH_EVENT_IDS:
                continue
            record_id = int(event.RecordNumber)
            exists = conn.execute(
                "SELECT 1 FROM windows_event_state WHERE record_id=?", (record_id,)
            ).fetchone()
            if exists:
                continue
            event_type = AUTH_EVENT_IDS[event_id]
            ip = _extract_ip(event)
            conn.execute(
                "INSERT INTO logs(event_type, ip_address, port, source) VALUES (?, ?, 0, ?)",
                (event_type, ip, f"Windows Security Event {event_id}")
            )
            conn.execute("INSERT INTO windows_event_state(record_id) VALUES (?)", (record_id,))
            inserted += 1
        conn.commit()
        if inserted:
            print(f"[SIEM] Collected {inserted} new Windows Security event(s).")
        return inserted
    except Exception as exc:
        print(f"[SIEM] Windows event collection error: {exc}")
        return 0
    finally:
        if handle is not None:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass
        conn.close()

if __name__ == "__main__":
    from modules.database_setup import init_db
    init_db()
    import time
    print("Collecting Windows Security events. Press Ctrl+C to stop.")
    while True:
        collect_windows_events_once()
        time.sleep(5)
