from flask import Flask, render_template, redirect, url_for, request, session, jsonify
from functools import wraps
from pathlib import Path
import sqlite3, threading, time, os
from modules.database_setup import init_db
from modules.log_collector import collect_windows_events_once
from modules.detection_engine import run_detection

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "database" / "siem.db"
app = Flask(__name__)
app.secret_key = os.environ.get("SIEM_SECRET_KEY", "change-this-demo-secret-key")
COLLECTOR_INTERVAL = 5
collector_started = False
collector_lock = threading.Lock()

def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def collector_loop():
    while True:
        try:
            collect_windows_events_once(DB_FILE)
            run_detection(DB_FILE)
        except Exception as exc:
            print(f"[SIEM] Background task error: {exc}")
        time.sleep(COLLECTOR_INTERVAL)

def start_collector():
    global collector_started
    with collector_lock:
        if not collector_started:
            threading.Thread(target=collector_loop, daemon=True, name="siem-collector").start()
            collector_started = True
            print("[SIEM] Live Windows event monitoring started (5-second polling).")

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Demo credentials; change before any non-local deployment.
        if username == os.environ.get("SIEM_USER", "admin") and password == os.environ.get("SIEM_PASSWORD", "admin123"):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        error = "Incorrect username or password"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    return render_template("index.html")

@app.route("/api/dashboard")
@login_required
def dashboard_data():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM logs")
    total_logs = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM logs WHERE event_type='Failed Login'")
    failed = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM logs WHERE event_type='Successful Login'")
    successful = cur.fetchone()[0]
    cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 30")
    logs = [dict(x) for x in cur.fetchall()]
    cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 20")
    alerts = [dict(x) for x in cur.fetchall()]
    cur.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'")
    high_alerts = cur.fetchone()[0]
    cur.execute("SELECT ip_address, COUNT(*) AS count FROM logs GROUP BY ip_address ORDER BY count DESC LIMIT 5")
    top_ips = [dict(x) for x in cur.fetchall()]
    cur.execute("SELECT timestamp FROM logs ORDER BY id DESC LIMIT 1")
    latest = cur.fetchone()
    conn.close()
    threat = "HIGH" if high_alerts >= 3 else "MEDIUM" if total_alerts else "LOW"
    return jsonify({
        "total_logs": total_logs, "total_alerts": total_alerts,
        "failed": failed, "successful": successful, "high_alerts": high_alerts,
        "threat": threat, "logs": logs, "alerts": alerts, "top_ips": top_ips,
        "last_event": latest["timestamp"] if latest else "No events collected yet"
    })

@app.route("/health")
def health():
    return jsonify({"status": "ok", "monitoring": collector_started})

if __name__ == "__main__":
    init_db(DB_FILE)
    start_collector()
    # Local-only demo server. Do not expose this development server to the internet.
    from waitress import serve
serve(app, host="127.0.0.1", port=5000)
