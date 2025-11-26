from flask import Flask, render_template, request, redirect, url_for, session, flash
from config import Config
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash
import requests
from datetime import datetime, timedelta

# -------------------------------------------------------------------
# App setup
# -------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY  # for sessions


# -------------------------------------------------------------------
# Default placeholder data (used when APIs are disabled/unreachable)
# -------------------------------------------------------------------
DEFAULT_WAZUH_ALERTS = [
    {
        "id": "1001",
        "level": "high",
        "agent": "server01",
        "rule": "SSH brute force",
        "time": "2025-11-26 08:00",
    },
    {
        "id": "1002",
        "level": "medium",
        "agent": "web01",
        "rule": "Suspicious process",
        "time": "2025-11-26 07:45",
    },
]

DEFAULT_LNMS_ALERTS = [
    {
        "id": "2001",
        "device": "switch-core-01",
        "severity": "critical",
        "message": "High CPU usage",
        "time": "2025-11-26 07:50",
    },
    {
        "id": "2002",
        "device": "router-edge-01",
        "severity": "warning",
        "message": "Interface errors",
        "time": "2025-11-26 07:40",
    },
]

DEFAULT_TOP_DEVICES = {
    "cpu": [
        {"device": "server01", "value": 95},
        {"device": "db01", "value": 92},
    ],
    "ram": [
        {"device": "db01", "value": 89},
        {"device": "server02", "value": 85},
    ],
    "bandwidth": [
        {"device": "router-edge-01", "value": 940},
        {"device": "switch-core-01", "value": 850},
    ],
    "storage": [
        {"device": "fileserver01", "value": 92},
        {"device": "backup01", "value": 88},
    ],
}


# -------------------------------------------------------------------
# Database helper
# -------------------------------------------------------------------
def get_db_connection():
    """
    Opens a new PostgreSQL connection using settings from Config.
    Caller is responsible for closing it.
    """
    conn = psycopg2.connect(
        dbname=Config.DB_NAME,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        cursor_factory=RealDictCursor,
    )
    return conn


# -------------------------------------------------------------------
# Wazuh & LNMS data fetch helpers
# -------------------------------------------------------------------
def fetch_wazuh_alerts(limit: int = 10):
    """
    Fetch recent Wazuh alerts via the Wazuh API.
    Returns a list of dicts matching the template fields, or default data on error.
    """
    if not Config.USE_WAZUH_API or not Config.WAZUH_API_URL:
        return DEFAULT_WAZUH_ALERTS

    try:
        # 1) Authenticate to get JWT token
        auth_resp = requests.post(
            f"{Config.WAZUH_API_URL}/security/user/authenticate",
            json={"username": Config.WAZUH_API_USER, "password": Config.WAZUH_API_PASSWORD},
            timeout=5,
            verify=Config.WAZUH_API_VERIFY_SSL,
        )
        auth_resp.raise_for_status()
        token = auth_resp.json().get("data", {}).get("token")
        if not token:
            app.logger.warning("Wazuh API: no token in auth response")
            return DEFAULT_WAZUH_ALERTS

        headers = {"Authorization": f"Bearer {token}"}

        # 2) Fetch alerts
        alerts_resp = requests.get(
            f"{Config.WAZUH_API_URL}/security/alerts",
            params={"limit": limit, "sort": "-timestamp"},
            headers=headers,
            timeout=5,
            verify=Config.WAZUH_API_VERIFY_SSL,
        )
        alerts_resp.raise_for_status()
        data = alerts_resp.json()
        raw_alerts = data.get("data", {}).get("alerts", [])

        alerts = []
        for a in raw_alerts:
            alerts.append(
                {
                    "id": a.get("id") or a.get("_id") or "",
                    "level": str(a.get("rule", {}).get("level", "")).lower(),
                    "agent": a.get("agent", {}).get("name", ""),
                    "rule": a.get("rule", {}).get("description", ""),
                    "time": a.get("@timestamp") or a.get("timestamp", ""),
                }
            )
        return alerts or DEFAULT_WAZUH_ALERTS
    except Exception as e:
        app.logger.warning(f"Wazuh API error: {e}")
        return DEFAULT_WAZUH_ALERTS


def _parse_lnms_timestamp(ts: str):
    """
    Try to parse LNMS alert timestamp into a datetime object.
    Expected format in your environment: 'YYYY-MM-DD HH:MM:SS'.
    Returns None on failure.
    """
    if not ts:
        return None
    try:
        # LibreNMS typically uses this format
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        try:
            # Fallback for ISO-like formats
            return datetime.fromisoformat(ts.replace("Z", ""))
        except Exception:
            return None


def fetch_lnms_data(limit_alerts: int = 10):
    """
    Fetch LNMS alerts and top devices (CPU/RAM/bandwidth/storage) from LibreNMS.
    Returns (alerts_list, top_devices_dict).
    - Alerts are limited to the last 24 hours.
    - Only the top `limit_alerts` most recent alerts are returned.
    """
    if (
        not Config.USE_LNMS_API
        or not Config.LNMS_API_URL
        or not Config.LNMS_API_TOKEN
    ):
        return DEFAULT_LNMS_ALERTS, DEFAULT_TOP_DEVICES

    headers = {"X-Auth-Token": Config.LNMS_API_TOKEN}
    cutoff = datetime.utcnow() - timedelta(days=1)

    try:
        # Grab a reasonable batch so filtering to 24h doesn't miss anything
        alerts_resp = requests.get(
            f"{Config.LNMS_API_URL}/alerts",
            params={"state": 1, "limit": 100},
            headers=headers,
            timeout=5,
            verify=Config.LNMS_API_VERIFY_SSL,
        )
        alerts_resp.raise_for_status()
        alerts_data = alerts_resp.json()
        raw_alerts = alerts_data.get("alerts", alerts_data.get("data", []))

        # Filter by last 24 hours and sort newest-first
        filtered = []
        for a in raw_alerts:
            ts_str = a.get("timestamp") or ""
            dt = _parse_lnms_timestamp(ts_str)
            if dt and dt >= cutoff:
                filtered.append((dt, a))

        # Newest first
        filtered.sort(key=lambda pair: pair[0], reverse=True)
        filtered = [a for _, a in filtered][:limit_alerts]

        lnms_alerts = []
        for a in filtered:
            lnms_alerts.append(
                {
                    "id": a.get("alert_id") or a.get("id"),
                    "device": a.get("hostname") or a.get("device_id"),
                    "severity": str(a.get("severity", "warning")).lower(),
                    "message": a.get("rule") or a.get("details", ""),
                    "time": a.get("timestamp") or "",
                }
            )

        # For now, keep using default top device data.
        top_devices = DEFAULT_TOP_DEVICES

        return lnms_alerts or DEFAULT_LNMS_ALERTS, top_devices
    except Exception as e:
        app.logger.warning(f"LNMS API error: {e}")
        return DEFAULT_LNMS_ALERTS, DEFAULT_TOP_DEVICES


# -------------------------------------------------------------------
# Auth helper
# -------------------------------------------------------------------
def login_required(view_func):
    """
    Decorator to protect routes that require a logged-in user.
    """
    from functools import wraps

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapped_view


# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    """
    Main dashboard page (protected).
    Pulls data from Wazuh + LNMS helpers with safe fallbacks.
    """
    wazuh_alerts = fetch_wazuh_alerts(limit=10)
    lnms_alerts, top_devices = fetch_lnms_data(limit_alerts=10)

    return render_template(
        "index.html",
        wazuh_alerts=wazuh_alerts,
        lnms_alerts=lnms_alerts,
        top_devices=top_devices,
        cfg=Config,
        username=session.get("username"),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Basic login form:
    - GET: show/login page
    - POST: validate username + password against DB
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template(
                "login.html", cfg=Config, username=session.get("username")
            )

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "SELECT id, username, password_hash, role, is_active "
                "FROM users WHERE username = %s",
                (username,),
            )
            user = cur.fetchone()
            cur.close()
        finally:
            if conn is not None:
                conn.close()

        if user is None:
            flash("Invalid username or password.", "error")
            return render_template(
                "login.html", cfg=Config, username=session.get("username")
            )

        if not user["is_active"]:
            flash("Account is disabled. Contact an administrator.", "error")
            return render_template(
                "login.html", cfg=Config, username=session.get("username")
            )

        if not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "error")
            return render_template(
                "login.html", cfg=Config, username=session.get("username")
            )

        # Authentication successful
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]

        next_url = request.args.get("next") or url_for("index")
        return redirect(next_url)

    # GET request
    return render_template(
        "login.html", cfg=Config, username=session.get("username")
    )


@app.route("/logout")
def logout():
    """
    Clear session and redirect to login.
    """
    session.clear()
    return redirect(url_for("login"))


@app.route("/ai")
@login_required
def ai_page():
    """
    Placeholder AI page (protected). Will eventually host the AI interface.
    """
    return render_template("ai.html", cfg=Config, username=session.get("username"))


@app.route("/healthz")
def healthz():
    """
    Simple health check endpoint for monitoring.
    """
    return "OK", 200


if __name__ == "__main__":
    # Dev mode: later we’ll run this via gunicorn + systemd + nginx
    app.run(host="0.0.0.0", port=5000, debug=True)
