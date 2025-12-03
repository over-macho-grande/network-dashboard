from flask import Flask, render_template, request, redirect, url_for, session, flash
from config import Config
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash
import requests
from datetime import datetime, timedelta
from typing import Any, Dict, List


EMPTY_TOP_DEVICES = {
    "cpu": [],
    "ram": [],
    "bandwidth": [],
    "storage": [],
}


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

# Shared time-window choices for both LNMS and Wazuh alerts
ALERT_WINDOW_CHOICES = {
    "1h": timedelta(hours=1),
    "4h": timedelta(hours=4),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}
ALERT_DEFAULT_WINDOW = "24h"


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
# Timestamp helpers
# -------------------------------------------------------------------
def _parse_wazuh_timestamp(ts: str):
    """
    Parse Wazuh alert timestamps into datetime objects.
    Wazuh indexer stores them in ISO 8601, e.g. '2025-11-26T08:00:00Z'.
    """
    if not ts:
        return None
    ts = ts.replace("Z", "")
    try:
        # Handles 'YYYY-MM-DDTHH:MM:SS' and with microseconds
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _parse_lnms_timestamp(ts: str):
    """
    Try to parse LNMS alert timestamp into a datetime object.
    Expected format in your environment: 'YYYY-MM-DD HH:MM:SS'.
    Returns None on failure.
    """
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        try:
            return datetime.fromisoformat(ts.replace("Z", ""))
        except Exception:
            return None


# -------------------------------------------------------------------
# Wazuh & LNMS data fetch helpers
# -------------------------------------------------------------------
def fetch_wazuh_alerts(limit: int = 10, window: timedelta | None = None):
    """
    Fetch recent Wazuh alerts via the Wazuh INDEXER API (OpenSearch).

    We search the 'wazuh-alerts-4.x-*' indices using a range query on
    @timestamp, sorted newest-first, and then normalize into the shape
    the template expects.
    """
    if window is None:
        window = ALERT_WINDOW_CHOICES[ALERT_DEFAULT_WINDOW]

    # Require indexer config to be enabled
    if (
        not getattr(Config, "USE_WAZUH_INDEXER", False)
        or not getattr(Config, "WAZUH_INDEXER_URL", "")
        or not getattr(Config, "WAZUH_INDEXER_USER", "")
        or not getattr(Config, "WAZUH_INDEXER_PASSWORD", "")
    ):
        return DEFAULT_WAZUH_ALERTS

    cutoff = datetime.utcnow() - window
    # ISO string for the indexer range query
    cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    try:
        auth = (Config.WAZUH_INDEXER_USER, Config.WAZUH_INDEXER_PASSWORD)
        headers = {"Content-Type": "application/json"}

        # Over-fetch a bit so we can filter & then trim to `limit`
        body = {
            "size": limit * 5,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": cutoff_iso,
                    }
                }
            },
        }

        resp = requests.get(
            f"{Config.WAZUH_INDEXER_URL}/wazuh-alerts-4.x-*/_search",
            auth=auth,
            headers=headers,
            json=body,
            timeout=5,
            verify=getattr(Config, "WAZUH_INDEXER_VERIFY_SSL", True),
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])

        filtered = []
        for h in hits:
            src = h.get("_source", {})
            ts_str = src.get("@timestamp") or src.get("timestamp") or ""
            dt = _parse_wazuh_timestamp(ts_str)
            if dt and dt >= cutoff:
                filtered.append((dt, src))

        # newest first
        filtered.sort(key=lambda pair: pair[0], reverse=True)
        filtered = [src for _, src in filtered][:limit]

        alerts = []
        for a in filtered:
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
        app.logger.warning(f"Wazuh indexer API error: {e}")
        return DEFAULT_WAZUH_ALERTS

def _get_lnms_top_devices(
    base_url: str,
    headers: dict[str, str],
    verify_ssl: bool,
    limit: int = 10,
) -> dict[str, list[dict[str, Any]]]:
    """
    Fetch top ports by bandwidth from LibreNMS and return them in the
    dashboard's top_devices format.

    Uses ifInOctets_rate / ifOutOctets_rate (octets per second) and converts
    to Mb/s. Label is ifAlias if present, otherwise ifName, otherwise port_id.
    """
    try:
        ports_resp = requests.get(
            f"{base_url}/ports",
            params={
                "limit": 500,
                "columns": "ifAlias,ifName,port_id,ifInOctets_rate,ifOutOctets_rate",
            },
            headers=headers,
            timeout=5,
            verify=verify_ssl,
        )
        ports_resp.raise_for_status()
        ports_data = ports_resp.json()
        ports = ports_data.get("ports", ports_data.get("data", [])) or []

        bw_entries: list[dict[str, Any]] = []

        for p in ports:
            # Octets (bytes) per second -> bits/sec -> Mb/s
            in_rate = float(p.get("ifInOctets_rate") or 0)
            out_rate = float(p.get("ifOutOctets_rate") or 0)
            total_bits_per_second = (in_rate + out_rate) * 8.0
            mbps = total_bits_per_second / 1_000_000.0

            # Skip totally idle ports
            if mbps <= 0:
                continue

            # Prefer the human-friendly alias, then ifName, then port_id
            label = (p.get("ifAlias") or "").strip()
            if not label:
                label = (p.get("ifName") or "").strip()
            if not label:
                label = f"port {p.get('port_id')}"

            bw_entries.append(
                {
                    "device": label,
                    "value": round(mbps, 1),
                }
            )

        # Sort by highest Mb/s and keep top N
        bw_entries.sort(key=lambda d: d["value"], reverse=True)
        bw_entries = bw_entries[:limit]

        return {
            "cpu": [],
            "ram": [],
            "bandwidth": bw_entries,
            "storage": [],
        }

    except Exception as e:
        app.logger.warning(f"LNMS /ports API error: {e}")
        return {
            "cpu": [],
            "ram": [],
            "bandwidth": [],
            "storage": [],
        }


def fetch_lnms_data(limit_alerts: int = 10, window=None):
    """
    Fetch LNMS alerts and top bandwidth devices.

    - If LNMS API is disabled or misconfigured, returns:
        ([], DEFAULT_TOP_DEVICES)
    - If /alerts fails, we log and show no LNMS alerts.
    - If /ports fails, we log and fall back to DEFAULT_TOP_DEVICES.
    """
    # If LNMS integration is disabled or missing config, just return demo top-devices
    if (
        not getattr(Config, "USE_LNMS_API", False)
        or not getattr(Config, "LNMS_API_URL", "")
        or not getattr(Config, "LNMS_API_TOKEN", "")
    ):
        return [], DEFAULT_TOP_DEVICES

    base_url = Config.LNMS_API_URL.rstrip("/")
    headers = {"X-Auth-Token": Config.LNMS_API_TOKEN}
    verify_ssl = getattr(Config, "LNMS_API_VERIFY_SSL", True)

    # Time window for alerts (window is a timedelta or None)
    if window is None:
        window = ALERT_WINDOW_CHOICES[ALERT_DEFAULT_WINDOW]
    cutoff = datetime.utcnow() - window

    lnms_alerts: list[dict] = []

    # ---------------------------
    # 1) Alerts (non-fatal if this fails)
    # ---------------------------
    try:
        alerts_resp = requests.get(
            f"{base_url}/alerts",
            headers=headers,
            params={
                # keep params simple to avoid 400s
                "limit": limit_alerts * 5,
                "sort": "timestamp",
                "order": "desc",
            },
            timeout=5,
            verify=verify_ssl,
        )

        alerts_resp.raise_for_status()
        data = alerts_resp.json() or {}
        raw_alerts = data.get("alerts") or data.get("data") or []

        # Filter by time window and sort newest first
        filtered: list[tuple[datetime, dict]] = []
        for a in raw_alerts:
            ts = (
                a.get("timestamp")
                or a.get("time_logged")
                or a.get("datetime")
                or ""
            )
            dt = _parse_lnms_timestamp(ts)
            if dt and dt >= cutoff:
                filtered.append((dt, a))

        filtered.sort(key=lambda pair: pair[0], reverse=True)
        filtered = filtered[:limit_alerts]

        for dt, a in filtered:
            lnms_alerts.append(
                {
                    "id": a.get("id") or a.get("alert_id"),
                    "device": a.get("device")
                    or a.get("hostname")
                    or a.get("host")
                    or "",
                    "severity": a.get("severity") or a.get("state") or "",
                    "message": a.get("message") or a.get("note") or "",
                    "time": dt.strftime("%Y-%m-%d %H:%M"),
                }
            )
    except Exception as e:
        app.logger.warning(f"LNMS /alerts API error: {e}")

    # ---------------------------
    # 2) Top bandwidth devices
    # ---------------------------
    # Re-use the helper so the shape is always:
    # {"cpu": [], "ram": [], "bandwidth": [...], "storage": []}
    top_devices = _get_lnms_top_devices(
        base_url=base_url,
        headers=headers,
        verify_ssl=verify_ssl,
        limit=10,
    )

    # If LNMS is enabled, never show fake alerts; show real or nothing.
    return lnms_alerts, top_devices


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
    Uses a shared time-window selector for both alert panels.
    """
    # Get selected time window from query string (shared by LNMS + Wazuh)
    alert_window_key = request.args.get("lnms_window", ALERT_DEFAULT_WINDOW)
    if alert_window_key not in ALERT_WINDOW_CHOICES:
        alert_window_key = ALERT_DEFAULT_WINDOW
    alert_window_delta = ALERT_WINDOW_CHOICES[alert_window_key]

    wazuh_alerts = fetch_wazuh_alerts(limit=10, window=alert_window_delta)
    lnms_alerts, top_devices = fetch_lnms_data(
        limit_alerts=10, window=alert_window_delta
    )

    return render_template(
        "index.html",
        wazuh_alerts=wazuh_alerts,
        lnms_alerts=lnms_alerts,
        top_devices=top_devices,
        lnms_window=alert_window_key,  # reused by the dropdown
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
