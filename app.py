from flask import Flask, render_template, request, redirect, url_for, session, flash
from config import Config
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash
import requests
from datetime import datetime, timedelta
from typing import Any, Dict, List


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

def _get_lnms_top_devices(headers: Dict[str, str], limit: int = 10) -> List[Dict[str, Any]]:
    """
    Get 'top devices' from LibreNMS using the /devices endpoint.

    For now we treat 'resource usage' as:
      - Devices with the highest last_polled_timetaken (slowest to poll)
      - We also pull last_ping_timetaken as an extra indicator

    We map this into the existing dashboard fields:
      - cpu / ram / storage: left as None (will show as N/A in the UI if handled)
      - bandwidth: we use last_polled_timetaken (seconds) as a 'resource score'
    """
    if not getattr(Config, "LNMS_API_URL", ""):
        return DEFAULT_TOP_DEVICES

    try:
        # Ask LibreNMS to sort devices by last_polled_timetaken descending if supported.
        # If the install ignores order/order_type, we still sort locally as a fallback.
        resp = requests.get(
            f"{Config.LNMS_API_URL}/devices",
            headers=headers,
            params={
                # These params are supported by list_devices on most LibreNMS installs.
                # If not, no harm done – we'll sort the returned list ourselves.
                "order": "last_polled_timetaken",
                "order_type": "desc",
                "limit": limit * 2,  # grab a few extra in case some are missing metrics
            },
            timeout=5,
            verify=getattr(Config, "LNMS_API_VERIFY_SSL", True),
        )
        resp.raise_for_status()
        data = resp.json()

        devices = data.get("devices", data.get("data", [])) or []
        cleaned: List[Dict[str, Any]] = []

        for d in devices:
            name = d.get("display") or d.get("sysName") or d.get("hostname") or d.get("ip")
            ip = d.get("ip") or d.get("hostname")

            # These come directly from your sample JSON
            # last_polled_timetaken ~ seconds, last_ping_timetaken ~ ms
            def _to_float(val: Any) -> float:
                try:
                    return float(val)
                except (TypeError, ValueError):
                    return 0.0

            poll_time = _to_float(d.get("last_polled_timetaken"))
            ping_ms = _to_float(d.get("last_ping_timetaken"))

            # Simple 'resource score' for now: primarily poll time, lightly weighted ping
            resource_score = poll_time + (ping_ms / 1000.0)

            cleaned.append(
                {
                    "name": name or "Unknown device",
                    "ip": ip or "",
                    # CPU / RAM / storage will stay None for now until we wire in health sensors.
                    "cpu": None,
                    "ram": None,
                    "storage": None,
                    # We'll surface this in the "Bandwidth" column for now; later we can rename in the UI.
                    "bandwidth": resource_score,
                }
            )

        # Sort locally as a safety net even if the API already sorted for us
        cleaned.sort(key=lambda d: d.get("bandwidth") or 0.0, reverse=True)

        if not cleaned:
            return DEFAULT_TOP_DEVICES

        return cleaned[:limit]

    except Exception as e:
        app.logger.warning(f"LNMS top devices error: {e}")
        return DEFAULT_TOP_DEVICES


def fetch_lnms_data(limit_alerts: int = 10, window: timedelta | None = None):
    """
    Fetch LNMS alerts and top devices (resource usage) from LibreNMS.
    Returns (alerts_list, top_devices_list).

    - Alerts are filtered to the given time window (default 24h).
    - Only the top `limit_alerts` most recent alerts are returned.
    - Top devices come from /devices and are sorted by last_polled_timetaken.
    """
    if window is None:
        window = ALERT_WINDOW_CHOICES[ALERT_DEFAULT_WINDOW]

    # If LNMS is disabled or not configured, return placeholders
    if (
        not getattr(Config, "USE_LNMS_API", False)
        or not getattr(Config, "LNMS_API_URL", "")
        or not getattr(Config, "LNMS_API_TOKEN", "")
    ):
        return DEFAULT_LNMS_ALERTS, DEFAULT_TOP_DEVICES

    headers = {
        "X-Auth-Token": Config.LNMS_API_TOKEN,
        "Accept": "application/json",
    }

    cutoff = datetime.utcnow() - window

    try:
        # -----------------------------
        # 1) LibreNMS Alerts
        # -----------------------------
        alerts_resp = requests.get(
            f"{Config.LNMS_API_URL}/alerts",
            # state=1 → active alerts; sort by newest first if supported
            params={"state": 1, "limit": 200, "sort": "timestamp", "order": "desc"},
            headers=headers,
            timeout=5,
            verify=getattr(Config, "LNMS_API_VERIFY_SSL", True),
        )
        alerts_resp.raise_for_status()
        alerts_data = alerts_resp.json()
        raw_alerts = alerts_data.get("alerts", alerts_data.get("data", [])) or []

        filtered: list[tuple[datetime, dict]] = []

        for a in raw_alerts:
            # Try multiple possible timestamp fields
            ts_str = (
                a.get("timestamp")
                or a.get("time_logged")
                or a.get("datetime")
                or a.get("last_changed")
            )
            dt: datetime | None = None

            if ts_str:
                # Common LibreNMS formats; if parsing fails we just skip time filtering
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S%z"):
                    try:
                        dt = datetime.strptime(ts_str, fmt)
                        break
                    except Exception:
                        continue

            if dt is not None and dt >= cutoff:
                filtered.append((dt, a))

        # If nothing survives the time filter, fall back to just "newest N"
        if not filtered and raw_alerts:
            for a in raw_alerts[:limit_alerts]:
                filtered.append((datetime.utcnow(), a))

        # Sort newest → oldest and keep only N
        filtered.sort(key=lambda pair: pair[0], reverse=True)
        filtered = filtered[:limit_alerts]

        lnms_alerts: list[dict[str, Any]] = []
        for dt, a in filtered:
            lnms_alerts.append(
                {
                    "id": a.get("alert_id") or a.get("id"),
                    "device": a.get("hostname") or a.get("device_id") or "",
                    "severity": str(a.get("severity", "warning")).lower(),
                    "message": a.get("rule") or a.get("details", ""),
                    "time": a.get("timestamp") or a.get("time_logged") or dt.isoformat(),
                }
            )

        # -----------------------------
        # 2) LibreNMS Top Devices
        # -----------------------------
        top_devices = _get_lnms_top_devices(headers=headers, limit=10)

        return lnms_alerts or DEFAULT_LNMS_ALERTS, top_devices or DEFAULT_TOP_DEVICES

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
