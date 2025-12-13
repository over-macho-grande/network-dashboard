from flask import Flask, render_template, request, redirect, url_for, session, flash
from config import Config
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash
import requests
from datetime import datetime, timedelta
from typing import Any, Dict, List
from services import (
    fetch_wazuh_alerts,
    fetch_lnms_data,
    fetch_device_details,
    fetch_device_processors,
    fetch_device_mempools,
    fetch_device_storage,
    fetch_device_ports,
    fetch_wazuh_agent_by_ip,
    fetch_wazuh_alerts_for_agent,
    ALERT_WINDOW_CHOICES,
    ALERT_DEFAULT_WINDOW,
)



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


@app.route("/device/<int:device_id>")
@login_required
def device_detail(device_id: int):
    """
    Device detail page showing comprehensive information from LNMS and Wazuh.
    Displays:
    - Device basic info (hostname, OS, hardware, status, uptime)
    - CPU/Processor metrics
    - Memory pool metrics
    - Storage metrics
    - Network port/bandwidth metrics
    - Wazuh agent info (if matched by IP)
    - Recent Wazuh alerts for this device
    """
    # Fetch device info from LNMS
    device = fetch_device_details(device_id)
    
    if not device:
        flash("Device not found.", "error")
        return redirect(url_for("index"))
    
    # Fetch all resource metrics
    processors = fetch_device_processors(device_id)
    mempools = fetch_device_mempools(device_id)
    storage = fetch_device_storage(device_id)
    ports = fetch_device_ports(device_id)
    
    # Try to find matching Wazuh agent by IP
    wazuh_agent = None
    wazuh_alerts = []
    
    # Get IP address - try ip_address field first, then hostname
    device_ip = device.get("ip_address") or device.get("hostname")
    
    if device_ip:
        wazuh_agent = fetch_wazuh_agent_by_ip(device_ip)
        
        # If we found a Wazuh agent, get recent alerts
        if wazuh_agent:
            agent_id = wazuh_agent.get("id")
            if agent_id:
                alert_window = ALERT_WINDOW_CHOICES.get(
                    request.args.get("alert_window", "24h"),
                    ALERT_WINDOW_CHOICES["24h"]
                )
                wazuh_alerts = fetch_wazuh_alerts_for_agent(
                    agent_id, 
                    limit=50,
                    window=alert_window
                )
    
    # Calculate summary stats
    summary = {
        "cpu_avg": None,
        "ram_avg": None,
        "storage_max": None,
        "active_ports": 0,
        "total_bandwidth_mbps": 0,
    }
    
    if processors:
        usages = [p.get("processor_usage", 0) for p in processors if p.get("processor_usage") is not None]
        if usages:
            summary["cpu_avg"] = round(sum(usages) / len(usages), 1)
    
    if mempools:
        percs = [m.get("mempool_perc", 0) for m in mempools if m.get("mempool_perc") is not None]
        if percs:
            summary["ram_avg"] = round(sum(percs) / len(percs), 1)
    
    if storage:
        percs = [s.get("storage_perc", 0) for s in storage if s.get("storage_perc") is not None]
        if percs:
            summary["storage_max"] = max(percs)
    
    if ports:
        summary["active_ports"] = sum(1 for p in ports if p.get("ifOperStatus") == "up")
        summary["total_bandwidth_mbps"] = round(
            sum(p.get("bandwidth_total_mbps", 0) for p in ports), 2
        )
    
    return render_template(
        "device.html",
        device=device,
        processors=processors,
        mempools=mempools,
        storage=storage,
        ports=ports,
        wazuh_agent=wazuh_agent,
        wazuh_alerts=wazuh_alerts,
        summary=summary,
        alert_window=request.args.get("alert_window", "24h"),
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
    # Dev mode: later we'll run this via gunicorn + systemd + nginx
    app.run(host="0.0.0.0", port=5000, debug=True)
