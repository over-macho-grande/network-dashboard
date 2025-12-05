# services.py
from datetime import datetime, timedelta
from typing import Any, Dict, List
import requests
from flask import current_app as app
from config import Config

# Shared time-window choices and default
ALERT_WINDOW_CHOICES = {
    "1h": timedelta(hours=1),
    "4h": timedelta(hours=4),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}
ALERT_DEFAULT_WINDOW = "24h"


def _parse_wazuh_timestamp(ts: str):
    if not ts:
        return None
    ts = ts.replace("Z", "")
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _parse_lnms_timestamp(ts: str):
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        try:
            return datetime.fromisoformat(ts.replace("Z", ""))
        except Exception:
            return None


def fetch_wazuh_alerts(limit: int = 10, window=None):
    if window is None:
        window = ALERT_WINDOW_CHOICES[ALERT_DEFAULT_WINDOW]

    if (
        not getattr(Config, "USE_WAZUH_INDEXER", False)
        or not getattr(Config, "WAZUH_INDEXER_URL", "")
        or not getattr(Config, "WAZUH_INDEXER_USER", "")
        or not getattr(Config, "WAZUH_INDEXER_PASSWORD", "")
    ):
        app.logger.debug("Wazuh indexer disabled or not configured; no Wazuh alerts.")
        return []

    cutoff = datetime.utcnow() - window
    cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    try:
        auth = (Config.WAZUH_INDEXER_USER, Config.WAZUH_INDEXER_PASSWORD)
        headers = {"Content-Type": "application/json"}

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

        filtered.sort(key=lambda pair: pair[0], reverse=True)
        filtered = [src for _, src in filtered][:limit]

        alerts: list[dict[str, Any]] = []
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
        return alerts

    except Exception as e:
        app.logger.warning(f"Wazuh indexer API error: {e}")
        return []


def _get_lnms_top_devices(base_url: str, headers: dict[str, str],
                          verify_ssl: bool, limit: int = 10) -> dict[str, list[dict[str, Any]]]:
    cpu_entries: list[dict[str, Any]] = []
    ram_entries: list[dict[str, Any]] = []
    storage_entries: list[dict[str, Any]] = []
    bw_entries: list[dict[str, Any]] = []

    # ---- CPU / RAM / STORAGE via LNMS DB ----
    if Config.LNMS_DB_ENABLED:
        try:
            import mysql.connector as mysql
            conn = mysql.connect(
                host=Config.LNMS_DB_HOST,
                port=Config.LNMS_DB_PORT,
                user=Config.LNMS_DB_USER,
                password=Config.LNMS_DB_PASSWORD,
                database=Config.LNMS_DB_NAME,
                connection_timeout=5,
            )
            try:
                cur = conn.cursor(dictionary=True)

                # CPU
                cur.execute(
                    """
                    SELECT d.hostname, p.processor_descr, p.processor_usage
                    FROM processors p
                    JOIN devices d ON p.device_id = d.device_id
                    WHERE p.processor_usage IS NOT NULL
                    ORDER BY p.processor_usage DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                for row in cur.fetchall() or []:
                    hostname = (row.get("hostname") or "").strip()
                    descr = (row.get("processor_descr") or "").strip()
                    label = hostname or descr or "(unknown device)"
                    if hostname and descr:
                        label = f"{hostname} – {descr}"
                    val = float(row.get("processor_usage") or 0.0)
                    cpu_entries.append({"device": label, "value": round(val, 1)})

                # RAM
                cur.execute(
                    """
                    SELECT d.hostname, mp.mempool_descr, mp.mempool_perc
                    FROM mempools mp
                    JOIN devices d ON mp.device_id = d.device_id
                    WHERE mp.mempool_perc IS NOT NULL
                    ORDER BY mp.mempool_perc DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                for row in cur.fetchall() or []:
                    hostname = (row.get("hostname") or "").strip()
                    descr = (row.get("mempool_descr") or "").strip()
                    label = hostname or descr or "(unknown device)"
                    if hostname and descr:
                        label = f"{hostname} – {descr}"
                    val = float(row.get("mempool_perc") or 0.0)
                    ram_entries.append({"device": label, "value": round(val, 1)})

                # STORAGE
                cur.execute(
                    """
                    SELECT d.hostname, s.storage_descr, s.storage_perc
                    FROM storage s
                    JOIN devices d ON s.device_id = d.device_id
                    WHERE s.storage_perc IS NOT NULL
                    ORDER BY s.storage_perc DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                for row in cur.fetchall() or []:
                    hostname = (row.get("hostname") or "").strip()
                    descr = (row.get("storage_descr") or "").strip()
                    label = hostname or descr or "(unknown device)"
                    if hostname and descr:
                        label = f"{hostname} – {descr}"
                    val = float(row.get("storage_perc") or 0.0)
                    storage_entries.append({"device": label, "value": round(val, 1)})

            finally:
                try:
                    cur.close()
                except Exception:
                    pass
                conn.close()
        except Exception as e:
            app.logger.warning(f"LNMS DB CPU/RAM/Storage query error: {e}")
    else:
        app.logger.debug("LNMS DB disabled (Config.LNMS_DB_ENABLED is False).")

    # ---- Device hostname map for bandwidth labels ----
    device_names: dict[str, str] = {}
    try:
        dev_resp = requests.get(
            f"{base_url}/devices",
            params={"limit": 500, "columns": "device_id,hostname"},
            headers=headers,
            timeout=5,
            verify=verify_ssl,
        )
        dev_resp.raise_for_status()
        dev_data = dev_resp.json() or {}
        devices = dev_data.get("devices") or dev_data.get("data") or []
        for d in devices:
            dev_id = d.get("device_id")
            hostname = (d.get("hostname") or "").strip()
            if dev_id is not None and hostname:
                device_names[str(dev_id)] = hostname
    except Exception as e:
        app.logger.warning(f"LNMS /devices API error (hostname map): {e}")

    # ---- Bandwidth from /ports ----
    try:
        ports_resp = requests.get(
            f"{base_url}/ports",
            params={
                "limit": 500,
                "columns": (
                    "device_id,ifAlias,ifName,ifDescr,port_id,"
                    "ifInOctets_rate,ifOutOctets_rate"
                ),
            },
            headers=headers,
            timeout=5,
            verify=verify_ssl,
        )
        ports_resp.raise_for_status()
        ports_data = ports_resp.json() or {}
        ports = ports_data.get("ports") or ports_data.get("data") or []

        for p in ports:
            in_rate = float(p.get("ifInOctets_rate") or 0)
            out_rate = float(p.get("ifOutOctets_rate") or 0)
            total_bits_per_second = (in_rate + out_rate) * 8.0
            if total_bits_per_second <= 0:
                continue
            mbps = total_bits_per_second / 1_000_000.0

            dev_id = p.get("device_id")
            hostname = device_names.get(str(dev_id), "") if dev_id is not None else ""

            iface_alias = (p.get("ifAlias") or "").strip()
            iface_name = (p.get("ifName") or "").strip()
            iface_descr = (p.get("ifDescr") or "").strip()
            base_label = iface_alias or iface_name or iface_descr or f"port {p.get('port_id')}"

            label = f"{hostname} – {base_label}" if hostname else base_label

            bw_entries.append({"device": label, "value": round(mbps, 1)})

        bw_entries.sort(key=lambda d: d["value"], reverse=True)
        bw_entries = bw_entries[:limit]
    except Exception as e:
        app.logger.warning(f"LNMS /ports API error: {e}")
        bw_entries = []

    return {
        "cpu": cpu_entries,
        "ram": ram_entries,
        "bandwidth": bw_entries,
        "storage": storage_entries,
    }


def fetch_lnms_data(limit_alerts: int = 10, window=None):
    if (
        not getattr(Config, "USE_LNMS_API", False)
        or not getattr(Config, "LNMS_API_URL", "")
        or not getattr(Config, "LNMS_API_TOKEN", "")
    ):
        return [], {"cpu": [], "ram": [], "bandwidth": [], "storage": []}

    base_url = Config.LNMS_API_URL.rstrip("/")
    headers = {"X-Auth-Token": Config.LNMS_API_TOKEN}
    verify_ssl = getattr(Config, "LNMS_API_VERIFY_SSL", True)

    if window is None:
        window = ALERT_WINDOW_CHOICES[ALERT_DEFAULT_WINDOW]
    cutoff = datetime.utcnow() - window

    lnms_alerts: list[dict] = []

    try:
        alerts_resp = requests.get(
            f"{base_url}/alerts",
            headers=headers,
            params={
                "limit": limit_alerts * 5,
                # order alone controls sort; this means "sort by timestamp descending"
                "order": "timestamp DESC",
                # optional: uncomment if you only want active alerts
                # "state": 1,
            },
            timeout=5,
            verify=verify_ssl,
        )

        alerts_resp.raise_for_status()
        data = alerts_resp.json() or {}
        raw_alerts = data.get("alerts") or data.get("data") or []

        filtered = []
        for a in raw_alerts:
            ts = a.get("timestamp") or a.get("time_logged") or a.get("datetime") or ""
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

    top_devices = _get_lnms_top_devices(
        base_url=base_url,
        headers=headers,
        verify_ssl=verify_ssl,
        limit=10,
    )

    return lnms_alerts, top_devices
