# config.py

class Config:
    # Flask secret key (used for sessions, CSRF, etc.)
    SECRET_KEY = "332b4e8171a390df50b7d07945add842acb4bba84bce6991685b22e97ae07b6c"

    # PostgreSQL connection settings
    DB_NAME = "networkdash_db"
    DB_USER = "networkdash_app"
    DB_PASSWORD = "o+pi55KSrL1JZ2t18U.JpKy0Z?tedMEg"
    DB_HOST = "127.0.0.1"
    DB_PORT = 5432

    # Convenience DSN for psycopg2
    @classmethod
    def db_dsn(cls) -> str:
        return (
            f"dbname={cls.DB_NAME} "
            f"user={cls.DB_USER} "
            f"password={cls.DB_PASSWORD} "
            f"host={cls.DB_HOST} "
            f"port={cls.DB_PORT}"
        )

    # External dashboards / links (update when ready)
    WAZUH_DASHBOARD_URL = "https://10.0.80.28"
    LNMS_DASHBOARD_URL = "https://http://10.0.80.27/"
    HELP_DESK_URL = "https://helpdesk.example.com"
    GOOGLE_MAPS_SITES_URL = "https://www.google.com/maps/d/edit?mid=1s9eZvhZPAPYeTm_9ddIpEtnB_cJ5pP0&usp=sharing"
    GOOGLE_DOCS_INDEX_URL = "https://docs.google.com"

        # --- Wazuh API settings ---
    # Base URL of the Wazuh API (manager), e.g. "https://wazuh-soc2:55000"
    WAZUH_API_URL = "https://10.0.80.28:55000"  # fill in later
    WAZUH_API_USER = "wazuh-wui"
    WAZUH_API_PASSWORD = "wazuh-wui"
    WAZUH_API_VERIFY_SSL = False  # often False with internal/self-signed

    # Enable/disable live Wazuh calls (False = use placeholder data)
    USE_WAZUH_API = True
    
    # Wazuh indexer (OpenSearch) settings for alerts
    USE_WAZUH_INDEXER = True
    WAZUH_INDEXER_URL = "https://10.0.80.38:9200"
    WAZUH_INDEXER_USER = "admin"          # or another accounts
    WAZUH_INDEXER_PASSWORD = "Soc2!WzX8#2025"  # your real password
    WAZUH_INDEXER_VERIFY_SSL = False      # True once you wire CA certs

    # --- LNMS (LibreNMS) API settings ---
    # Base URL of the LibreNMS API, e.g. "https://lnms.yourdomain.com/api/v0"
    LNMS_API_URL = "http://10.0.80.27/api/v0"  # fill in later
    LNMS_API_TOKEN = "83305c95720dd231c8abac1775b9ddc9"  # API token from LibreNMS user
    LNMS_API_VERIFY_SSL = False
    
    
    LNMS_DB_ENABLED = True
    LNMS_DB_HOST = "10.0.80.27"
    LNMS_DB_PORT = 3306
    LNMS_DB_NAME = "librenms"
    LNMS_DB_USER = "networkdash"
    LNMS_DB_PASSWORD = "NdWkC68cvxQa8dy2Xlvh9fmnpvkL*fnH"
    # Enable/disable live LNMS calls (False = use placeholder data)
    USE_LNMS_API = True

    # Grafana settings for embedded panels
    GRAFANA_URL = "http://10.0.80.50:3000"
