"""
ACTIS Central Threat Intelligence Backend Database
Manages shared verified threat intelligence across ACTIS installations.
Stores only security indicators (hashes, URLs, domains) - NEVER user personal files.
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from config.config import CENTRAL_BACKEND_DB, get_logger

logger = get_logger("CentralBackendDB")


def get_backend_db_connection() -> sqlite3.Connection:
    CENTRAL_BACKEND_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(CENTRAL_BACKEND_DB), timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_central_database():
    """Initializes central threat intelligence schema and seeds default API key."""
    conn = get_backend_db_connection()
    cursor = conn.cursor()

    # 1. Verified indicators table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS verified_indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator_type TEXT NOT NULL,
        indicator_value TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        threat_name TEXT NOT NULL,
        confidence REAL NOT NULL DEFAULT 0.9,
        status TEXT NOT NULL DEFAULT 'CONFIRMED',
        notes TEXT,
        reporter_id TEXT DEFAULT 'actis_network',
        verified_at TEXT NOT NULL,
        UNIQUE(indicator_type, indicator_value)
    );
    """)

    # 2. Client API keys table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS client_api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL UNIQUE,
        api_key TEXT NOT NULL UNIQUE,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_central_ind ON verified_indicators(indicator_type, indicator_value);")

    # Seed default client key if not present
    cursor.execute("SELECT COUNT(*) as cnt FROM client_api_keys;")
    if cursor.fetchone()["cnt"] == 0:
        now = datetime.now().isoformat()
        cursor.execute("""
        INSERT INTO client_api_keys (client_id, api_key, is_active, created_at)
        VALUES ('actis-endpoint-node-1', 'actis-client-default-secret-token', 1, ?)
        """, (now,))

    # Seed sample verified indicators
    cursor.execute("SELECT COUNT(*) as cnt FROM verified_indicators;")
    if cursor.fetchone()["cnt"] == 0:
        now = datetime.now().isoformat()
        cursor.execute("""
        INSERT INTO verified_indicators (indicator_type, indicator_value, threat_type, threat_name, confidence, status, notes, verified_at)
        VALUES 
        ('sha256', 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa', 'Ransomware', 'WannaCry', 1.0, 'CONFIRMED', 'Known global WannaCry executable hash', ?),
        ('domain', 'paypal-security-verification.xyz', 'Phishing', 'PayPal Harvester', 0.98, 'CONFIRMED', 'Confirmed phishing portal', ?)
        """, (now, now))

    conn.commit()
    conn.close()
    logger.info("Central Threat Intelligence Backend database initialized.")


init_central_database()
