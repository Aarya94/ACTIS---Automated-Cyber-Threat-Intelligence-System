"""
ACTIS Threat Database Module
Manages SQLite relational database for threats, indicators, scans, and detections.
Supports thread-safe database operations, migrations, and indicator lookups.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from config.config import DATABASE_PATH, get_logger

logger = get_logger("ThreatDatabase")


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with row factory enabled."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DATABASE_PATH), timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def initialize_database():
    """Initializes the database tables and indexes if they do not exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Threats table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_type TEXT NOT NULL,
        name TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'SUSPICIOUS',
        description TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        verified_by TEXT DEFAULT 'local_detection'
    );
    """)

    # 2. Indicators table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id INTEGER REFERENCES threats(id) ON DELETE SET NULL,
        indicator_type TEXT NOT NULL,
        indicator_value TEXT NOT NULL,
        source TEXT NOT NULL,
        confidence REAL NOT NULL DEFAULT 0.8,
        status TEXT NOT NULL DEFAULT 'SUSPICIOUS',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE(indicator_type, indicator_value)
    );
    """)

    # 3. Scans table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT NOT NULL,
        target TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        status TEXT NOT NULL DEFAULT 'running',
        files_scanned INTEGER DEFAULT 0,
        threats_found INTEGER DEFAULT 0,
        error_count INTEGER DEFAULT 0
    );
    """)

    # 4. Detections table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
        indicator_id INTEGER REFERENCES indicators(id) ON DELETE SET NULL,
        target TEXT NOT NULL,
        target_type TEXT NOT NULL,
        model_name TEXT,
        model_score REAL DEFAULT 0.0,
        rule_score REAL DEFAULT 0.0,
        intel_score REAL DEFAULT 0.0,
        final_score REAL NOT NULL,
        risk_level TEXT NOT NULL,
        explanation_json TEXT,
        detected_at TEXT NOT NULL
    );
    """)

    # 5. Scan items table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        path_or_target TEXT NOT NULL,
        sha256 TEXT,
        status TEXT NOT NULL,
        risk_score REAL DEFAULT 0.0,
        scanned_at TEXT NOT NULL
    );
    """)

    # Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_type_val ON indicators(indicator_type, indicator_value);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_detections_target ON detections(target);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(detected_at);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(started_at);")

    # Seed known threat indicators if empty
    cursor.execute("SELECT COUNT(*) as cnt FROM indicators;")
    if cursor.fetchone()["cnt"] == 0:
        _seed_sample_threat_intelligence(cursor)

    conn.commit()
    conn.close()
    logger.info("Threat intelligence database initialized successfully.")


def _seed_sample_threat_intelligence(cursor: sqlite3.Cursor):
    """Populates seed threat intelligence with verified reference indicators."""
    now = datetime.now().isoformat()
    
    # 1. Seed WannaCry Ransomware
    cursor.execute("""
    INSERT INTO threats (threat_type, name, risk_level, status, description, first_seen, last_seen, verified_by)
    VALUES ('Ransomware', 'WannaCry', 'CRITICAL', 'CONFIRMED', 'WannaCry ransomware cryptoworm targeting Windows SMB', ?, ?, 'ACTIS_Seed')
    """, (now, now))
    threat_wc_id = cursor.lastrowid

    # Known WannaCry hash indicator
    cursor.execute("""
    INSERT INTO indicators (threat_id, indicator_type, indicator_value, source, confidence, status, first_seen, last_seen)
    VALUES (?, 'sha256', 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa', 'Threat_Intel_Ref', 1.0, 'CONFIRMED', ?, ?)
    """, (threat_wc_id, now, now))

    # 2. Seed Generic Phishing Domain
    cursor.execute("""
    INSERT INTO threats (threat_type, name, risk_level, status, description, first_seen, last_seen, verified_by)
    VALUES ('Phishing', 'PayPal Credential Harvester', 'HIGH', 'CONFIRMED', 'Known phishing credential theft portal', ?, ?, 'ACTIS_Seed')
    """, (now, now))
    threat_phish_id = cursor.lastrowid

    # Known phishing domain indicator
    cursor.execute("""
    INSERT INTO indicators (threat_id, indicator_type, indicator_value, source, confidence, status, first_seen, last_seen)
    VALUES (?, 'domain', 'paypal-security-verification.xyz', 'PhishTank_Ref', 0.98, 'CONFIRMED', ?, ?)
    """, (threat_phish_id, now, now))
    
    cursor.execute("""
    INSERT INTO indicators (threat_id, indicator_type, indicator_value, source, confidence, status, first_seen, last_seen)
    VALUES (?, 'url', 'http://paypal-security-verification.xyz/login.php', 'PhishTank_Ref', 0.98, 'CONFIRMED', ?, ?)
    """, (threat_phish_id, now, now))


def lookup_indicator(indicator_type: str, indicator_value: str) -> Dict[str, Any]:
    """Queries local database for an indicator by type and normalized value."""
    conn = get_db_connection()
    cursor = conn.cursor()

    val_clean = indicator_value.strip().lower()

    cursor.execute("""
    SELECT i.id, i.threat_id, i.indicator_type, i.indicator_value, i.source,
           i.confidence, i.status, i.first_seen, i.last_seen,
           t.threat_type, t.name as threat_name, t.risk_level as threat_risk_level, t.description
    FROM indicators i
    LEFT JOIN threats t ON i.threat_id = t.id
    WHERE i.indicator_type = ? AND lower(i.indicator_value) = ?
    """, (indicator_type.lower(), val_clean))

    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "found": True,
            "id": row["id"],
            "threat_id": row["threat_id"],
            "indicator_type": row["indicator_type"],
            "indicator_value": row["indicator_value"],
            "source": row["source"],
            "confidence": float(row["confidence"]),
            "status": row["status"],
            "threat_type": row["threat_type"] or "Unknown",
            "threat_name": row["threat_name"] or "Unknown",
            "threat_risk_level": row["threat_risk_level"] or "HIGH",
            "description": row["description"] or "",
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"]
        }
    return {"found": False}


def record_detection(
    target: str,
    target_type: str,
    final_score: float,
    risk_level: str,
    model_name: str = "",
    model_score: float = 0.0,
    rule_score: float = 0.0,
    intel_score: float = 0.0,
    explanation_list: Optional[List[str]] = None,
    scan_id: Optional[int] = None,
    indicator_id: Optional[int] = None
) -> int:
    """Records a security detection event into the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    exp_json = json.dumps(explanation_list or [])

    cursor.execute("""
    INSERT INTO detections (
        scan_id, indicator_id, target, target_type, model_name,
        model_score, rule_score, intel_score, final_score,
        risk_level, explanation_json, detected_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id, indicator_id, target, target_type, model_name,
        model_score, rule_score, intel_score, final_score,
        risk_level, exp_json, now
    ))

    detection_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return detection_id


def register_indicator(
    indicator_type: str,
    indicator_value: str,
    source: str = "local_detection",
    confidence: float = 0.8,
    status: str = "SUSPICIOUS",
    threat_type: str = "Generic Threat",
    threat_name: str = "Generic Indicator"
) -> int:
    """Registers or updates a threat indicator in the local threat intelligence database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    val_clean = indicator_value.strip().lower()

    # Check if indicator already exists
    cursor.execute(
        "SELECT id, confidence, status FROM indicators WHERE indicator_type = ? AND lower(indicator_value) = ?",
        (indicator_type.lower(), val_clean)
    )
    existing = cursor.fetchone()

    if existing:
        # Update last seen and adjust confidence
        new_conf = min(1.0, max(existing["confidence"], confidence))
        cursor.execute("""
        UPDATE indicators
        SET last_seen = ?, confidence = ?, source = ?
        WHERE id = ?
        """, (now, new_conf, source, existing["id"]))
        conn.commit()
        ind_id = existing["id"]
    else:
        # Create threat record first if needed
        cursor.execute("""
        INSERT INTO threats (threat_type, name, risk_level, status, description, first_seen, last_seen, verified_by)
        VALUES (?, ?, 'HIGH', ?, 'Automated detection indicator', ?, ?, ?)
        """, (threat_type, threat_name, status, now, now, source))
        threat_id = cursor.lastrowid

        cursor.execute("""
        INSERT INTO indicators (threat_id, indicator_type, indicator_value, source, confidence, status, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (threat_id, indicator_type.lower(), val_clean, source, confidence, status, now, now))
        ind_id = cursor.lastrowid
        conn.commit()

    conn.close()
    return ind_id


# Initialize tables on import
initialize_database()
