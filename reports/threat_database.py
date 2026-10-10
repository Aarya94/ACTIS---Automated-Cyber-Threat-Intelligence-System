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

    # 6. File scan states table (Incremental Scan State)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS file_scan_states (
        canonical_path TEXT PRIMARY KEY,
        file_size INTEGER NOT NULL,
        mtime REAL NOT NULL,
        sha256 TEXT NOT NULL,
        last_scanned_at TEXT NOT NULL,
        scan_status TEXT NOT NULL,
        risk_score REAL DEFAULT 0.0,
        risk_level TEXT DEFAULT 'LOW',
        analyzer_version TEXT,
        model_version TEXT,
        rule_version TEXT,
        detection_reasons TEXT
    );
    """)

    # 7. Threat sync runs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_sync_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT UNIQUE NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        overall_status TEXT NOT NULL,
        total_received INTEGER DEFAULT 0,
        total_inserted INTEGER DEFAULT 0,
        total_updated INTEGER DEFAULT 0,
        total_rejected INTEGER DEFAULT 0,
        details_json TEXT
    );
    """)

    # 8. Threat feed status table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_feed_status (
        provider TEXT PRIMARY KEY,
        last_attempt TEXT,
        last_successful TEXT,
        status TEXT NOT NULL DEFAULT 'NEVER_SYNCED',
        records_received INTEGER DEFAULT 0,
        records_inserted INTEGER DEFAULT 0,
        records_updated INTEGER DEFAULT 0,
        records_rejected INTEGER DEFAULT 0,
        error_category TEXT,
        error_message TEXT,
        updated_at TEXT NOT NULL
    );
    """)

    # Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_type_val ON indicators(indicator_type, indicator_value);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_detections_target ON detections(target);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(detected_at);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(started_at);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_states_sha256 ON file_scan_states(sha256);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_states_mtime ON file_scan_states(mtime);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sync_runs_started ON threat_sync_runs(started_at);")

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


def save_file_scan_state(state: Dict[str, Any]) -> None:
    """Inserts or updates an incremental file scan state record in SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    reasons_json = json.dumps(state.get("detection_reasons", []))
    cursor.execute("""
    INSERT INTO file_scan_states (
        canonical_path, file_size, mtime, sha256, last_scanned_at,
        scan_status, risk_score, risk_level, analyzer_version,
        model_version, rule_version, detection_reasons
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(canonical_path) DO UPDATE SET
        file_size = excluded.file_size,
        mtime = excluded.mtime,
        sha256 = excluded.sha256,
        last_scanned_at = excluded.last_scanned_at,
        scan_status = excluded.scan_status,
        risk_score = excluded.risk_score,
        risk_level = excluded.risk_level,
        analyzer_version = excluded.analyzer_version,
        model_version = excluded.model_version,
        rule_version = excluded.rule_version,
        detection_reasons = excluded.detection_reasons;
    """, (
        str(state["canonical_path"]),
        int(state.get("file_size", 0)),
        float(state.get("mtime", 0.0)),
        str(state.get("sha256", "")),
        str(state.get("last_scanned_at", "")),
        str(state.get("scan_status", "CLEAN")),
        float(state.get("risk_score", 0.0)),
        str(state.get("risk_level", "LOW")),
        str(state.get("analyzer_version", "1.0.0")),
        str(state.get("model_version", "rf_malware_pe_v1")),
        str(state.get("rule_version", "pe_heuristics_v1")),
        reasons_json
    ))
    conn.commit()
    conn.close()


def get_file_scan_state(canonical_path: str) -> Optional[Dict[str, Any]]:
    """Retrieves stored scan state for a canonical path if present."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM file_scan_states WHERE canonical_path = ?", (str(canonical_path),))
    row = cursor.fetchone()
    conn.close()
    if row:
        d = dict(row)
        try:
            d["detection_reasons"] = json.loads(d["detection_reasons"])
        except Exception:
            d["detection_reasons"] = []
        return d
    return None


def get_all_file_scan_states() -> List[Dict[str, Any]]:
    """Retrieves all stored incremental file scan states."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM file_scan_states")
    rows = cursor.fetchall()
    conn.close()
    results = []
    for row in rows:
        d = dict(row)
        try:
            d["detection_reasons"] = json.loads(d["detection_reasons"])
        except Exception:
            d["detection_reasons"] = []
        results.append(d)
    return results


def delete_file_scan_state(canonical_path: str) -> bool:
    """Removes a scan state record for a given canonical path."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM file_scan_states WHERE canonical_path = ?", (str(canonical_path),))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def clear_file_scan_states() -> None:
    """Clears all stored incremental file scan states."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM file_scan_states;")
    conn.commit()
    conn.close()


def upsert_feed_records(records: List[Dict[str, Any]]) -> Tuple[int, int, int]:
    """
    Idempotently inserts or updates threat indicators from an upstream feed in SQLite.
    Returns a tuple of (inserted_count, updated_count, unchanged_count).
    Ensures safe transaction isolation, parameterized execution, and historical preservation.
    """
    if not records:
        return 0, 0, 0

    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()

    inserted = 0
    updated = 0
    unchanged = 0

    try:
        with conn:
            for rec in records:
                itype = str(rec.get("indicator_type", "")).strip().lower()
                ival = str(rec.get("indicator_value", "")).strip().lower()
                if not itype or not ival:
                    continue

                source = rec.get("source", "Upstream_Feed")
                confidence = float(rec.get("confidence", 0.8))
                status = str(rec.get("status", "SUSPICIOUS")).upper()
                threat_type = rec.get("threat_type", "Malware")
                threat_name = rec.get("threat_name", "Upstream Feed Detection")
                first_seen = rec.get("first_seen") or now
                last_seen = rec.get("last_seen") or now

                # Check if indicator already exists
                cursor.execute(
                    "SELECT id, threat_id, confidence, status, source FROM indicators WHERE indicator_type = ? AND lower(indicator_value) = ?",
                    (itype, ival)
                )
                existing = cursor.fetchone()

                if existing:
                    old_conf = float(existing["confidence"])
                    old_status = existing["status"]
                    old_source = existing["source"]

                    # Upgrade confidence or status if newly observed data is higher confidence
                    new_conf = max(old_conf, confidence)
                    new_status = "CONFIRMED" if "CONFIRMED" in (old_status, status) else status
                    new_source = old_source if source in old_source else f"{old_source},{source}"

                    cursor.execute("""
                    UPDATE indicators
                    SET last_seen = ?, confidence = ?, status = ?, source = ?
                    WHERE id = ?
                    """, (last_seen, new_conf, new_status, new_source, existing["id"]))

                    if new_conf > old_conf or new_status != old_status or new_source != old_source:
                        updated += 1
                    else:
                        unchanged += 1
                else:
                    # Insert threat record
                    cursor.execute("""
                    INSERT INTO threats (threat_type, name, risk_level, status, description, first_seen, last_seen, verified_by)
                    VALUES (?, ?, 'HIGH', ?, 'Upstream threat intelligence feed import', ?, ?, ?)
                    """, (threat_type, threat_name, status, first_seen, last_seen, source))
                    threat_id = cursor.lastrowid

                    # Insert indicator
                    cursor.execute("""
                    INSERT INTO indicators (threat_id, indicator_type, indicator_value, source, confidence, status, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (threat_id, itype, ival, source, confidence, status, first_seen, last_seen))
                    inserted += 1

    finally:
        conn.close()

    return inserted, updated, unchanged


def record_sync_run(run_data: Dict[str, Any]) -> None:
    """Inserts a structured sync run record into threat_sync_runs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    details_json = json.dumps(run_data.get("provider_results", {}))
    with conn:
        cursor.execute("""
        INSERT INTO threat_sync_runs (
            run_id, started_at, completed_at, overall_status,
            total_received, total_inserted, total_updated, total_rejected, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id) DO UPDATE SET
            completed_at = excluded.completed_at,
            overall_status = excluded.overall_status,
            total_received = excluded.total_received,
            total_inserted = excluded.total_inserted,
            total_updated = excluded.total_updated,
            total_rejected = excluded.total_rejected,
            details_json = excluded.details_json;
        """, (
            str(run_data.get("run_id", "")),
            str(run_data.get("started_at", "")),
            run_data.get("completed_at"),
            str(run_data.get("overall_status", "SUCCESS")),
            int(run_data.get("total_records_received", 0)),
            int(run_data.get("total_records_inserted", 0)),
            int(run_data.get("total_records_updated", 0)),
            int(run_data.get("total_records_rejected", 0)),
            details_json,
        ))
    conn.close()


def update_feed_status(status_data: Dict[str, Any]) -> None:
    """Updates live provider synchronization status in threat_feed_status."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    with conn:
        cursor.execute("""
        INSERT INTO threat_feed_status (
            provider, last_attempt, last_successful, status,
            records_received, records_inserted, records_updated, records_rejected,
            error_category, error_message, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(provider) DO UPDATE SET
            last_attempt = excluded.last_attempt,
            last_successful = COALESCE(excluded.last_successful, threat_feed_status.last_successful),
            status = excluded.status,
            records_received = excluded.records_received,
            records_inserted = excluded.records_inserted,
            records_updated = excluded.records_updated,
            records_rejected = excluded.records_rejected,
            error_category = excluded.error_category,
            error_message = excluded.error_message,
            updated_at = excluded.updated_at;
        """, (
            str(status_data.get("provider", "")),
            status_data.get("last_attempt"),
            status_data.get("last_successful"),
            str(status_data.get("status", "NEVER_SYNCED")),
            int(status_data.get("records_received", 0)),
            int(status_data.get("records_inserted", 0)),
            int(status_data.get("records_updated", 0)),
            int(status_data.get("records_rejected", 0)),
            status_data.get("error_category"),
            status_data.get("error_message"),
            now,
        ))
    conn.close()


def get_feed_statuses() -> List[Dict[str, Any]]:
    """Retrieves current synchronization status for all registered threat feeds."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_feed_status ORDER BY provider ASC;")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_latest_sync_run() -> Optional[Dict[str, Any]]:
    """Retrieves the most recent sync run record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_sync_runs ORDER BY id DESC LIMIT 1;")
    row = cursor.fetchone()
    conn.close()
    if row:
        d = dict(row)
        try:
            d["details_json"] = json.loads(d["details_json"])
        except Exception:
            pass
        return d
    return None


def get_recent_sync_runs(limit: int = 10) -> List[Dict[str, Any]]:
    """Retrieves recent sync run records."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_sync_runs ORDER BY id DESC LIMIT ?;", (limit,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        try:
            d["details_json"] = json.loads(d["details_json"])
        except Exception:
            pass
        results.append(d)
    return results


# Initialize tables on import
initialize_database()

