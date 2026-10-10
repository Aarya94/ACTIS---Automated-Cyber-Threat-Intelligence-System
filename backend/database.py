"""
ACTIS Central Threat Intelligence Backend Database
Manages shared verified threat intelligence across ACTIS installations.
Stores only security indicators (hashes, URLs, domains, public IPs) - NEVER user personal files.
Implements candidate contribution persistence with anti-poisoning state enforcement.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config.config import CENTRAL_BACKEND_DB, get_logger

logger = get_logger("CentralBackendDB")


def get_backend_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Returns a thread-safe connection to the central threat intelligence SQLite database."""
    target_path = db_path or CENTRAL_BACKEND_DB
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path), timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_central_database(db_path: Optional[Path] = None) -> None:
    """
    Initializes central threat intelligence schema, performs non-destructive migrations,
    and seeds default API keys and initial verified indicators.
    """
    conn = get_backend_db_connection(db_path)
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
        source_type TEXT NOT NULL DEFAULT 'UPSTREAM_FEED',
        tags TEXT DEFAULT '',
        review_status TEXT NOT NULL DEFAULT 'APPROVED',
        first_seen TEXT,
        last_seen TEXT,
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
        roles TEXT NOT NULL DEFAULT 'read,contribute',
        rate_limit_rpm INTEGER NOT NULL DEFAULT 60,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );
    """)

    # Non-destructive migrations for existing databases
    cursor.execute("PRAGMA table_info(client_api_keys);")
    client_cols = {row["name"] for row in cursor.fetchall()}
    if "roles" not in client_cols:
        cursor.execute("ALTER TABLE client_api_keys ADD COLUMN roles TEXT NOT NULL DEFAULT 'read,contribute';")
    if "rate_limit_rpm" not in client_cols:
        cursor.execute("ALTER TABLE client_api_keys ADD COLUMN rate_limit_rpm INTEGER NOT NULL DEFAULT 60;")

    cursor.execute("PRAGMA table_info(verified_indicators);")
    indicator_cols = {row["name"] for row in cursor.fetchall()}
    if "source_type" not in indicator_cols:
        cursor.execute("ALTER TABLE verified_indicators ADD COLUMN source_type TEXT NOT NULL DEFAULT 'UPSTREAM_FEED';")
    if "tags" not in indicator_cols:
        cursor.execute("ALTER TABLE verified_indicators ADD COLUMN tags TEXT DEFAULT '';")
    if "review_status" not in indicator_cols:
        cursor.execute("ALTER TABLE verified_indicators ADD COLUMN review_status TEXT NOT NULL DEFAULT 'APPROVED';")
    if "first_seen" not in indicator_cols:
        cursor.execute("ALTER TABLE verified_indicators ADD COLUMN first_seen TEXT;")
    if "last_seen" not in indicator_cols:
        cursor.execute("ALTER TABLE verified_indicators ADD COLUMN last_seen TEXT;")

    # Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_central_ind ON verified_indicators(indicator_type, indicator_value);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_central_status ON verified_indicators(status, confidence);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_central_verified_at ON verified_indicators(verified_at);")

    now = datetime.now(timezone.utc).isoformat()

    # Seed client keys if missing
    cursor.execute("SELECT COUNT(*) as cnt FROM client_api_keys;")
    if cursor.fetchone()["cnt"] == 0:
        cursor.execute("""
        INSERT INTO client_api_keys (client_id, api_key, roles, rate_limit_rpm, is_active, created_at)
        VALUES 
        ('actis-endpoint-node-1', 'actis-client-default-secret-token', 'read,contribute', 120, 1, ?),
        ('actis-readonly-client', 'actis-client-readonly-token', 'read', 60, 1, ?),
        ('actis-admin-node', 'actis-admin-secret-token', 'read,contribute,admin', 300, 1, ?)
        """, (now, now, now))
    else:
        # Ensure default test keys exist with correct roles
        for c_id, a_key, r_scope, r_lim in [
            ('actis-readonly-client', 'actis-client-readonly-token', 'read', 60),
            ('actis-admin-node', 'actis-admin-secret-token', 'read,contribute,admin', 300),
        ]:
            cursor.execute("SELECT COUNT(*) as cnt FROM client_api_keys WHERE client_id = ?", (c_id,))
            if cursor.fetchone()["cnt"] == 0:
                cursor.execute("""
                INSERT INTO client_api_keys (client_id, api_key, roles, rate_limit_rpm, is_active, created_at)
                VALUES (?, ?, ?, ?, 1, ?)
                """, (c_id, a_key, r_scope, r_lim, now))

    # Seed sample verified indicators if empty
    cursor.execute("SELECT COUNT(*) as cnt FROM verified_indicators;")
    if cursor.fetchone()["cnt"] == 0:
        cursor.execute("""
        INSERT INTO verified_indicators (
            indicator_type, indicator_value, threat_type, threat_name,
            confidence, status, notes, reporter_id, source_type, tags,
            review_status, first_seen, last_seen, verified_at
        ) VALUES 
        ('sha256', 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa', 'Ransomware', 'WannaCry', 1.0, 'CONFIRMED', 'Known global WannaCry executable hash', 'actis_network', 'UPSTREAM_FEED', '["ransomware","wannacry"]', 'APPROVED', ?, ?, ?),
        ('domain', 'paypal-security-verification.xyz', 'Phishing', 'PayPal Harvester', 0.98, 'CONFIRMED', 'Confirmed phishing portal', 'actis_network', 'UPSTREAM_FEED', '["phishing","credential_theft"]', 'APPROVED', ?, ?, ?)
        """, (now, now, now, now, now, now))
    else:
        # Non-destructive backfill of seed tags on existing indicators
        cursor.execute("""
            UPDATE verified_indicators 
            SET tags = '["phishing","credential_theft"]' 
            WHERE indicator_value = 'paypal-security-verification.xyz' AND (tags IS NULL OR tags = '' OR tags = '[]');
        """)
        cursor.execute("""
            UPDATE verified_indicators 
            SET tags = '["ransomware","wannacry"]' 
            WHERE indicator_value = 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa' AND (tags IS NULL OR tags = '' OR tags = '[]');
        """)

    conn.commit()
    conn.close()
    logger.info("Central Threat Intelligence Backend database initialized successfully.")


# Repository functions


def get_client_by_key(api_key: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Retrieves client metadata by API key."""
    conn = get_backend_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT client_id, api_key, roles, rate_limit_rpm, is_active FROM client_api_keys WHERE api_key = ?",
        (api_key,)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_indicator_by_type_value(
    indicator_type: str,
    indicator_value: str,
    db_path: Optional[Path] = None
) -> Optional[Dict[str, Any]]:
    """Retrieves indicator record matching type and normalized value."""
    conn = get_backend_db_connection(db_path)
    cursor = conn.cursor()
    val_clean = indicator_value.strip().lower()
    cursor.execute("""
    SELECT id, indicator_type, indicator_value, threat_type, threat_name,
           confidence, status, notes, reporter_id, source_type, tags,
           review_status, first_seen, last_seen, verified_at
    FROM verified_indicators
    WHERE indicator_type = ? AND lower(indicator_value) = ?
    """, (indicator_type.lower(), val_clean))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    if d.get("tags"):
        try:
            d["tags"] = json.loads(d["tags"])
        except (json.JSONDecodeError, TypeError):
            d["tags"] = [t.strip() for t in str(d["tags"]).split(",") if t.strip()]
    else:
        d["tags"] = []
    return d


def query_indicators(
    min_confidence: float = 0.8,
    status_filter: Optional[str] = "CONFIRMED",
    indicator_types: Optional[List[str]] = None,
    since_timestamp: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
    db_path: Optional[Path] = None
) -> Tuple[List[Dict[str, Any]], int, bool]:
    """
    Executes a bounded, parameterized query for verified indicators.
    Returns (indicators, total_matching, has_more).
    """
    conn = get_backend_db_connection(db_path)
    cursor = conn.cursor()

    where_clauses = ["confidence >= ?"]
    params: List[Any] = [min_confidence]

    if status_filter:
        where_clauses.append("status = ?")
        params.append(status_filter)

    if indicator_types:
        placeholders = ",".join("?" for _ in indicator_types)
        where_clauses.append(f"indicator_type IN ({placeholders})")
        params.extend([t.lower() for t in indicator_types])

    if since_timestamp:
        where_clauses.append("verified_at >= ?")
        params.append(since_timestamp)

    where_str = " AND ".join(where_clauses)

    # Count total matching
    count_sql = f"SELECT COUNT(*) as cnt FROM verified_indicators WHERE {where_str};"
    cursor.execute(count_sql, params)
    total_matching = cursor.fetchone()["cnt"]

    # Select paged items
    query_sql = f"""
    SELECT id, indicator_type, indicator_value, threat_type, threat_name,
           confidence, status, notes, reporter_id, source_type, tags,
           review_status, first_seen, last_seen, verified_at
    FROM verified_indicators
    WHERE {where_str}
    ORDER BY id DESC
    LIMIT ? OFFSET ?;
    """
    paged_params = list(params) + [limit, offset]
    cursor.execute(query_sql, paged_params)
    rows = cursor.fetchall()
    conn.close()

    results: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        if d.get("tags"):
            try:
                d["tags"] = json.loads(d["tags"])
            except (json.JSONDecodeError, TypeError):
                d["tags"] = [t.strip() for t in str(d["tags"]).split(",") if t.strip()]
        else:
            d["tags"] = []
        results.append(d)

    has_more = (offset + len(results)) < total_matching
    return results, total_matching, has_more


def insert_candidate_contribution(
    client_id: str,
    indicator_type: str,
    indicator_value: str,
    threat_type: str,
    threat_name: str,
    confidence: float,
    tags: List[str],
    notes: Optional[str] = None,
    status_override: Optional[str] = None,
    db_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Inserts a candidate indicator submitted by an authorized client.
    Guarantees status is stored as CANDIDATE and review_status as PENDING by default.
    Allows status_override when authorized by legacy or administrative flows.
    """
    conn = get_backend_db_connection(db_path)
    cursor = conn.cursor()

    val_clean = indicator_value.strip().lower()
    ind_type = indicator_type.strip().lower()
    now = datetime.now(timezone.utc).isoformat()
    tags_json = json.dumps(tags) if tags else ""

    # Check for existing record
    cursor.execute(
        "SELECT id, status, review_status, confidence FROM verified_indicators WHERE indicator_type = ? AND lower(indicator_value) = ?",
        (ind_type, val_clean)
    )
    existing = cursor.fetchone()

    target_status = status_override or "CANDIDATE"
    target_review = "APPROVED" if target_status == "CONFIRMED" else "PENDING"

    if existing:
        ind_id = existing["id"]
        existing_status = existing["status"]
        new_status = target_status if status_override else existing_status
        new_review = target_review if status_override else existing["review_status"]
        new_conf = min(1.0, max(existing["confidence"], confidence))
        cursor.execute("""
        UPDATE verified_indicators
        SET last_seen = ?, confidence = ?, status = ?, review_status = ?, notes = coalesce(notes, '') || ' | ' || coalesce(?, '')
        WHERE id = ?
        """, (now, new_conf, new_status, new_review, f"Reported by {client_id}: {notes or ''}", ind_id))
        conn.commit()
        ret_status = new_status
        ret_review = new_review
    else:
        cursor.execute("""
        INSERT INTO verified_indicators (
            indicator_type, indicator_value, threat_type, threat_name,
            confidence, status, notes, reporter_id, source_type, tags,
            review_status, first_seen, last_seen, verified_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'CLIENT_CONTRIBUTION', ?, ?, ?, ?, ?)
        """, (
            ind_type, val_clean, threat_type, threat_name,
            confidence, target_status, notes, client_id, tags_json, target_review, now, now, now
        ))
        conn.commit()
        ind_id = cursor.lastrowid
        ret_status = target_status
        ret_review = target_review

    conn.close()
    return {
        "id": ind_id,
        "indicator_type": ind_type,
        "indicator_value": val_clean,
        "status": ret_status,
        "review_status": ret_review,
        "reporter_id": client_id,
    }


def admin_review_indicator(
    indicator_id: int,
    reviewer_id: str,
    action: str,
    notes: Optional[str] = None,
    db_path: Optional[Path] = None
) -> Optional[Dict[str, Any]]:
    """
    Administrative review operation. Allows promoting CANDIDATE to CONFIRMED
    or marking FALSE_POSITIVE / REJECTED.
    """
    action_upper = action.strip().upper()
    status_map = {
        "APPROVE": ("CONFIRMED", "APPROVED"),
        "REJECT": ("CANDIDATE", "REJECTED"),
        "MARK_FALSE_POSITIVE": ("FALSE_POSITIVE", "APPROVED"),
    }
    if action_upper not in status_map:
        raise ValueError(f"Invalid review action: {action}. Must be one of: {list(status_map.keys())}")

    target_status, target_review = status_map[action_upper]
    now = datetime.now(timezone.utc).isoformat()

    conn = get_backend_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM verified_indicators WHERE id = ?", (indicator_id,))
    if not cursor.fetchone():
        conn.close()
        return None

    audit_note = f"Reviewed by {reviewer_id} ({action_upper}) at {now}: {notes or ''}"
    cursor.execute("""
    UPDATE verified_indicators
    SET status = ?, review_status = ?, notes = coalesce(notes, '') || ' | ' || ?
    WHERE id = ?
    """, (target_status, target_review, audit_note, indicator_id))
    conn.commit()
    conn.close()

    return {
        "indicator_id": indicator_id,
        "status": target_status,
        "review_status": target_review,
        "action": action_upper,
    }


def count_indicators(db_path: Optional[Path] = None) -> int:
    """Returns total indicator count."""
    conn = get_backend_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM verified_indicators;")
    count = cursor.fetchone()["cnt"]
    conn.close()
    return count


# Auto-initialize on import
init_central_database()

