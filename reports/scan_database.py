"""
ACTIS Scan Database & Analytics Module
Provides query functions for scan history, aggregated statistics, risk distribution,
and detection exploration.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from reports.threat_database import get_db_connection


def create_scan_session(scan_type: str, target: str) -> int:
    """Creates a new scan record in running state and returns its ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    started_at = datetime.now().isoformat()
    cursor.execute("""
    INSERT INTO scans (scan_type, target, started_at, status, files_scanned, threats_found, error_count)
    VALUES (?, ?, ?, 'running', 0, 0, 0)
    """, (scan_type, target, started_at))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def finish_scan_session(
    scan_id: int,
    status: str = "completed",
    files_scanned: int = 0,
    threats_found: int = 0,
    error_count: int = 0
):
    """Updates scan session upon completion or cancellation."""
    conn = get_db_connection()
    cursor = conn.cursor()
    completed_at = datetime.now().isoformat()
    cursor.execute("""
    UPDATE scans
    SET completed_at = ?, status = ?, files_scanned = ?, threats_found = ?, error_count = ?
    WHERE id = ?
    """, (completed_at, status, files_scanned, threats_found, error_count, scan_id))
    conn.commit()
    conn.close()


def record_scan_item(scan_id: int, path_or_target: str, sha256: str, status: str, risk_score: float):
    """Records an individual scanned file/item in a scan session."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    cursor.execute("""
    INSERT INTO scan_items (scan_id, path_or_target, sha256, status, risk_score, scanned_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (scan_id, path_or_target, sha256, status, risk_score, now))
    conn.commit()
    conn.close()


def get_system_statistics() -> Dict[str, Any]:
    """Computes high-level aggregated cybersecurity statistics."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total scans
    cursor.execute("SELECT COUNT(*) as total_scans, SUM(files_scanned) as total_files, SUM(threats_found) as total_threats FROM scans;")
    scan_agg = cursor.fetchone()

    # Detections count by risk level
    cursor.execute("""
    SELECT risk_level, COUNT(*) as cnt
    FROM detections
    GROUP BY risk_level;
    """)
    risk_dist = {row["risk_level"]: row["cnt"] for row in cursor.fetchall()}

    # Threats count
    cursor.execute("SELECT COUNT(*) as total_indicators FROM indicators;")
    ind_cnt = cursor.fetchone()["total_indicators"]

    # Phishing vs Malware detections
    cursor.execute("SELECT target_type, COUNT(*) as cnt FROM detections GROUP BY target_type;")
    type_dist = {row["target_type"]: row["cnt"] for row in cursor.fetchall()}

    conn.close()

    return {
        "total_scans": scan_agg["total_scans"] or 0,
        "total_files_scanned": scan_agg["total_files"] or 0,
        "total_threats_found": scan_agg["total_threats"] or 0,
        "total_indicators": ind_cnt or 0,
        "risk_distribution": {
            "CRITICAL": risk_dist.get("CRITICAL", 0),
            "HIGH": risk_dist.get("HIGH", 0),
            "MEDIUM": risk_dist.get("MEDIUM", 0),
            "LOW": risk_dist.get("LOW", 0)
        },
        "target_type_distribution": type_dist
    }


def get_recent_detections(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves most recent detections with decoded explanations."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT d.id, d.scan_id, d.target, d.target_type, d.model_name,
           d.model_score, d.rule_score, d.intel_score, d.final_score,
           d.risk_level, d.explanation_json, d.detected_at,
           s.scan_type
    FROM detections d
    LEFT JOIN scans s ON d.scan_id = s.id
    ORDER BY d.detected_at DESC
    LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        try:
            explanations = json.loads(r["explanation_json"] or "[]")
        except Exception:
            explanations = []
        results.append({
            "id": r["id"],
            "scan_id": r["scan_id"],
            "target": r["target"],
            "target_type": r["target_type"],
            "model_name": r["model_name"],
            "final_score": r["final_score"],
            "risk_level": r["risk_level"],
            "detected_at": r["detected_at"],
            "scan_type": r["scan_type"] or "manual",
            "explanations": explanations
        })
    return results


def get_recent_scans(limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves recent scan execution records."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, scan_type, target, started_at, completed_at, status, files_scanned, threats_found, error_count
    FROM scans
    ORDER BY started_at DESC
    LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
