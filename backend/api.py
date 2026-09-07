"""
ACTIS Central Threat Intelligence REST API
Provides endpoints for clients to query indicators, synchronize verified threat feeds,
and submit verified findings to the shared network.
"""

from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, Header, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware

from backend.database import get_backend_db_connection, init_central_database
from backend.models import (
    HealthResponse,
    IndicatorSubmitRequest,
    IndicatorResponse,
    IndicatorLookupResponse,
    SyncResponse
)
from config.config import get_logger

logger = get_logger("CentralBackendAPI")

app = FastAPI(
    title="ACTIS Central Threat Intelligence Network API",
    description="Decentralized indicator sharing and intelligence synchronization for ACTIS endpoints.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_api_key(x_actis_api_key: Optional[str] = Header(None)) -> str:
    """Authenticates requesting ACTIS client using API key header."""
    if not x_actis_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-ACTIS-API-Key header."
        )

    conn = get_backend_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT client_id, is_active FROM client_api_keys WHERE api_key = ?",
        (x_actis_api_key,)
    )
    client = cursor.fetchone()
    conn.close()

    if not client or not client["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or deactivated API key."
        )
    return client["client_id"]


@app.get("/api/health", response_model=HealthResponse)
def health():
    """Returns backend service health and indicator metrics."""
    conn = get_backend_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM verified_indicators;")
    count = cursor.fetchone()["cnt"]
    conn.close()

    return HealthResponse(
        status="ONLINE",
        total_indicators=count,
        timestamp=datetime.now().isoformat()
    )


@app.get("/api/indicator/{indicator_type}/{value}", response_model=IndicatorLookupResponse)
def get_indicator(indicator_type: str, value: str):
    """Queries central threat intelligence database for an indicator."""
    conn = get_backend_db_connection()
    cursor = conn.cursor()
    val_clean = value.strip().lower()

    cursor.execute("""
    SELECT id, indicator_type, indicator_value, threat_type, threat_name,
           confidence, status, notes, verified_at
    FROM verified_indicators
    WHERE indicator_type = ? AND lower(indicator_value) = ?
    """, (indicator_type.lower(), val_clean))
    row = cursor.fetchone()
    conn.close()

    if row:
        ind = IndicatorResponse(
            id=row["id"],
            indicator_type=row["indicator_type"],
            indicator_value=row["indicator_value"],
            threat_type=row["threat_type"],
            threat_name=row["threat_name"],
            confidence=row["confidence"],
            status=row["status"],
            notes=row["notes"],
            verified_at=row["verified_at"]
        )
        return IndicatorLookupResponse(found=True, indicator=ind)
    return IndicatorLookupResponse(found=False, message="Indicator not recorded in central intelligence repository.")


@app.post("/api/indicator", response_model=IndicatorResponse)
def submit_indicator(
    payload: IndicatorSubmitRequest,
    client_id: Optional[str] = Header(None, alias="X-ACTIS-API-Key")
):
    """
    Submits a newly observed indicator to the central intelligence repository.
    Validates confidence and deduplicates records.
    """
    # Verify auth
    authenticated_client = verify_api_key(client_id)
    
    val_clean = payload.indicator_value.strip().lower()
    now = datetime.now().isoformat()

    conn = get_backend_db_connection()
    cursor = conn.cursor()

    # Check existing
    cursor.execute("""
    SELECT id, confidence, status FROM verified_indicators
    WHERE indicator_type = ? AND lower(indicator_value) = ?
    """, (payload.indicator_type.lower(), val_clean))
    existing = cursor.fetchone()

    # Rule: newly submitted indicators start as CANDIDATE or SUSPICIOUS unless high confidence
    target_status = payload.status
    if payload.confidence < 0.90 and target_status == "CONFIRMED":
        target_status = "SUSPICIOUS"

    if existing:
        new_conf = min(1.0, max(existing["confidence"], payload.confidence))
        cursor.execute("""
        UPDATE verified_indicators
        SET confidence = ?, status = ?, notes = ?, verified_at = ?
        WHERE id = ?
        """, (new_conf, target_status, payload.notes, now, existing["id"]))
        conn.commit()
        ind_id = existing["id"]
    else:
        cursor.execute("""
        INSERT INTO verified_indicators (
            indicator_type, indicator_value, threat_type, threat_name,
            confidence, status, notes, reporter_id, verified_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            payload.indicator_type.lower(),
            val_clean,
            payload.threat_type,
            payload.threat_name,
            payload.confidence,
            target_status,
            payload.notes,
            authenticated_client,
            now
        ))
        conn.commit()
        ind_id = cursor.lastrowid

    cursor.execute("SELECT * FROM verified_indicators WHERE id = ?", (ind_id,))
    created_row = cursor.fetchone()
    conn.close()

    logger.info(f"Received indicator from {authenticated_client}: {payload.indicator_type} = {val_clean} ({target_status})")

    return IndicatorResponse(
        id=created_row["id"],
        indicator_type=created_row["indicator_type"],
        indicator_value=created_row["indicator_value"],
        threat_type=created_row["threat_type"],
        threat_name=created_row["threat_name"],
        confidence=created_row["confidence"],
        status=created_row["status"],
        notes=created_row["notes"],
        verified_at=created_row["verified_at"]
    )


@app.get("/api/indicators", response_model=SyncResponse)
def sync_indicators(
    min_confidence: float = Query(0.8, ge=0.0, le=1.0),
    status_filter: Optional[str] = Query("CONFIRMED"),
    limit: int = Query(500, le=1000)
):
    """
    Returns verified indicators for endpoint synchronization.
    Allows ACTIS clients to benefit from globally verified threats.
    """
    conn = get_backend_db_connection()
    cursor = conn.cursor()

    if status_filter:
        cursor.execute("""
        SELECT * FROM verified_indicators
        WHERE confidence >= ? AND status = ?
        ORDER BY id DESC LIMIT ?
        """, (min_confidence, status_filter, limit))
    else:
        cursor.execute("""
        SELECT * FROM verified_indicators
        WHERE confidence >= ?
        ORDER BY id DESC LIMIT ?
        """, (min_confidence, limit))

    rows = cursor.fetchall()
    conn.close()

    indicators = [
        IndicatorResponse(
            id=r["id"],
            indicator_type=r["indicator_type"],
            indicator_value=r["indicator_value"],
            threat_type=r["threat_type"],
            threat_name=r["threat_name"],
            confidence=r["confidence"],
            status=r["status"],
            notes=r["notes"],
            verified_at=r["verified_at"]
        ) for r in rows
    ]

    return SyncResponse(total=len(indicators), indicators=indicators)


@app.get("/api/threat/{threat_id}")
def get_threat_details(threat_id: int):
    """Retrieves threat metadata."""
    conn = get_backend_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM verified_indicators WHERE id = ?", (threat_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Threat ID not found")
    return dict(row)
