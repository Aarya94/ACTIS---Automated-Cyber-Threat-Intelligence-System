"""
ACTIS Central Threat Intelligence REST API
Provides endpoints for authorized ACTIS clients to query indicators,
synchronize verified threat feeds, and submit candidate findings with
provenance preservation and anti-poisoning enforcement.
"""

import hmac
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.database import (
    admin_review_indicator,
    count_indicators,
    get_backend_db_connection,
    get_client_by_key,
    get_indicator_by_type_value,
    init_central_database,
    insert_candidate_contribution,
    query_indicators,
)
from backend.models import (
    AdminReviewRequest,
    AdminReviewResponse,
    ClientInfoResponse,
    ContributionRequest,
    ContributionResponse,
    HealthResponse,
    IndicatorLookupResponse,
    IndicatorRecord,
    IndicatorResponse,
    IndicatorSubmitRequest,
    SyncPullRequest,
    SyncPullResponse,
    SyncResponse,
)
from config.config import get_logger
from detection_engine.threat_intel_contract import IndicatorType
from threat_intelligence.indicator_validator import (
    is_safe_public_ip,
    validate_and_normalize_indicator,
)

logger = get_logger("CentralBackendAPI")

app = FastAPI(
    title="ACTIS Central Threat Intelligence Network API",
    description="Centralized indicator sharing and intelligence synchronization for ACTIS endpoints.",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# Rate Limiting Subsystem


class RateLimiter:
    """Thread-safe sliding-window in-memory rate limiter per client."""

    def __init__(self):
        self._requests: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def check_rate_limit(self, client_id: str, limit_rpm: int) -> bool:
        now = time.time()
        window_start = now - 60.0
        with self._lock:
            history = self._requests.setdefault(client_id, [])
            history = [t for t in history if t > window_start]
            if len(history) >= limit_rpm:
                self._requests[client_id] = history
                return False
            history.append(now)
            self._requests[client_id] = history
            return True

    def reset(self):
        with self._lock:
            self._requests.clear()


rate_limiter = RateLimiter()


# Global Sanitized Error Handler


@app.exception_handler(Exception)
async def sanitized_exception_handler(request: Request, exc: Exception):
    """Sanitizes unexpected exceptions, shielding internal paths, SQL details, and tracebacks."""
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "HTTP_EXCEPTION", "detail": exc.detail, "status_code": exc.status_code},
        )
    logger.error(f"Unhandled server error on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "detail": "An internal service error occurred. Diagnostics recorded.",
            "status_code": 500,
        },
    )


# Authentication and Authorization Dependency


def verify_api_key(
    x_actis_api_key: Optional[str] = Header(None, alias="X-ACTIS-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    required_role: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Authenticates requesting client and authorizes requested operation scope.
    Supports both X-ACTIS-API-Key header and Authorization: Bearer <key>.
    """
    key = x_actis_api_key
    if not key and authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            key = parts[1]
        elif len(parts) == 1:
            key = parts[0]

    if not key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials. Provide X-ACTIS-API-Key or Authorization Bearer header.",
        )

    client = get_client_by_key(key)
    if not client or not client.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid, inactive, or revoked API key.",
        )

    # Constant-time token verification to mitigate timing side-channels
    if not hmac.compare_digest(client["api_key"], key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid authentication credentials.",
        )

    # Role authorization
    client_roles = [r.strip().lower() for r in client.get("roles", "read").split(",") if r.strip()]
    if required_role and required_role.lower() not in client_roles and "admin" not in client_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: client lacks required role '{required_role}'.",
        )

    # Rate limiting
    rpm = int(client.get("rate_limit_rpm", 60))
    if not rate_limiter.check_rate_limit(client["client_id"], rpm):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded ({rpm} req/min). Please throttle requests.",
        )

    return client


# 1. Service Health Endpoints


@app.get("/api/v1/health", response_model=HealthResponse)
@app.get("/api/health", response_model=HealthResponse)
def health():
    """Returns backend service health status, database connectivity, and indicator counts."""
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        count = count_indicators()
        db_status = "HEALTHY"
    except Exception as e:
        logger.error(f"Health check failed database connectivity: {e}")
        count = 0
        db_status = "DEGRADED"

    return HealthResponse(
        status="ONLINE" if db_status == "HEALTHY" else "DEGRADED",
        total_indicators=count,
        service="ACTIS Central Threat Intelligence Network",
        version="1.1.0",
        api_version="v1",
        database_status=db_status,
        timestamp=now_iso,
    )


# 2. Authenticated Client Info


@app.get("/api/v1/client/me", response_model=ClientInfoResponse)
def get_client_profile(
    x_actis_api_key: Optional[str] = Header(None, alias="X-ACTIS-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """Returns authenticated client metadata, active roles, and rate limit quotas."""
    client = verify_api_key(x_actis_api_key=x_actis_api_key, authorization=authorization)
    roles = [r.strip().lower() for r in client.get("roles", "read").split(",") if r.strip()]
    return ClientInfoResponse(
        client_id=client["client_id"],
        roles=roles,
        rate_limit_rpm=int(client.get("rate_limit_rpm", 60)),
        is_active=bool(client.get("is_active", 1)),
    )


# 3. Indicator Query Endpoints


@app.get("/api/v1/indicators/{indicator_type}/{value}", response_model=IndicatorLookupResponse)
@app.get("/api/indicator/{indicator_type}/{value}", response_model=IndicatorLookupResponse)
def get_indicator(indicator_type: str, value: str):
    """
    Queries central threat intelligence repository for an indicator.
    Validates and normalizes type and value before lookup.
    """
    val_clean = value.strip()
    ind_type = indicator_type.strip().lower()

    # Reject private/loopback IP queries from returning threat data
    if ind_type == "ip":
        is_safe, _ = is_safe_public_ip(val_clean)
        if not is_safe:
            return IndicatorLookupResponse(
                found=False,
                indicator=None,
                message="Private and loopback IP addresses cannot be recorded as threats.",
            )

    # Normalize canonical value
    is_valid, norm_val, _, _ = validate_and_normalize_indicator(val_clean, ind_type)
    search_val = norm_val if is_valid else val_clean

    row = get_indicator_by_type_value(ind_type, search_val)
    if row:
        ind = IndicatorRecord(
            id=row["id"],
            indicator_type=row["indicator_type"],
            indicator_value=row["indicator_value"],
            threat_type=row["threat_type"],
            threat_name=row["threat_name"],
            confidence=row["confidence"],
            status=row["status"],
            source_type=row.get("source_type", "UPSTREAM_FEED"),
            reporter_id=row.get("reporter_id", "actis_network"),
            tags=row.get("tags", []),
            notes=row.get("notes"),
            review_status=row.get("review_status", "APPROVED"),
            first_seen=row.get("first_seen"),
            last_seen=row.get("last_seen"),
            verified_at=row["verified_at"],
        )
        return IndicatorLookupResponse(found=True, indicator=ind)

    return IndicatorLookupResponse(
        found=False,
        indicator=None,
        message="Indicator not recorded in central intelligence repository.",
    )


# 4. Synchronization Pull Endpoints (GET and POST)


@app.get("/api/v1/indicators", response_model=SyncPullResponse)
def list_indicators_v1(
    min_confidence: float = Query(0.8, ge=0.0, le=1.0),
    status_filter: Optional[str] = Query("CONFIRMED"),
    indicator_type: Optional[str] = Query(None),
    since_timestamp: Optional[str] = Query(None),
    limit: int = Query(500, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Versioned paged indicator retrieval with structured envelope."""
    types_list = [indicator_type] if indicator_type else None
    rows, total, has_more = query_indicators(
        min_confidence=min_confidence,
        status_filter=status_filter,
        indicator_types=types_list,
        since_timestamp=since_timestamp,
        limit=limit,
        offset=offset,
    )
    indicators = [
        IndicatorRecord(
            id=r["id"],
            indicator_type=r["indicator_type"],
            indicator_value=r["indicator_value"],
            threat_type=r["threat_type"],
            threat_name=r["threat_name"],
            confidence=r["confidence"],
            status=r["status"],
            source_type=r.get("source_type", "UPSTREAM_FEED"),
            reporter_id=r.get("reporter_id", "actis_network"),
            tags=r.get("tags", []),
            notes=r.get("notes"),
            review_status=r.get("review_status", "APPROVED"),
            first_seen=r.get("first_seen"),
            last_seen=r.get("last_seen"),
            verified_at=r["verified_at"],
        )
        for r in rows
    ]
    return SyncPullResponse(
        total=total,
        limit=limit,
        offset=offset,
        has_more=has_more,
        indicators=indicators,
    )


@app.get("/api/indicators", response_model=SyncResponse)
def sync_indicators_legacy(
    min_confidence: float = Query(0.8, ge=0.0, le=1.0),
    status_filter: Optional[str] = Query("CONFIRMED"),
    limit: int = Query(500, le=1000),
):
    """Legacy backward-compatible synchronization endpoint."""
    rows, _, _ = query_indicators(
        min_confidence=min_confidence,
        status_filter=status_filter,
        limit=limit,
        offset=0,
    )
    indicators = [
        IndicatorResponse(
            id=r["id"],
            indicator_type=r["indicator_type"],
            indicator_value=r["indicator_value"],
            threat_type=r["threat_type"],
            threat_name=r["threat_name"],
            confidence=r["confidence"],
            status=r["status"],
            notes=r.get("notes"),
            verified_at=r["verified_at"],
        )
        for r in rows
    ]
    return SyncResponse(total=len(indicators), indicators=indicators)


@app.post("/api/v1/sync/pull", response_model=SyncPullResponse)
def sync_pull_post(
    req: SyncPullRequest,
    x_actis_api_key: Optional[str] = Header(None, alias="X-ACTIS-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Authenticated POST-based synchronization pull with parameter envelope.
    Requires client with 'read' role.
    """
    verify_api_key(x_actis_api_key=x_actis_api_key, authorization=authorization, required_role="read")
    rows, total, has_more = query_indicators(
        min_confidence=req.min_confidence,
        status_filter=req.status_filter,
        indicator_types=req.indicator_types,
        since_timestamp=req.since_timestamp,
        limit=req.limit,
        offset=req.offset,
    )
    indicators = [
        IndicatorRecord(
            id=r["id"],
            indicator_type=r["indicator_type"],
            indicator_value=r["indicator_value"],
            threat_type=r["threat_type"],
            threat_name=r["threat_name"],
            confidence=r["confidence"],
            status=r["status"],
            source_type=r.get("source_type", "UPSTREAM_FEED"),
            reporter_id=r.get("reporter_id", "actis_network"),
            tags=r.get("tags", []),
            notes=r.get("notes"),
            review_status=r.get("review_status", "APPROVED"),
            first_seen=r.get("first_seen"),
            last_seen=r.get("last_seen"),
            verified_at=r["verified_at"],
        )
        for r in rows
    ]
    return SyncPullResponse(
        total=total,
        limit=req.limit,
        offset=req.offset,
        has_more=has_more,
        indicators=indicators,
    )


# 5. Candidate Indicator Contribution Endpoints


@app.post("/api/v1/contributions", response_model=ContributionResponse)
def contribute_indicator_v1(
    payload: ContributionRequest,
    x_actis_api_key: Optional[str] = Header(None, alias="X-ACTIS-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Submits a newly observed indicator report from an authorized ACTIS client.
    Guarantees that contributed records start as CANDIDATE with review_status=PENDING.
    Clients CANNOT self-promote submissions to globally CONFIRMED.
    """
    client = verify_api_key(
        x_actis_api_key=x_actis_api_key,
        authorization=authorization,
        required_role="contribute",
    )
    client_id = client["client_id"]

    ind_type = payload.indicator_type.strip().lower()
    raw_val = payload.indicator_value.strip()

    # Reject private/loopback IP addresses
    if ind_type == "ip":
        is_safe, _ = is_safe_public_ip(raw_val)
        if not is_safe:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Private, loopback, or reserved IP addresses cannot be registered as global threats.",
            )

    # Validate and normalize indicator
    is_valid, norm_val, err, _ = validate_and_normalize_indicator(raw_val, ind_type)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid indicator format for type '{ind_type}': {err}",
        )

    res = insert_candidate_contribution(
        client_id=client_id,
        indicator_type=ind_type,
        indicator_value=norm_val,
        threat_type=payload.threat_type,
        threat_name=payload.threat_name,
        confidence=payload.confidence,
        tags=payload.tags,
        notes=payload.notes,
        status_override=None,  # Always CANDIDATE for v1 endpoint
    )

    logger.info(f"Accepted candidate indicator from {client_id}: {ind_type}={norm_val} (Status: {res['status']})")
    return ContributionResponse(
        success=True,
        indicator_id=res["id"],
        indicator_type=res["indicator_type"],
        indicator_value=res["indicator_value"],
        status=res["status"],
        review_status=res["review_status"],
        message="Candidate indicator received and queued for network verification.",
    )


@app.post("/api/indicator", response_model=IndicatorResponse)
def submit_indicator_legacy(
    payload: IndicatorSubmitRequest,
    client_id: Optional[str] = Header(None, alias="X-ACTIS-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Legacy submission endpoint with anti-poisoning enforcement.
    Requires client with 'contribute' role.
    """
    client = verify_api_key(
        x_actis_api_key=client_id,
        authorization=authorization,
        required_role="contribute",
    )
    auth_client_id = client["client_id"]

    ind_type = payload.indicator_type.strip().lower()
    raw_val = payload.indicator_value.strip()

    # Shield private IPs
    if ind_type == "ip":
        is_safe, _ = is_safe_public_ip(raw_val)
        if not is_safe:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Private or loopback IP addresses cannot be registered as global threats.",
            )

    is_valid, norm_val, err, _ = validate_and_normalize_indicator(raw_val, ind_type)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid indicator format: {err}",
        )

    # Legacy rule: newly submitted indicators start as CANDIDATE or SUSPICIOUS unless high confidence
    target_status = payload.status
    if payload.confidence < 0.90 and target_status == "CONFIRMED":
        target_status = "SUSPICIOUS"

    res = insert_candidate_contribution(
        client_id=auth_client_id,
        indicator_type=ind_type,
        indicator_value=norm_val,
        threat_type=payload.threat_type,
        threat_name=payload.threat_name,
        confidence=payload.confidence,
        tags=[],
        notes=payload.notes,
        status_override=target_status,
    )

    now_iso = datetime.now(timezone.utc).isoformat()
    return IndicatorResponse(
        id=res["id"],
        indicator_type=res["indicator_type"],
        indicator_value=res["indicator_value"],
        threat_type=payload.threat_type,
        threat_name=payload.threat_name,
        confidence=payload.confidence,
        status=res["status"],
        notes=payload.notes,
        verified_at=now_iso,
    )


# 6. Admin Review & Verification Endpoints


@app.post("/api/v1/admin/indicators/{indicator_id}/review", response_model=AdminReviewResponse)
def review_candidate_indicator(
    indicator_id: int,
    payload: AdminReviewRequest,
    x_actis_api_key: Optional[str] = Header(None, alias="X-ACTIS-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Administrative review endpoint. Promotes CANDIDATE indicators to CONFIRMED
    or marks them as FALSE_POSITIVE. Requires 'admin' role.
    """
    admin_client = verify_api_key(
        x_actis_api_key=x_actis_api_key,
        authorization=authorization,
        required_role="admin",
    )

    try:
        res = admin_review_indicator(
            indicator_id=indicator_id,
            reviewer_id=admin_client["client_id"],
            action=payload.action,
            notes=payload.notes,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    if not res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Indicator #{indicator_id} not found.")

    logger.info(f"Admin {admin_client['client_id']} reviewed indicator #{indicator_id} -> {res['status']}")
    return AdminReviewResponse(
        success=True,
        indicator_id=indicator_id,
        new_status=res["status"],
        new_review_status=res["review_status"],
        message=f"Indicator status successfully transitioned to {res['status']}.",
    )


# 7. Legacy Threat Details


@app.get("/api/threat/{threat_id}")
def get_threat_details(threat_id: int):
    """Retrieves threat metadata by ID."""
    conn = get_backend_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM verified_indicators WHERE id = ?", (threat_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Threat ID not found")
    return dict(row)

