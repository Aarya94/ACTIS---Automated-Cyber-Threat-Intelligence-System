"""
ACTIS Central Backend Pydantic Models
Data schemas for REST API requests and responses.
Defines versioned v1 contracts, bounded pagination envelopes,
and candidate indicator contribution models.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Central service health status and indicator repository metrics."""
    status: str = "ONLINE"
    total_indicators: int = 0
    service: str = "ACTIS Central Threat Intelligence Network"
    version: str = "1.0.0"
    api_version: str = "v1"
    database_status: str = "HEALTHY"
    timestamp: str


class ClientInfoResponse(BaseModel):
    """Authenticated client identity, permission roles, and rate limit allocation."""
    client_id: str
    roles: List[str]
    rate_limit_rpm: int
    is_active: bool


class IndicatorRecord(BaseModel):
    """Normalized threat intelligence indicator record with provenance."""
    id: int
    indicator_type: str
    indicator_value: str
    threat_type: str = "Unknown"
    threat_name: str = "Generic Threat"
    confidence: float = 0.8
    status: str = "CONFIRMED"
    source_type: str = "UPSTREAM_FEED"
    reporter_id: str = "actis_network"
    tags: List[str] = Field(default_factory=list)
    notes: Optional[str] = None
    review_status: str = "APPROVED"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    verified_at: str


class IndicatorResponse(BaseModel):
    """Legacy backward-compatible indicator response."""
    id: int
    indicator_type: str
    indicator_value: str
    threat_type: str
    threat_name: str
    confidence: float
    status: str
    notes: Optional[str] = None
    verified_at: str


class IndicatorLookupResponse(BaseModel):
    """Indicator query response distinguishing found matches from absence."""
    found: bool
    indicator: Optional[IndicatorRecord] = None
    message: Optional[str] = None


class SyncPullRequest(BaseModel):
    """Parameters for bounded client synchronization query."""
    min_confidence: float = Field(0.8, ge=0.0, le=1.0)
    status_filter: Optional[str] = "CONFIRMED"
    indicator_types: Optional[List[str]] = None
    since_timestamp: Optional[str] = None
    limit: int = Field(500, ge=1, le=1000)
    offset: int = Field(0, ge=0)


class SyncPullResponse(BaseModel):
    """Paginated sync pull response envelope."""
    total: int
    limit: int
    offset: int
    has_more: bool
    indicators: List[IndicatorRecord]


class SyncResponse(BaseModel):
    """Legacy backward-compatible synchronization response."""
    total: int
    indicators: List[IndicatorResponse]


class IndicatorSubmitRequest(BaseModel):
    """Legacy submission request."""
    indicator_type: str = Field(..., description="url, domain, sha256, md5, ip")
    indicator_value: str = Field(..., description="The indicator value")
    threat_type: str = Field("Unknown", description="Malware, Phishing, Ransomware, Trojan")
    threat_name: str = Field("Generic Threat", description="Threat family or name")
    confidence: float = Field(0.8, ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    status: str = Field("CANDIDATE", description="CANDIDATE, REPORTED, SUSPICIOUS, CONFIRMED")
    notes: Optional[str] = None


class ContributionRequest(BaseModel):
    """
    Candidate indicator contribution request from authorized client.
    Submitted indicators start as CANDIDATE and cannot force global CONFIRMED status.
    """
    indicator_type: str = Field(..., description="url, domain, sha256, md5, ip")
    indicator_value: str = Field(..., min_length=1, max_length=2048, description="Normalized indicator string")
    threat_type: str = Field("Generic Threat", description="Threat classification")
    threat_name: str = Field("Local Detection", description="Malware or campaign name")
    confidence: float = Field(0.5, ge=0.0, le=1.0, description="Observation confidence score")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    notes: Optional[str] = Field(None, max_length=1000, description="Investigation notes")


class ContributionResponse(BaseModel):
    """Response returned upon accepting a candidate indicator submission."""
    success: bool
    indicator_id: int
    indicator_type: str
    indicator_value: str
    status: str = "CANDIDATE"
    review_status: str = "PENDING"
    message: str


class AdminReviewRequest(BaseModel):
    """Parameters for administrative indicator status review."""
    action: str = Field(..., description="APPROVE, REJECT, MARK_FALSE_POSITIVE")
    notes: Optional[str] = None


class AdminReviewResponse(BaseModel):
    """Result of administrative review action."""
    success: bool
    indicator_id: int
    new_status: str
    new_review_status: str
    message: str
