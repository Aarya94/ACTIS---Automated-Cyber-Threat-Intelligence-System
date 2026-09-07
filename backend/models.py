"""
ACTIS Central Backend Pydantic Models
Data schemas for REST API requests and responses.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class HealthResponse(BaseModel):
    status: str
    total_indicators: int
    service: str = "ACTIS Central Threat Intelligence Network"
    version: str = "1.0.0"
    timestamp: str


class IndicatorSubmitRequest(BaseModel):
    indicator_type: str = Field(..., description="url, domain, sha256, md5, ip")
    indicator_value: str = Field(..., description="The indicator value")
    threat_type: str = Field("Unknown", description="Malware, Phishing, Ransomware, Trojan")
    threat_name: str = Field("Generic Threat", description="Threat family or name")
    confidence: float = Field(0.8, ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    status: str = Field("CANDIDATE", description="CANDIDATE, REPORTED, SUSPICIOUS, CONFIRMED")
    notes: Optional[str] = None


class IndicatorResponse(BaseModel):
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
    found: bool
    indicator: Optional[IndicatorResponse] = None
    message: Optional[str] = None


class SyncResponse(BaseModel):
    total: int
    indicators: List[IndicatorResponse]
