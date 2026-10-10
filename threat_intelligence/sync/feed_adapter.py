"""
ACTIS Upstream Threat Feed Adapters
Standard adapter interfaces and provider implementations for upstream threat intelligence
feeds (URLhaus, AbuseIPDB, VirusTotal) with rate-limiting, timeout bounds, and error isolation.
"""

from abc import ABC, abstractmethod
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import requests

from detection_engine.threat_intel_contract import IndicatorType
from threat_intelligence.indicator_validator import (
    validate_and_normalize_indicator,
    is_safe_public_ip,
)
from threat_intelligence.sync.sync_models import (
    FeedRecord,
    ProviderSyncResult,
    SyncStatus,
    SyncErrorCategory,
)
from config.config import (
    URLHAUS_API_KEY,
    URLHAUS_ENABLED,
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_ENABLED,
    VIRUSTOTAL_API_KEY,
    VIRUSTOTAL_ENABLED,
    ACTIS_BACKEND_URL,
    ACTIS_CLIENT_API_KEY,
    TI_SYNC_CENTRAL,
    TI_REQUEST_TIMEOUT,
    get_logger,
)

logger = get_logger("FeedAdapters")


class BaseFeedAdapter(ABC):
    """Abstract base class for all upstream threat intelligence feed adapters."""

    def __init__(self, provider_name: str, enabled: bool = True, timeout: float = 10.0):
        self.provider_name = provider_name
        self.enabled = enabled
        self.timeout = timeout

    @abstractmethod
    def is_configured(self) -> bool:
        """Determines whether the provider adapter is enabled and has requisite credentials."""
        pass

    @abstractmethod
    def fetch_feed(
        self,
        max_records: int = 500,
        timeout: Optional[float] = None
    ) -> Tuple[List[FeedRecord], ProviderSyncResult]:
        """
        Retrieves, validates, and normalizes feed records from the upstream source.
        Returns a tuple of (validated_records, ProviderSyncResult).
        """
        pass


class URLhausFeedAdapter(BaseFeedAdapter):
    """
    URLhaus Upstream Feed Adapter (abuse.ch).
    Retrieves recent malicious URLs via public JSON feed API.
    Community access requires no commercial license.
    """

    RECENT_URLS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    def __init__(
        self,
        api_key: Optional[str] = None,
        enabled: Optional[bool] = None,
        timeout: Optional[float] = None,
    ):
        eff_enabled = enabled if enabled is not None else URLHAUS_ENABLED
        eff_timeout = timeout or TI_REQUEST_TIMEOUT or 10.0
        super().__init__(provider_name="URLhaus", enabled=eff_enabled, timeout=eff_timeout)
        self.api_key = api_key if api_key is not None else URLHAUS_API_KEY
        self.headers = {
            "Accept": "application/json",
            "User-Agent": "ACTIS-Security-Endpoint/1.0",
        }
        if self.api_key:
            self.headers["Auth-Key"] = self.api_key

    def is_configured(self) -> bool:
        """URLhaus recent URLs feed is operational without mandatory API key when enabled."""
        return bool(self.enabled)

    def fetch_feed(
        self,
        max_records: int = 500,
        timeout: Optional[float] = None
    ) -> Tuple[List[FeedRecord], ProviderSyncResult]:
        """Retrieves and normalizes recent malicious URLs from URLhaus."""
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.time()
        req_timeout = timeout or self.timeout

        if not self.enabled:
            dur = time.time() - t0
            res = ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.DISABLED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.NONE,
                error_message="URLhaus feed sync is disabled in configuration.",
                duration_seconds=dur,
            )
            return [], res

        try:
            # Query recent URLs endpoint
            resp = requests.post(
                self.RECENT_URLS_ENDPOINT,
                headers=self.headers,
                data={"limit": str(max_records)},
                timeout=req_timeout,
            )

            dur = time.time() - t0
            completed_at = datetime.now(timezone.utc).isoformat()

            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except Exception as e:
                    return [], ProviderSyncResult(
                        provider=self.provider_name,
                        status=SyncStatus.FAILED,
                        started_at=started_at,
                        completed_at=completed_at,
                        error_category=SyncErrorCategory.MALFORMED_RESPONSE,
                        error_message=f"Invalid JSON response: {e}",
                        duration_seconds=dur,
                    )

                query_status = payload.get("query_status", "")
                if query_status != "ok":
                    return [], ProviderSyncResult(
                        provider=self.provider_name,
                        status=SyncStatus.FAILED,
                        started_at=started_at,
                        completed_at=completed_at,
                        error_category=SyncErrorCategory.MALFORMED_RESPONSE,
                        error_message=f"URLhaus reported query status: {query_status}",
                        duration_seconds=dur,
                    )

                raw_urls = payload.get("urls", [])
                if not isinstance(raw_urls, list):
                    raw_urls = []

                records_received = len(raw_urls)
                validated_records: List[FeedRecord] = []
                rejected_count = 0

                for item in raw_urls[:max_records]:
                    if not isinstance(item, dict):
                        rejected_count += 1
                        continue

                    raw_url = item.get("url")
                    if not raw_url:
                        rejected_count += 1
                        continue

                    is_valid, norm_url, err, det_type = validate_and_normalize_indicator(
                        raw_url, expected_type=IndicatorType.URL
                    )
                    if not is_valid or not norm_url:
                        rejected_count += 1
                        continue

                    url_status = str(item.get("url_status", "")).lower()
                    status = "CONFIRMED" if url_status == "online" else "SUSPICIOUS"
                    threat_type = item.get("threat") or "Malware Download"
                    date_added = item.get("date_added")
                    tags = item.get("tags") or []
                    if isinstance(tags, str):
                        tags = [tags]

                    rec = FeedRecord(
                        indicator=norm_url,
                        indicator_type=IndicatorType.URL,
                        source_feed="URLhaus",
                        confidence=0.95 if status == "CONFIRMED" else 0.85,
                        status=status,
                        threat_type=f"URLhaus: {threat_type}",
                        threat_name="Malicious URL Distribution",
                        first_seen=date_added,
                        last_seen=date_added or datetime.now(timezone.utc).isoformat(),
                        tags=tags,
                        metadata={
                            "urlhaus_id": item.get("id"),
                            "url_status": url_status,
                            "host": item.get("host"),
                            "urlhaus_reference": item.get("urlhaus_reference"),
                        },
                    )
                    validated_records.append(rec)

                return validated_records, ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.SUCCESS,
                    started_at=started_at,
                    completed_at=completed_at,
                    records_received=records_received,
                    records_validated=len(validated_records),
                    records_rejected=rejected_count,
                    error_category=SyncErrorCategory.NONE,
                    duration_seconds=dur,
                )

            elif resp.status_code == 429:
                return [], ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.FAILED,
                    started_at=started_at,
                    completed_at=completed_at,
                    error_category=SyncErrorCategory.RATE_LIMITED,
                    error_message="HTTP 429: Rate limit exceeded on URLhaus feed.",
                    duration_seconds=dur,
                )
            elif resp.status_code in (401, 403):
                return [], ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.FAILED,
                    started_at=started_at,
                    completed_at=completed_at,
                    error_category=SyncErrorCategory.AUTH_FAILURE,
                    error_message=f"HTTP {resp.status_code}: URLhaus authentication error.",
                    duration_seconds=dur,
                )
            else:
                return [], ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.FAILED,
                    started_at=started_at,
                    completed_at=completed_at,
                    error_category=SyncErrorCategory.HTTP_ERROR,
                    error_message=f"HTTP {resp.status_code}: URLhaus feed returned unexpected status.",
                    duration_seconds=dur,
                )

        except requests.exceptions.Timeout:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.NETWORK_TIMEOUT,
                error_message=f"URLhaus feed request timed out after {req_timeout:.1f}s.",
                duration_seconds=dur,
            )
        except requests.exceptions.RequestException as e:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.CONNECTION_ERROR,
                error_message=f"URLhaus feed network connection error: {e}",
                duration_seconds=dur,
            )
        except Exception as e:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.MALFORMED_RESPONSE,
                error_message=f"Unexpected error processing URLhaus feed: {e}",
                duration_seconds=dur,
            )


class AbuseIPDBFeedAdapter(BaseFeedAdapter):
    """
    AbuseIPDB Upstream Feed Adapter.
    Retrieves high-confidence abusive public IP addresses via blacklist endpoint.
    Strictly enforces local RFC 1918 / loopback shielding.
    """

    BLACKLIST_ENDPOINT = "https://api.abuseipdb.com/api/v2/blacklist"

    def __init__(
        self,
        api_key: Optional[str] = None,
        enabled: Optional[bool] = None,
        timeout: Optional[float] = None,
    ):
        eff_enabled = enabled if enabled is not None else ABUSEIPDB_ENABLED
        eff_timeout = timeout or TI_REQUEST_TIMEOUT or 10.0
        super().__init__(provider_name="AbuseIPDB", enabled=eff_enabled, timeout=eff_timeout)
        self.api_key = api_key if api_key is not None else ABUSEIPDB_API_KEY
        self.headers = {
            "Accept": "application/json",
            "Key": self.api_key or "",
            "User-Agent": "ACTIS-Security-Endpoint/1.0",
        }

    def is_configured(self) -> bool:
        """AbuseIPDB blacklist feed requires an enabled flag and an API key."""
        return bool(self.enabled and self.api_key and len(self.api_key.strip()) >= 16)

    def fetch_feed(
        self,
        max_records: int = 500,
        timeout: Optional[float] = None
    ) -> Tuple[List[FeedRecord], ProviderSyncResult]:
        """Retrieves and normalizes abusive IP addresses from AbuseIPDB blacklist."""
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.time()
        req_timeout = timeout or self.timeout

        if not self.enabled:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.DISABLED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.NONE,
                error_message="AbuseIPDB feed sync is disabled in configuration.",
                duration_seconds=dur,
            )

        if not self.is_configured():
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.AUTH_FAILURE,
                error_message="AbuseIPDB API key is not configured or invalid.",
                duration_seconds=dur,
            )

        try:
            params = {
                "confidenceMinimum": "90",
                "limit": str(min(max_records, 1000)),
            }
            resp = requests.get(
                self.BLACKLIST_ENDPOINT,
                headers=self.headers,
                params=params,
                timeout=req_timeout,
            )

            dur = time.time() - t0
            completed_at = datetime.now(timezone.utc).isoformat()

            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except Exception as e:
                    return [], ProviderSyncResult(
                        provider=self.provider_name,
                        status=SyncStatus.FAILED,
                        started_at=started_at,
                        completed_at=completed_at,
                        error_category=SyncErrorCategory.MALFORMED_RESPONSE,
                        error_message=f"Invalid JSON response: {e}",
                        duration_seconds=dur,
                    )

                data = payload.get("data", [])
                if not isinstance(data, list):
                    data = []

                records_received = len(data)
                validated_records: List[FeedRecord] = []
                rejected_count = 0

                for item in data[:max_records]:
                    if not isinstance(item, dict):
                        rejected_count += 1
                        continue

                    raw_ip = item.get("ipAddress")
                    if not raw_ip:
                        rejected_count += 1
                        continue

                    # Defensive local privacy boundary: reject private/reserved IPs
                    is_safe, priv_err = is_safe_public_ip(str(raw_ip))
                    if not is_safe:
                        rejected_count += 1
                        continue

                    is_valid, norm_ip, err, det_type = validate_and_normalize_indicator(
                        str(raw_ip), expected_type=IndicatorType.IP_ADDRESS
                    )
                    if not is_valid or not norm_ip:
                        rejected_count += 1
                        continue

                    conf_score = item.get("abuseConfidenceScore", 90)
                    try:
                        conf_val = float(conf_score) / 100.0
                    except Exception:
                        conf_val = 0.90

                    last_rep = item.get("lastReportedAt")
                    country = item.get("countryCode", "Unknown")

                    rec = FeedRecord(
                        indicator=norm_ip,
                        indicator_type=IndicatorType.IP_ADDRESS,
                        source_feed="AbuseIPDB",
                        confidence=max(0.5, min(1.0, conf_val)),
                        status="CONFIRMED" if conf_val >= 0.95 else "SUSPICIOUS",
                        threat_type="AbuseIPDB: Abusive Host",
                        threat_name="Malicious IP Blacklist",
                        first_seen=last_rep,
                        last_seen=last_rep or datetime.now(timezone.utc).isoformat(),
                        tags=["blacklist", f"country:{country}"],
                        metadata={
                            "abuse_confidence_score": conf_score,
                            "country_code": country,
                        },
                    )
                    validated_records.append(rec)

                return validated_records, ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.SUCCESS,
                    started_at=started_at,
                    completed_at=completed_at,
                    records_received=records_received,
                    records_validated=len(validated_records),
                    records_rejected=rejected_count,
                    error_category=SyncErrorCategory.NONE,
                    duration_seconds=dur,
                )

            elif resp.status_code == 429:
                return [], ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.FAILED,
                    started_at=started_at,
                    completed_at=completed_at,
                    error_category=SyncErrorCategory.RATE_LIMITED,
                    error_message="HTTP 429: Rate limit exceeded on AbuseIPDB blacklist endpoint.",
                    duration_seconds=dur,
                )
            elif resp.status_code in (401, 403):
                return [], ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.FAILED,
                    started_at=started_at,
                    completed_at=completed_at,
                    error_category=SyncErrorCategory.AUTH_FAILURE,
                    error_message=f"HTTP {resp.status_code}: AbuseIPDB authentication error (invalid API key).",
                    duration_seconds=dur,
                )
            else:
                return [], ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.FAILED,
                    started_at=started_at,
                    completed_at=completed_at,
                    error_category=SyncErrorCategory.HTTP_ERROR,
                    error_message=f"HTTP {resp.status_code}: AbuseIPDB blacklist endpoint returned error.",
                    duration_seconds=dur,
                )

        except requests.exceptions.Timeout:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.NETWORK_TIMEOUT,
                error_message=f"AbuseIPDB feed request timed out after {req_timeout:.1f}s.",
                duration_seconds=dur,
            )
        except requests.exceptions.RequestException as e:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.CONNECTION_ERROR,
                error_message=f"AbuseIPDB network error: {e}",
                duration_seconds=dur,
            )
        except Exception as e:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.MALFORMED_RESPONSE,
                error_message=f"Unexpected error processing AbuseIPDB feed: {e}",
                duration_seconds=dur,
            )


class VirusTotalFeedAdapter(BaseFeedAdapter):
    """
    VirusTotal Upstream Feed Adapter.
    Documents and honors provider capabilities: VirusTotal v3 bulk feeds are restricted
    to Enterprise/Premium subscription accounts. Public API keys support individual lookups only.
    """

    FEEDS_ENDPOINT = "https://www.virustotal.com/api/v3/feeds/files"

    def __init__(
        self,
        api_key: Optional[str] = None,
        enabled: Optional[bool] = None,
        timeout: Optional[float] = None,
    ):
        eff_enabled = enabled if enabled is not None else VIRUSTOTAL_ENABLED
        eff_timeout = timeout or TI_REQUEST_TIMEOUT or 10.0
        super().__init__(provider_name="VirusTotal", enabled=eff_enabled, timeout=eff_timeout)
        self.api_key = api_key if api_key is not None else VIRUSTOTAL_API_KEY
        self.headers = {
            "x-apikey": self.api_key or "",
            "Accept": "application/json",
            "User-Agent": "ACTIS-Security-Endpoint/1.0",
        }

    def is_configured(self) -> bool:
        """VirusTotal requires an enabled flag and an API key."""
        return bool(self.enabled and self.api_key and len(self.api_key.strip()) >= 16)

    def fetch_feed(
        self,
        max_records: int = 500,
        timeout: Optional[float] = None
    ) -> Tuple[List[FeedRecord], ProviderSyncResult]:
        """
        Reports provider limitation or attempts Enterprise feed query.
        Public API keys are isolated cleanly as UNSUPPORTED_OPERATION without inventing fake feeds.
        """
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.time()
        req_timeout = timeout or self.timeout

        if not self.enabled:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.DISABLED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.NONE,
                error_message="VirusTotal feed sync is disabled in configuration.",
                duration_seconds=dur,
            )

        if not self.is_configured():
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.AUTH_FAILURE,
                error_message="VirusTotal API key is not configured or invalid.",
                duration_seconds=dur,
            )

        # Attempt feeds endpoint, safely isolating 403 / Enterprise tier restriction
        try:
            resp = requests.get(
                self.FEEDS_ENDPOINT,
                headers=self.headers,
                timeout=req_timeout,
            )
            dur = time.time() - t0
            completed_at = datetime.now(timezone.utc).isoformat()

            if resp.status_code == 200:
                # If an enterprise subscription is present
                data = resp.json().get("data", [])
                records_received = len(data)
                validated_records: List[FeedRecord] = []
                for item in data[:max_records]:
                    attrs = item.get("attributes", {})
                    h = attrs.get("sha256")
                    if h:
                        is_v, n_h, _, _ = validate_and_normalize_indicator(h, IndicatorType.SHA256)
                        if is_v and n_h:
                            validated_records.append(
                                FeedRecord(
                                    indicator=n_h,
                                    indicator_type=IndicatorType.SHA256,
                                    source_feed="VirusTotal",
                                    confidence=1.0,
                                    status="CONFIRMED",
                                    threat_type="VirusTotal Enterprise Feed",
                                    threat_name="Malicious PE Binary",
                                )
                            )
                return validated_records, ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.SUCCESS,
                    started_at=started_at,
                    completed_at=completed_at,
                    records_received=records_received,
                    records_validated=len(validated_records),
                    records_rejected=records_received - len(validated_records),
                    duration_seconds=dur,
                )

            elif resp.status_code in (401, 403):
                # Standard public keys receive 403 Forbidden for feeds
                return [], ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.FAILED,
                    started_at=started_at,
                    completed_at=completed_at,
                    error_category=SyncErrorCategory.UNSUPPORTED_OPERATION,
                    error_message="VirusTotal live bulk feeds require an Enterprise subscription (public API keys support individual lookups only).",
                    duration_seconds=dur,
                )
            elif resp.status_code == 429:
                return [], ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.FAILED,
                    started_at=started_at,
                    completed_at=completed_at,
                    error_category=SyncErrorCategory.RATE_LIMITED,
                    error_message="VirusTotal feed rate limit exceeded (HTTP 429).",
                    duration_seconds=dur,
                )
            else:
                return [], ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.FAILED,
                    started_at=started_at,
                    completed_at=completed_at,
                    error_category=SyncErrorCategory.HTTP_ERROR,
                    error_message=f"HTTP {resp.status_code}: VirusTotal feeds endpoint error.",
                    duration_seconds=dur,
                )

        except requests.exceptions.Timeout:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.NETWORK_TIMEOUT,
                error_message=f"VirusTotal feed request timed out after {req_timeout:.1f}s.",
                duration_seconds=dur,
            )
        except requests.exceptions.RequestException as e:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.CONNECTION_ERROR,
                error_message=f"VirusTotal connection error: {e}",
                duration_seconds=dur,
            )
        except Exception as e:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.MALFORMED_RESPONSE,
                error_message=f"Unexpected error querying VirusTotal feed: {e}",
                duration_seconds=dur,
            )


class CentralACTISFeedAdapter(BaseFeedAdapter):
    """
    Central ACTIS Threat Intelligence Feed Adapter.
    Synchronizes verified threat indicators from the central ACTIS REST API backend
    into the local ACTIS SQLite database using authenticated pull queries.
    Enforces timeout bounds, private IP shielding, and provider failure isolation.
    """

    def __init__(
        self,
        backend_url: Optional[str] = None,
        api_key: Optional[str] = None,
        enabled: Optional[bool] = None,
        timeout: Optional[float] = None,
        min_confidence: float = 0.8,
        status_filter: str = "CONFIRMED",
    ):
        eff_enabled = enabled if enabled is not None else TI_SYNC_CENTRAL
        eff_timeout = timeout or TI_REQUEST_TIMEOUT or 10.0
        super().__init__(provider_name="CentralACTIS", enabled=eff_enabled, timeout=eff_timeout)
        self.backend_url = (backend_url or ACTIS_BACKEND_URL or "http://127.0.0.1:8000").rstrip("/")
        self.api_key = api_key or ACTIS_CLIENT_API_KEY or "actis-client-default-secret-token"
        self.min_confidence = min_confidence
        self.status_filter = status_filter
        self.headers = {
            "X-ACTIS-API-Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ACTIS-Security-Endpoint/1.0",
        }

    def is_configured(self) -> bool:
        """Central ACTIS requires enabled flag, a backend URL, and an API key."""
        return bool(self.enabled and self.backend_url and self.api_key)

    def fetch_feed(
        self,
        max_records: int = 500,
        timeout: Optional[float] = None,
    ) -> Tuple[List[FeedRecord], ProviderSyncResult]:
        """
        Retrieves, validates, and normalizes indicators from the Central ACTIS service.
        Returns a tuple of (validated_records, ProviderSyncResult).
        """
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.time()
        req_timeout = timeout or self.timeout

        if not self.enabled:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.DISABLED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.NONE,
                error_message="Central ACTIS feed sync is disabled in configuration.",
                duration_seconds=dur,
            )

        if not self.is_configured():
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.UNCONFIGURED,
                error_message="Central ACTIS feed adapter is not configured (missing URL or API key).",
                duration_seconds=dur,
            )

        # Primary endpoint: versioned /api/v1/indicators; fallback to /api/indicators
        endpoint_url = f"{self.backend_url}/api/v1/indicators"
        params = {
            "min_confidence": self.min_confidence,
            "status_filter": self.status_filter,
            "limit": min(max_records, 1000),
            "offset": 0,
        }

        try:
            resp = requests.get(
                endpoint_url,
                params=params,
                headers=self.headers,
                timeout=req_timeout,
            )

            # Fallback to legacy endpoint if v1 route not found (404)
            if resp.status_code == 404:
                legacy_url = f"{self.backend_url}/api/indicators"
                resp = requests.get(
                    legacy_url,
                    params={"min_confidence": self.min_confidence, "status_filter": self.status_filter, "limit": max_records},
                    headers=self.headers,
                    timeout=req_timeout,
                )

            dur = time.time() - t0
            completed_at = datetime.now(timezone.utc).isoformat()

            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except Exception as e:
                    return [], ProviderSyncResult(
                        provider=self.provider_name,
                        status=SyncStatus.FAILED,
                        started_at=started_at,
                        completed_at=completed_at,
                        error_category=SyncErrorCategory.MALFORMED_RESPONSE,
                        error_message=f"Central ACTIS returned malformed JSON: {e}",
                        duration_seconds=dur,
                    )

                raw_indicators: List[Dict[str, Any]] = payload.get("indicators", [])
                records_received = len(raw_indicators)
                validated_records: List[FeedRecord] = []
                records_rejected = 0

                for item in raw_indicators:
                    raw_val = str(item.get("indicator_value", "")).strip()
                    raw_type = str(item.get("indicator_type", "")).strip().lower()

                    if not raw_val or not raw_type:
                        records_rejected += 1
                        continue

                    # Shield private/loopback IP addresses
                    if raw_type == "ip":
                        is_safe, _ = is_safe_public_ip(raw_val)
                        if not is_safe:
                            records_rejected += 1
                            continue

                    # Defensive normalization
                    is_valid, norm_val, err, resolved_type = validate_and_normalize_indicator(raw_val, raw_type)
                    if not is_valid or not norm_val or not resolved_type:
                        records_rejected += 1
                        continue

                    threat_type = str(item.get("threat_type", "Generic Threat"))
                    threat_name = str(item.get("threat_name", "Network Threat"))
                    confidence = float(item.get("confidence", 0.9))
                    rec_status = str(item.get("status", "CONFIRMED"))
                    tags = item.get("tags", [])
                    if isinstance(tags, str):
                        tags = [t.strip() for t in tags.split(",") if t.strip()]

                    feed_rec = FeedRecord(
                        indicator=norm_val,
                        indicator_type=resolved_type,
                        source_feed="central_actis_network",
                        confidence=confidence,
                        status=rec_status,
                        threat_type=threat_type,
                        threat_name=threat_name,
                        first_seen=item.get("first_seen"),
                        last_seen=item.get("last_seen") or item.get("verified_at"),
                        tags=list(tags),
                        metadata={"notes": str(item.get("notes") or "Synchronized from central ACTIS threat network.")},
                    )
                    validated_records.append(feed_rec)

                logger.info(
                    f"Central ACTIS feed fetch complete: {records_received} received, "
                    f"{len(validated_records)} validated, {records_rejected} rejected in {dur:.2f}s."
                )

                return validated_records, ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.SUCCESS,
                    started_at=started_at,
                    completed_at=completed_at,
                    records_received=records_received,
                    records_validated=len(validated_records),
                    records_rejected=records_rejected,
                    duration_seconds=dur,
                )

            elif resp.status_code in (401, 403):
                return [], ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.FAILED,
                    started_at=started_at,
                    completed_at=completed_at,
                    error_category=SyncErrorCategory.AUTH_FAILURE,
                    error_message=f"HTTP {resp.status_code}: Central ACTIS authentication failure. Check API key.",
                    duration_seconds=dur,
                )
            elif resp.status_code == 429:
                return [], ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.FAILED,
                    started_at=started_at,
                    completed_at=completed_at,
                    error_category=SyncErrorCategory.RATE_LIMITED,
                    error_message="HTTP 429: Central ACTIS rate limit exceeded.",
                    duration_seconds=dur,
                )
            else:
                return [], ProviderSyncResult(
                    provider=self.provider_name,
                    status=SyncStatus.FAILED,
                    started_at=started_at,
                    completed_at=completed_at,
                    error_category=SyncErrorCategory.HTTP_ERROR,
                    error_message=f"HTTP {resp.status_code}: Central ACTIS service returned error status.",
                    duration_seconds=dur,
                )

        except requests.exceptions.Timeout:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.NETWORK_TIMEOUT,
                error_message=f"Central ACTIS request timed out after {req_timeout:.1f}s.",
                duration_seconds=dur,
            )
        except requests.exceptions.RequestException as e:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.CONNECTION_ERROR,
                error_message=f"Cannot connect to Central ACTIS backend: {e}",
                duration_seconds=dur,
            )
        except Exception as e:
            dur = time.time() - t0
            return [], ProviderSyncResult(
                provider=self.provider_name,
                status=SyncStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_category=SyncErrorCategory.MALFORMED_RESPONSE,
                error_message=f"Unexpected error querying Central ACTIS feed: {e}",
                duration_seconds=dur,
            )

