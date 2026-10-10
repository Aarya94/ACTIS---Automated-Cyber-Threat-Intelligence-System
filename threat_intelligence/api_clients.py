"""
ACTIS Threat Intelligence API Clients
Implements provider adapters for external threat intelligence services
(VirusTotal, URLhaus, AbuseIPDB) with rate limiting, timeouts, response validation,
and offline fallback.
"""

import base64
import time
import requests
from typing import Dict, Any, Optional, Set, Tuple

from detection_engine.threat_intel_contract import (
    ThreatIntelEvidence,
    ThreatIntelVerdict,
    IndicatorType,
)
from threat_intelligence.provider_base import BaseThreatClient
from threat_intelligence.indicator_validator import (
    validate_and_normalize_indicator,
    is_safe_public_ip,
)
from config.config import (
    VIRUSTOTAL_API_KEY,
    ABUSEIPDB_API_KEY,
    URLHAUS_API_KEY,
    VIRUSTOTAL_ENABLED,
    URLHAUS_ENABLED,
    ABUSEIPDB_ENABLED,
    TI_REQUEST_TIMEOUT,
    VT_RATE_LIMIT_RPM,
    get_logger,
)

logger = get_logger("APIClients")


class VirusTotalClient(BaseThreatClient):
    """
    VirusTotal v3 API Client.
    Supports file hashes (SHA-256, MD5, SHA-1), URLs, domains, and IP addresses
    with rate-limit controls, bounded timeouts, and normalized ThreatIntelEvidence output.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: Optional[str] = None,
        enabled: Optional[bool] = None,
        timeout: Optional[float] = None,
        rate_limit_rpm: Optional[int] = None,
    ):
        supported = {
            IndicatorType.SHA256,
            IndicatorType.MD5,
            IndicatorType.SHA1,
            IndicatorType.URL,
            IndicatorType.DOMAIN,
            IndicatorType.IP_ADDRESS,
        }
        effective_timeout = timeout or TI_REQUEST_TIMEOUT
        effective_rpm = rate_limit_rpm or VT_RATE_LIMIT_RPM
        super().__init__(
            provider_name="VirusTotal",
            supported_types=supported,
            timeout=effective_timeout,
            rate_limit_rpm=effective_rpm,
        )
        self.api_key = api_key if api_key is not None else VIRUSTOTAL_API_KEY
        self.enabled = enabled if enabled is not None else VIRUSTOTAL_ENABLED
        self.headers = {
            "x-apikey": self.api_key or "",
            "Accept": "application/json",
            "User-Agent": "ACTIS-Security-Endpoint/1.0",
        }

    def is_configured(self) -> bool:
        """VirusTotal requires an enabled flag and a valid API key (at least 16 characters)."""
        return bool(self.enabled and self.api_key and len(self.api_key.strip()) >= 16)

    def _check_rate_limit(self) -> Tuple[bool, Optional[str]]:
        """Tracks local request rate within a rolling 60-second window."""
        if not self.rate_limit_rpm:
            return True, None

        now = time.time()
        if now - self._window_start_time > 60.0:
            self._window_start_time = now
            self._request_count_window = 0

        if self._request_count_window >= self.rate_limit_rpm:
            return False, f"VirusTotal local rate limit reached ({self.rate_limit_rpm} req/min)."

        self._request_count_window += 1
        return True, None

    def lookup(
        self,
        indicator: str,
        indicator_type: IndicatorType,
        timeout: Optional[float] = None
    ) -> ThreatIntelEvidence:
        """Queries VirusTotal v3 for an indicator and returns normalized ThreatIntelEvidence."""
        if not self.enabled:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason="VirusTotal integration is disabled by configuration.",
                indicator_type=indicator_type,
                provider="VirusTotal"
            )

        if not self.is_configured():
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason="VirusTotal API key is not configured or invalid.",
                indicator_type=indicator_type,
                provider="VirusTotal"
            )

        # Validate and normalize indicator
        is_val, normalized, err, detected_type = validate_and_normalize_indicator(indicator, expected_type=indicator_type)
        if not is_val or not normalized:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason=f"Indicator validation failed: {err}",
                indicator_type=indicator_type,
                provider="VirusTotal"
            )

        req_timeout = timeout or self.timeout

        # Determine endpoint URL
        try:
            if detected_type in (IndicatorType.SHA256, IndicatorType.MD5, IndicatorType.SHA1):
                url = f"{self.BASE_URL}/files/{normalized}"
            elif detected_type == IndicatorType.URL:
                url_id = base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("utf-8").strip("=")
                url = f"{self.BASE_URL}/urls/{url_id}"
            elif detected_type == IndicatorType.DOMAIN:
                url = f"{self.BASE_URL}/domains/{normalized}"
            elif detected_type == IndicatorType.IP_ADDRESS:
                url = f"{self.BASE_URL}/ip_addresses/{normalized}"
            else:
                return ThreatIntelEvidence.unavailable(
                    indicator=indicator,
                    reason=f"Unsupported indicator type for VirusTotal: {detected_type}",
                    indicator_type=indicator_type,
                    provider="VirusTotal"
                )
        except Exception as e:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason=f"Endpoint formatting failed: {e}",
                indicator_type=indicator_type,
                provider="VirusTotal"
            )

        # Check rate limit
        allowed, rl_reason = self._check_rate_limit()
        if not allowed:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason=rl_reason or "Rate limit exceeded",
                indicator_type=indicator_type,
                provider="VirusTotal"
            )

        try:
            resp = requests.get(url, headers=self.headers, timeout=req_timeout)
            if resp.status_code == 200:
                payload = resp.json()
                attrs = payload.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values())
                conf = round(positives / max(1, total), 2)
                reputation = attrs.get("reputation", 0)

                raw_data = {
                    "source": "VirusTotal",
                    "available": True,
                    "indicator": normalized,
                    "indicator_type": detected_type.value,
                    "malicious": (positives > 1 or reputation < -10),
                    "positives": positives,
                    "total": total,
                    "confidence": conf,
                    "reputation": reputation,
                    "details": stats,
                }

                if positives >= 3 or reputation < -20:
                    verdict = ThreatIntelVerdict.MALICIOUS
                    is_confirmed = True
                elif positives in (1, 2) or reputation < 0:
                    verdict = ThreatIntelVerdict.SUSPICIOUS
                    is_confirmed = False
                elif total > 0 and positives == 0:
                    verdict = ThreatIntelVerdict.CLEAN
                    is_confirmed = False
                else:
                    verdict = ThreatIntelVerdict.UNKNOWN
                    is_confirmed = False

                return ThreatIntelEvidence(
                    indicator=normalized,
                    indicator_type=detected_type,
                    verdict=verdict,
                    confidence=max(0.5, conf) if verdict != ThreatIntelVerdict.UNKNOWN else 0.0,
                    threat_type="External Reputation Consensus",
                    provider="VirusTotal",
                    is_confirmed_threat=is_confirmed,
                    raw_data=raw_data
                )

            elif resp.status_code == 404:
                return ThreatIntelEvidence.unknown(
                    indicator=normalized,
                    indicator_type=detected_type,
                    provider="VirusTotal"
                )

            elif resp.status_code in (401, 403):
                return ThreatIntelEvidence.unavailable(
                    indicator=normalized,
                    reason="VirusTotal authentication failed (invalid or forbidden API key).",
                    indicator_type=detected_type,
                    provider="VirusTotal"
                )

            elif resp.status_code == 429:
                return ThreatIntelEvidence.unavailable(
                    indicator=normalized,
                    reason="VirusTotal rate limit exceeded (HTTP 429).",
                    indicator_type=detected_type,
                    provider="VirusTotal"
                )

            else:
                return ThreatIntelEvidence.unavailable(
                    indicator=normalized,
                    reason=f"VirusTotal responded with HTTP {resp.status_code}.",
                    indicator_type=detected_type,
                    provider="VirusTotal"
                )

        except requests.exceptions.Timeout:
            return ThreatIntelEvidence.unavailable(
                indicator=normalized,
                reason=f"VirusTotal request timed out after {req_timeout:.1f}s.",
                indicator_type=detected_type,
                provider="VirusTotal"
            )
        except requests.exceptions.RequestException as e:
            return ThreatIntelEvidence.unavailable(
                indicator=normalized,
                reason=f"VirusTotal connection error: {e}",
                indicator_type=detected_type,
                provider="VirusTotal"
            )
        except Exception as e:
            return ThreatIntelEvidence.unavailable(
                indicator=normalized,
                reason=f"VirusTotal unexpected error: {e}",
                indicator_type=detected_type,
                provider="VirusTotal"
            )


class URLhausClient(BaseThreatClient):
    """
    URLhaus API Client (abuse.ch).
    Specialized for malicious URLs, payload hashes, and domain reputation.
    Supports community queries without mandatory API keys.
    """

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(
        self,
        api_key: Optional[str] = None,
        enabled: Optional[bool] = None,
        timeout: Optional[float] = None,
    ):
        supported = {
            IndicatorType.URL,
            IndicatorType.SHA256,
            IndicatorType.MD5,
            IndicatorType.DOMAIN,
        }
        effective_timeout = timeout or TI_REQUEST_TIMEOUT
        super().__init__(
            provider_name="URLhaus",
            supported_types=supported,
            timeout=effective_timeout,
            rate_limit_rpm=60,
        )
        self.api_key = api_key if api_key is not None else URLHAUS_API_KEY
        self.enabled = enabled if enabled is not None else URLHAUS_ENABLED
        self.headers = {
            "Accept": "application/json",
            "User-Agent": "ACTIS-Security-Endpoint/1.0",
        }
        if self.api_key:
            self.headers["Auth-Key"] = self.api_key

    def is_configured(self) -> bool:
        """URLhaus community query endpoint is operational when enabled."""
        return bool(self.enabled)

    def lookup(
        self,
        indicator: str,
        indicator_type: IndicatorType,
        timeout: Optional[float] = None
    ) -> ThreatIntelEvidence:
        """Queries URLhaus for malicious URL, hash, or domain intelligence."""
        if not self.enabled:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason="URLhaus integration is disabled by configuration.",
                indicator_type=indicator_type,
                provider="URLhaus"
            )

        is_val, normalized, err, detected_type = validate_and_normalize_indicator(indicator, expected_type=indicator_type)
        if not is_val or not normalized:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason=f"Indicator validation failed: {err}",
                indicator_type=indicator_type,
                provider="URLhaus"
            )

        req_timeout = timeout or self.timeout

        try:
            if detected_type == IndicatorType.URL:
                endpoint = f"{self.BASE_URL}/url/"
                data = {"url": normalized}
            elif detected_type == IndicatorType.SHA256:
                endpoint = f"{self.BASE_URL}/payload/"
                data = {"sha256_hash": normalized}
            elif detected_type == IndicatorType.MD5:
                endpoint = f"{self.BASE_URL}/payload/"
                data = {"md5_hash": normalized}
            elif detected_type == IndicatorType.DOMAIN:
                endpoint = f"{self.BASE_URL}/host/"
                data = {"host": normalized}
            else:
                return ThreatIntelEvidence.unavailable(
                    indicator=indicator,
                    reason=f"Unsupported indicator type for URLhaus: {detected_type}",
                    indicator_type=indicator_type,
                    provider="URLhaus"
                )

            resp = requests.post(endpoint, data=data, headers=self.headers, timeout=req_timeout)
            if resp.status_code == 200:
                payload = resp.json()
                query_status = payload.get("query_status", "").lower()

                if query_status == "ok":
                    url_status = payload.get("url_status", "online")
                    threat_desc = payload.get("threat") or "Malware Payload Distribution"
                    raw_data = {
                        "source": "URLhaus",
                        "available": True,
                        "indicator": normalized,
                        "indicator_type": detected_type.value,
                        "malicious": True,
                        "positives": 1,
                        "total": 1,
                        "confidence": 0.95,
                        "details": payload,
                    }
                    return ThreatIntelEvidence(
                        indicator=normalized,
                        indicator_type=detected_type,
                        verdict=ThreatIntelVerdict.MALICIOUS,
                        confidence=0.95,
                        threat_type=threat_desc,
                        provider="URLhaus",
                        is_confirmed_threat=True,
                        raw_data=raw_data
                    )
                elif query_status == "no_results":
                    return ThreatIntelEvidence.unknown(
                        indicator=normalized,
                        indicator_type=detected_type,
                        provider="URLhaus"
                    )
                else:
                    return ThreatIntelEvidence.unavailable(
                        indicator=normalized,
                        reason=f"URLhaus reported status: '{query_status}'.",
                        indicator_type=detected_type,
                        provider="URLhaus"
                    )
            else:
                return ThreatIntelEvidence.unavailable(
                    indicator=normalized,
                    reason=f"URLhaus responded with HTTP {resp.status_code}.",
                    indicator_type=detected_type,
                    provider="URLhaus"
                )

        except requests.exceptions.Timeout:
            return ThreatIntelEvidence.unavailable(
                indicator=normalized,
                reason=f"URLhaus request timed out after {req_timeout:.1f}s.",
                indicator_type=detected_type,
                provider="URLhaus"
            )
        except requests.exceptions.RequestException as e:
            return ThreatIntelEvidence.unavailable(
                indicator=normalized,
                reason=f"URLhaus connection error: {e}",
                indicator_type=detected_type,
                provider="URLhaus"
            )
        except Exception as e:
            return ThreatIntelEvidence.unavailable(
                indicator=normalized,
                reason=f"URLhaus unexpected error: {e}",
                indicator_type=detected_type,
                provider="URLhaus"
            )


class AbuseIPDBClient(BaseThreatClient):
    """
    AbuseIPDB API v2 Client.
    Specialized for public IPv4/IPv6 threat confidence and abuse reporting.
    Strictly filters private/RFC 1918 and loopback addresses locally.
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(
        self,
        api_key: Optional[str] = None,
        enabled: Optional[bool] = None,
        timeout: Optional[float] = None,
    ):
        supported = {IndicatorType.IP_ADDRESS}
        effective_timeout = timeout or TI_REQUEST_TIMEOUT
        super().__init__(
            provider_name="AbuseIPDB",
            supported_types=supported,
            timeout=effective_timeout,
            rate_limit_rpm=60,
        )
        self.api_key = api_key if api_key is not None else ABUSEIPDB_API_KEY
        self.enabled = enabled if enabled is not None else ABUSEIPDB_ENABLED
        self.headers = {
            "Key": self.api_key or "",
            "Accept": "application/json",
            "User-Agent": "ACTIS-Security-Endpoint/1.0",
        }

    def is_configured(self) -> bool:
        """AbuseIPDB requires an enabled flag and an API key."""
        return bool(self.enabled and self.api_key and len(self.api_key.strip()) >= 16)

    def lookup(
        self,
        indicator: str,
        indicator_type: IndicatorType,
        timeout: Optional[float] = None
    ) -> ThreatIntelEvidence:
        """Queries AbuseIPDB check endpoint for public IP address reputation."""
        if not self.enabled:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason="AbuseIPDB integration is disabled by configuration.",
                indicator_type=indicator_type,
                provider="AbuseIPDB"
            )

        if not self.is_configured():
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason="AbuseIPDB API key is not configured or invalid.",
                indicator_type=indicator_type,
                provider="AbuseIPDB"
            )

        if indicator_type != IndicatorType.IP_ADDRESS:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason=f"AbuseIPDB only supports IP addresses (requested {indicator_type}).",
                indicator_type=indicator_type,
                provider="AbuseIPDB"
            )

        # Enforce private IP boundary
        is_safe, privacy_reason = is_safe_public_ip(indicator)
        if not is_safe:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason=privacy_reason or "Non-public IP address shielded by privacy policy.",
                indicator_type=indicator_type,
                provider="AbuseIPDB"
            )

        req_timeout = timeout or self.timeout

        try:
            url = f"{self.BASE_URL}/check"
            params = {"ipAddress": indicator.strip(), "maxAgeInDays": 90, "verbose": True}
            resp = requests.get(url, params=params, headers=self.headers, timeout=req_timeout)

            if resp.status_code == 200:
                payload = resp.json().get("data", {})
                score = payload.get("abuseConfidenceScore", 0)  # 0-100
                total_reports = payload.get("totalReports", 0)
                is_whitelisted = payload.get("isWhitelisted", False)

                raw_data = {
                    "source": "AbuseIPDB",
                    "available": True,
                    "indicator": indicator.strip(),
                    "indicator_type": "ip_address",
                    "malicious": (score >= 50),
                    "positives": total_reports if score >= 50 else 0,
                    "total": max(1, total_reports),
                    "confidence": round(score / 100.0, 2),
                    "details": payload,
                }

                if is_whitelisted or (score < 10 and total_reports == 0):
                    verdict = ThreatIntelVerdict.CLEAN
                    confidence = 0.85
                elif score >= 50:
                    verdict = ThreatIntelVerdict.MALICIOUS
                    confidence = round(score / 100.0, 2)
                elif score >= 20 or total_reports > 0:
                    verdict = ThreatIntelVerdict.SUSPICIOUS
                    confidence = round(score / 100.0, 2)
                else:
                    verdict = ThreatIntelVerdict.UNKNOWN
                    confidence = 0.0

                return ThreatIntelEvidence(
                    indicator=indicator.strip(),
                    indicator_type=IndicatorType.IP_ADDRESS,
                    verdict=verdict,
                    confidence=confidence,
                    threat_type="Malicious Host / Infrastructure Abuse" if verdict == ThreatIntelVerdict.MALICIOUS else "IP Reputation",
                    provider="AbuseIPDB",
                    is_confirmed_threat=(score >= 75),
                    is_whitelisted=is_whitelisted,
                    raw_data=raw_data
                )

            elif resp.status_code == 404:
                return ThreatIntelEvidence.unknown(
                    indicator=indicator,
                    indicator_type=IndicatorType.IP_ADDRESS,
                    provider="AbuseIPDB"
                )

            elif resp.status_code in (401, 403):
                return ThreatIntelEvidence.unavailable(
                    indicator=indicator,
                    reason="AbuseIPDB authentication failed (invalid or forbidden API key).",
                    indicator_type=IndicatorType.IP_ADDRESS,
                    provider="AbuseIPDB"
                )

            elif resp.status_code == 429:
                return ThreatIntelEvidence.unavailable(
                    indicator=indicator,
                    reason="AbuseIPDB daily check quota or rate limit exceeded.",
                    indicator_type=IndicatorType.IP_ADDRESS,
                    provider="AbuseIPDB"
                )

            else:
                return ThreatIntelEvidence.unavailable(
                    indicator=indicator,
                    reason=f"AbuseIPDB responded with HTTP {resp.status_code}.",
                    indicator_type=IndicatorType.IP_ADDRESS,
                    provider="AbuseIPDB"
                )

        except requests.exceptions.Timeout:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason=f"AbuseIPDB request timed out after {req_timeout:.1f}s.",
                indicator_type=IndicatorType.IP_ADDRESS,
                provider="AbuseIPDB"
            )
        except requests.exceptions.RequestException as e:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason=f"AbuseIPDB connection error: {e}",
                indicator_type=IndicatorType.IP_ADDRESS,
                provider="AbuseIPDB"
            )
        except Exception as e:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason=f"AbuseIPDB unexpected error: {e}",
                indicator_type=IndicatorType.IP_ADDRESS,
                provider="AbuseIPDB"
            )


# Global default client singletons
vt_client = VirusTotalClient()
urlhaus_client = URLhausClient()
abuseipdb_client = AbuseIPDBClient()
