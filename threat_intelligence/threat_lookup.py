"""
ACTIS Threat Lookup Coordinator
Coordinates defensive local-first intelligence lookups against SQLite threat database,
applies canonical indicator validation, executes optional external provider lookups
(VirusTotal, URLhaus, AbuseIPDB), integrates thread-safe TTL caching, and synthesizes
homogeneous ThreatIntelEvidence contracts with explicit outcome states.
"""

from typing import Dict, Any, Optional, List, Union

from reports.threat_database import lookup_indicator as db_lookup_indicator
from detection_engine.threat_intel_contract import (
    ThreatIntelEvidence,
    ThreatIntelVerdict,
    IndicatorType,
)
from threat_intelligence.api_clients import (
    vt_client,
    urlhaus_client,
    abuseipdb_client,
    BaseThreatClient,
)
from threat_intelligence.indicator_validator import (
    validate_and_normalize_indicator,
    detect_indicator_type,
)
from threat_intelligence.threat_cache import threat_cache, ThreatIntelligenceCache
from config.config import get_logger

logger = get_logger("ThreatLookup")


# Canonical Query Outcome States
OUTCOME_FOUND_MALICIOUS = "FOUND_MALICIOUS"
OUTCOME_FOUND_SUSPICIOUS = "FOUND_SUSPICIOUS"
OUTCOME_FOUND_BENIGN = "FOUND_BENIGN"
OUTCOME_NOT_FOUND = "NOT_FOUND"
OUTCOME_PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
OUTCOME_REQUEST_TIMEOUT = "REQUEST_TIMEOUT"
OUTCOME_INVALID_RESPONSE = "INVALID_RESPONSE"
OUTCOME_QUERY_SKIPPED = "QUERY_SKIPPED"


class ThreatLookup:
    """
    Unified threat lookup layer orchestrating local database queries,
    TTL caching, and external threat intelligence providers with strict
    privacy boundaries and explicit outcome state tracking.
    """

    def __init__(
        self,
        external_client: Optional[BaseThreatClient] = None,
        cache: Optional[ThreatIntelligenceCache] = None,
    ):
        self.external_client = external_client or vt_client
        self.cache = cache or threat_cache
        self.available_providers: List[BaseThreatClient] = [
            self.external_client,
            urlhaus_client,
            abuseipdb_client,
        ]

    def _select_provider_for_indicator(
        self,
        indicator_type: IndicatorType,
        preferred_provider: Optional[str] = None
    ) -> Optional[BaseThreatClient]:
        """Selects the most suitable, configured provider for the indicator type."""
        if preferred_provider:
            for p in self.available_providers:
                if p.provider_name.lower() == preferred_provider.lower():
                    if p.supports_indicator_type(indicator_type) and p.is_configured():
                        return p

        # Priority selection based on indicator type:
        # IP Address -> AbuseIPDB (specialized), then VirusTotal
        if indicator_type == IndicatorType.IP_ADDRESS:
            if abuseipdb_client.is_configured():
                return abuseipdb_client
            if vt_client.is_configured():
                return vt_client

        # URL -> URLhaus (real-time malware payloads), then VirusTotal
        elif indicator_type == IndicatorType.URL:
            if vt_client.is_configured():
                return vt_client
            if urlhaus_client.is_configured():
                return urlhaus_client

        # File Hashes -> VirusTotal (multi-engine consensus), then URLhaus
        elif indicator_type in (IndicatorType.SHA256, IndicatorType.MD5, IndicatorType.SHA1):
            if vt_client.is_configured():
                return vt_client
            if urlhaus_client.is_configured():
                return urlhaus_client

        # Domains -> VirusTotal, then URLhaus
        elif indicator_type == IndicatorType.DOMAIN:
            if vt_client.is_configured():
                return vt_client
            if urlhaus_client.is_configured():
                return urlhaus_client

        # Fallback to configured external_client if it supports this type
        if self.external_client.supports_indicator_type(indicator_type) and self.external_client.is_configured():
            return self.external_client

        return None

    def lookup_indicator(
        self,
        indicator: str,
        indicator_type: Optional[Union[str, IndicatorType]] = None,
        query_external: bool = False,
        preferred_provider: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes ordered, 9-stage local-first threat lookup:
        1. Validate & normalize indicator
        2. Query local SQLite threat database
        3. Policy check: determine if external lookup is appropriate
        4. Consult cache for external intelligence
        5. Query configured provider with bounded timeout
        6. Validate and normalize evidence
        7. Cache durable intelligence
        8. Synthesize local + external evidence into primary verdict
        """
        # Step 1: Validate and Normalize Indicator
        is_val, normalized, err, resolved_type = validate_and_normalize_indicator(
            indicator,
            expected_type=indicator_type
        )
        if not is_val or not normalized or not resolved_type:
            unavail_ev = ThreatIntelEvidence.unavailable(
                indicator=indicator or "",
                reason=err or "Invalid indicator",
                indicator_type=resolved_type or IndicatorType.GENERIC,
                provider="ACTIS_Validator"
            )
            return {
                "indicator": indicator,
                "indicator_type": resolved_type.value if resolved_type else "GENERIC",
                "local_intel": {"found": False, "error": err},
                "external_intel": {"available": False, "reason": err},
                "local_evidence": unavail_ev,
                "external_evidence": None,
                "primary_evidence": unavail_ev,
                "is_known_threat": False,
                "outcome_state": OUTCOME_INVALID_RESPONSE,
            }

        # Step 2: Query Local Database
        local_db_type = resolved_type.value.lower()
        if resolved_type == IndicatorType.SHA256:
            local_db_type = "sha256"
        elif resolved_type == IndicatorType.IP_ADDRESS:
            local_db_type = "ip"

        local_intel = db_lookup_indicator(local_db_type, normalized)
        local_evidence = ThreatIntelEvidence.from_local_intel(
            intel=local_intel,
            indicator=normalized,
            indicator_type=resolved_type
        )

        local_found = local_intel.get("found", False)
        is_known_threat = local_evidence.verdict in (ThreatIntelVerdict.MALICIOUS, ThreatIntelVerdict.SUSPICIOUS)

        outcome_state = OUTCOME_NOT_FOUND
        if local_found:
            if local_evidence.verdict == ThreatIntelVerdict.MALICIOUS:
                outcome_state = OUTCOME_FOUND_MALICIOUS
            elif local_evidence.verdict == ThreatIntelVerdict.SUSPICIOUS:
                outcome_state = OUTCOME_FOUND_SUSPICIOUS
            elif local_evidence.verdict in (ThreatIntelVerdict.CLEAN, ThreatIntelVerdict.FALSE_POSITIVE):
                outcome_state = OUTCOME_FOUND_BENIGN

        # Step 3: Determine External Query
        external_intel: Dict[str, Any] = {"available": False, "reason": "External lookup not requested"}
        external_evidence: Optional[ThreatIntelEvidence] = None

        if query_external:
            provider = self._select_provider_for_indicator(resolved_type, preferred_provider=preferred_provider)
            if not provider or not provider.is_configured():
                external_intel = {
                    "available": False,
                    "reason": "No configured external provider for this indicator type."
                }
                if outcome_state == OUTCOME_NOT_FOUND:
                    outcome_state = OUTCOME_QUERY_SKIPPED
            else:
                # Check Cache First
                cached_ev = self.cache.get(provider.provider_name, resolved_type, normalized)
                if cached_ev:
                    external_evidence = cached_ev
                    external_intel = provider._evidence_to_legacy_dict(cached_ev)
                    external_intel["from_cache"] = True
                else:
                    # Query Provider with Defensive Error Bounds
                    external_evidence = provider.lookup(normalized, resolved_type)
                    external_intel = provider._evidence_to_legacy_dict(external_evidence)

                    # Cache durable results (never cache transient errors)
                    if external_evidence.verdict != ThreatIntelVerdict.UNAVAILABLE:
                        self.cache.set(external_evidence)

                # Determine outcome state from external evidence if local was not found
                if not local_found:
                    if external_evidence.verdict == ThreatIntelVerdict.MALICIOUS:
                        outcome_state = OUTCOME_FOUND_MALICIOUS
                        is_known_threat = True
                    elif external_evidence.verdict == ThreatIntelVerdict.SUSPICIOUS:
                        outcome_state = OUTCOME_FOUND_SUSPICIOUS
                        is_known_threat = True
                    elif external_evidence.verdict == ThreatIntelVerdict.CLEAN:
                        outcome_state = OUTCOME_FOUND_BENIGN
                    elif external_evidence.verdict == ThreatIntelVerdict.UNKNOWN:
                        outcome_state = OUTCOME_NOT_FOUND
                    elif external_evidence.verdict == ThreatIntelVerdict.UNAVAILABLE:
                        raw_reason = str(external_intel.get("reason", "")).lower()
                        if "timeout" in raw_reason or "timed out" in raw_reason:
                            outcome_state = OUTCOME_REQUEST_TIMEOUT
                        elif "rate limit" in raw_reason:
                            outcome_state = OUTCOME_PROVIDER_UNAVAILABLE
                        elif "disabled" in raw_reason or "not configured" in raw_reason:
                            outcome_state = OUTCOME_QUERY_SKIPPED
                        else:
                            outcome_state = OUTCOME_PROVIDER_UNAVAILABLE

        # Step 4: Primary Evidence Selection
        # If local is confirmed malicious or suspicious, local takes precedence
        if local_found and local_evidence.verdict in (ThreatIntelVerdict.MALICIOUS, ThreatIntelVerdict.SUSPICIOUS, ThreatIntelVerdict.FALSE_POSITIVE):
            primary_evidence = local_evidence
        elif external_evidence and external_evidence.verdict != ThreatIntelVerdict.UNAVAILABLE:
            primary_evidence = external_evidence
        else:
            primary_evidence = local_evidence

        return {
            "indicator": normalized,
            "indicator_type": resolved_type.value,
            "local_intel": local_intel,
            "external_intel": external_intel,
            "local_evidence": local_evidence,
            "external_evidence": external_evidence,
            "primary_evidence": primary_evidence,
            "is_known_threat": is_known_threat,
            "outcome_state": outcome_state,
        }

    def lookup_hash(self, sha256_hash: str, query_external: bool = False) -> Dict[str, Any]:
        """Looks up a file hash locally, and optionally queries external intel."""
        return self.lookup_indicator(
            indicator=sha256_hash,
            indicator_type=IndicatorType.SHA256,
            query_external=query_external
        )

    def lookup_url(self, url: str, domain: Optional[str] = None, query_external: bool = False) -> Dict[str, Any]:
        """Looks up a URL and its domain locally and optionally externally."""
        # 1. Lookup exact URL
        url_res = self.lookup_indicator(
            indicator=url,
            indicator_type=IndicatorType.URL,
            query_external=query_external
        )
        if url_res.get("is_known_threat", False):
            url_res["domain"] = domain or ""
            return url_res

        # 2. If URL is not a known threat, check parent domain locally
        if domain:
            dom_res = self.lookup_indicator(
                indicator=domain,
                indicator_type=IndicatorType.DOMAIN,
                query_external=False  # Keep external focused on canonical URL to conserve quota
            )
            if dom_res.get("is_known_threat", False):
                # Domain is malicious! Inherit domain intelligence
                url_res["is_known_threat"] = True
                url_res["domain"] = domain
                url_res["local_intel"] = dom_res["local_intel"]
                url_res["local_evidence"] = dom_res["local_evidence"]
                url_res["primary_evidence"] = dom_res["primary_evidence"]
                url_res["outcome_state"] = dom_res["outcome_state"]
                return url_res

        url_res["domain"] = domain or ""
        return url_res

    def lookup_domain(self, domain: str, query_external: bool = False) -> Dict[str, Any]:
        """Looks up a domain locally and optionally queries external intel."""
        return self.lookup_indicator(
            indicator=domain,
            indicator_type=IndicatorType.DOMAIN,
            query_external=query_external
        )

    def lookup_ip(self, ip_address: str, query_external: bool = False) -> Dict[str, Any]:
        """Looks up an IP address locally and optionally queries external intel."""
        return self.lookup_indicator(
            indicator=ip_address,
            indicator_type=IndicatorType.IP_ADDRESS,
            query_external=query_external
        )


# Global threat lookup singleton
threat_lookup = ThreatLookup()
