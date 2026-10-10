"""
ACTIS Threat Intelligence Pipeline Integration Tests
Comprehensive verification of local-first lookup, caching, multi-provider conflict resolution,
detection engine integration, risk calculation, provider failure isolation, and secret masking.
"""

import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from detection_engine.threat_intel_contract import (
    ThreatIntelEvidence,
    ThreatIntelVerdict,
    IndicatorType,
)
from threat_intelligence.provider_base import BaseThreatClient
from threat_intelligence.threat_cache import ThreatIntelligenceCache
from threat_intelligence.threat_lookup import (
    ThreatLookup,
    OUTCOME_FOUND_MALICIOUS,
    OUTCOME_FOUND_SUSPICIOUS,
    OUTCOME_FOUND_BENIGN,
    OUTCOME_NOT_FOUND,
    OUTCOME_PROVIDER_UNAVAILABLE,
    OUTCOME_REQUEST_TIMEOUT,
    OUTCOME_INVALID_RESPONSE,
    OUTCOME_QUERY_SKIPPED,
)
from detection_engine.threat_detector import threat_detector
from detection_engine.risk_engine import RiskEngine
from scanners.url_scanner import scan_url_logic
from scanners.text_analyzer import TextAnalyzer
from config.settings import ExternalApiConfig
from threat_intelligence.api_clients import VirusTotalClient, URLhausClient, AbuseIPDBClient


class MockProvider(BaseThreatClient):
    """Configurable mock threat intelligence client for deterministic testing."""

    def __init__(self, name: str, supported_types, mock_verdict=ThreatIntelVerdict.MALICIOUS, confidence=0.85):
        super().__init__(provider_name=name, supported_types=set(supported_types), timeout=2.0)
        self.api_key = "test-mock-key-12345"
        self.mock_verdict = mock_verdict
        self.mock_confidence = confidence
        self.call_count = 0

    def is_configured(self) -> bool:
        return True

    def lookup(self, indicator: str, indicator_type: IndicatorType, timeout=None) -> ThreatIntelEvidence:
        self.call_count += 1
        if self.mock_verdict == ThreatIntelVerdict.UNAVAILABLE:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason="Simulated connection timeout",
                indicator_type=indicator_type,
                provider=self.provider_name
            )
        return ThreatIntelEvidence(
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=self.mock_verdict,
            confidence=self.mock_confidence,
            threat_type="Phishing Campaign",
            provider=self.provider_name,
            is_confirmed_threat=(self.mock_verdict == ThreatIntelVerdict.MALICIOUS),
            raw_data={"mock_field": "val"}
        )


@pytest.fixture
def clean_cache():
    return ThreatIntelligenceCache(default_ttl_seconds=60)


@pytest.fixture
def mock_vt():
    return MockProvider("MockVT", [IndicatorType.URL, IndicatorType.SHA256, IndicatorType.DOMAIN], ThreatIntelVerdict.MALICIOUS, 0.90)


@pytest.fixture
def mock_urlhaus():
    return MockProvider("MockURLhaus", [IndicatorType.URL, IndicatorType.DOMAIN], ThreatIntelVerdict.CLEAN, 0.70)


# ============================================================================
# 1. LOCAL-FIRST LOOKUP & OUTCOME STATES
# ============================================================================

def test_local_first_lookup_known_malicious(clean_cache, mock_vt):
    """Known malicious indicator in local DB must take precedence and set OUTCOME_FOUND_MALICIOUS."""
    lookup = ThreatLookup(external_client=mock_vt, cache=clean_cache)

    fake_local = {
        "found": True,
        "indicator_type": "url",
        "indicator": "http://evil-known-local.com",
        "status": "CONFIRMED",
        "type": "Phishing",
        "confidence": 0.95,
        "source": "Local Blacklist"
    }

    with patch("threat_intelligence.threat_lookup.db_lookup_indicator", return_value=fake_local):
        res = lookup.lookup_indicator("http://evil-known-local.com", IndicatorType.URL, query_external=False)

        assert res["is_known_threat"] is True
        assert res["outcome_state"] == OUTCOME_FOUND_MALICIOUS
        assert res["primary_evidence"].verdict == ThreatIntelVerdict.MALICIOUS
        assert res["primary_evidence"].provider == "LOCAL_DATABASE"
        assert mock_vt.call_count == 0


def test_local_not_found_queries_external_provider(clean_cache, mock_vt):
    """When indicator is absent from local DB, external provider must be queried and integrated."""
    lookup = ThreatLookup(external_client=mock_vt, cache=clean_cache)
    lookup.available_providers = [mock_vt]

    with patch("threat_intelligence.threat_lookup.db_lookup_indicator", return_value={"found": False}):
        res = lookup.lookup_indicator("http://new-external-phish.com", IndicatorType.URL, query_external=True)

        assert res["is_known_threat"] is True
        assert res["outcome_state"] == OUTCOME_FOUND_MALICIOUS
        assert res["primary_evidence"].verdict == ThreatIntelVerdict.MALICIOUS
        assert res["primary_evidence"].provider == "MockVT"
        assert mock_vt.call_count == 1


# ============================================================================
# 2. CACHING BEHAVIOR
# ============================================================================

def test_caching_layer_bypasses_repeated_external_calls(clean_cache, mock_vt):
    """Subsequent lookups for identical indicator must hit the TTL cache and avoid external requests."""
    lookup = ThreatLookup(external_client=mock_vt, cache=clean_cache)
    lookup.available_providers = [mock_vt]

    with patch("threat_intelligence.threat_lookup.db_lookup_indicator", return_value={"found": False}):
        # First query: cache miss
        res1 = lookup.lookup_indicator("http://cached-target.com", IndicatorType.URL, query_external=True)
        assert res1["outcome_state"] == OUTCOME_FOUND_MALICIOUS
        assert mock_vt.call_count == 1
        assert res1["external_intel"].get("from_cache", False) is False

        # Second query: cache hit
        res2 = lookup.lookup_indicator("http://cached-target.com", IndicatorType.URL, query_external=True)
        assert res2["outcome_state"] == OUTCOME_FOUND_MALICIOUS
        assert mock_vt.call_count == 1  # No additional network call
        assert res2["external_intel"].get("from_cache") is True


def test_cache_does_not_cache_transient_failures(clean_cache):
    """Transient network errors and timeouts must NEVER be cached as valid intelligence."""
    failing_provider = MockProvider("FailVT", [IndicatorType.URL], ThreatIntelVerdict.UNAVAILABLE)
    lookup = ThreatLookup(external_client=failing_provider, cache=clean_cache)
    lookup.available_providers = [failing_provider]

    with patch("threat_intelligence.threat_lookup.db_lookup_indicator", return_value={"found": False}):
        res1 = lookup.lookup_indicator("http://retry-target.com", IndicatorType.URL, query_external=True)
        assert res1["outcome_state"] == OUTCOME_REQUEST_TIMEOUT
        assert clean_cache.size == 0  # Cache remains clean!


# ============================================================================
# 3. CONFLICT RESOLUTION & MULTI-PROVIDER AGGREGATION
# ============================================================================

def test_conflicting_provider_findings_resolution(clean_cache, mock_vt, mock_urlhaus):
    """When one provider reports MALICIOUS and another reports CLEAN, MALICIOUS takes precedence."""
    lookup = ThreatLookup(external_client=mock_vt, cache=clean_cache)
    lookup.available_providers = [mock_vt, mock_urlhaus]

    res = lookup.lookup_indicator_multi_provider(
        "http://conflict-domain.com/path",
        IndicatorType.URL,
        provider_names=["MockVT", "MockURLhaus"]
    )

    agg = res["aggregated_evidence"]
    assert agg.verdict == ThreatIntelVerdict.MALICIOUS
    assert agg.confidence == 0.90
    assert "MockVT" in agg.provider
    assert res["outcome_state"] == OUTCOME_FOUND_MALICIOUS
    assert agg.raw_data.get("conflict_resolved") is True


def test_duplicate_findings_deduplication(clean_cache):
    """Multiple identical or collaborative detections merge threat types and preserve attribution without score inflation."""
    provider1 = MockProvider("P1", [IndicatorType.URL], ThreatIntelVerdict.MALICIOUS, 0.80)
    provider2 = MockProvider("P2", [IndicatorType.URL], ThreatIntelVerdict.MALICIOUS, 0.92)

    ev1 = provider1.lookup("http://dup-target.com", IndicatorType.URL)
    ev2 = provider2.lookup("http://dup-target.com", IndicatorType.URL)

    aggregated = ThreatIntelEvidence.aggregate_findings([ev1, ev2])

    assert aggregated.verdict == ThreatIntelVerdict.MALICIOUS
    assert aggregated.confidence == 0.92  # Max confidence preserved, not added (0.80 + 0.92 = 1.72 clamped)
    assert "P1" in aggregated.provider and "P2" in aggregated.provider


# ============================================================================
# 4. DETECTION ENGINE & RISK ENGINE INTEGRATION
# ============================================================================

def test_threat_detector_url_analysis_with_external_ti(mock_vt):
    """analyze_url integrates external intelligence into RiskEngine and DetectionDecisionEngine."""
    with patch("threat_intelligence.threat_lookup.threat_lookup.lookup_url") as mock_lookup:
        mock_lookup.return_value = {
            "indicator": "http://evil-external-phish.net",
            "indicator_type": "URL",
            "local_intel": {"found": False},
            "external_intel": {
                "available": True,
                "malicious": True,
                "confidence": 0.95,
                "positives": 15,
                "total": 85,
                "source": "VirusTotal",
                "permalink": "https://virustotal.com/gui/url/abc"
            },
            "local_evidence": ThreatIntelEvidence.unknown("http://evil-external-phish.net"),
            "external_evidence": ThreatIntelEvidence(
                indicator="http://evil-external-phish.net",
                indicator_type=IndicatorType.URL,
                verdict=ThreatIntelVerdict.MALICIOUS,
                confidence=0.95,
                provider="VirusTotal",
                is_confirmed_threat=True
            ),
            "primary_evidence": ThreatIntelEvidence(
                indicator="http://evil-external-phish.net",
                indicator_type=IndicatorType.URL,
                verdict=ThreatIntelVerdict.MALICIOUS,
                confidence=0.95,
                provider="VirusTotal",
                is_confirmed_threat=True
            ),
            "is_known_threat": True,
            "outcome_state": OUTCOME_FOUND_MALICIOUS,
            "domain": "evil-external-phish.net"
        }

        result = threat_detector.analyze_url("http://evil-external-phish.net", check_external=True)

        assert result["is_valid"] is True
        assert result["score"] >= 35.0
        assert result["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
        assert result["is_threat"] is True
        # Check reasons include external TI attribution
        assert any("VirusTotal" in r or "External threat intelligence" in r or "Known MALICIOUS" in r for r in result["reasons"])



def test_provider_failure_isolation_in_detection():
    """A provider timeout or exception must NOT crash detection; local analysis completes cleanly."""
    with patch("threat_intelligence.threat_lookup.threat_lookup.lookup_url") as mock_lookup:
        mock_lookup.return_value = {
            "indicator": "http://test-safe-site.com",
            "indicator_type": "URL",
            "local_intel": {"found": False},
            "external_intel": {"available": False, "reason": "Connection timed out"},
            "local_evidence": ThreatIntelEvidence.unknown("http://test-safe-site.com"),
            "external_evidence": None,
            "primary_evidence": ThreatIntelEvidence.unavailable("http://test-safe-site.com", reason="Timeout"),
            "is_known_threat": False,
            "outcome_state": OUTCOME_REQUEST_TIMEOUT,
            "domain": "test-safe-site.com"
        }

        # Analyze URL must run through ML and Heuristics without exception
        result = threat_detector.analyze_url("http://test-safe-site.com", check_external=True)

        assert result["is_valid"] is True
        assert "score" in result
        assert "risk_level" in result


# ============================================================================
# 5. SECRET MASKING & PRIVACY BOUNDARIES
# ============================================================================

def test_secret_masking_in_repr_and_config():
    """API keys must never be leaked via repr, str, or logging representations."""
    vt = VirusTotalClient(api_key="super-secret-vt-key-99999")
    urlhaus = URLhausClient(api_key="confidential-auth-token")
    abuse = AbuseIPDBClient(api_key="private-ipdb-secret")

    vt_repr = repr(vt)
    urlhaus_repr = repr(urlhaus)
    abuse_repr = repr(abuse)

    assert "super-secret-vt-key-99999" not in vt_repr
    assert "confidential-auth-token" not in urlhaus_repr
    assert "private-ipdb-secret" not in abuse_repr
    assert "***" in vt_repr

    cfg = ExternalApiConfig(
        virustotal_api_key="secret-key-123",
        abuseipdb_api_key="another-secret"
    )
    cfg_repr = repr(cfg)
    assert "secret-key-123" not in cfg_repr
    assert "another-secret" not in cfg_repr
    assert "****" in cfg_repr

    cfg_dict = cfg.to_dict(mask_secrets=True)
    assert cfg_dict["virustotal_api_key"] != "secret-key-123"
    assert "****" in cfg_dict["virustotal_api_key"]



# ============================================================================
# 6. SCANNER REGRESSION INTEGRATION
# ============================================================================

def test_url_scanner_scan_url_logic_regression():
    """Verify scanners.url_scanner.scan_url_logic maintains backwards compatibility."""
    res = scan_url_logic("http://example.com/test", check_external=False)
    assert "score" in res
    assert "risk_level" in res
    assert "is_threat" in res
    assert "reasons" in res


def test_text_analyzer_regression():
    """Verify scanners.text_analyzer.TextAnalyzer continues functioning seamlessly."""
    res = TextAnalyzer.analyze_message("URGENT: Your bank account is locked! Click http://verify-bank.com to restore access.")
    assert res["is_suspicious_message"] is True
    assert res["overall_risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert res["total_url_count"] >= 1

