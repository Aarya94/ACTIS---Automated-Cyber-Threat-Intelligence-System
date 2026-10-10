"""
Unit and Mocked Integration Tests for ACTIS External Threat Intelligence Providers
Tests provider adapter contracts, response parsing, status codes, timeouts,
rate limits, authentication errors, malformed payloads, and privacy shielding.
Operates strictly without live internet calls or required API keys.
"""

import base64
import pytest
from unittest.mock import patch, MagicMock
import requests

from detection_engine.threat_intel_contract import (
    ThreatIntelEvidence,
    ThreatIntelVerdict,
    IndicatorType,
)
from threat_intelligence.api_clients import (
    VirusTotalClient,
    URLhausClient,
    AbuseIPDBClient,
)
from threat_intelligence.indicator_validator import (
    validate_and_normalize_indicator,
    detect_indicator_type,
    is_safe_public_ip,
)


class TestIndicatorValidator:
    """Tests indicator syntax validation, canonical normalization, and privacy boundaries."""

    def test_sha256_normalization_and_validation(self):
        valid_upper = "ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA"
        is_val, norm, err, ind_type = validate_and_normalize_indicator(valid_upper)
        assert is_val is True
        assert norm == valid_upper.lower()
        assert ind_type == IndicatorType.SHA256
        assert err is None

    def test_malformed_sha256_rejection(self):
        too_short = "ed01ebfbc9eb5bbea545af4d01bf5f10"
        is_val, norm, err, ind_type = validate_and_normalize_indicator(too_short, expected_type=IndicatorType.SHA256)
        assert is_val is False
        assert "Malformed SHA-256" in err

    def test_url_canonical_normalization(self):
        raw_url = "HTTP://Example.COM:80/path/test?q=1#frag"
        is_val, norm, err, ind_type = validate_and_normalize_indicator(raw_url)
        assert is_val is True
        assert norm == "http://example.com/path/test?q=1"
        assert ind_type == IndicatorType.URL

    def test_private_and_loopback_ip_shielding(self):
        for private_ip in ("127.0.0.1", "10.0.0.5", "192.168.1.100", "172.16.0.1", "169.254.1.1"):
            is_val, norm, err, ind_type = validate_and_normalize_indicator(private_ip)
            assert is_val is False
            assert "shielded" in err or "Loopback" in err or "must not be transmitted" in err

    def test_public_ip_acceptance(self):
        public_ip = "8.8.8.8"
        is_val, norm, err, ind_type = validate_and_normalize_indicator(public_ip)
        assert is_val is True
        assert norm == "8.8.8.8"
        assert ind_type == IndicatorType.IP_ADDRESS


class TestVirusTotalClient:
    """Tests VirusTotal v3 adapter with mocked HTTP responses."""

    @pytest.fixture
    def vt(self):
        return VirusTotalClient(api_key="mocked_valid_vt_api_key_123456", enabled=True, timeout=3.0)

    def test_is_configured_and_disabled_state(self):
        configured_client = VirusTotalClient(api_key="valid_key_123456789", enabled=True)
        assert configured_client.is_configured() is True

        no_key_client = VirusTotalClient(api_key="", enabled=True)
        assert no_key_client.is_configured() is False
        unavail = no_key_client.lookup("ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", IndicatorType.SHA256)
        assert unavail.verdict == ThreatIntelVerdict.UNAVAILABLE

        disabled_client = VirusTotalClient(api_key="valid_key_123456789", enabled=False)
        assert disabled_client.is_configured() is False
        unavail_dis = disabled_client.lookup("ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", IndicatorType.SHA256)
        assert unavail_dis.verdict == ThreatIntelVerdict.UNAVAILABLE

    @patch("requests.get")
    def test_lookup_hash_malicious_confirmed(self, mock_get, vt):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 45,
                        "suspicious": 3,
                        "undetected": 20,
                        "harmless": 2
                    },
                    "reputation": -50
                }
            }
        }
        mock_get.return_value = mock_resp

        h = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ev = vt.lookup(h, IndicatorType.SHA256)

        assert ev.verdict == ThreatIntelVerdict.MALICIOUS
        assert ev.is_confirmed_threat is True
        assert ev.provider == "VirusTotal"
        assert ev.raw_data["positives"] == 48
        assert ev.raw_data["total"] == 70
        assert ev.confidence >= 0.60

    @patch("requests.get")
    def test_lookup_hash_suspicious(self, mock_get, vt):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 1,
                        "undetected": 65,
                        "harmless": 0
                    },
                    "reputation": -5
                }
            }
        }
        mock_get.return_value = mock_resp

        h = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ev = vt.lookup(h, IndicatorType.SHA256)

        assert ev.verdict == ThreatIntelVerdict.SUSPICIOUS
        assert ev.is_confirmed_threat is False
        assert ev.raw_data["positives"] == 2

    @patch("requests.get")
    def test_lookup_hash_clean(self, mock_get, vt):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 5,
                        "harmless": 65
                    },
                    "reputation": 40
                }
            }
        }
        mock_get.return_value = mock_resp

        h = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ev = vt.lookup(h, IndicatorType.SHA256)

        assert ev.verdict == ThreatIntelVerdict.CLEAN
        assert ev.is_confirmed_threat is False

    @patch("requests.get")
    def test_lookup_not_found_404(self, mock_get, vt):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        h = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ev = vt.lookup(h, IndicatorType.SHA256)

        assert ev.verdict == ThreatIntelVerdict.UNKNOWN
        assert ev.provider == "VirusTotal"

    @patch("requests.get")
    def test_lookup_rate_limit_429(self, mock_get, vt):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        h = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ev = vt.lookup(h, IndicatorType.SHA256)

        assert ev.verdict == ThreatIntelVerdict.UNAVAILABLE
        assert "429" in ev.raw_data["reason"] or "rate limit" in ev.raw_data["reason"].lower()

    @patch("requests.get")
    def test_lookup_auth_failure_401(self, mock_get, vt):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp

        h = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ev = vt.lookup(h, IndicatorType.SHA256)

        assert ev.verdict == ThreatIntelVerdict.UNAVAILABLE
        assert "authentication failed" in ev.raw_data["reason"].lower()

    @patch("requests.get")
    def test_lookup_timeout_isolation(self, mock_get, vt):
        mock_get.side_effect = requests.exceptions.Timeout("Connection timed out after 3.0s")

        h = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ev = vt.lookup(h, IndicatorType.SHA256)

        assert ev.verdict == ThreatIntelVerdict.UNAVAILABLE
        assert "timed out" in ev.raw_data["reason"].lower()

    @patch("requests.get")
    def test_lookup_malformed_json_resilience(self, mock_get, vt):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Expecting value: line 1 column 1 (char 0)")
        mock_get.return_value = mock_resp

        h = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ev = vt.lookup(h, IndicatorType.SHA256)

        assert ev.verdict == ThreatIntelVerdict.UNAVAILABLE
        assert "malformed json" in ev.raw_data["reason"].lower()

    @patch("requests.get")
    def test_lookup_url_base64_identifier(self, mock_get, vt):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 8, "suspicious": 1, "undetected": 60},
                    "reputation": -30
                }
            }
        }
        mock_get.return_value = mock_resp

        target_url = "http://phishing-site.example.com/login"
        ev = vt.lookup(target_url, IndicatorType.URL)

        assert ev.verdict == ThreatIntelVerdict.MALICIOUS
        # Verify base64 identifier was in URL
        called_url = mock_get.call_args[0][0]
        expected_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        assert expected_id in called_url


class TestURLhausClient:
    """Tests URLhaus adapter with mocked HTTP responses."""

    @pytest.fixture
    def uh(self):
        return URLhausClient(enabled=True, timeout=3.0)

    @patch("requests.post")
    def test_urlhaus_malicious_hit(self, mock_post, uh):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "id": "123456",
            "url": "http://evil-malware-drop.top/mal.exe",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["exe", "Mozi"]
        }
        mock_post.return_value = mock_resp

        ev = uh.lookup("http://evil-malware-drop.top/mal.exe", IndicatorType.URL)
        assert ev.verdict == ThreatIntelVerdict.MALICIOUS
        assert ev.is_confirmed_threat is True
        assert ev.provider == "URLhaus"
        assert ev.threat_type == "malware_download"

    @patch("requests.post")
    def test_urlhaus_no_results(self, mock_post, uh):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_results"}
        mock_post.return_value = mock_resp

        ev = uh.lookup("http://clean-site.org/index.html", IndicatorType.URL)
        assert ev.verdict == ThreatIntelVerdict.UNKNOWN
        assert ev.provider == "URLhaus"

    @patch("requests.post")
    def test_urlhaus_timeout(self, mock_post, uh):
        mock_post.side_effect = requests.exceptions.Timeout("Timeout")
        ev = uh.lookup("http://slow-site.com", IndicatorType.URL)
        assert ev.verdict == ThreatIntelVerdict.UNAVAILABLE
        assert "timed out" in ev.raw_data["reason"].lower()


class TestAbuseIPDBClient:
    """Tests AbuseIPDB adapter with mocked HTTP responses."""

    @pytest.fixture
    def aip(self):
        return AbuseIPDBClient(api_key="mocked_valid_abuseipdb_key_123456", enabled=True, timeout=3.0)

    def test_private_ip_boundary_enforced(self, aip):
        ev = aip.lookup("192.168.1.1", IndicatorType.IP_ADDRESS)
        assert ev.verdict == ThreatIntelVerdict.UNAVAILABLE
        assert "shielded" in ev.raw_data["reason"].lower() or "privacy" in ev.raw_data["reason"].lower()

    @patch("requests.get")
    def test_public_ip_malicious(self, mock_get, aip):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "185.220.101.5",
                "isPublic": True,
                "abuseConfidenceScore": 88,
                "totalReports": 340,
                "isWhitelisted": False
            }
        }
        mock_get.return_value = mock_resp

        ev = aip.lookup("185.220.101.5", IndicatorType.IP_ADDRESS)
        assert ev.verdict == ThreatIntelVerdict.MALICIOUS
        assert ev.is_confirmed_threat is True
        assert ev.provider == "AbuseIPDB"
        assert ev.confidence == 0.88

    @patch("requests.get")
    def test_public_ip_clean(self, mock_get, aip):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "8.8.8.8",
                "isPublic": True,
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "isWhitelisted": True
            }
        }
        mock_get.return_value = mock_resp

        ev = aip.lookup("8.8.8.8", IndicatorType.IP_ADDRESS)
        assert ev.verdict == ThreatIntelVerdict.CLEAN
        assert ev.is_whitelisted is True
