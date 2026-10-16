"""
ACTIS Day 27 — Part 2: Repeated-Scan & Evidence Aggregation Invariant Tests.
Validates that:
1. Genuine external threat intelligence (e.g. VirusTotal) contributes independent evidence to Layer 1.
2. In-memory cache hits do not fabricate new evidence or alter verdicts.
3. Repeated rule executions on identical input produce deduplicated, deterministic signal sets.
"""

import tempfile
import pathlib
import pytest

import config.config as cfg
import reports.threat_database as tdb
from detection_engine.threat_detector import ThreatDetector
from scanners.url_scanner import normalize_url
from detection_engine.risk_engine import RiskEngine


@pytest.fixture
def isolated_ti_db():
    """Provides an isolated, temporary SQLite database for threat intelligence."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = pathlib.Path(tmpdir) / "test_part2_scans.db"
        orig_db = tdb.DATABASE_PATH
        tdb.DATABASE_PATH = test_db
        tdb.initialize_database()
        try:
            yield test_db
        finally:
            tdb.DATABASE_PATH = orig_db


class TestDay27Part2RepeatedScansAndEvidence:
    """Invariant tests ensuring evidence aggregation prevents duplicate or synthetic amplification."""

    def test_external_independent_intelligence_still_contributes(self, isolated_ti_db):
        """
        Validates that genuine independent external intelligence (e.g. VirusTotal)
        properly contributes to Layer 1 threat intelligence weighting.
        """
        norm_url = "https://verified-c2-node.example.org/beacon"
        tdb.register_indicator(
            indicator_type="url",
            indicator_value=norm_url,
            source="VirusTotal",
            confidence=0.90,
            status="CONFIRMED",
            threat_type="Malware C2"
        )

        known_intel = tdb.lookup_indicator("url", norm_url)
        risk_res = RiskEngine.calculate_risk(
            target_type="url",
            target_value=norm_url,
            known_intel=known_intel
        )

        assert risk_res["is_threat"] is True
        assert risk_res["risk_level"] == "CRITICAL"
        assert risk_res["score"] == 90.0
        assert any("CONFIRMED threat" in r for r in risk_res["reasons"])

    def test_cache_hit_does_not_fabricate_new_evidence(self):
        """
        Validates that retrieving an analysis from in-memory cache returns identical
        evidence structures and scores without multiplying signals.
        """
        detector = ThreatDetector()
        url = "https://cache-idempotent-test.example.com/login"

        # 1. First execution (cache miss)
        res1 = detector.analyze_url(url)
        assert res1["from_cache"] is False

        # 2. Second execution (cache hit)
        res2 = detector.analyze_url(url)
        assert res2["from_cache"] is True

        # Assert perfect equality of decision metrics
        assert res2["score"] == res1["score"]
        assert res2["risk_level"] == res1["risk_level"]
        assert res2["is_threat"] == res1["is_threat"]
        assert len(res2["reasons"]) == len(res1["reasons"])

    def test_repeated_identical_observations_do_not_duplicate_rule_signals(self):
        """
        Validates that evaluating the same URL multiple times does not append duplicate
        rule signal records to the detection reasons.
        """
        from detection_engine.rule_engine import RuleEngine
        url = "http://198.51.100.22:8080/login/update/account"

        res_a = RuleEngine.evaluate_url(url)
        res_b = RuleEngine.evaluate_url(url)

        assert res_a["heuristic_score"] == res_b["heuristic_score"]
        assert sorted(res_a["rules_triggered"]) == sorted(res_b["rules_triggered"])
        assert len(res_a["rules_triggered"]) == len(set(res_a["rules_triggered"]))

    def test_repeated_scan_score_stability_and_invariance(self, isolated_ti_db):
        """
        Validates that rescanning a target across isolated detector instances
        (where in-memory cache is empty but threat database holds the prior suspicious entry)
        preserves identical composite risk score and risk level without feedback-loop dilution.
        """
        url = "http://wellsfargo-security.biz/update"

        # Scan 1: Cold database and cache
        detector1 = ThreatDetector()
        res1 = detector1.analyze_url(url)
        assert res1["score"] == 68.0
        assert res1["risk_level"] == "HIGH"
        assert res1["is_threat"] is True

        # Verify indicator was recorded as SUSPICIOUS with source="actis_url_scanner"
        ind = tdb.lookup_indicator("url", url)
        assert ind["found"] is True
        assert ind["status"] == "SUSPICIOUS"
        assert ind["source"] == "actis_url_scanner"

        # Scan 2: Fresh instance (cache miss, DB hit)
        detector2 = ThreatDetector()
        assert detector2._url_cache.size == 0
        res2 = detector2.analyze_url(url)

        # Invariant: Score and risk level must remain strictly identical
        assert res2["score"] == res1["score"] == 68.0
        assert res2["risk_level"] == res1["risk_level"] == "HIGH"
        assert res2["is_threat"] == res1["is_threat"] is True

