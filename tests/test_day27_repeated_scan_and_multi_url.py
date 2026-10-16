"""
ACTIS Day 27 — Part 1: Repeated-Scan Feedback Loops, Multi-URL Deadlines & Benchmark False Negatives.
Reproduces and documents:
1. Repeated-scan feedback loop score dilution (Scan 1: 68.0 HIGH -> Scan 2: 59.6 MEDIUM).
2. Unbounded multi-URL execution and absence of deadline enforcement in TextAnalyzer.
3. Reproduction and root-cause verification of historical false negatives:
   - PHISH_URL_010 (percent-encoded @ delimiter under-scored).
   - PHISH_MIX_012 (.docm macro extension missing from DANGEROUS_ATTACHMENT_EXTENSIONS).
   - EDGE_ROB_009 (unclosed HTML anchor tag misses display-text mismatch).
"""

import json
import tempfile
import pathlib
import time
import pytest

import reports.threat_database as tdb
from detection_engine.threat_detector import ThreatDetector
from scanners.text_analyzer import TextAnalyzer
from scanners.mime_parser import DANGEROUS_ATTACHMENT_EXTENSIONS
from benchmarks.message_analysis.dataset import DEFAULT_MANIFEST_PATH


@pytest.fixture
def isolated_ti_db():
    """Provides an isolated, temporary SQLite database for threat intelligence."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = pathlib.Path(tmpdir) / "test_feedback_loop.db"
        orig_db = tdb.DATABASE_PATH
        tdb.DATABASE_PATH = test_db
        tdb.initialize_database()
        try:
            yield test_db
        finally:
            tdb.DATABASE_PATH = orig_db


class TestDay27RepeatedScansAndAnalysisDefects:
    """Deterministic regression tests capturing repeated-scan feedback and analysis boundary defects."""

    def test_repeated_scan_score_dilution_feedback_loop(self, isolated_ti_db):
        """
        Defect Reproduction:
        Demonstrates that analyzing a URL repeatedly without any new external intelligence
        causes score instability and downward risk-level dilution.
        
        Scan 1:
          - Target: 'http://wellsfargo-security.biz/update'
          - No prior TI exists in database. Active layers: ML (0.35) + Rules (0.25).
          - Score = 68.0, Risk Level = 'HIGH'.
          - ThreatDetector auto-registers indicator in SQLite with status='SUSPICIOUS', confidence=0.68.
          
        Scan 2:
          - Fresh ThreatDetector instance (or after cache expiry).
          - ThreatLookup queries SQLite and retrieves the self-persisted 'SUSPICIOUS' indicator.
          - RiskEngine Layer 1 activates with known_score = 47.6 (weight 0.40).
          - Composite normalized score drops from 68.0 to 59.6, downgrading risk from 'HIGH' to 'MEDIUM'.
        """
        test_url = "http://wellsfargo-security.biz/update"

        # 1. First Scan
        detector1 = ThreatDetector()
        res1 = detector1.analyze_url(test_url)
        assert res1["score"] == 68.0
        assert res1["risk_level"] == "HIGH"
        assert res1["is_threat"] is True

        # Verify indicator was auto-persisted as SUSPICIOUS
        ind = tdb.lookup_indicator("url", test_url)
        assert ind["found"] is True
        assert ind["status"] == "SUSPICIOUS"
        assert ind["confidence"] == 0.68

        # 2. Second Scan (isolated instance to bypass in-memory cache)
        detector2 = ThreatDetector()
        assert detector2._url_cache.size == 0

        res2 = detector2.analyze_url(test_url)

        # 3. VERIFY DEFECT RESOLUTION: Repeated scan maintains identical score and risk level (68.0 HIGH)
        assert res2["score"] == 68.0, f"Expected stable score 68.0, got {res2['score']}"
        assert res2["risk_level"] == "HIGH", f"Expected stable risk level 'HIGH', got {res2['risk_level']}"
        assert res2["score"] == res1["score"], "Repeated scan without new evidence must preserve score stability"

    def test_multi_url_analysis_unbounded_by_mime_deadline(self):
        """
        Architecture Audit & Defect Reproduction:
        In scanners/mime_parser.py, SafeMIMEParser enforces max_parse_duration = 5.0 seconds.
        However, that timeout is strictly confined to MIME header and body parsing.
        
        In scanners/text_analyzer.py, TextAnalyzer.analyze_message_structured() iterates sequentially
        through canonical_urls:
            for url in canonical_urls:
                res = scan_url_logic(url, ...)
                
        There is NO deadline check or timeout parameter in TextAnalyzer. If a message contains
        120 unique URLs (such as EDGE_ROB_003), execution continues across all 120 URLs,
        taking upwards of 26 seconds without cooperative cancellation or timeout enforcement.
        """
        # Generate message with 10 synthetic URLs
        urls = [f"http://perf-test-host-{i}.example.org/path/{i}" for i in range(10)]
        content = "Subject: Multi-URL Test\n\n" + "\n".join(urls)

        # Confirm TextAnalyzer does not accept deadline/timeout parameter
        import inspect
        sig = inspect.signature(TextAnalyzer.analyze_message_structured)
        param_names = list(sig.parameters.keys())
        
        assert "deadline" not in param_names
        assert "timeout" not in param_names
        assert "cancel_token" not in param_names

        # Execute scan and verify all 10 URLs were scanned sequentially
        res = TextAnalyzer.analyze_message_structured(content)
        assert res.unique_url_count == 10
        assert len(res.url_results) == 10
        # MIME parser limit was not reached because MIME parsing is fast; URL scanning has no limit
        assert res.analysis_completeness == "COMPLETE"

    def test_reproduce_benchmark_false_negative_edge_cases(self, isolated_ti_db):
        """
        Validates the resolution of the 3 historical false negatives from the Day 26 synthetic benchmark corpus:
        1. PHISH_URL_010: Percent-encoded @ userinfo (https://legit-service.example.org%40evil-host.example.com/login)
           is deobfuscated and triggers high-severity userinfo deception rules.
        2. PHISH_MIX_012: Invoice.docm macro-enabled attachment is flagged because .docm is
           included in DANGEROUS_ATTACHMENT_EXTENSIONS in scanners/mime_parser.py.
        3. EDGE_ROB_009: Malformed unclosed HTML anchor (<a href="https://attacker.example.com">...<p>)
           correctly flushes display text and triggers RULE_MSG_DISPLAY_TEXT_MISMATCH.
        """
        assert DEFAULT_MANIFEST_PATH.exists()
        with open(DEFAULT_MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        sample_map = {s["id"]: s for s in manifest["samples"]}
        detector = ThreatDetector()

        # 1. PHISH_URL_010: Percent-encoded @ delimiter
        s_url010 = sample_map["PHISH_URL_010"]
        assert s_url010["label"] == "PHISHING"
        r_url010 = detector.analyze_message(s_url010["content"])
        assert r_url010["is_threat"] is True
        assert r_url010["risk_level"] in ("HIGH", "CRITICAL")

        # 2. PHISH_MIX_012: Macro-enabled docm invoice
        s_mix012 = sample_map["PHISH_MIX_012"]
        assert s_mix012["label"] == "PHISHING"
        assert ".docm" in DANGEROUS_ATTACHMENT_EXTENSIONS
        r_mix012 = detector.analyze_message(s_mix012["content"])
        assert r_mix012["is_threat"] is True
        assert r_mix012["risk_level"] in ("HIGH", "CRITICAL")

        # 3. EDGE_ROB_009: Malformed unclosed HTML anchor
        s_rob009 = sample_map["EDGE_ROB_009"]
        assert s_rob009["label"] == "PHISHING"
        r_rob009 = detector.analyze_message(s_rob009["content"])
        assert r_rob009["is_threat"] is True
        assert r_rob009["risk_level"] in ("HIGH", "CRITICAL")
        assert any("Display-text mismatch" in r or "Link Display Text" in r for r in r_rob009["reasons"])
