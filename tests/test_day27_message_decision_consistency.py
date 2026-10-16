"""
ACTIS Day 27 — Message Decision Engine & URL Signal Consistency Regression Test.
Verifies that:
1. Suspicious URLs (score >= 35.0) embedded in messages are properly propagated
   to DetectionDecisionEngine as structured EvidenceSignals.
2. Messages flagged as threats (is_threat=True) never produce contradictory
   telemetry (score=0.0 or risk_level=INFORMATIONAL).
3. The reasons audit trail explicitly explains the embedded URL anomaly.
4. Clean messages with benign attachments (BENIGN_FIN_001, BENIGN_FIN_002)
   remain True Negatives with score 0.0, risk_level=INFORMATIONAL, and is_threat=False.
"""

import pytest
from detection_engine.threat_detector import threat_detector
from benchmarks.message_analysis.dataset import load_benchmark_dataset
from benchmarks.message_analysis.runner import map_actis_verdict_to_prediction


def test_medium_risk_url_signal_propagated_to_decision_engine():
    """Validates that a URL with score between 35 and 59.9 produces consistent message telemetry."""
    # Synthetic message containing a suspicious link
    message = (
        "Subject: Routine Security Audit\n\n"
        "Please review your account settings at: https://accounts.example.com/security"
    )
    res = threat_detector.analyze_message(message, check_external=False)
    
    # Assert core invariants
    assert res["is_valid"] is True
    assert res["analysis_completeness"] == "COMPLETE"
    assert len(res["url_results"]) == 1
    
    url_score = res["url_results"][0]["score"]
    assert 35.0 <= url_score < 60.0, f"Expected medium-risk URL score, got {url_score}"
    
    # Critical Decision Consistency Invariant:
    # A threat must NEVER report score 0.0 or INFORMATIONAL severity.
    assert res["is_threat"] is True
    assert res["score"] >= 35.0, f"Expected message score >= 35.0, got {res['score']}"
    assert res["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL"), f"Expected non-informational risk level, got {res['risk_level']}"
    
    # Explainability Invariant:
    # Reasons audit trail must cite the URL anomaly
    reasons_str = " ".join(res.get("reasons", []))
    assert "URL in Message" in reasons_str or "accounts.example.com" in reasons_str, (
        f"Audit trail missing URL anomaly explanation: {res.get('reasons')}"
    )


@pytest.mark.parametrize("sample_id", [
    "BENIGN_SEC_002",
    "BENIGN_SEC_004",
    "BENIGN_SEC_007",
    "BENIGN_SEC_008",
    "BENIGN_FIN_006",
    "BENIGN_FIN_009",
    "BENIGN_AWR_006",
    "BENIGN_AWR_008",
    "PHISH_IMP_010",
    "PHISH_FIN_003"
])
def test_benchmark_threat_verdict_score_consistency(sample_id):
    """
    Verifies that all benchmark samples flagged as threats produce non-zero scores
    and matching non-informational risk levels across the entire pipeline.
    """
    dataset = load_benchmark_dataset()
    sample = dataset.get_sample(sample_id)
    assert sample is not None, f"Sample {sample_id} not found in manifest"
    
    res = threat_detector.analyze_message(sample.content, check_external=False)
    
    if res.get("is_threat"):
        assert res.get("score", 0.0) >= 35.0, (
            f"Sample {sample_id} is_threat=True but has inconsistent score {res.get('score')}"
        )
        assert res.get("risk_level") not in ("INFORMATIONAL", "LOW"), (
            f"Sample {sample_id} is_threat=True but has inconsistent risk_level {res.get('risk_level')}"
        )


def test_benign_financial_samples_remain_true_negatives():
    """Confirms BENIGN_FIN_001 and BENIGN_FIN_002 remain clean True Negatives."""
    dataset = load_benchmark_dataset()
    for sid in ["BENIGN_FIN_001", "BENIGN_FIN_002"]:
        sample = dataset.get_sample(sid)
        res = threat_detector.analyze_message(sample.content, check_external=False)
        pred = map_actis_verdict_to_prediction(res)
        
        assert pred == "BENIGN"
        assert res.get("score") == 0.0
        assert res.get("risk_level") == "INFORMATIONAL"
        assert res.get("is_threat") is False
        assert len(res.get("url_results", [])) == 0
