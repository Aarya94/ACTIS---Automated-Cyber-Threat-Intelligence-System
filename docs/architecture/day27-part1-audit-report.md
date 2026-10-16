# ACTIS Day 27 — Part 1: Comprehensive Audit & Implementation Handoff Report

**Date:** October 16, 2026  
**Project:** ACTIS (Automated Cyber Threat Intelligence System)  
**Phase:** Part 1 of 3 (Audit, Baseline Verification & Defect Reproduction)  
**Author / Auditor:** Aaryan Suman <aaryansuman17@gmail.com>  
**Status:** Audit Completed & Defect Invariants Verified  

---

## 1. Executive Summary

This audit establishes an evidence-backed analysis of the ACTIS threat detection lifecycle, indicator trust escalation, SQLite persistence, cache consistency, and multi-URL analysis performance.

During Part 1, no architectural modifications or weight calibrations were implemented. Instead, the focus was strictly on verifying current repository behavior, preserving historical benchmark baselines, deterministically reproducing confirmed defects, and profiling execution latency.

### Core Discoveries:
1. **Cache Invalidation Defect:** `ThreatDetector.invalidate_url()` queries `canonical_url` directly while the scan cache keys entries with `f"{canonical_url}__redir_{follow_redirects}"`. This key mismatch guarantees that cache invalidation always fails silently, leaving stale reputation verdicts cached in memory.
2. **Unverified ML-to-TI Escalation:** High-risk heuristic/ML URL scores trigger automatic registration into SQLite as `status="CONFIRMED"` (if risk is `CRITICAL`) or `status="SUSPICIOUS"` (if risk is `HIGH`). On any subsequent scan, `ThreatLookup` queries the local database and treats the self-persisted indicator as authoritative local threat intelligence, triggering the fast-track 100.0 CRITICAL override and permanently bypassing multi-attribute risk calculation.
3. **Repeated-Scan Feedback Dilution:** Scanning a URL twice causes downward score fluctuation (e.g. from 68.0 HIGH to 59.6 MEDIUM) purely because the self-generated `SUSPICIOUS` indicator activates Layer 1 (TI) on the second scan, diluting the active normalized weights.
4. **Status Rigidity & Provenance Erasure in Database:** In `reports.threat_database.register_indicator()`, the `UPDATE` statement omits the `status` column, preventing legitimate indicator promotions or resolutions. Furthermore, `source` is unconditionally overwritten by local scanners, destroying authoritative external provider provenance.
5. **Unbounded Multi-URL Scanning:** The 5.0-second timeout in `SafeMIMEParser` applies exclusively to MIME unpacking. URL scanning in `TextAnalyzer.analyze_message_structured()` is completely unbounded by any deadline, sequentially evaluating each URL against SQLite and ML models, resulting in ~26.4 seconds of latency for messages containing 120 URLs (`EDGE_ROB_003`).
6. **False-Negative Root Causes Verified:**
   - `PHISH_URL_010`: Delimiter obfuscation (`%40`) lacked urgency language, keeping the score below detection threshold.
   - `PHISH_MIX_012`: `.docm` macro-enabled attachment extension is omitted from `DANGEROUS_ATTACHMENT_EXTENSIONS` in `scanners/mime_parser.py`.
   - `EDGE_ROB_009`: Malformed unclosed HTML anchor tag (`<p><a href="...">...<p>`) terminates display-text accumulation, preventing display mismatch detection.

---

## 2. Repository State

| Property | Value |
| :--- | :--- |
| **Starting Commit** | `67b4f8e0bbaf888b4b418bb0290c2e97ac6d3d95` |
| **Branch** | `main` |
| **Upstream Remote** | `origin/main` (`https://github.com/Aarya94/ACTIS---Automated-Cyber-Threat-Intelligence-System.git`) |
| **Starting Working Tree** | Clean (0 modified, 0 untracked files) |
| **Committer & Author** | `Aaryan Suman <aaryansuman17@gmail.com>` |
| **Ending Working Tree** | Clean |

---

## 3. Baseline Verification

### Test Suite Baseline:
- **Command:** `pytest tests/ -q`
- **Starting Count:** 715 passed, 4 warnings in 57.63s
- **Ending Count:** 726 passed (+11 new deterministic tests across 3 modules), 4 warnings in 58.44s
- **Warnings:** 4 benign deprecation warnings originating from third-party libraries (e.g. `datetime.utcnow()` in dependencies).

### Phishing Benchmark Baseline:
- **Manifest:** `tests/fixtures/phishing_benchmark/manifest.json`
- **Manifest Hash (SHA-256):** `baa051b9daf69dd49e5a715bf07879d440d97244e7d10723993382f65b1eea85`
- **Samples:** 140 total (138 evaluated, 2 boundary abstentions)
- **Confusion Matrix:** TP=84, TN=32, FP=19, FN=3
- **Precision:** 81.55%
- **Recall (Sensitivity):** 96.55%
- **F1 Score:** 88.42%
- **False Positive Rate:** 37.25%
- **Accuracy:** 84.06%
- **Balanced Accuracy:** 79.65%
- **Coverage:** 98.57%
- **Preserved Baseline Files:**
  - Historical Day 26: `reports/benchmarks/message_analysis/baseline.json` & `.md` (preserved untouched)
  - Day 27 Pre-Change: `reports/benchmarks/message_analysis/day27_prechange_baseline.json` & `.md`

---

## 4. Detection Lifecycle

```
[Target URL / Message Content]
          │
          ▼
1. Canonicalization: `normalize_url()` / `SafeMIMEParser.parse()`
          │
          ▼
2. Memory Cache: `ThreatDetector._url_cache.get(f"{canonical_url}__redir_{follow}")`
   ├─ Hit ──► Return Cached Result
   └─ Miss ─┐
            ▼
3. Local TI Lookup: `ThreatLookup.lookup_url()` -> `reports.threat_database.lookup_indicator()`
          │
          ▼
4. Feature Extraction: `URLScanner.extract_features()` (12 morphological features)
          │
          ▼
5. ML Inference: `URLScanner.predict_url()` (RandomForest classifier)
          │
          ▼
6. Heuristics: `RuleEngine.evaluate_url()` / `evaluate_social_engineering()`
          │
          ▼
7. Fusion & Risk Scoring: `RiskEngine.calculate_risk()`
   ├─ If known_intel['is_known_malicious'] ──► Fast-track CRITICAL 100.0
   └─ Normal ──► Weighted sum of active layers (TI 0.40, ML 0.35, Rules 0.25)
          │
          ▼
8. Explainability: `ExplanationGenerator.generate_url_explanation()`
          │
          ▼
9. Auto-Registration: `ThreatDetector.analyze_url()` (lines 517–530)
   └─ Writes indicator to SQLite: status='CONFIRMED' if CRITICAL else 'SUSPICIOUS'
          │
          ▼
10. Cache Update: `ThreatDetector._url_cache.set(f"{canonical_url}__redir_{follow}", result)`
```

---

## 5. Indicator Trust Findings

### Escalation Mechanism:
- In `ThreatDetector.analyze_url()` (lines 517–530), any URL flagged as `is_threat` that is not already known malicious triggers:
  ```python
  register_indicator(
      indicator_type="url",
      indicator_value=canonical_url,
      source="actis_url_scanner",
      confidence=round(risk_res["score"] / 100.0, 2),
      status="SUSPICIOUS" if risk_res["risk_level"] != "CRITICAL" else "CONFIRMED",
      threat_type="Phishing",
      threat_name=domain
  )
  ```
- **Trust Inversion:** An uncorroborated heuristic rule firing (or high ML probability) that yields score $\ge 80$ is written to SQLite as `status="CONFIRMED"`.
- When subsequently retrieved by `ThreatLookup`, `status="CONFIRMED"` sets `is_known_malicious=True` and `primary_evidence.is_confirmed_threat=True`.
- In `RiskEngine`, `is_known_malicious=True` immediately forces `risk_score=100.0` and `risk_level="CRITICAL"`, bypassing all feature weights and rule evaluation.

---

## 6. Repeated-Scan Findings

### Mathematical Dilution Feedback:
- When a URL scoring in the `HIGH` band (e.g. 68.0 on Scan 1) is scanned, it is registered as `status="SUSPICIOUS"` with confidence 0.68.
- On Scan 2:
  - Without TI: Active weights are ML (0.35) and Rules (0.25), normalized to $\frac{0.35}{0.60}$ and $\frac{0.25}{0.60}$.
  - With newly saved TI: Layer 1 activates with weight 0.40 and score $70.0 \times 0.68 = 47.6$.
  - The new normalized score drops:
    $$\text{Score} = (0.40 \times 47.6) + (0.35 \times \text{ML}) + (0.25 \times \text{Rule}) = 59.6$$
  - Result: Risk level downgrades from `HIGH` to `MEDIUM` on the second scan of identical input with zero new external data.

---

## 7. Cache and Database Consistency Findings

### 1. Cache Invalidation Key Mismatch:
- In `ThreatDetector.analyze_url()` line 463:
  `cache_key = f"{canonical_url}__redir_{follow_redirects}"`
- In `ThreatDetector.invalidate_url()` line 64:
  `norm = normalize_url(url)`
  `return self._url_cache.invalidate(norm)`
- The cache key lookup in `invalidate_url()` searches for `norm`, while the cache holds `norm__redir_False`. The lookup always misses, returning `False`.
- Consequently, cache entries are never evicted when `register_indicator()` triggers cache invalidation.

### 2. Status Rigidity in SQLite Updates:
- In `reports.threat_database.register_indicator()` line 318:
  ```sql
  UPDATE indicators
  SET last_seen = ?, confidence = ?, source = ?
  WHERE id = ?
  ```
- The `status` column is omitted. A record registered as `SUSPICIOUS` cannot be promoted to `CONFIRMED` or demoted to `FALSE_POSITIVE` via `register_indicator()`.

### 3. Provider Provenance Loss:
- In the same `UPDATE` query, `source = ?` unconditionally overwrites existing provenance. If an indicator was ingested from `VirusTotal`, subsequent local analysis overwrites `source` with `"actis_url_scanner"`.

---

## 8. False-Positive and False-Negative Findings

### False Positives (19 in benchmark):
- Driven primarily by legitimate corporate and authentication domains such as `https://accounts.example.com/security` and `https://login.example.com/confirm`.
- The Random Forest model (`url_phishing_rf.joblib`) calculates high anomaly scores on token combinations containing `accounts`, `security`, and `login` when no domain whitelist grounding is present.

### False Negatives (3 in benchmark):
1. **`PHISH_URL_010` (Score: 30.0 / LOW):**
   - URL: `https://legit-service.example.org%40evil-host.example.com/login`
   - Ground Truth: `PHISHING`
   - Cause: Percent-encoded delimiter (`%40`) userinfo parsing was not sufficiently penalized, and message body lacked overt urgency cues.
2. **`PHISH_MIX_012` (Score: 20.0 / LOW):**
   - Attachment: `Invoice.docm`
   - Ground Truth: `PHISHING`
   - Cause: `.docm` is omitted from `DANGEROUS_ATTACHMENT_EXTENSIONS` in `scanners/mime_parser.py`, allowing the macro attachment to pass without `RULE_MSG_SUSPICIOUS_ATTACHMENT`.
3. **`EDGE_ROB_009` (Score: 0.0 / INFORMATIONAL):**
   - HTML: `<a href="https://attacker.example.com">https://secure.example.com <p>`
   - Ground Truth: `PHISHING`
   - Cause: Streaming HTML parser terminates display-text extraction on unclosed `<p>` tag, preventing `RULE_MSG_DISPLAY_TEXT_MISMATCH` from firing.

---

## 9. Performance Findings

### Multi-URL Latency Bottleneck:
- Test fixture `EDGE_ROB_003` contains 120 URLs and runs in ~26.4 seconds.
- Profiling reveals:
  1. `TextAnalyzer.analyze_message_structured()` iterates sequentially through canonical URLs without threading or asynchronous scheduling.
  2. For every URL, `ThreatDetector.analyze_url()` opens a SQLite connection, performs indicator queries, executes ML feature extraction, and writes detection/indicator rows.
  3. SafeMIMEParser's 5.0-second timeout strictly bounds MIME structure parsing; it is never passed to or evaluated by `TextAnalyzer`, leaving message URL scanning unbounded.

---

## 10. Tests Added

Three dedicated test modules (+11 tests) were created and validated:

1. **`tests/test_day27_indicator_trust_and_provenance.py` (4 tests):**
   - `test_cache_invalidation_key_mismatch_reproduction`
   - `test_unverified_heuristic_ml_escalates_to_confirmed_ti`
   - `test_escalated_indicator_bypasses_multi_attribute_scoring_on_rescan`
   - `test_ti_provenance_collapse_in_sqlite_persistence`
2. **`tests/test_day27_benchmark_baseline.py` (3 tests):**
   - `test_manifest_sha256_hash_integrity`
   - `test_historical_day26_baseline_preserved`
   - `test_day27_prechange_baseline_matches_historical`
3. **`tests/test_day27_ti_status_transitions.py` (4 tests):**
   - `test_status_rigidly_retained_on_existing_indicator_update`
   - `test_authoritative_provenance_overwritten_by_subsequent_scans`
   - `test_register_indicator_idempotency_and_uniqueness`
   - `test_persistence_triggered_invalidation_fails_due_to_cache_key_defect`
4. **`tests/test_day27_repeated_scan_and_multi_url.py` (3 tests):**
   - `test_repeated_scan_score_dilution_feedback_loop`
   - `test_multi_url_analysis_unbounded_by_mime_deadline`
   - `test_reproduce_benchmark_false_negative_edge_cases`

---

## 11. Commits

All commits adhere to the Conventional Commits specification and were verified before and after each commit:

| Hash | Subject | Author / Committer |
| :--- | :--- | :--- |
| `6f009cb` | `docs(day27): document repository baseline and detection lifecycle audit` | Aaryan Suman <aaryansuman17@gmail.com> |
| `862c9d9` | `test(day27): capture baseline indicator trust and cache invalidation defects` | Aaryan Suman <aaryansuman17@gmail.com> |
| `cbd6cdd` | `test(benchmarks): preserve day27 pre-change benchmark baseline` | Aaryan Suman <aaryansuman17@gmail.com> |
| `23836d8` | `test(ti): reproduce untrusted indicator promotion and status transitions` | Aaryan Suman <aaryansuman17@gmail.com> |
| `8199ec1` | `test(detection): cover repeated-scan evidence behavior and multi-URL latency` | Aaryan Suman <aaryansuman17@gmail.com> |

---

## 12. Confirmed Defects

1. **Defect 1:** Cache invalidation key mismatch in `ThreatDetector.invalidate_url()` (`norm` vs `norm__redir_{follow}`).
2. **Defect 2:** Unverified ML/heuristic score escalation to `CONFIRMED` in `ThreatDetector.analyze_url()`.
3. **Defect 3:** Repeated-scan score dilution due to feedback loop between SQLite and `RiskEngine` Layer 1.
4. **Defect 4:** Indicator status rigidity in `reports.threat_database.register_indicator()` (omitted `status` from `UPDATE`).
5. **Defect 5:** Overwrite of authoritative threat intelligence provenance in `reports.threat_database.register_indicator()`.
6. **Defect 6:** Unbounded URL scanning in `TextAnalyzer` lacking deadline/cancellation token enforcement.
7. **Defect 7:** Missing `.docm` (and related Office macro formats) in `DANGEROUS_ATTACHMENT_EXTENSIONS`.
8. **Defect 8:** Broken display-text extraction on unclosed HTML anchor tags.

---

## 13. Unresolved Questions

1. **Local Domain Whitelist Integration:** Whether `ThreatLookup` should maintain a curated local whitelist of trusted corporate/auth domains to suppress false positives on subdomains like `accounts.example.com`. (Deferred to Part 2 design discussion).
2. **Remote Redirect Inspection Security Boundary:** Whether DNS-rebinding protection can be safely implemented for local redirect resolution without outbound network hazards. (Remote redirects remain disabled by default).

---

## 14. Part 2 Recommendations (Behavioral & Trust Fixes)

1. **Fix Cache Invalidation Key:** Update `ThreatDetector.invalidate_url()` to evict `f"{norm}__redir_False"` and `f"{norm}__redir_True"`.
2. **Prevent ML-to-TI Escalation:** 
   - Never auto-register internal engine detections as `status="CONFIRMED"`. Use `status="OBSERVED"` or `status="CANDIDATE"`.
   - Update `ThreatLookup.lookup_url()` so that self-generated detections (`source="actis_url_scanner"`) do not trigger `is_known_malicious=True` or the 100.0 fast-track override.
3. **Fix Status Transitions & Provenance:**
   - Update `reports.threat_database.register_indicator()` to include `status` in the `UPDATE` query when an authoritative or higher-precedence status is supplied.
   - Preserve existing authoritative provenance (e.g. do not overwrite `source="VirusTotal"` with `"actis_url_scanner"`).
4. **Add Macro Extensions:** Add `.docm`, `.xlsm`, `.pptm`, `.dotm`, `.xltm` to `DANGEROUS_ATTACHMENT_EXTENSIONS`.
5. **Fix Unclosed HTML Anchors:** Update HTML parser to capture display text up to block delimiters even when unclosed.

---

## 15. Part 3 Recommendations (Performance & Optimization)

1. **Global Message-Analysis Deadline:**
   - Pass an explicit deadline or timeout into `TextAnalyzer.analyze_message_structured()`.
   - Abort remaining URL scans if deadline expires, setting `analysis_completeness="PARTIAL"` and `limit_reached="TIMEOUT"`.
2. **Batch SQLite Reads & Writes:**
   - Query all URLs in a message via a single SQL `SELECT ... WHERE indicator_value IN (...)`.
   - Batch detection event writes into a single SQLite transaction.
3. **URL Evaluation Deduplication:**
   - Fully deduplicate normalized canonical URLs before model inference.

---

## 16. Final Verification

- **Full Test Suite:** 726 passed, 4 warnings in 58.44s (`pytest tests/ -q`)
- **Benchmark Manifest:** Verified SHA-256 `baa051b9daf69dd49e5a715bf07879d440d97244e7d10723993382f65b1eea85`
- **Git Status:** Clean
- **Execution Safety:** 100% offline, zero live network requests, zero Defender modifications, read-only defensive analysis.
