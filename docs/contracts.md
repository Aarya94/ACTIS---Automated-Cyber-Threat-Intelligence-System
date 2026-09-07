# Database & ML Contracts (Week 1)

## Local Threat Intelligence Database (SQLite)

Top-level conceptual tables (implementation in `reports/threat_database.py`):

- `threats` — id, threat_type, name, risk_level, status, description, first_seen, last_seen, verified_by
- `indicators` — id, threat_id (FK), indicator_type (url, domain, sha256, md5, ip), indicator_value, source, confidence (0.0-1.0), status, first_seen, last_seen
- `scans` — id, scan_type, target, started_at, completed_at, status, files_scanned, threats_found, error_count
- `detections` — id, scan_id (FK), indicator_id (FK), target, target_type, model_name, model_score, rule_score, intel_score, final_score, risk_level, explanation_json, detected_at
- `scan_items` — id, scan_id (FK), path_or_target, sha256, status, risk_score, scanned_at

Status enum for indicators and detections:

- `CONFIRMED`
- `SUSPICIOUS`
- `CANDIDATE`
- `REPORTED`
- `FALSE_POSITIVE`

Notes:
- ML predictions are never automatically marked `CONFIRMED` without manual or high-confidence verification.

## Phishing Model Contract (Existing)

Current phishing model contract (as of Week 1):

INPUT:

- A fixed ordered vector of 19 URL features in this exact order:

  1. url_length
  2. n_dots
  3. n_hypens
  4. n_underline
  5. n_slash
  6. n_questionmark
  7. n_equal
  8. n_at
  9. n_and
  10. n_exclamation
  11. n_space
  12. n_tilde
  13. n_comma
  14. n_plus
  15. n_asterisk
  16. n_hastag
  17. n_dollar
  18. n_percent
  19. n_redirection

OUTPUT:

- `prediction` — label (e.g., `phishing` / `legitimate` or 1/0)
- `probability` — confidence/probability for the predicted class when available
- `model_version` — semantic version string

Implementation notes:

- The feature order is authoritative. Do not change feature order without a coordinated model contract update and metadata bump.
- Metadata for the current phishing model is stored in `models/phishing_model_metadata.json`.

## Malware Model Contract (Planned)

This contract defines the expected interface for a future Windows/PE malware classifier (do not train during Week 1):

INPUT:

- A fixed feature vector derived from Windows/PE static analysis. The exact feature names and order will be defined after dataset selection (Week 3). Hashes (SHA-256) are NOT ML numeric features but are canonical indicators stored separately in the DB.

OUTPUT:

- `prediction` — label (benign / malicious)
- `probability` — confidence for predicted class
- `model_version` — semantic version
- `feature_schema_version` — identifier documenting feature names and order

Security and safety notes:

- No model should ever be allowed to modify files or execute binaries as part of inference.
- Model files should be tracked carefully; large binaries may be stored in release artifacts rather than Git.
