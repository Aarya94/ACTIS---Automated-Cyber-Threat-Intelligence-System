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

## Central Threat Intelligence Service API Contracts (Day 13)

Implemented in `backend/api.py`, `backend/models.py`, and `backend/database.py`.
Status: **IMPLEMENTED AND VERIFIED** (Day 13)

### 1. Endpoint Contract Summary

| Endpoint | Method | Required Role | Request Body | Response Model | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/api/v1/health` | `GET` | *Public* | None | `HealthResponse` | Service and database liveness and indicator metrics |
| `/api/v1/client/info` | `GET` | Any Valid Key | None | `ClientInfoResponse` | Authenticated client identity, roles, and rate limit allocation |
| `/api/v1/indicators/{type}/{value}` | `GET` | `read` | None | `IndicatorLookupResponse` | Point lookup for specific indicator value and provenance |
| `/api/v1/indicators` | `GET` | `read` | Query params | `SyncPullResponse` | Bounded indicator listing with pagination and status filter |
| `/api/v1/sync/pull` | `POST` | `read` | `SyncPullRequest` | `SyncPullResponse` | Incremental client synchronization with timestamp watermark |
| `/api/v1/contributions` | `POST` | `contribute` | `ContributionRequest` | `ContributionResponse` | Candidate indicator submission (isolated as CANDIDATE/PENDING) |
| `/api/v1/admin/indicators/{id}/review` | `POST` | `admin` | `AdminReviewRequest` | `AdminReviewResponse` | Administrative triage (APPROVE, REJECT, MARK_FALSE_POSITIVE) |

### 2. Core Schemas (`backend/models.py`)

#### `IndicatorRecord`
Canonical schema for indicators served to downstream ACTIS agents:
- `id` (`int`): Primary key.
- `indicator_type` (`str`): One of `url`, `domain`, `sha256`, `md5`, `ip`.
- `indicator_value` (`str`): Normalized lowercase/stripped indicator value.
- `threat_type` (`str`): Threat classification (`Malware`, `Phishing`, `Ransomware`, `Trojan`, etc.).
- `threat_name` (`str`): Associated campaign, malware family, or threat designation.
- `confidence` (`float`, 0.0 - 1.0): Verified confidence score.
- `status` (`str`): Workflow status (`CONFIRMED`, `CANDIDATE`, `SUSPICIOUS`, `REPORTED`, `FALSE_POSITIVE`).
- `source_type` (`str`): Provenance source (`UPSTREAM_FEED`, `CLIENT_CONTRIBUTION`, `MANUAL`).
- `reporter_id` (`str`): Identifier of contributing node or source feed.
- `tags` (`List[str]`): Contextual categorization tags.
- `notes` (`Optional[str]`): Administrative or investigation notes.
- `review_status` (`str`): Administrative state (`APPROVED`, `PENDING`, `REJECTED`).
- `first_seen` / `last_seen` / `verified_at` (`str`): ISO 8601 UTC timestamps.

#### `SyncPullRequest` & `SyncPullResponse`
Bounded synchronization request parameters:
- `min_confidence` (`float`, 0.0 - 1.0, default 0.8): Confidence threshold.
- `status_filter` (`Optional[str]`, default `"CONFIRMED"`): Filter by lifecycle state.
- `indicator_types` (`Optional[List[str]]`): Subsets indicators by type (e.g., `["sha256", "url"]`).
- `since_timestamp` (`Optional[str]`): High-water mark timestamp for incremental pull.
- `limit` (`int`, 1 - 1000, default 500): Pagination page size.
- `offset` (`int`, >= 0, default 0): Pagination offset.

Response includes pagination metadata: `total`, `limit`, `offset`, `has_more`, and `indicators: List[IndicatorRecord]`.

#### `ContributionRequest`
Candidate indicator submission parameters:
- `indicator_type` (`str`): `url`, `domain`, `sha256`, `md5`, `ip`.
- `indicator_value` (`str`, 1 - 2048 chars): Normalized indicator.
- `threat_type` (`str`): Observed threat classification.
- `threat_name` (`str`): Threat name or local detection tag.
- `confidence` (`float`, 0.0 - 1.0, default 0.5): Submitting client's observation score.
- `tags` (`List[str]`): Contextual tags.
- `notes` (`Optional[str]`, max 1000 chars): Local triage context.

**Anti-Poisoning Enforcement:** Central service overrides client status; all accepted submissions are recorded with `status="CANDIDATE"` and `review_status="PENDING"`. Upstream global sync queries filter for `CONFIRMED` and `APPROVED`, ensuring candidate indicators cannot pollute downstream client endpoints before human admin review.

