# ACTIS Architecture v1

This document records the finalized Week 1 architecture for ACTIS — Automated Cyber Threat Intelligence System.

## Purpose

ACTIS is a Windows-oriented desktop cybersecurity platform for read-only analysis of URLs, messages and files, providing local and optional centralized threat intelligence sharing.

## High-level architecture

See approved architecture diagram (README). Key components:

- Scanners: `scanners/` — URL, text/message, file (PE/static), device, file-watcher, clipboard.
- Detection Engine: `detection_engine/` — core orchestration, `model_manager.py`, `risk_engine.py`, `rule_engine.py`, `threat_detector.py`.
- Threat Intelligence: `threat_intelligence/` — local SQLite DB, external API clients, sync manager.
- Models: `models/` — ML artifacts (phishing, future malware models) plus metadata.
- Backend: `backend/` — FastAPI service for central threat sharing (optional remote).
- Dashboard: `dashboard/` — Streamlit command center UI.
- Notifications: `notifications/` — user alerts and formatters.
- Config & Logging: `config/` — centralized configuration and logging setup.
- Reports & Database: `reports/` — schemas and report generation.

## Module responsibilities

- scanners/: feature extraction and safe read-only inspection.
- detection_engine/: fuse evidence from ML, heuristics, and TI to produce a risk score and explanation.
- threat_intelligence/: store and query indicators, enrich with external providers.
- backend/: provide optional central sharing API; clients use `sync_manager` to push/pull.

## Data flow

1. Scanners extract features and canonical indicators (hashes, normalized URLs).
2. Detection Engine requests ML inference via `model_manager` and heuristics from `rule_engine`.
3. Evidence is combined in `risk_engine` to compute a 0-100 risk score and explanation.
4. Detection records are persisted into the local threat DB (scans, detections, indicators).
5. Optional sync with central backend occurs via `threat_intelligence/sync_manager.py`.

## Security boundaries & principles

- Read-only analysis only: files are inspected, hashes computed, but not executed or modified.
- No secrets or personal file contents should be logged or uploaded.

## Currently implemented (Week 1 inspection)

- Basic scanners (URL, text analyzer) exist.
- `models/phishing_model.pkl` and metadata present.
- `config/config.py` with `get_logger()` exists and is used across modules.
- Local SQLite DB file present at `data/threat_intelligence.db` (schema documented in README).

## Planned/Future (not implemented in Week 1)

- Final Windows/PE malware model training and integration (Week 3+).
- Centralized deployment & hardened sync server.
- Richer dashboard and persistent storage backends.

---

Document authored for Week 1 validation.
