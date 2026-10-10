# ACTIS Threat Intelligence Workflow & Verification Lifecycle

**Authoritative Architecture Document**  
**Milestone:** Post-Day-7 Architectural Evolution  
**Status:** Approved Target Architecture  

This document describes the threat intelligence ingestion, canonical normalization, lifecycle state transitions, and client-server synchronization protocols across ACTIS.

---

## 1. Threat Intelligence as Shared Infrastructure

In the post-Day-7 architecture, Threat Intelligence operates as **shared infrastructure** accessible by the Analysis Orchestrator and Detection Engine across all event pathways:

```text
               +-------------------------------------------------+
               |       Local Threat Intelligence Database        |
               |          (SQLite: threats & indicators)         |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |      External Threat Intelligence Sources       |
               |      (VirusTotal v3, URLhaus, AbuseIPDB)        |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |       Indicator Canonical Normalization         |
               |         (Hashes, FQDNs, URL Schemes)            |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |             Verification Evaluation             |
               |          (Corroboration & State Engine)         |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |            Analysis Orchestrator Handoff        |
               |           (Supplies ThreatIntelEvidence)        |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |       Central ACTIS Threat Intelligence API     |
               |                (Authenticated REST)             |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |        Shared Verified Threat Intelligence      |
               |          (Distributed to ACTIS Clients)         |
               +-------------------------------------------------+
```

---

## 2. Standardized Indicator Status State Machine

To prevent threat intelligence contamination and protect against poisoning, ACTIS models all threat indicators through an explicit verification state machine:

```text
       [Newly Observed / ML Signal] 
                     |
                     v
             +---------------+
             |   CANDIDATE   |  (Preliminary detection, uncorroborated)
             +-------+-------+
                     |
         +-----------+-----------+
         |                       | (Reported by client / external provider)
         v                       v
 +---------------+       +---------------+
 |  SUSPICIOUS   |       |   REPORTED    |
 +-------+-------+       +-------+-------+
         |                       |
         +-----------+-----------+
                     |
         +-----------+-----------+
         | (Multi-engine confirm)| (Debunked / Whitelisted)
         v                       v
 +---------------+       +------------------+
 |   CONFIRMED   |       |  FALSE_POSITIVE  |
 +---------------+       +------------------+
```

### State Definitions

1. **`CANDIDATE`:** An indicator identified by internal heuristic rules or machine learning models during local scanning, awaiting external corroboration or user validation.
2. **`REPORTED`:** An indicator submitted to the local database or central backend by an endpoint, telemetry channel, or external feed.
3. **`SUSPICIOUS`:** An indicator exhibiting multiple corroborating warning signs (e.g., suspicious PE section entropy, high ML probability, social engineering language) but lacking definitive external consensus.
4. **`CONFIRMED`:** A thoroughly verified malicious indicator corroborated by multiple trusted intelligence sources (e.g. VirusTotal $\ge 5$ detections, confirmed URLhaus listing, verified signature). **Only `CONFIRMED` indicators trigger immediate automatic high-priority enterprise blocks.**
5. **`FALSE_POSITIVE`:** An indicator previously flagged as suspicious that has been investigated and certified benign (e.g. authorized enterprise binaries, legitimate software updates, common CDN infrastructure). Overrides heuristic and ML warnings.

---

## 3. Central Synchronization & Anti-Poisoning Safeguards

1. **Unverified Predictions Are Never Auto-Promoted:** An ML prediction, no matter how confident (e.g., 99.8% probability), remains categorized as `CANDIDATE` or `SUSPICIOUS`. It **NEVER** transitions automatically to `CONFIRMED`.
2. **Candidate Anti-Poisoning Enforcement:** Client contributions via `/api/v1/contributions` are strictly tagged as `CANDIDATE` with `review_status="PENDING"`. Contributing clients cannot self-promote indicators to `CONFIRMED`.
3. **Administrative Verification Gate:** Only authenticated operators possessing the `admin` role may call `/api/v1/admin/indicators/{id}/review` to promote candidate records to `CONFIRMED` (`APPROVED`) or dismiss them as `FALSE_POSITIVE` (`REJECTED`).
4. **RFC 1918 Private IP Shielding:** All submission and query pathways enforce `is_safe_public_ip()` boundary validation, rejecting private, loopback, or reserved IP ranges with HTTP 422 to prevent internal enterprise network topology leakage.
5. **Zero Payload Transmission:** Threat intelligence synchronization operates exclusively over canonical indicators (SHA-256 hashes, domain names, normalized URLs, public IP addresses). Full file binaries, user documents, and private messages are strictly forbidden from transmission.

---

## 4. Central ACTIS Threat Intelligence Service & Client Synchronization

The Day 13 Central Threat Intelligence service (`backend/`) extends the platform with a hardened, versioned REST API enabling fleet synchronization:

```text
External Providers (URLhaus, AbuseIPDB)
                   │
                   ▼
       Central ACTIS Backend API (/api/v1)
        [FastAPI + HMAC Auth + SQLite Central DB]
                   │
         ┌─────────┴─────────┐
         ▼                   ▲
   POST /api/v1/sync/pull    │ POST /api/v1/contributions
   (Batch indicator pull)    │ (Candidate submission only)
         │                   │
         ▼                   │
    CentralACTISFeedAdapter  │
         │                   │
         ▼                   │
  Local Threat Database (SQLite) ── (Contribute verified local alerts)
         │
         ▼
  ThreatLookup / Detection Pipeline
```

### Versioned Endpoints (`/api/v1`)
- `GET /api/v1/health`: Public service telemetry, database status, verified indicator count, and uptime.
- `GET /api/v1/client/info`: Client identity inspection, assigned roles (`read`, `contribute`, `admin`), and rate limits.
- `GET /api/v1/indicators/{indicator_type}/{indicator_value}`: Point lookup returning indicator metadata, provenance, and review status.
- `GET /api/v1/indicators`: Bounded pagination query with filters (`status`, `threat_type`, `min_confidence`).
- `POST /api/v1/sync/pull`: Incremental bulk indicator pull for client fleet updates.
- `POST /api/v1/contributions`: Client candidate indicator submission (anti-poisoning enforced: queued as `CANDIDATE`).
- `POST /api/v1/admin/indicators/{id}/review`: Administrative review promoting/rejecting candidate records (`APPROVE`, `REJECT`).

### Client Adapter & Offline Resilience
The client-side `CentralACTISFeedAdapter` (implementing `BaseFeedAdapter`) fetches verified central intelligence and idempotently persists records into the local SQLite database via `upsert_feed_records`. Central service outages or network failures are completely isolated: local scanning, file monitoring, and risk scoring continue running 100% autonomously.
