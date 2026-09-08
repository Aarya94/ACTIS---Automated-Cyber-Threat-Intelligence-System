# ACTIS Threat Intelligence Workflow & Verification Lifecycle

This document describes the threat intelligence ingestion, normalization, lifecycle state transitions, and client-server synchronization protocols utilized across ACTIS.

---

## The Threat Intelligence Lifecycle

```text
               +-------------------------------------------------+
               |       Local Threat Intelligence Database        |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |      External Threat Intelligence Sources       |
               |      (VirusTotal, URLhaus, AbuseIPDB)           |
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
               |          (Corroboration & Thresholds)           |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |       Risk Engine Multi-Criteria Scoring        |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |           Local Persistent Storage              |
               |        (SQLite: threats & indicators)           |
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

## Standardized Indicator Status State Machine

To prevent threat intelligence contamination, ACTIS models all threat indicators through an explicit verification state machine:

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

1. **`CANDIDATE`**: An indicator identified by internal heuristic rules or machine learning models during local scanning, awaiting external corroboration or user validation.
2. **`REPORTED`**: An indicator submitted to the local database or central backend by an endpoint, telemetry channel, or external feed.
3. **`SUSPICIOUS`**: An indicator exhibiting multiple corroborating warning signs (e.g., suspicious PE section entropy, high ML probability, social engineering language) but lacking definitive external consensus.
4. **`CONFIRMED`**: A thoroughly verified malicious indicator corroborated by multiple trusted intelligence sources (e.g. VirusTotal $\ge 5$ detections, confirmed URLhaus listing, verified signature). **Only `CONFIRMED` indicators trigger immediate automatic high-priority enterprise blocks.**
5. **`FALSE_POSITIVE`**: An indicator previously flagged as suspicious that has been investigated and certified benign (e.g. authorized enterprise binaries, legitimate software updates, common CDN infrastructure). Overrides heuristic and ML warnings.

---

## Central Synchronization & Anti-Poisoning Safeguards

1. **Unverified Predictions Are Never Auto-Promoted**: An ML prediction, no matter how confident (e.g., 99.8% probability), remains categorized as `CANDIDATE` or `SUSPICIOUS`. It **NEVER** transitions automatically to `CONFIRMED`.
2. **Sync Client Push Protocol**: Clients push only indicators that have met strict verification criteria. Unverified raw telemetry remains local to the client.
3. **Central Backend Verification Gate**: The central FastAPI service validates indicator syntax, checks against known white-lists, and requires verified status before including indicators in the shared distribution feed for other ACTIS clients.
4. **Offline Resilience**: If the central backend or external APIs are unreachable, ACTIS seamlessly falls back to the local SQLite database without operational degradation.
