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
2. **Sync Client Push Protocol:** Clients push only indicators that have met strict verification criteria. Unverified raw telemetry remains local to the client.
3. **Zero Payload Transmission:** Threat intelligence synchronization operates exclusively over canonical indicators (SHA-256 hashes, domain names, normalized URLs, IP addresses). Full file payloads are strictly forbidden from transmission.
