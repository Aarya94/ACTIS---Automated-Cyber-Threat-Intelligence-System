# ACTIS Official Four-Month Development Roadmap (16 Weeks)

This directory defines the authoritative, day-by-day technical execution plan for **ACTIS — Automated Cyber Threat Intelligence System**.

---

## Roadmap Structure & Milestones

The ACTIS development lifecycle spans 4 months (16 weeks), structured into four distinct milestone versions:

```text
+-------------------------------------------------------------------------+
| MONTH 1: FOUNDATION (Weeks 1 - 4) -> Version v0.1.0                     |
| Architecture, configuration, logging, database schemas, ML contracts,   |
| static PE feature extraction, heuristic rules, and initial pipelines.   |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| MONTH 2: SCANNERS & DETECTION (Weeks 5 - 8) -> Version v0.2.0           |
| Deep PE inspection, multi-engine detection integration, URL/message     |
| pipelines, and recursive device scanning with loop protection.          |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| MONTH 3: REAL-TIME & THREAT INTEL (Weeks 9 - 12) -> Version v0.3.0      |
| Background file watching (watchdog), clipboard URL monitor, external    |
| threat API connectors (VirusTotal), central FastAPI intelligence sync.  |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| MONTH 4: PRODUCTIZATION & RELEASE (Weeks 13 - 16) -> Version v1.0.0     |
| Streamlit command dashboard, Windows alert notifications, AI security   |
| assistant, enterprise security hardening, test coverage, and release.   |
+-------------------------------------------------------------------------+
```

---

## Authoritative Development Rules

1. **Strict Day-by-Day Sequencing**: Developers and AI coding agents must work strictly within the scope of the currently assigned development day.
2. **No Working Ahead**: Do not implement tasks assigned to future days or future weeks, even if doing so appears trivial.
3. **Check "Not Included" Sections**: Each daily specification explicitly enumerates what is **NOT** included to prevent scope creep.
4. **Milestone Version Tagging**: Git version tags (`v0.1.0`, `v0.2.0`, etc.) are cut strictly when the corresponding milestone has passed full automated test suites.

---

## Monthly Roadmap Documents

- [`month-1.md`](./month-1.md): Month 1 — Foundation (Weeks 1 – 4, Days 1 – 28)
- [`month-2.md`](./month-2.md): Month 2 — Scanners & Detection (Weeks 5 – 8, Days 29 – 56)
- [`month-3.md`](./month-3.md): Month 3 — Real-Time & Threat Intelligence (Weeks 9 – 12, Days 57 – 84)
- [`month-4.md`](./month-4.md): Month 4 — Productization & Release (Weeks 13 – 16, Days 85 – 112)
