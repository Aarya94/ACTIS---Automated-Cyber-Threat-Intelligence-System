# ACTIS Roadmap — Month 4: Productization & Release (Weeks 13 – 16)

**Milestone Version**: `v1.0.0 — ACTIS Production Release`

Month 4 delivers the user-facing command center (interactive Streamlit dashboard with Plotly telemetry), native desktop alert notifications, the offline-grounded natural language AI Security Assistant, rigorous end-to-end security hardening, comprehensive test coverage, and final deployment packaging.

---

## Week 13: Interactive Cybersecurity Command Dashboard

### Days 85–87: Streamlit Command Center & Telemetry Views
- **Goal**: Polish the central user interface (`dashboard/app.py`).
- **Tasks**: Real-time status cards (total files scanned, threats detected, average risk score), threat timeline charts, and severity breakdowns using Plotly.
- **Files/Components**: `dashboard/app.py`.
- **Validation**: Launch dashboard (`streamlit run dashboard/app.py`) and verify page rendering and component interactivity.
- **Dependencies**: `config`, `reports/scan_database.py`.
- **Not Included**: Arbitrary system administration commands.

### Days 88–90: Interactive Scanner & Threat Lookup Workflows
- **Goal**: Provide UI workflows for manual URL scanning, single-file inspection, directory scanning, and indicator database lookups.
- **Files/Components**: `dashboard/app.py`.

### Day 91: Week 13 Review & Performance Tuning
- **Goal**: Optimize Streamlit query caching and memory consumption during high-volume telemetry rendering.

---

## Week 14: Desktop Notifications & Grounded AI Security Assistant

### Days 92–94: Actionable Desktop Alert System
- **Goal**: Build non-intrusive Windows desktop toast alerts for high-risk and critical detections.
- **Tasks**: Dispatch desktop alerts upon `CRITICAL` risk scores (e.g. ransomware payload detected, phishing link copied).
- **Files/Components**: `notifications/notifier.py`.
- **Validation**: Trigger synthetic critical detection and verify notification display.
- **Dependencies**: `config`, `detection_engine/risk_engine.py`.
- **Not Included**: Intrusive full-screen locks.

### Days 95–97: Grounded AI Security Assistant
- **Goal**: Build an explainable, offline-grounded natural language security assistant (`assistant/security_assistant.py`).
- **Tasks**: Query local SQLite threat detection records; explain binary entropy, malicious API imports, and phishing characteristics in plain English; provide defensive guidance.
- **Files/Components**: `assistant/security_assistant.py`.
- **Validation**: Ask assistant questions about a detected threat and verify responses are grounded strictly in database facts.
- **Dependencies**: `reports/threat_database.py`.
- **Not Included**: Unrestricted command shell execution (`cmd.exe`, PowerShell).

### Day 98: Week 14 Integration Review
- **Goal**: Test concurrent execution of dashboard, notifications, and AI assistant.

---

## Week 15: Security Hardening & End-to-End Stress Testing

### Days 99–101: Security Audit & Boundary Verification
- **Goal**: Verify complete adherence to `docs/architecture/security-boundaries.md`.
- **Tasks**: Confirm zero execution hooks, verify read-only filesystem access, audit all network calls, ensure complete secret isolation.
- **Files/Components**: Full repository audit.
- **Validation**: Execute automated static security linters and permission checkers.

### Days 102–104: Stress Testing & Failure Resilience
- **Goal**: Test system behavior under stress (corrupted files, giant files > 500 MB, network drops, malformed URLs).
- **Files/Components**: `tests/`.
- **Validation**: Verify zero uncaught exceptions and graceful degradation across all modules.

### Day 105: Week 15 Verification
- **Goal**: Full test suite execution across all test modules with > 85% branch coverage.

---

## Week 16: Documentation, Demonstration & Final Release Preparation

### Days 106–108: User Manual, API Docs & Quickstart
- **Goal**: Complete all deployment and user documentation.
- **Tasks**: Finalize `README.md`, developer guides, configuration references, and slide deck assets.
- **Files/Components**: `docs/`, `README.md`.

### Days 109–111: Academic Demo Packaging & Presentation Scenarios
- **Goal**: Prepare realistic demonstration scenarios:
  1. Safe static detection of a packed PE binary.
  2. Real-time interception of a phishing link copied to the clipboard.
  3. Natural language query to the AI Security Assistant explaining why the binary is dangerous.
  4. Central threat intelligence sharing demonstration between two simulated client nodes.
- **Files/Components**: `main.py`, demo scripts.

### Day 112: Final Release Cut (`v1.0.0`)
- **Goal**: Complete final repository audit, update `docs/CHANGELOG.md`, and cut the official production release tag `v1.0.0`.
