# ACTIS Roadmap — Month 3: Real-Time & Threat Intelligence (Weeks 9 – 12)

**Milestone Version**: `v0.3.0 — Monitoring & Threat Intelligence`

Month 3 implements proactive real-time defensive monitoring on the Windows endpoint (event-driven directory watcher and clipboard scanner), integrates external threat intelligence providers with rate-limited caching, and establishes the central FastAPI intelligence sharing backend.

---

## Week 9: Background File Watcher

### Days 57–59: Windows Filesystem Event Hooking
- **Goal**: Hook into Windows directory modification events via `watchdog` (`ReadDirectoryChangesW`).
- **Tasks**: Listen for file creation, modification, and rename events in user-designated folders (e.g. `Downloads`, `Desktop`).
- **Files/Components**: `scanners/file_watcher.py`.
- **Validation**: Write dummy test files to a monitored scratch directory and verify event capture.
- **Dependencies**: `config`, `scanners/file_scanner.py`.
- **Not Included**: Kernel mini-filter drivers.

### Days 60–62: Write-Stability Debounce & Thread Safety
- **Goal**: Prevent race conditions when inspecting files currently being written by browsers or installers.
- **Tasks**: Implement a debounce delay (`WATCHDOG_DEBOUNCE_SECONDS = 2.0s`) checking file size stability before triggering scan.
- **Files/Components**: `scanners/file_watcher.py`.

### Day 63: Week 9 Integration Review
- **Goal**: Validate continuous background file watching without CPU spikes or memory leaks.

---

## Week 10: Clipboard URL Scanner

### Days 64–66: Clipboard Polling & Privacy Filter
- **Goal**: Monitor the Windows clipboard for copied URL strings in the background.
- **Tasks**: Extract text, apply strict URL regex filter (discarding passwords or personal notes), check against recent URL LRU cache.
- **Files/Components**: `scanners/clipboard_scanner.py`.
- **Validation**: Copy synthetic test URLs to clipboard and verify background detection triggers.
- **Dependencies**: `config`, `scanners/url_scanner.py`.
- **Not Included**: Keylogging or full clipboard history logging.

### Days 67–69: Notification Queue Integration
- **Goal**: Wire clipboard detection events directly to the notification alert queue.
- **Files/Components**: `scanners/clipboard_scanner.py`, `notifications/notifier.py`.

### Day 70: Week 10 Integration Review
- **Goal**: Test background clipboard monitoring alongside file watching.

---

## Week 11: Online Threat Intelligence APIs

### Days 71–73: VirusTotal v3 API Client
- **Goal**: Query VirusTotal v3 file hash and URL endpoints with strict rate limiting and error handling.
- **Tasks**: Implement exponential backoff, handle HTTP 429 (rate limit) and HTTP 404 (unknown hash), parse engine detection ratios.
- **Files/Components**: `threat_intelligence/api_clients.py`.
- **Validation**: Mock HTTP unit tests verifying response parsing.
- **Dependencies**: `config/settings.py` (API keys).
- **Not Included**: Full file binary uploads to VirusTotal.

### Days 74–76: AbuseIPDB & URLhaus Connectors
- **Goal**: Integrate secondary threat intelligence feeds for IP reputation and malware domain queries.
- **Files/Components**: `threat_intelligence/api_clients.py`.

### Day 77: Week 11 Integration Review
- **Goal**: Verify offline fallback behavior when external APIs are disconnected.

---

## Week 12: Central ACTIS Threat Intelligence API & Synchronization

### Days 78–80: Central FastAPI Backend Service
- **Goal**: Host the centralized threat intelligence sharing REST API (`backend/api.py`).
- **Tasks**: Implement JWT/token authentication (`ACTIS_CLIENT_API_KEY`), database schema for shared indicators, endpoints for push/pull.
- **Files/Components**: `backend/api.py`, `backend/database.py`, `backend/models.py`.
- **Validation**: `pytest tests/test_backend_api.py`.
- **Dependencies**: `config`, `fastapi`, `uvicorn`.

### Days 81–83: Client Sync Manager
- **Goal**: Implement client-side pull/push synchronization logic (`threat_intelligence/sync_manager.py`).
- **Tasks**: Pull verified indicators (`CONFIRMED`, `SUSPICIOUS`) from central backend into local SQLite DB; push high-confidence local discoveries.
- **Files/Components**: `threat_intelligence/sync_manager.py`.

### Day 84: Month 3 Milestone Audit (`v0.3.0`)
- **Goal**: Run complete test suite across real-time watchers, threat lookups, and backend sync. Tag version `v0.3.0`.
