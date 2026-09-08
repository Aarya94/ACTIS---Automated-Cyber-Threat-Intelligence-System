# ACTIS Local Threat Database Reference (SQLite Schema)

This document describes the active SQLite schema implemented in `reports/threat_database.py`.

---

## Active Schema Tables

### 1. `threats`
Represents high-level classified threat entities.

```sql
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type TEXT NOT NULL,      -- 'malware', 'phishing', 'ransomware', 'suspicious_link'
    name TEXT NOT NULL,             -- Human-readable identifier or campaign name
    risk_level TEXT NOT NULL,       -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    status TEXT NOT NULL,           -- 'CONFIRMED', 'SUSPICIOUS', 'CANDIDATE', 'REPORTED', 'FALSE_POSITIVE'
    description TEXT,               -- Contextual threat summary
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_by TEXT DEFAULT 'system'
);
```

### 2. `indicators`
Canonical atomic indicators of compromise (IoCs) tied to threat entities.

```sql
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER,
    indicator_type TEXT NOT NULL,   -- 'sha256', 'md5', 'url', 'domain', 'ip'
    indicator_value TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,           -- 'local_scan', 'virustotal', 'urlhaus', 'abuseipdb'
    confidence REAL DEFAULT 0.5,    -- 0.0 to 1.0 confidence score
    status TEXT NOT NULL,           -- 'CONFIRMED', 'SUSPICIOUS', 'CANDIDATE', 'REPORTED', 'FALSE_POSITIVE'
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(threat_id) REFERENCES threats(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(indicator_value);
```

### 3. `scans`
Scan session metadata recording targets, runtimes, and telemetry.

```sql
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,        -- 'file', 'url', 'text', 'device_quick', 'device_full'
    target TEXT NOT NULL,           -- Filepath, URL string, or directory root
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT DEFAULT 'running',  -- 'running', 'completed', 'failed', 'cancelled'
    files_scanned INTEGER DEFAULT 0,
    threats_found INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0
);
```

### 4. `detections`
Specific detection events associating a scan session with an indicator or target.

```sql
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    indicator_id INTEGER,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,      -- 'file', 'url', 'message'
    model_name TEXT,
    model_score REAL,
    rule_score REAL,
    intel_score REAL,
    final_score REAL,               -- Composite 0 - 100 risk score
    risk_level TEXT,                -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    explanation_json TEXT,          -- JSON-serialized evidence breakdown
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY(indicator_id) REFERENCES indicators(id) ON DELETE SET NULL
);
```

### 5. `scan_items`
Individual items processed during multi-file or directory scan sessions.

```sql
CREATE TABLE IF NOT EXISTS scan_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    path_or_target TEXT NOT NULL,
    sha256 TEXT,
    status TEXT NOT NULL,           -- 'clean', 'suspicious', 'malicious', 'error'
    risk_score REAL DEFAULT 0.0,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
```
