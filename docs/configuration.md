# ACTIS Configuration Guide (Week 1 — Day 2)

## Overview

ACTIS (Automated Cyber Threat Intelligence System) employs a centralized, type-annotated, and secure configuration architecture designed to decouple operational settings, project paths, and threat intelligence credentials from core cybersecurity detection logic.

---

## Architecture & Modules

The configuration subsystem is organized under `config/`:

| Module | Responsibility |
|---|---|
| `config/settings.py` | Structured dataclasses defining configuration domains (`DatabaseConfig`, `ModelConfig`, `ExternalApiConfig`, `RiskEngineConfig`, `ScannerConfig`, `ServerConfig`, `AppConfig`) with `to_dict(mask_secrets=True)` safe serialization. |
| `config/paths.py` | Filesystem paths resolved dynamically relative to `ACTIS_ROOT` with isolated test database paths (`TEST_DATABASE_PATH`, `TEST_CENTRAL_BACKEND_DB`). |
| `config/defaults.py` | Baseline operational defaults and environment profiles (`development`, `testing`, `staging`, `production`). |
| `config/env_loader.py` | Safe typed parsing of environment variables (`get_str`, `get_int`, `get_float`, `get_bool`, `get_list`, `get_int_bounded`, `get_float_bounded`, `get_path`) and `.env` loader. |
| `config/validator.py` | Constraint validation checking weights, severity threshold monotonicity, scanner operational limits, server ports, log levels, environment profiles, database timeouts, and API request timeouts. |
| `config/config.py` | Central import hub providing singleton access via `get_config(reload=False)`, `load_app_config()`, and backward-compatible global constants. |

---

## Environment Profiles

ACTIS supports 4 standard deployment environments:

1. **`development`** (Default):
   - Database: `data/threat_intelligence.db`
   - Log Level: `DEBUG`
   - WAL Mode: Enabled
2. **`testing`**:
   - Database: `data/test_threat_intelligence.db` (strictly isolated from operational data)
   - Backend DB: `backend/test_central_threat_intel.db`
   - Log Level: `WARNING`
3. **`production`**:
   - Database: `data/threat_intelligence.db`
   - Log Level: `INFO`
   - WAL Mode: Enabled
4. **`staging`**:
   - Mirrors production configuration with `INFO` logging.

---

## Environment Variables Reference

| Variable | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `ACTIS_ENVIRONMENT` | `str` | `development` | `development`, `testing`, `staging`, `production` | Operational mode controlling paths and logging. |
| `ACTIS_LOG_LEVEL` | `str` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` | Standard logging verbosity level. |
| `ACTIS_BACKEND_URL` | `str` | `http://127.0.0.1:8000` | Valid HTTP/HTTPS URL | URL for central threat intelligence sharing backend. |
| `ACTIS_CLIENT_API_KEY` | `str` | `actis-client-default-secret-token` | Non-empty | Client authentication token for sync backend. |
| `ACTIS_SERVER_HOST` | `str` | `127.0.0.1` | Valid host / IP | Bind address for local ACTIS backend server. |
| `ACTIS_SERVER_PORT` | `int` | `8000` | `1` - `65535` | Port for local ACTIS backend server. |
| `ACTIS_DB_TIMEOUT` | `float` | `30.0` | `> 0` | SQLite connection timeout in seconds. |
| `ACTIS_DB_WAL` | `bool` | `true` | Boolean string | Enable SQLite Write-Ahead Logging mode. |
| `VIRUSTOTAL_API_KEY` | `str` | `""` | Optional | VirusTotal v3 API key for threat enrichment. |
| `ABUSEIPDB_API_KEY` | `str` | `""` | Optional | AbuseIPDB API key for IP reputation lookups. |
| `URLHAUS_API_KEY` | `str` | `""` | Optional | Abuse.ch URLhaus API key for malware URL checks. |
| `OPENPHISH_API_KEY` | `str` | `""` | Optional | OpenPhish API key for phishing feed integration. |
| `PHISHTANK_API_KEY` | `str` | `""` | Optional | PhishTank developer key for URL verification. |
| `ACTIS_REQUEST_TIMEOUT` | `float` | `10.0` | `0 < t <= 120` | HTTP request timeout in seconds for threat intel lookups. |
| `ACTIS_MAX_FILE_SIZE_MB` | `int` | `100` | `> 0` | Maximum file size in MB for deep static PE inspection. |
| `ACTIS_WATCHDOG_DEBOUNCE_SECONDS` | `float` | `2.0` | `>= 0` | Settle time in seconds before scanning newly modified files. |

---

## Security Guidelines

1. **Never Commit Secrets**: Real credentials, API keys, private certificates, and `.env` files must NEVER be staged or committed to Git.
2. **Use `.env.example`**: `.env.example` contains only non-sensitive placeholder values. Copy it locally:
   ```bash
   copy .env.example .env
   ```
3. **Automatic Secret Redaction**: Dataclasses redacting sensitive credentials in `__repr__` (e.g. `vt****89`) and `to_dict(mask_secrets=True)` prevent accidental leakage in diagnostic dumps or log files.
4. **Git Protection**: `.gitignore` explicitly blocks `.env`, `.env.*`, `*.pem`, `*.key`, `credentials.json`, and `secrets/`.

---

## Validation Rules

The configuration validator (`config/validator.py`) enforces strict operational constraints:

- **Environment Name**: Must match one of `{"development", "testing", "staging", "production"}`.
- **Application Name**: Must be a non-empty string.
- **Database Settings**: `timeout_seconds` must be strictly positive; `db_path` must not be empty.
- **API Settings**: Request timeout must satisfy $0 < t \le 120$ seconds.
- **Evidence Fusion Weights**: All weights must lie within `[0.0, 1.0]` and their sum must equal `1.0` ($\pm 0.001$).
- **Risk Severity Thresholds**: Thresholds must adhere to strict monotonic ordering:
  $$0 \le \text{threshold\_medium} < \text{threshold\_high} < \text{threshold\_critical} \le 100$$
- **Scanner Constraints**: File size limits and streaming hash chunk sizes must be strictly positive integers. Debounce delay must be non-negative.
- **Network Endpoints**: Central backend URL must specify a valid `http://` or `https://` protocol and host. Server port must reside in `[1, 65535]`.
- **Log Level**: Must match standard Python logging levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`.

---

## Developer Usage

### 1. Central Singleton Configuration Access

```python
from config.config import get_config, ACTIS_ROOT, DATABASE_PATH

# Retrieve active singleton
cfg = get_config()
print("Environment:", cfg.environment)
print("Database Path:", cfg.database.db_path)
```

### 2. Dynamic Reloading & Testing Profiles

```python
from config.config import get_config

# Reload with isolated testing profile
test_cfg = get_config(reload=True, environment="testing")
assert test_cfg.environment == "testing"
```

### 3. Safe Diagnostic Serialization

```python
from config.config import get_config

cfg = get_config()
# Export safe dictionary with API keys masked (e.g. "vt****45")
safe_dump = cfg.to_dict(mask_secrets=True)
```
