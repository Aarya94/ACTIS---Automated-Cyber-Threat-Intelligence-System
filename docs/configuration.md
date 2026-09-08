# ACTIS Configuration Guide (Week 1 — Day 2)

## Overview

ACTIS (Automated Cyber Threat Intelligence System) employs a centralized, type-annotated, and secure configuration architecture designed to decouple operational settings, project paths, and threat intelligence credentials from core cybersecurity detection logic.

---

## Architecture & Modules

The configuration subsystem is organized under `config/`:

| Module | Responsibility |
|---|---|
| `config/settings.py` | Structured dataclasses defining configuration domains (`DatabaseConfig`, `ModelConfig`, `ExternalApiConfig`, `RiskEngineConfig`, `ScannerConfig`, `ServerConfig`, `AppConfig`). |
| `config/paths.py` | Filesystem paths resolved dynamically relative to `ACTIS_ROOT` without hardcoded system paths. |
| `config/defaults.py` | Baseline operational defaults and environment presets (`development`, `testing`, `production`). |
| `config/env_loader.py` | Safe typed parsing of environment variables (`get_str`, `get_int`, `get_float`, `get_bool`, `get_list`) and `.env` loader. |
| `config/validator.py` | Constraint validation checking weights, severity threshold monotonicity, scanner operational limits, and network endpoints. |
| `config/config.py` | Central import hub providing backward-compatible global constants and structured configuration instances. |

---

## Environment Variables Reference

| Variable | Type | Default | Description |
|---|---|---|---|
| `ACTIS_ENVIRONMENT` | `str` | `development` | Operational mode: `development`, `testing`, `production`. |
| `ACTIS_LOG_LEVEL` | `str` | `INFO` | Standard logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `ACTIS_BACKEND_URL` | `str` | `http://127.0.0.1:8000` | URL for central threat intelligence sharing backend. |
| `ACTIS_CLIENT_API_KEY` | `str` | `actis-client-default-secret-token` | Client authentication token for sync backend. |
| `ACTIS_SERVER_HOST` | `str` | `127.0.0.1` | Bind address for local ACTIS backend server. |
| `ACTIS_SERVER_PORT` | `int` | `8000` | Port for local ACTIS backend server. |
| `VIRUSTOTAL_API_KEY` | `str` | `""` | VirusTotal v3 API key for threat enrichment. |
| `ABUSEIPDB_API_KEY` | `str` | `""` | AbuseIPDB API key for IP reputation lookups. |
| `URLHAUS_API_KEY` | `str` | `""` | Abuse.ch URLhaus API key for malware URL checks. |
| `OPENPHISH_API_KEY` | `str` | `""` | OpenPhish API key for phishing feed integration. |
| `PHISHTANK_API_KEY` | `str` | `""` | PhishTank developer key for URL verification. |
| `ACTIS_REQUEST_TIMEOUT` | `float` | `10.0` | HTTP request timeout in seconds for threat intel lookups. |
| `ACTIS_MAX_FILE_SIZE_MB` | `int` | `100` | Maximum file size in MB for deep static PE inspection. |
| `ACTIS_WATCHDOG_DEBOUNCE_SECONDS` | `float` | `2.0` | Settle time in seconds before scanning newly modified files. |

---

## Security Guidelines

1. **Never Commit Secrets**: Real credentials, API keys, private certificates, and `.env` files must NEVER be staged or committed to Git.
2. **Use `.env.example`**: `.env.example` contains only non-sensitive placeholder values. Copy it locally:
   ```bash
   copy .env.example .env
   ```
3. **Automatic Secret Redaction**: Dataclasses redacting sensitive credentials in `__repr__` (e.g. `vt****89`) prevent accidental leakage in diagnostic dumps or log files.
4. **Git Protection**: `.gitignore` explicitly blocks `.env`, `.env.*`, `*.pem`, `*.key`, `credentials.json`, and `secrets/`.

---

## Validation Rules

The configuration validator (`config/validator.py`) enforces strict operational constraints:

- **Evidence Fusion Weights**: All weights must lie within `[0.0, 1.0]` and their sum must equal `1.0` ($\pm 0.001$).
- **Risk Severity Thresholds**: Thresholds must adhere to strict monotonic ordering:
  $$0 \le \text{threshold\_medium} < \text{threshold\_high} < \text{threshold\_critical} \le 100$$
- **Scanner Constraints**: File size limits and streaming hash chunk sizes must be strictly positive integers. Debounce delay must be non-negative.
- **Network Endpoints**: Central backend URL must specify a valid `http://` or `https://` protocol and host. Server port must reside in `[1, 65535]`.
- **Log Level**: Must match standard Python logging levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`.

---

## Developer Usage

### 1. Basic Configuration Access

```python
from config.config import config, ACTIS_ROOT, DATABASE_PATH

# Access structured settings
print("Log Level:", config.log_level)
print("Risk Critical Threshold:", config.risk.threshold_critical)
print("Database Path:", config.database.db_path)
```

### 2. Custom Environment Instantiation

```python
from config.defaults import create_default_config
from config.validator import validate_config

cfg = create_default_config(environment="testing")
validate_config(cfg, strict=True)
```
