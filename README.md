# ACTIS — Automated Cyber Threat Intelligence System

**ACTIS** is an AI-assisted, read-only endpoint cybersecurity and threat-intelligence platform designed for Windows desktop computers. It provides deep static file inspection, URL phishing classification, email/message link triage, recursive filesystem scanning, real-time file and clipboard sensors, and a centralized threat intelligence sharing network.

---

## 🛡 Security Principles & Scope

ACTIS operates under a **Read-Only / Non-Destructive** security architecture:

- **What ACTIS DOES:**
  - Reads metadata, file headers, and calculate cryptographic hashes (SHA-256, MD5).
  - Inspects Windows Portable Executable (PE) headers, sections, imports, and certificates.
  - Computes Shannon entropy to identify packers and encryption.
  - Runs machine-learning inference and heuristic rules.
  - Correlates local and external threat intelligence indicators.
  - Generates transparent, itemized risk explanations and recommended actions.
  - Alerts the user via desktop notifications and the interactive command-center UI.
- **What ACTIS DOES NOT DO:**
  - Never executes suspicious files.
  - Never deletes, modifies, or renames user files automatically.
  - Never encrypts/decrypts user data.
  - Never uploads personal user documents to external clouds (only hashes/URLs are queried).
  - Never bypasses Windows security controls or claims to replace enterprise antivirus.

---

## 🏛 System Architecture

```
                         ┌────────────────────┐
                         │        USER        │
                         └─────────┬──────────┘
                                   │
 ┌───────────────┬─────────┬───────┴───────┬───────────────┬────────────────────┐
 ▼               ▼         ▼               ▼               ▼                    ▼
URL Scanner  Message    File Scanner  Device Scanner  File Watcher       Clipboard Monitor
             Scanner    (PE Analysis) (Quick/Full)    (Real-time drops)  (Opt-in URL hook)
        │         │         │               │               │                    │
        └─────────┴─────────┼───────────────┴───────────────┴────────────────────┘
                            ▼
              ┌──────────────────────────┐
              │   Detection Engine       │
              │ (Core Intelligence Layer)│
              └─────────────┬────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
 Threat Intelligence DB   ML Models Engine    Rule-Based Engine
 (SQLite Relational)     (Phishing + Malware) (Heuristics & Packers)
        │                   │                   │
        └───────────┬───────┴───────────┬───────┘
                    ▼                   ▼
          ┌───────────────────┐   ┌──────────────────────┐
          │  Decision Engine  │   │ Logging & Reporting  │
          │ (0-100 Risk Score)│   │ (Threat Records & DB)│
          └─────────┬─────────┘   └──────────┬───────────┘
                    ▼                        ▼
           Notification System           Dashboard (UI)
           (Desktop Alerts)           (Streamlit Command Center)
                    │                        │
                    └───────────┬────────────┘
                                ▼
               Central Threat Intelligence REST API
                    (FastAPI Sharing & Sync)
```

---

## 📦 Project Structure

```
ACTIS/
│
├── config/
│   ├── config.py                 # Central settings, paths, API keys, weights
│   └── .env.example              # Environment variables template
│
├── data/
│   ├── phishing_dataset.csv      # 100,077 URL samples (19 morphological features)
│   ├── malware_dataset.csv       # 62,485 Windows PE samples (15 static PE features)
│   └── threat_intelligence.db    # Relational SQLite local indicator database
│
├── models/
│   ├── phishing_model.pkl        # Trained Random Forest URL classifier
│   ├── phishing_model_metadata.json
│   ├── malware_model.pkl         # Trained Random Forest Windows PE classifier
│   └── malware_model_metadata.json
│
├── scanners/
│   ├── url_scanner.py            # URL normalization, 19-feature extraction, ML inference
│   ├── text_analyzer.py          # Message URL extraction & urgency keyword analysis
│   ├── file_feature_extractor.py # Safe static PE analysis using pefile and hashlib
│   ├── file_scanner.py           # Single file analysis orchestrator
│   ├── device_scanner.py         # Quick Scan, Custom Scan, Full System Scan
│   ├── file_watcher.py           # Real-time watchdog file drop monitor with debounce
│   └── clipboard_scanner.py      # Background clipboard URL monitor
│
├── detection_engine/
│   ├── threat_detector.py        # Central detection pipeline orchestrator
│   ├── risk_engine.py            # Multi-criteria evidence fusion & explainability
│   ├── rule_engine.py            # Deterministic heuristic rules for URLs and binaries
│   └── model_manager.py          # Model schema validation & inference manager
│
├── threat_intelligence/
│   ├── threat_lookup.py          # Local DB & external provider lookup coordinator
│   ├── api_clients.py            # VirusTotal v3 API client with offline fallback
│   └── sync_manager.py           # Client-side sync manager for central API
│
├── reports/
│   ├── threat_database.py        # Relational schema (threats, indicators, detections)
│   ├── scan_database.py          # Scan session tracking and analytics queries
│   └── report_generator.py       # JSON, CSV, and Markdown audit export
│
├── notifications/
│   └── notifier.py               # Security alerts, formatters, and dispatching
│
├── dashboard/
│   └── app.py                    # Streamlit desktop cybersecurity command center (13 views)
│
├── assistant/
│   └── security_assistant.py     # Grounded AI Security Assistant
│
├── backend/
│   ├── api.py                    # FastAPI central threat intelligence sharing service
│   ├── database.py               # Central backend SQLite database
│   └── models.py                 # Pydantic validation models
│
├── tests/
│   ├── test_url_scanner.py
│   ├── test_text_analyzer.py
│   ├── test_static_pe.py
│   ├── test_risk_engine.py
│   ├── test_threat_database.py
│   └── test_backend_api.py
│
├── train_phishing_pipeline.py    # Phishing model training script
├── train_malware_pipeline.py     # Windows PE malware model training script
├── main.py                       # CLI, background services & application launcher
├── requirements.txt              # Core dependencies
└── README.md
```

---

## 🧠 Machine Learning Models & Metrics

### 1. URL Phishing Classifier
- **Algorithm:** Random Forest (`n_estimators=100`, `class_weight='balanced'`)
- **Dataset:** 100,077 samples (63,715 Legitimate, 36,362 Phishing)
- **Features (19):** `url_length`, `n_dots`, `n_hypens`, `n_underline`, `n_slash`, `n_questionmark`, `n_equal`, `n_at`, `n_and`, `n_exclamation`, `n_space`, `n_tilde`, `n_comma`, `n_plus`, `n_asterisk`, `n_hastag`, `n_dollar`, `n_percent`, `n_redirection`.
- **Test Performance:**
  - **Accuracy:** 88.78%
  - **Precision:** 82.73%
  - **Recall:** 87.35%
  - **F1 Score:** 84.98%
  - **ROC-AUC:** 95.35%

### 2. Windows PE Malware Classifier
- **Algorithm:** Random Forest (`n_estimators=150`, `class_weight='balanced'`)
- **Dataset:** 62,485 Windows PE executables/DLLs (35,367 Malicious, 27,118 Benign)
- **Features (15 PE Header Features):** `Machine`, `DebugSize`, `DebugRVA`, `MajorImageVersion`, `MajorOSVersion`, `ExportRVA`, `ExportSize`, `IatVRA`, `MajorLinkerVersion`, `MinorLinkerVersion`, `NumberOfSections`, `SizeOfStackReserve`, `DllCharacteristics`, `ResourceSize`, `BitcoinAddresses`.
- **Test Performance:**
  - **Accuracy:** 99.65%
  - **Precision:** 99.63%
  - **Recall:** 99.75%
  - **F1 Score:** 99.69%
  - **ROC-AUC:** 99.94%
  - **Top Features:** `DllCharacteristics` (25.2%), `MajorLinkerVersion` (13.0%), `DebugRVA` (11.2%), `DebugSize` (10.3%), `MajorOSVersion` (8.4%).

---

## 🗄 Relational Database Schema

Local SQLite database (`data/threat_intelligence.db`):
- **`threats`**: id, threat_type, name, risk_level, status, description, first_seen, last_seen, verified_by.
- **`indicators`**: id, threat_id (FK), indicator_type (url, domain, sha256, md5, ip), indicator_value, source, confidence (0.0-1.0), status (`CONFIRMED`, `SUSPICIOUS`, `CANDIDATE`, `REPORTED`, `FALSE_POSITIVE`), first_seen, last_seen.
- **`scans`**: id, scan_type, target, started_at, completed_at, status, files_scanned, threats_found, error_count.
- **`detections`**: id, scan_id (FK), indicator_id (FK), target, target_type, model_name, model_score, rule_score, intel_score, final_score, risk_level, explanation_json, detected_at.
- **`scan_items`**: id, scan_id (FK), path_or_target, sha256, status, risk_score, scanned_at.

---

## 🚀 How to Run ACTIS

### 1. Launch the Command Center Web Dashboard (Streamlit)
```bash
python main.py --dashboard
```
*Access the dashboard at:* `http://localhost:8501`

### 2. Launch the Central Threat Intelligence REST API (FastAPI)
```bash
python main.py --server
```
*Access interactive API documentation at:* `http://127.0.0.1:8000/docs`

### 3. Interactive Command Line Interface (CLI)
```bash
python main.py
```

### 4. Direct CLI Commands
```bash
# Scan a single URL
python main.py --scan-url "https://suspicious-site.xyz/login.php"

# Safe static inspection on a file
python main.py --scan-file "C:\Windows\notepad.exe"

# Execute a Quick Scan of persistence folders
python main.py --quick-scan
```

### 5. Run Automated Unit & Integration Tests
```bash
pytest tests/ -v
```
*(20/20 test cases covering feature extraction, models, DB, heuristics, and API endpoints)*

---

## 🔒 Privacy & Operational Principles

1. **Indicator Sharing Only:** Only verified threat indicators (hashes, malicious URLs, domains) are submitted to the central network — user documents, files, and personal data are never uploaded.
2. **Offline Capable:** ACTIS operates fully offline for local file and URL analysis using trained local models and local SQLite threat intelligence. External API feeds serve as an optional enrichment layer.
3. **Transparent Explainability:** Every threat evaluation provides understandable, bulleted reasoning for why a risk score was assigned and what defensive action the user should take.
