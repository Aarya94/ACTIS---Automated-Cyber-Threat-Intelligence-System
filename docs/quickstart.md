# 🚀 Quick Start Guide

Welcome to **ACTIS** (Automated Cyber Threat Intelligence System) — an AI-assisted endpoint cybersecurity and threat intelligence platform designed for Windows workstations.

This guide will walk you through setting up the environment, launching the interactive web dashboard, running the central REST API, and performing security scans.

---

## 📋 Prerequisites

- **Operating System:** Windows 10 / Windows 11 (64-bit)
- **Python Version:** Python 3.10 to 3.13
- **Git:** Installed and available in PATH
- **Privileges:** Standard user access (administrative privileges recommended only for system-wide drive scanning)

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```powershell
git clone https://github.com/Aarya94/ACTIS---Automated-Cyber-Threat-Intelligence-System.git
cd ACTIS---Automated-Cyber-Threat-Intelligence-System
```

### 2. Create and Activate Virtual Environment
```powershell
# Create virtual environment
python -m venv venv

# Activate on Windows PowerShell
.\venv\Scripts\Activate.ps1

# Or on Windows Command Prompt
.\venv\Scripts\activate.bat
```

### 3. Install Dependencies
```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy the template environment file to create your active `.env`:
```powershell
copy .env.example .env
```
*(Optional: Add your VirusTotal or AlienVault OTX API keys to `.env` to enable online enrichment).*

---

## 🖥️ Launching the Web Dashboard (Streamlit)

ACTIS provides a modern desktop cybersecurity command center built with Streamlit featuring 13 security views:

```powershell
python main.py --dashboard
```

* **Dashboard URL:** `http://localhost:8501`
* **Features Included:**
  - **Live Threat Monitor:** Real-time summary of scan statistics and detected risks.
  - **URL Scanner View:** Interactive phishing analysis and lexical feature breakdowns.
  - **Static File Analyzer:** PE header analysis, section entropy charts, and risk scoring without file execution.
  - **Threat Database Browser:** Search and filter indexed indicators and scan session histories.
  - **AI Security Assistant:** Ask natural-language questions about threat findings and remediation.

---

## 🌐 Launching the Central Threat Intelligence API (FastAPI)

ACTIS includes a high-performance REST API service for threat intelligence sharing and synchronization:

```powershell
python main.py --server
```

* **API Server:** `http://127.0.0.1:8000`
* **Interactive Swagger Documentation:** `http://127.0.0.1:8000/docs`
* **OpenAPI Schema:** `http://127.0.0.1:8000/openapi.json`

### Core Versioned API Endpoints (`/api/v1`):
- `GET /api/v1/health` — Central service health, database status, and verified indicator count.
- `GET /api/v1/client/info` — Verify client credentials, assigned roles (`read`, `contribute`, `admin`), and rate limits.
- `GET /api/v1/indicators/{indicator_type}/{indicator_value}` — Query indicator with provenance and review status.
- `GET /api/v1/indicators` — Bounded paginated query with filters (`status`, `threat_type`, `min_confidence`).
- `POST /api/v1/sync/pull` — Incremental bulk indicator pull for client fleet synchronization.
- `POST /api/v1/contributions` — Submit candidate indicator report (anti-poisoning: queued as `CANDIDATE` / `PENDING`).
- `POST /api/v1/admin/indicators/{id}/review` — Administrative review promoting/rejecting candidate records (`APPROVE`, `REJECT`).
*(Backward-compatible legacy endpoints `/api/health`, `/api/indicator/{indicator_value}`, `/api/sync/pull`, and `/api/indicator` remain operational).*

---

## 🔍 Running CLI Scanners

You can also run ACTIS directly from the command line for fast headless scanning or script automation:

### 1. Scan a Single URL
Analyze lexical features, entropy, and evaluate with the trained Random Forest classifier:
```powershell
python main.py --scan-url "https://secure-login-verify-account.suspicious-domain.xyz"
```

### 2. Safe Static Inspection on a File
Inspect Windows PE headers, calculate file hashes, extract 54 structural features, and evaluate malware probability **without executing the binary**:
```powershell
python main.py --scan-file "C:\Windows\notepad.exe"
```

### 3. Run a Quick Persistence Scan
Scan startup locations, scheduled tasks, and common persistence folders:
```powershell
python main.py --quick-scan
```

---

## 🤖 Grounded AI Security Assistant (Offline)

ACTIS provides a safe, read-only AI security assistant that answers queries about detections, indicators, statistics, and methodology without arbitrary shell execution or file modifications:

### 1. Interactive CLI Mode
Launch the unified CLI menu and select option `7`:
```powershell
python main.py
# Select [7] AI Security Assistant
```

### 2. Streamlit Web Command Center
Navigate to the **AI Security Assistant** tab in the Streamlit dashboard (`http://localhost:8501`).

### Example Queries:
- **Recent Detections:** `"What did ACTIS detect recently?"` or `"Show recent high-risk detections"`
- **Explain Flagged Target:** `"Why was notepad.exe flagged?"` or `"Explain why 185.220.101.5 was flagged"`
- **Threat Indicator Lookup:** `"Lookup indicator 185.220.101.5"` or `"Is domain evil-phish.com in the threat database?"`
- **Detection Statistics:** `"Show scan statistics"` or `"What is the detection summary?"`
- **Detection Methodology:** `"Explain ACTIS detection methodology"` or `"How does ACTIS detect malware?"`
- **Defensive Guidance:** `"What should I do if a file is flagged as malicious?"`

---

## 🎯 Running the Safe System Demonstration

ACTIS provides a reproducible, 100% offline demonstration script that verifies the complete defensive cybersecurity pipeline across 7 representative flows:

```powershell
python scripts/demo_actis.py
```

### Demonstration Scenarios Covered:
- **DEMO A — Benign URL Inspection:** Real normalization, 19 morphological features, ML inference, and safe risk scoring in offline mode.
- **DEMO B — Synthetic Phishing URL Detection:** Lexical heuristics, credential keyword cues, and Random Forest classifier identification.
- **DEMO C — Synthetic Malformed Binary Inspection:** Safe static inspection of a corrupt PE binary without code execution, followed by immediate cleanup.
- **DEMO D — Threat Intelligence Lifecycle:** Differentiating `CONFIRMED`, `CANDIDATE` (anti-poisoning protection), and `UNKNOWN` indicators (negative-evidence trap avoidance).
- **DEMO E — Grounded AI Security Assistant:** Multi-factor evidence breakdown, absence-of-evidence safety warnings, and prompt injection / secret masking boundaries.
- **DEMO F — Security Audit Reporting:** Exporting structured compliance reports to JSON, CSV, and Markdown in an isolated directory.
- **DEMO G — Incremental Scan State Optimization:** Demonstrating change classification (`NEW_FILE` vs `UNCHANGED_FILE`) and redundant scan suppression.

*Guarantees: Zero mutation of production databases, zero user file modification, zero live malware execution, and 100% offline execution.*

---

## 🧪 Running Automated Tests

ACTIS includes an automated test suite with 100% pass rate:

```powershell
# Run the complete test suite (430 tests)
pytest tests/ -q

# Run the release candidate integration suite
pytest tests/test_release_integration.py -v

# Run adversarial security & privacy safeguard suites
pytest tests/test_adversarial_security.py -v
pytest tests/test_privacy_safeguards.py -v

# Run specific subsystem tests
pytest tests/test_security_assistant.py -v
pytest tests/test_central_ti_service.py -v
pytest tests/test_url_scanner.py -v
pytest tests/test_static_pe.py -v
```

---

## 📚 Updating Project Documentation

ACTIS includes an automated progress generator that inspects the repository and updates live project metrics:

```powershell
# Check project status and verify repository integrity
python scripts/generate_docs.py --check -v

# Generate/update all status reports in docs/generated/
python scripts/generate_docs.py
```
