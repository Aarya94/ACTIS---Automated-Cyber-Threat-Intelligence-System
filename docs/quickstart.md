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

### Core API Endpoints:
- `GET /health` — Service health and operational status.
- `GET /threats/{indicator}` — Query known indicators (URL, domain, SHA256).
- `POST /threats` — Submit verified threat indicators (requires API key).
- `GET /threats/sync` — Synchronize local threat cache with the central network.

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

## 🧪 Running Automated Tests

ACTIS includes an automated unit and integration test suite:

```powershell
# Run all tests
pytest tests/ -v

# Run specific subsystem tests
pytest tests/test_config_loading.py -v
pytest tests/test_config_validation.py -v
pytest tests/test_threat_database.py -v
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
