# ACTIS Machine Learning Workflow & Model Contracts

**Authoritative Architecture Document**  
**Milestone:** Post-Day-7 Architectural Evolution  
**Status:** Approved Target Architecture  

This document specifies the lifecycle, feature schemas, training requirements, metadata contracts, and inference rules for machine learning models deployed within the ACTIS analysis pipeline.

---

## 1. Machine Learning Integration in the Target Architecture

In the post-Day-7 architecture, machine learning classifiers are **evidence contributors**, not autonomous decision-makers. They are orchestrated centrally by the **Analysis Orchestrator** and evaluated alongside Threat Intelligence and Heuristic Rules within the **Detection Engine**:

```text
               +-------------------------------------------------+
               |            Curated Ground-Truth Data            |
               |       (Phishing URLs / Windows PE Binaries)     |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |        Static Feature Extraction Engine         |
               |          (Deterministic Morphological/PE)       |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |       Preprocessing & Normalization Pipeline    |
               |             (Type Encodings, Scalers)           |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |              Offline Model Training             |
               |         (Random Forest Ensemble Estimators)     |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |             Evaluation & Validation             |
               |         (Accuracy, Precision, Recall, ROC-AUC)  |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |       Artifact Serialization & Schema Lock      |
               |      (*_model.pkl + *_model_metadata.json)      |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |            Analysis Orchestrator                |
               |     (Extracts features & invokes ModelManager)  |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |              MLPredictionResult                 |
               |      (Probabilities, confidence, label)         |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |            Detection Decision Engine            |
               |    (Fused with Local TI, Rules, & External TI)  |
               +-------------------------------------------------+
```

---

## 2. Phishing URL Detection Model

- **Algorithm:** `RandomForestClassifier` (Scikit-Learn)
- **Artifact Path:** `models/phishing_model.pkl`
- **Metadata Contract:** `models/phishing_model_metadata.json`
- **Dataset:** `data/phishing_dataset.csv` (100,077 URL samples)
- **Status:** `IMPLEMENTED` & Integrated with Day 7 hardened pipeline.

### Morphological Feature Vector (19 Ordered Features)

The scanner and inference engine must provide features in this **exact ordered sequence**:

| Index | Feature Key | Data Type | Description |
|---|---|---|---|
| 0 | `url_length` | integer | Total string length of normalized URL |
| 1 | `n_dots` | integer | Total count of dot (`.`) characters |
| 2 | `n_hypens` | integer | Total count of hyphen (`-`) characters |
| 3 | `n_underline` | integer | Total count of underscore (`_`) characters |
| 4 | `n_slash` | integer | Total count of forward slash (`/`) characters |
| 5 | `n_questionmark`| integer | Total count of question mark (`?`) characters |
| 6 | `n_equal` | integer | Total count of equals (`=`) characters |
| 7 | `n_at` | integer | Total count of at (`@`) symbols |
| 8 | `n_and` | integer | Total count of ampersand (`&`) characters |
| 9 | `n_exclamation` | integer | Total count of exclamation mark (`!`) characters |
| 10 | `n_space` | integer | Total count of whitespace characters |
| 11 | `n_tilde` | integer | Total count of tilde (`~`) characters |
| 12 | `n_comma` | integer | Total count of comma (`,`) characters |
| 13 | `n_plus` | integer | Total count of plus (`+`) characters |
| 14 | `n_asterisk` | integer | Total count of asterisk (`*`) characters |
| 15 | `n_hastag` | integer | Total count of hashtag (`#`) characters |
| 16 | `n_dollar` | integer | Total count of dollar (`$`) characters |
| 17 | `n_percent` | integer | Total count of percent (`%`) characters |
| 18 | `n_redirection` | integer | Total count of double-slash (`//`) occurrences |

---

## 3. Windows PE Malware Detection Model

- **Algorithm:** `RandomForestClassifier(n_estimators=150)` (Scikit-Learn)
- **Artifact Path:** `models/malware_model.pkl`
- **Metadata Contract:** `models/malware_model_metadata.json`
- **Dataset:** `data/malware_dataset.csv` (62,485 Windows PE samples: 41,323 benign / 21,162 malicious)
- **Status:** Baseline model artifact and metadata contract verified; integration scheduled for Days 8–10.

### Static PE Header Feature Vector (15 Ordered Features)

Extracted in memory from file binary bytes using `pefile` without execution:

| Index | Feature Key | Description |
|---|---|---|
| 0 | `Machine` | Target architecture integer from COFF File Header |
| 1 | `DebugSize` | Size of Debug directory table in Optional Header |
| 2 | `DebugRVA` | Relative Virtual Address of Debug table |
| 3 | `MajorImageVersion` | User-defined major binary image version |
| 4 | `MajorOSVersion` | Minimum major operating system version required |
| 5 | `ExportRVA` | Relative Virtual Address of Export Table |
| 6 | `ExportSize` | Byte size of Export Table |
| 7 | `IATRVA` | Relative Virtual Address of Import Address Table |
| 8 | `ResMinSize` | Minimum resource section size |
| 9 | `ResourceSize` | Cumulative byte size of Resource section |
| 10 | `NumberOfSections` | Section count in Section Table (e.g. `.text`, `.data`) |
| 11 | `Characteristics` | Binary flags (DLL, Executable, 32-bit, Large Address) |
| 12 | `MinorSubsystemVersion` | Subsystem minor version |
| 13 | `SizeOfImage` | Total memory footprint when binary is mapped to memory |
| 14 | `Subsystem` | Target execution environment (e.g. GUI vs Console) |

---

## 4. Strict Operational Rules for ML Inference

1. **ML Is Evidence, Not Verdict:** An ML prediction alone **never** transitions a target to `CONFIRMED`. Statistical probability is fused with threat intelligence and heuristic rules.
2. **Metadata Contract Enforcement:** `model_manager.py` verifies incoming feature vectors against `*_model_metadata.json` before calling `predict_proba()`. Mismatched dimensions raise controlled exceptions.
3. **Strictly In-Memory Static Extraction:** Binaries and URLs are evaluated as static structures. No binary execution, debugging, or network connections occur during feature extraction.
4. **Deterministic Feature Ordering:** Extraction routines guarantee consistent, deterministic feature vector sequence.
5. **Safe Fallback on Failure:** When a model artifact is unavailable or evaluation fails, the pipeline logs an observable warning and falls back to deterministic heuristic and threat intelligence evaluation without crashing.
