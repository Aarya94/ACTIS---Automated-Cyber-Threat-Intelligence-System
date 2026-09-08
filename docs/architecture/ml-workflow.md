# ACTIS Machine Learning Workflow & Model Contracts

This document specifies the lifecycle, feature schemas, training requirements, metadata contracts, and inference rules for machine learning models deployed in ACTIS.

---

## Machine Learning Lifecycle

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
               |       Production Inference Runtime              |
               |     (detection_engine/model_manager.py)         |
               +-----------------------+-------------------------+
                                       |
                                       v
               +-------------------------------------------------+
               |        Risk Engine Multi-Criteria Fusion        |
               |           (Score Combined with TI & Rules)      |
               +-------------------------------------------------+
```

---

## 1. Phishing URL Detection Model

- **Algorithm**: `RandomForestClassifier` (Scikit-Learn)
- **Artifact Path**: `models/phishing_model.pkl`
- **Metadata Contract**: `models/phishing_model_metadata.json`
- **Dataset**: `data/phishing_dataset.csv` (100,077 URL samples)
- **Observed Metrics**: Test Accuracy: ~88.78%, Test ROC-AUC: 95.35%

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

## 2. Windows PE Malware Detection Model

- **Algorithm**: `RandomForestClassifier(n_estimators=150)` (Scikit-Learn)
- **Artifact Path**: `models/malware_model.pkl`
- **Metadata Contract**: `models/malware_model_metadata.json`
- **Dataset**: `data/malware_dataset.csv` (62,485 Windows PE samples: 41,323 benign / 21,162 malicious)
- **Observed Metrics**: Test Accuracy: 99.65%, Test ROC-AUC: 99.94%

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
| 11 | `Characteristics` | Binary flag flags (DLL, Executable, 32-bit, Large Address) |
| 12 | `MinorSubsystemVersion` | Subsystem minor version |
| 13 | `SizeOfImage` | Total memory footprint when binary is mapped to memory |
| 14 | `Subsystem` | Target execution environment (e.g. GUI vs Console) |

---

## Strict Contract Verification Rules

1. **Metadata Enforcement**: `model_manager.py` verifies the incoming feature dictionary against `*_model_metadata.json` before performing prediction. Missing features trigger explicit warnings; mismatched feature dimensions raise exceptions.
2. **Never Execute Live Binaries**: Feature extraction is strictly static. Binaries are parsed as byte structures. No process spawning, thread injection, or debugging API is ever invoked.
3. **No Dynamic Weights Modification**: Models are static artifacts loaded at startup. Runtime tuning occurs solely through the multi-criteria Risk Engine weights.
