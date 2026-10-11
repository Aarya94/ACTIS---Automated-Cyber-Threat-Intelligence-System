# Safe Windows PE Static File Analysis Subsystem

**ACTIS — Automated Cyber Threat Intelligence System**  
**Document Version:** 1.0.0 (Week 1 Day 5)  
**Primary Modules:** `scanners/file_feature_extractor.py`, `scanners/pe_feature_contract.py`  
**Integration Point:** `scanners/file_scanner.py`  
**Test Suite:** `tests/test_static_pe.py`

---

## 1. Executive Summary & Objective

On **Development Day 5**, ACTIS established the foundational subsystem for safe, read-only Windows Portable Executable (PE) static file analysis.

The primary mission of this subsystem is to inspect, parse, and extract structural, header, section, import, and entropy features from executable binaries while strictly prohibiting runtime execution, dynamic hooking, or destructive modifications.

> [!IMPORTANT]
> **Strict Day 5 Security & Scope Boundaries**:
> - **Non-Destructive & Read-Only**: The analyzer only reads bytes from disk. It never invokes, executes, or sandboxes files.
> - **Zero Automatic Remediation**: The analyzer does not delete, quarantine, or modify suspect files.
> - **Zero Real Malware in Repo**: All testing relies on safe, dynamically generated synthetic PE fixtures and mocks.
> - **Scope Isolation**: Does not train models, run live inference, monitor clipboards, or call external threat intelligence APIs.

---

## 2. Core Static Analysis Capabilities

The static analysis pipeline is decomposed into six modular functional capabilities:

```
Candidate File
    │
    ├─► 1. Streaming Cryptographic Hashing (SHA-256, MD5, SHA-1)
    │
    ├─► 2. Non-Destructive Pre-Parser Binary Detection (MZ, e_lfanew, PE\0\0)
    │
    ├─► 3. Shannon Entropy Profiling (File & Section Level)
    │
    ├─► 4. PE Header Metadata Extraction (Machine, Subsystem, EntryPoint, ImageBase)
    │
    ├─► 5. Section Analysis (Virtual/Raw Sizes, Characteristics, W+X Heuristics)
    │
    └─► 6. Import Table & Suspicious API Heuristics (DLLs, Threat API matching)
            │
            ▼
    Structured Feature Contract (PEStaticFeatures)
            │
            ├─► Threat Identifiers (Hashes, File Path) -> Threat Database / TI
            └─► 15 PE ML Features Vector -> Future Malware Detection Engine
```

### 1. Streaming Cryptographic Hashing
- **Function:** `calculate_file_hashes(file_path, algorithms, chunk_size)`
- Streams files in chunks (`64 KB` default) to compute SHA-256, MD5, and SHA-1 digests concurrently.
- Immune to out-of-memory errors on large executables.

### 2. Fast Binary Pre-Parser Detection
- **Functions:** `is_pe_file(file_path)` and `detect_pe_format(file_path)`
- Reads only minimal initial bytes before invoking full parsing libraries.
- Validates the DOS header magic (`b"MZ"` / `0x5A4D`), validates the `e_lfanew` pointer bounds at `0x3C`, verifies the PE signature (`b"PE\x00\x00"`), and determines the target machine architecture (`I386`, `AMD64`, `ARM`, `ARM64`, `IA64`).

### 3. Shannon Entropy Profiling
- **Functions:** `calculate_shannon_entropy(data)`, `calculate_file_entropy(file_path)`, `analyze_pe_entropy_distribution(sections, file_entropy)`
- Computes Shannon entropy over byte frequency distributions:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
- Identifies potential packing, encryption, or obfuscation signals when file or section entropy exceeds $7.0 - 7.2$.

### 4. Header & Section Structural Analysis
- **Functions:** `extract_pe_header_metadata(pe)`, `extract_pe_section_features(pe)`
- Extracts CPU architecture, subsystem (GUI vs Console), entry point RVA, image base, linker versions, and stack sizes.
- Extracts per-section virtual and raw sizes, section characteristics, and flags risky memory attributes such as combined Write + Execute (`W+X`).

### 5. Import Table, Imphash & Suspicious API Detection
- **Function:** `extract_pe_import_features(pe)` and `calculate_imphash(pe)`
- Catalogs imported dynamic-link libraries and function names.
- Computes standard Mandiant import hash (`imphash`) for clustering and binary classification, with fallback support for ordinal imports.
- Categorizes dangerous Windows APIs across 10 threat categories (`PROCESS_HOLLOWING`, `TOKEN_IMPERSONATION`, `DYNAMIC_RESOLUTION`, `ANTI_DEBUGGING`, `PERSISTENCE_SERVICE`, `KEYLOGGING_INPUT`, `NETWORK_DOWNLOAD`, `EXECUTION_COMMAND`, `MEMORY_PROTECTION`, `CRYPTOGRAPHY`).

### 6. Advanced PE Heuristic Rules (`detection_engine/rule_engine.py`)
- Evaluates extracted structural metrics against heuristic detection rules:
  - `RULE_PE_PROCESS_HOLLOWING` (CRITICAL, +45.0)
  - `RULE_PE_TOKEN_IMPERSONATION` (HIGH, +30.0)
  - `RULE_PE_DYNAMIC_API_RESOLVER` (HIGH, +25.0)
  - `RULE_PE_ANTI_ANALYSIS` (MEDIUM, +20.0)
  - `RULE_PE_PERSISTENCE_APIS` (MEDIUM, +20.0)
  - `RULE_PE_SECTION_ENTROPY_ANOMALY` (HIGH, +25.0)
  - `RULE_PE_SECTION_UNPACKING_STUB` (HIGH, +25.0)
  - `RULE_PE_WX_SECTION` (CRITICAL, +40.0)
  - `RULE_PE_PACKER_SECTION` (HIGH, +30.0)
  - `RULE_PE_BITCOIN_ADDRESS` (CRITICAL, +40.0)

---

## 3. Structured Feature Contract (`scanners/pe_feature_contract.py`)

To prevent machine learning data leakage and maintain high code quality, extracted data is represented by strongly-typed immutable dataclasses:

| Contract Component | Fields | Purpose |
|---|---|---|
| `PEIdentifiers` | `path`, `filename`, `sha256`, `md5`, `sha1` | **Threat Intelligence Identifiers**: Lookup keys for indicators of compromise (IOCs). Never fed into ML models. |
| `FileMetadata` | `file_size`, `extension`, `entropy`, `is_pe`, `is_valid` | Generic file system and binary properties. |
| `PEMetadata` | `architecture`, `machine`, `entry_point`, `image_base`, `subsystem`, `dll_characteristics`, `size_of_stack_reserve` | Header-level architectural attributes. |
| `PESectionFeature` | `name`, `virtual_size`, `raw_size`, `characteristics`, `entropy`, `is_write_and_execute`, `is_high_entropy` | Granular per-section metrics. |
| `PEImportFeature` | `imported_dll_count`, `imported_function_count`, `imported_dlls`, `imported_functions`, `suspicious_apis_found`, `imphash`, `api_categories_found` | API interaction heuristics, import hashing, and threat family mapping. |
| `PEStaticFeatures` | Aggregates all above + `pe_features_15` + `to_ml_feature_vector()` | Master structured contract with export helpers. |

---

## 4. Hardened Malformed File Handling

The analyzer incorporates defense-in-depth error handling:
- **Nonexistent Files:** Handled gracefully with clean error messages; no unhandled `FileNotFoundError`.
- **Empty Files (0 bytes):** Verified as safe non-PE with explicit warning; no zero-byte crashes.
- **Directories:** Rejects directories passed as target file paths.
- **Corrupted / Truncated PE Headers:** Caught via `detect_pe_format` and `pefile.PEFormatError` with sanitized diagnostic warnings.
- **Oversized Files:** Checked against `MAX_FILE_SIZE_BYTES` to prevent memory exhaustion attacks.
- **Sanitized Messages:** File system errors do not expose internal runtime stack traces.

---

## 5. Verification & Test Suite

The subsystem is verified by automated unit tests in `tests/test_static_pe.py` and `tests/test_detection_engine.py`:
- `TestSafeFileHashing`: Multi-algorithm correctness, missing file handling, invalid algorithm rejection.
- `TestShannonEntropyCalculations`: Empty, homogeneous, and uniform bytes; file-level entropy; PE section entropy distributions.
- `TestWindowsPEFileDetection`: Synthetic PE detection, text files, random binaries, truncated DOS headers.
- `TestPEMetadataAndSectionExtraction`: Synthetic header/section extraction, mocked import heuristics, imphash calculation, ordinal handling.
- `TestStructuredPEFeatureContract`: Separation of threat identifiers from ML feature vectors, import contract serialization.
- `TestMalformedAndEdgeCaseHandling`: Nonexistent files, empty files, corrupted PE signatures, directories.
- `TestRuleEngineContractsAndEvaluation`: Process hollowing, token impersonation, dynamic API resolver, anti-analysis, persistence, unpacking stub, and entropy anomaly rules.
- `test_pe_static_analysis_notepad`: Windows host executable integration test.

All 472 automated tests in the ACTIS test suite pass with 100% success.
