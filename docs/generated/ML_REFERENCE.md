# ACTIS Machine Learning Models Reference

This document provides a factual summary of the trained machine learning models currently deployed in `models/` and referenced by `detection_engine/model_manager.py`.

---

## 1. Phishing URL Random Forest Classifier

- **Model Identifier**: `actis_phishing_rf` (Version `1.0.0`)
- **Serialized Artifact**: `models/phishing_model.pkl`
- **Metadata Specification**: `models/phishing_model_metadata.json`
- **Algorithm**: `RandomForestClassifier` (Scikit-Learn)
- **Dataset**: `data/phishing_dataset.csv` (100,077 URL samples)
- **Test Performance**:
  - Test Accuracy: ~88.78%
  - Test ROC-AUC: 95.35%
- **Input Feature Dimension**: 19 morphological features
- **Ordered Features**:
  1. `url_length`
  2. `n_dots`
  3. `n_hypens`
  4. `n_underline`
  5. `n_slash`
  6. `n_questionmark`
  7. `n_equal`
  8. `n_at`
  9. `n_and`
  10. `n_exclamation`
  11. `n_space`
  12. `n_tilde`
  13. `n_comma`
  14. `n_plus`
  15. `n_asterisk`
  16. `n_hastag`
  17. `n_dollar`
  18. `n_percent`
  19. `n_redirection`

---

## 2. Windows PE Malware Random Forest Classifier

- **Model Identifier**: `actis_windows_pe_malware_rf` (Version `1.0.0`)
- **Serialized Artifact**: `models/malware_model.pkl`
- **Metadata Specification**: `models/malware_model_metadata.json`
- **Algorithm**: `RandomForestClassifier(n_estimators=150)` (Scikit-Learn)
- **Dataset**: `data/malware_dataset.csv` (62,485 Windows PE binaries: 41,323 benign / 21,162 malicious)
- **Test Performance**:
  - Test Accuracy: 99.65%
  - Test ROC-AUC: 99.94%
- **Input Feature Dimension**: 15 static PE header features
- **Ordered Features**:
  1. `Machine`
  2. `DebugSize`
  3. `DebugRVA`
  4. `MajorImageVersion`
  5. `MajorOSVersion`
  6. `ExportRVA`
  7. `ExportSize`
  8. `IATRVA`
  9. `ResMinSize`
  10. `ResourceSize`
  11. `NumberOfSections`
  12. `Characteristics`
  13. `MinorSubsystemVersion`
  14. `SizeOfImage`
  15. `Subsystem`

---

## Contract Compliance Check

Both model artifacts are accompanied by version-locked metadata contracts in JSON format. `detection_engine/model_manager.py` strictly validates feature dictionary presence and vector dimensionality prior to executing inference.
