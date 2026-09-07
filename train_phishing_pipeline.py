"""
ACTIS Phishing Model Training Pipeline
Trains a Random Forest classifier on URL morphological features.
Saves model artifact and JSON metadata schema.
"""

import json
from datetime import datetime
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
)
import joblib

ACTIS_ROOT = Path(__file__).resolve().parent
DATA_PATH = ACTIS_ROOT / "data" / "phishing_dataset.csv"
MODEL_PATH = ACTIS_ROOT / "models" / "phishing_model.pkl"
METADATA_PATH = ACTIS_ROOT / "models" / "phishing_model_metadata.json"

def train_phishing_model():
    print(f"[+] Loading phishing dataset from {DATA_PATH}...")
    df = pd.read_csv(DATA_PATH)
    print(f"    Dataset shape: {df.shape}")
    
    label_col = "phishing"
    if label_col not in df.columns:
        raise ValueError(f"Expected label column '{label_col}' not found in dataset.")
        
    X = df.drop(columns=[label_col])
    y = df[label_col]
    feature_names = list(X.columns)
    
    print(f"    Features count: {len(feature_names)}")
    print(f"    Class distribution:\n{y.value_counts()}")
    
    # Stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"    Training samples: {len(X_train)}, Testing samples: {len(X_test)}")
    
    print("[+] Training Random Forest Classifier (n_estimators=100)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )
    clf.fit(X_train, y_train)
    
    print("[+] Evaluating model on test set...")
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    roc = float(roc_auc_score(y_test, y_prob))
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    print(f"    Accuracy:  {acc:.4f} ({acc*100:.2f}%)")
    print(f"    Precision: {prec:.4f}")
    print(f"    Recall:    {rec:.4f}")
    print(f"    F1 Score:  {f1:.4f}")
    print(f"    ROC-AUC:   {roc:.4f}")
    print(f"    Confusion Matrix: {cm}")
    
    # Save model artifact
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"[+] Model saved to {MODEL_PATH}")
    
    # Save metadata
    metadata = {
        "model_name": "actis_phishing_rf",
        "model_version": "1.0.0",
        "created_at": datetime.now().isoformat(),
        "algorithm": "RandomForestClassifier",
        "dataset_name": "web-page-phishing.csv",
        "dataset_samples": int(len(df)),
        "features": feature_names,
        "feature_count": len(feature_names),
        "target_mapping": {"0": "legitimate", "1": "phishing"},
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc, 4),
            "confusion_matrix": cm
        }
    }
    
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
    print(f"[+] Model metadata schema saved to {METADATA_PATH}")

if __name__ == "__main__":
    train_phishing_model()
