"""
ACTIS Model Manager Module
Coordinates machine learning model loading, schema validation, version verification,
and safe inference for phishing URL and Windows PE malware models.
"""

import json
from typing import Dict, Any, List, Optional, Union
import numpy as np
import joblib

from config.config import (
    PHISHING_MODEL_PATH,
    PHISHING_METADATA_PATH,
    MALWARE_MODEL_PATH,
    MALWARE_METADATA_PATH,
    get_logger
)

logger = get_logger("ModelManager")


class ModelManager:
    """Manages ML models, validates schemas, and provides structured inference results."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModelManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return
        self.phishing_model = None
        self.phishing_metadata = {}
        self.malware_model = None
        self.malware_metadata = {}
        self._load_models()
        self._initialized = True

    def _load_models(self):
        """Loads both phishing and malware models and their metadata schemas."""
        # 1. Phishing Model
        if PHISHING_MODEL_PATH.exists() and PHISHING_METADATA_PATH.exists():
            try:
                self.phishing_model = joblib.load(PHISHING_MODEL_PATH)
                with open(PHISHING_METADATA_PATH, "r", encoding="utf-8") as f:
                    self.phishing_metadata = json.load(f)
                logger.info(
                    f"Phishing model loaded successfully: {self.phishing_metadata.get('model_name')} "
                    f"v{self.phishing_metadata.get('model_version')} "
                    f"(Accuracy: {self.phishing_metadata.get('metrics', {}).get('accuracy')})"
                )
            except Exception as e:
                logger.error(f"Failed to load phishing model from {PHISHING_MODEL_PATH}: {e}")
                self.phishing_model = None
        else:
            logger.warning(f"Phishing model or metadata not found at {PHISHING_MODEL_PATH}")

        # 2. Windows PE Malware Model
        if MALWARE_MODEL_PATH.exists() and MALWARE_METADATA_PATH.exists():
            try:
                self.malware_model = joblib.load(MALWARE_MODEL_PATH)
                with open(MALWARE_METADATA_PATH, "r", encoding="utf-8") as f:
                    self.malware_metadata = json.load(f)
                logger.info(
                    f"Windows PE Malware model loaded: {self.malware_metadata.get('model_name')} "
                    f"v{self.malware_metadata.get('model_version')} "
                    f"(Accuracy: {self.malware_metadata.get('metrics', {}).get('accuracy')})"
                )
            except Exception as e:
                logger.error(f"Failed to load malware model from {MALWARE_MODEL_PATH}: {e}")
                self.malware_model = None
        else:
            logger.warning(f"Malware model or metadata not found at {MALWARE_MODEL_PATH}")

    def get_phishing_feature_schema(self) -> List[str]:
        """Returns the exact ordered feature list required by the phishing model."""
        return self.phishing_metadata.get("features", [])

    def get_malware_feature_schema(self) -> List[str]:
        """Returns the exact ordered feature list required by the malware model."""
        return self.malware_metadata.get("features", [])

    def predict_phishing(self, features: Union[List[float], Dict[str, Any]]) -> Dict[str, Any]:
        """
        Executes inference for URL phishing.
        Features can be a list in exact schema order or a feature dictionary.
        """
        if self.phishing_model is None:
            return {
                "available": False,
                "error": "Phishing ML model not loaded.",
                "is_phishing": False,
                "probability": 0.0,
                "confidence": 0.0
            }
            
        expected_features = self.get_phishing_feature_schema()
        
        try:
            # Prepare feature vector
            if isinstance(features, dict):
                feature_vec = [float(features.get(f, 0)) for f in expected_features]
            else:
                if len(features) != len(expected_features):
                    raise ValueError(
                        f"Phishing feature length mismatch: expected {len(expected_features)}, got {len(features)}"
                    )
                feature_vec = [float(x) for x in features]
                
            import pandas as pd
            X = pd.DataFrame([feature_vec], columns=expected_features)
            pred = int(self.phishing_model.predict(X)[0])
            
            # Predict probabilities if supported
            if hasattr(self.phishing_model, "predict_proba"):
                probs = self.phishing_model.predict_proba(X)[0]
                prob_phishing = float(probs[1]) if len(probs) > 1 else float(probs[0])
            else:
                prob_phishing = 1.0 if pred == 1 else 0.0
                
            is_phishing = bool(pred == 1)
            confidence = prob_phishing if is_phishing else (1.0 - prob_phishing)
            
            return {
                "available": True,
                "model_name": self.phishing_metadata.get("model_name", "phishing_rf"),
                "model_version": self.phishing_metadata.get("model_version", "1.0.0"),
                "is_phishing": is_phishing,
                "prediction": pred,
                "probability": round(prob_phishing, 4),
                "confidence": round(confidence, 4),
                "label": "phishing" if is_phishing else "legitimate"
            }
            
        except Exception as e:
            logger.error(f"Error during phishing inference: {e}")
            return {
                "available": False,
                "error": str(e),
                "is_phishing": False,
                "probability": 0.0,
                "confidence": 0.0
            }

    def predict_malware(self, features: Union[List[float], Dict[str, Any]]) -> Dict[str, Any]:
        """
        Executes inference for Windows PE malware.
        Features can be a list in exact schema order or a feature dictionary.
        """
        if self.malware_model is None:
            return {
                "available": False,
                "error": "Windows PE Malware ML model not loaded.",
                "is_malware": False,
                "probability": 0.0,
                "confidence": 0.0
            }
            
        expected_features = self.get_malware_feature_schema()
        
        try:
            if isinstance(features, dict):
                feature_vec = [float(features.get(f, 0)) for f in expected_features]
            else:
                if len(features) != len(expected_features):
                    raise ValueError(
                        f"Malware feature length mismatch: expected {len(expected_features)}, got {len(features)}"
                    )
                feature_vec = [float(x) for x in features]
                
            import pandas as pd
            X = pd.DataFrame([feature_vec], columns=expected_features)
            pred = int(self.malware_model.predict(X)[0])
            
            if hasattr(self.malware_model, "predict_proba"):
                probs = self.malware_model.predict_proba(X)[0]
                prob_malware = float(probs[1]) if len(probs) > 1 else float(probs[0])
            else:
                prob_malware = 1.0 if pred == 1 else 0.0
                
            is_malware = bool(pred == 1)
            confidence = prob_malware if is_malware else (1.0 - prob_malware)
            
            return {
                "available": True,
                "model_name": self.malware_metadata.get("model_name", "windows_pe_malware_rf"),
                "model_version": self.malware_metadata.get("model_version", "1.0.0"),
                "is_malware": is_malware,
                "prediction": pred,
                "probability": round(prob_malware, 4),
                "confidence": round(confidence, 4),
                "label": "malicious" if is_malware else "benign"
            }
            
        except Exception as e:
            logger.error(f"Error during Windows PE malware inference: {e}")
            return {
                "available": False,
                "error": str(e),
                "is_malware": False,
                "probability": 0.0,
                "confidence": 0.0
            }


# Global singleton instance
model_manager = ModelManager()
