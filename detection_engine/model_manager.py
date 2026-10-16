"""
ACTIS Model Manager Module
Coordinates machine learning model loading, schema validation, version verification,
and safe inference for phishing URL and Windows PE malware models.
Provides structured MLPredictionResult generation and feature contract validation.
"""

import json
from typing import Dict, Any, List, Optional, Union, Tuple
import numpy as np
import pandas as pd
import joblib

from config.config import (
    PHISHING_MODEL_PATH,
    PHISHING_METADATA_PATH,
    MALWARE_MODEL_PATH,
    MALWARE_METADATA_PATH,
    get_logger
)
from detection_engine.ml_prediction_contract import (
    MLModelType,
    MLPredictionStatus,
    MLPredictionResult,
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
        self.phishing_metadata: Dict[str, Any] = {}
        self.malware_model = None
        self.malware_metadata: Dict[str, Any] = {}
        self._load_models()
        self._initialized = True

    def _load_models(self):
        """Loads both phishing and malware models and their metadata schemas."""
        # 1. Phishing Model
        if PHISHING_MODEL_PATH.exists() and PHISHING_METADATA_PATH.exists():
            try:
                self.phishing_model = joblib.load(PHISHING_MODEL_PATH)
                if hasattr(self.phishing_model, "n_jobs"):
                    self.phishing_model.n_jobs = 1
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
                if hasattr(self.malware_model, "n_jobs"):
                    self.malware_model.n_jobs = 1
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

    # --------------------------------------------------------------------------
    # Status & Feature Schema Accessors
    # --------------------------------------------------------------------------

    def is_phishing_model_available(self) -> bool:
        """Returns True if phishing model is loaded and ready for inference."""
        return self.phishing_model is not None

    def is_malware_model_available(self) -> bool:
        """Returns True if malware model is loaded and ready for inference."""
        return self.malware_model is not None

    def get_phishing_feature_schema(self) -> List[str]:
        """Returns ordered list of feature names expected by the phishing model."""
        return self.phishing_metadata.get("features", [])

    def get_malware_feature_schema(self) -> List[str]:
        """Returns ordered list of feature names expected by the malware model."""
        return self.malware_metadata.get("features", [])

    def get_phishing_features(self) -> List[str]:
        """Alias for get_phishing_feature_schema."""
        return self.get_phishing_feature_schema()

    def get_malware_features(self) -> List[str]:
        """Alias for get_malware_feature_schema."""
        return self.get_malware_feature_schema()

    def get_model_metadata(self, model_type: MLModelType) -> Dict[str, Any]:
        """Returns complete metadata dictionary for the requested model type."""
        if model_type == MLModelType.PHISHING_URL:
            return dict(self.phishing_metadata)
        elif model_type == MLModelType.WINDOWS_PE_MALWARE:
            return dict(self.malware_metadata)
        return {}

    def validate_feature_vector(self, model_type: MLModelType, features: List[float]) -> Tuple[bool, Optional[str]]:
        """Validates that a feature vector matches expected dimensions and value constraints."""
        expected_features = (
            self.get_phishing_feature_schema() if model_type == MLModelType.PHISHING_URL
            else self.get_malware_feature_schema()
        )
        if not expected_features:
            return True, None

        if len(features) != len(expected_features):
            return False, f"Expected {len(expected_features)} features, received {len(features)}."

        if any(np.isnan(f) or np.isinf(f) for f in features):
            return False, "Feature vector contains NaN or Infinite values."

        return True, None

    # --------------------------------------------------------------------------
    # Structured Inference (Day 6 Contract)
    # --------------------------------------------------------------------------

    def predict_phishing_structured(self, features: Union[List[float], Dict[str, Any]]) -> MLPredictionResult:
        """
        Executes phishing model inference returning a strongly-typed MLPredictionResult.
        """
        model_name = self.phishing_metadata.get("model_name", "phishing_rf")
        model_version = self.phishing_metadata.get("model_version", "1.0.0")

        if not self.is_phishing_model_available():
            return MLPredictionResult.unavailable(
                model_name=model_name,
                model_type=MLModelType.PHISHING_URL,
                reason="Phishing model binary is not loaded or missing."
            )

        expected_cols = self.get_phishing_feature_schema()
        try:
            if isinstance(features, dict):
                feature_vec = [float(features.get(f, 0)) for f in expected_cols]
            else:
                feature_vec = [float(x) for x in features]

            valid, error_msg = self.validate_feature_vector(MLModelType.PHISHING_URL, feature_vec)
            if not valid:
                return MLPredictionResult(
                    model_name=model_name,
                    model_version=model_version,
                    model_type=MLModelType.PHISHING_URL,
                    status=MLPredictionStatus.SCHEMA_MISMATCH,
                    error_message=error_msg
                )

            X = pd.DataFrame([feature_vec], columns=expected_cols)
            pred = int(self.phishing_model.predict(X)[0])
            
            if hasattr(self.phishing_model, "predict_proba"):
                probs = self.phishing_model.predict_proba(X)[0]
                prob_phishing = float(probs[1]) if len(probs) > 1 else float(probs[0])
            else:
                prob_phishing = 1.0 if pred == 1 else 0.0

            is_threat = (pred == 1)
            confidence = prob_phishing if is_threat else (1.0 - prob_phishing)
            label = "phishing" if is_threat else "legitimate"

            return MLPredictionResult(
                model_name=model_name,
                model_version=model_version,
                model_type=MLModelType.PHISHING_URL,
                status=MLPredictionStatus.AVAILABLE,
                is_threat=is_threat,
                probability=round(prob_phishing, 4),
                confidence=round(confidence, 4),
                prediction_label=label,
                features_used=expected_cols
            )
        except Exception as e:
            logger.error(f"Error executing phishing prediction: {e}")
            return MLPredictionResult.from_error(model_name, MLModelType.PHISHING_URL, e)

    def predict_malware_structured(self, features: Union[List[float], Dict[str, Any]]) -> MLPredictionResult:
        """
        Executes Windows PE malware model inference returning a strongly-typed MLPredictionResult.
        """
        model_name = self.malware_metadata.get("model_name", "windows_pe_malware_rf")
        model_version = self.malware_metadata.get("model_version", "1.0.0")

        if not self.is_malware_model_available():
            return MLPredictionResult.unavailable(
                model_name=model_name,
                model_type=MLModelType.WINDOWS_PE_MALWARE,
                reason="Malware model binary is not loaded or missing."
            )

        expected_cols = self.get_malware_feature_schema()
        try:
            if isinstance(features, dict):
                feature_vec = [float(features.get(f, 0)) for f in expected_cols]
            else:
                feature_vec = [float(x) for x in features]

            valid, error_msg = self.validate_feature_vector(MLModelType.WINDOWS_PE_MALWARE, feature_vec)
            if not valid:
                return MLPredictionResult(
                    model_name=model_name,
                    model_version=model_version,
                    model_type=MLModelType.WINDOWS_PE_MALWARE,
                    status=MLPredictionStatus.SCHEMA_MISMATCH,
                    error_message=error_msg
                )

            X = pd.DataFrame([feature_vec], columns=expected_cols)
            pred = int(self.malware_model.predict(X)[0])
            
            if hasattr(self.malware_model, "predict_proba"):
                probs = self.malware_model.predict_proba(X)[0]
                prob_malware = float(probs[1]) if len(probs) > 1 else float(probs[0])
            else:
                prob_malware = 1.0 if pred == 1 else 0.0

            is_threat = (pred == 1)
            confidence = prob_malware if is_threat else (1.0 - prob_malware)
            label = "malicious" if is_threat else "benign"

            return MLPredictionResult(
                model_name=model_name,
                model_version=model_version,
                model_type=MLModelType.WINDOWS_PE_MALWARE,
                status=MLPredictionStatus.AVAILABLE,
                is_threat=is_threat,
                probability=round(prob_malware, 4),
                confidence=round(confidence, 4),
                prediction_label=label,
                features_used=expected_cols
            )
        except Exception as e:
            logger.error(f"Error executing malware prediction: {e}")
            return MLPredictionResult.from_error(model_name, MLModelType.WINDOWS_PE_MALWARE, e)

    # --------------------------------------------------------------------------
    # Legacy Compatibility Methods
    # --------------------------------------------------------------------------

    def prediction_to_legacy_dict(self, res: MLPredictionResult) -> Dict[str, Any]:
        """
        Converts a strongly-typed MLPredictionResult to the legacy dictionary format
        without re-executing inference.
        """
        threat_key = "is_phishing" if res.model_type == MLModelType.PHISHING_URL else "is_malware"
        if res.status != MLPredictionStatus.AVAILABLE:
            error_msg = res.error_message or (
                "Phishing ML model not loaded." if res.model_type == MLModelType.PHISHING_URL
                else "Windows PE Malware ML model not loaded."
            )
            return {
                "available": False,
                "error": error_msg,
                threat_key: False,
                "probability": 0.0,
                "confidence": 0.0
            }

        return {
            "available": True,
            "model_name": res.model_name,
            "model_version": res.model_version,
            threat_key: res.is_threat,
            "prediction": 1 if res.is_threat else 0,
            "probability": res.probability,
            "confidence": res.confidence,
            "label": res.prediction_label
        }

    def predict_phishing(self, features: Union[List[float], Dict[str, Any]]) -> Dict[str, Any]:
        """Legacy dict-based phishing prediction."""
        res = self.predict_phishing_structured(features)
        return self.prediction_to_legacy_dict(res)

    def predict_malware(self, features: Union[List[float], Dict[str, Any]]) -> Dict[str, Any]:
        """Legacy dict-based malware prediction."""
        res = self.predict_malware_structured(features)
        return self.prediction_to_legacy_dict(res)


# Global singleton instance
model_manager = ModelManager()
