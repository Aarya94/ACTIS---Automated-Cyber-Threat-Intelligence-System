"""
ACTIS Message & Phishing Benchmark Dataset Module
Provides structured contracts, schema validation, and loading utilities
for the versioned synthetic message analysis verification benchmark corpus.
"""

import json
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Set


VALID_LABELS: Set[str] = {"PHISHING", "BENIGN"}

VALID_SCENARIOS: Set[str] = {
    "credential_harvesting",
    "impersonation_social_engineering",
    "financial_manipulation",
    "deceptive_links_url_obfuscation",
    "mixed_phishing_indicators",
    "legitimate_security_account",
    "benign_financial_business",
    "security_awareness_education",
    "malformed_resource_limits"
}

DEFAULT_MANIFEST_PATH = Path("tests/fixtures/phishing_benchmark/manifest.json")


class DatasetValidationError(Exception):
    """Raised when benchmark dataset manifest fails structural or semantic validation."""
    pass


@dataclass(frozen=True)
class BenchmarkSample:
    """
    Contract for an individual synthetic benchmark evaluation sample.
    Immutable to guarantee deterministic evaluation.
    """
    id: str
    label: str
    scenario: str
    description: str
    content: Union[str, bytes]
    is_mime: bool = False
    expected_indicators: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the benchmark sample to a dictionary representation."""
        return {
            "id": self.id,
            "label": self.label,
            "scenario": self.scenario,
            "description": self.description,
            "content": self.content if isinstance(self.content, str) else self.content.decode("latin1", errors="replace"),
            "is_mime": self.is_mime,
            "expected_indicators": list(self.expected_indicators),
            "metadata": dict(self.metadata)
        }


@dataclass
class BenchmarkDataset:
    """
    In-memory representation of the loaded and validated benchmark dataset.
    """
    version: str
    description: str
    created_date: str
    license: str
    dataset_hash: str
    samples: List[BenchmarkSample]

    def __len__(self) -> int:
        return len(self.samples)

    def __iter__(self):
        return iter(self.samples)

    def get_sample(self, sample_id: str) -> Optional[BenchmarkSample]:
        """Retrieves sample by unique ID or returns None if not found."""
        for s in self.samples:
            if s.id == sample_id:
                return s
        return None

    @property
    def phishing_samples(self) -> List[BenchmarkSample]:
        """Returns all ground-truth phishing samples."""
        return [s for s in self.samples if s.label == "PHISHING"]

    @property
    def benign_samples(self) -> List[BenchmarkSample]:
        """Returns all ground-truth benign samples."""
        return [s for s in self.samples if s.label == "BENIGN"]

    @property
    def edge_case_samples(self) -> List[BenchmarkSample]:
        """Returns all edge cases and robustness boundary samples."""
        return [s for s in self.samples if s.scenario == "malformed_resource_limits"]

    @property
    def standard_samples(self) -> List[BenchmarkSample]:
        """Returns all standard samples excluding edge-case robustness boundary tests."""
        return [s for s in self.samples if s.scenario != "malformed_resource_limits"]

    def filter_by_scenario(self, scenario: str) -> List[BenchmarkSample]:
        """Returns samples belonging to a specific scenario category."""
        return [s for s in self.samples if s.scenario == scenario]

    def summary(self) -> Dict[str, Any]:
        """Returns statistical distribution of dataset samples."""
        scenarios: Dict[str, int] = {}
        for s in self.samples:
            scenarios[s.scenario] = scenarios.get(s.scenario, 0) + 1

        return {
            "version": self.version,
            "hash": self.dataset_hash,
            "total_count": len(self.samples),
            "phishing_count": len(self.phishing_samples),
            "benign_count": len(self.benign_samples),
            "edge_case_count": len(self.edge_case_samples),
            "scenarios": scenarios
        }


def validate_dataset_manifest(data: Any) -> None:
    """
    Validates benchmark manifest data structure and semantics.
    Raises DatasetValidationError on any missing required field, duplicate ID,
    invalid label, unsupported scenario, or malformed type.
    """
    if not isinstance(data, dict):
        raise DatasetValidationError(f"Dataset manifest must be a JSON object, received {type(data).__name__}.")

    if "dataset_version" not in data or not isinstance(data["dataset_version"], str) or not data["dataset_version"].strip():
        raise DatasetValidationError("Manifest missing required non-empty 'dataset_version' string.")

    if "samples" not in data or not isinstance(data["samples"], list):
        raise DatasetValidationError("Manifest missing required 'samples' list.")

    if not data["samples"]:
        raise DatasetValidationError("Manifest 'samples' list cannot be empty.")

    seen_ids: Set[str] = set()

    for idx, item in enumerate(data["samples"]):
        if not isinstance(item, dict):
            raise DatasetValidationError(f"Sample at index {idx} is not an object.")

        # Required fields
        for req in ("id", "label", "scenario", "description", "content"):
            if req not in item:
                raise DatasetValidationError(f"Sample at index {idx} missing required field '{req}'.")

        sample_id = item["id"]
        if not isinstance(sample_id, str) or not sample_id.strip():
            raise DatasetValidationError(f"Sample at index {idx} has invalid or empty 'id'.")

        if sample_id in seen_ids:
            raise DatasetValidationError(f"Duplicate sample ID detected: '{sample_id}' at index {idx}.")
        seen_ids.add(sample_id)

        label = item["label"]
        if label not in VALID_LABELS:
            raise DatasetValidationError(
                f"Sample '{sample_id}' has invalid label '{label}'. Must be one of {sorted(VALID_LABELS)}."
            )

        scenario = item["scenario"]
        if scenario not in VALID_SCENARIOS:
            raise DatasetValidationError(
                f"Sample '{sample_id}' has unsupported scenario '{scenario}'. Must be one of {sorted(VALID_SCENARIOS)}."
            )

        if not isinstance(item["description"], str) or not item["description"].strip():
            raise DatasetValidationError(f"Sample '{sample_id}' has empty description.")

        if not isinstance(item["content"], (str, bytes)):
            raise DatasetValidationError(f"Sample '{sample_id}' content must be str or bytes, got {type(item['content']).__name__}.")


def compute_manifest_hash(data: Dict[str, Any]) -> str:
    """Computes deterministic SHA-256 hash of dataset manifest."""
    serialized = json.dumps(data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def load_benchmark_dataset(manifest_path: Optional[Union[str, Path]] = None) -> BenchmarkDataset:
    """
    Loads and validates the benchmark dataset from JSON file.
    If path is omitted, uses the default project fixture path.
    """
    path = Path(manifest_path) if manifest_path else DEFAULT_MANIFEST_PATH

    if not path.exists():
        raise FileNotFoundError(f"Benchmark manifest fixture file not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    validate_dataset_manifest(data)
    d_hash = compute_manifest_hash(data)

    parsed_samples = []
    for item in data["samples"]:
        sample = BenchmarkSample(
            id=item["id"],
            label=item["label"],
            scenario=item["scenario"],
            description=item["description"],
            content=item["content"],
            is_mime=bool(item.get("is_mime", False)),
            expected_indicators=list(item.get("expected_indicators", [])),
            metadata=dict(item.get("metadata", {}))
        )
        parsed_samples.append(sample)

    return BenchmarkDataset(
        version=data.get("dataset_version", "1.0.0"),
        description=data.get("description", ""),
        created_date=data.get("created_date", ""),
        license=data.get("license", ""),
        dataset_hash=d_hash,
        samples=parsed_samples
    )
