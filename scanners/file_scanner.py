"""
ACTIS Single File Scanner Module
Provides direct helper functions to scan an individual file via the central detection engine.
"""

from pathlib import Path
from typing import Dict, Any, Optional
from detection_engine.threat_detector import threat_detector
from config.config import get_logger

logger = get_logger("FileScanner")


def scan_file(file_path: Path, scan_id: Optional[int] = None, check_external: bool = False) -> Dict[str, Any]:
    """
    Scans a single file using safe, read-only static analysis and the risk engine.
    """
    path = Path(file_path)
    if not path.exists():
        return {
            "error": f"File does not exist: {path}",
            "is_valid": False,
            "target": str(path),
            "score": 0.0,
            "risk_level": "LOW",
            "is_threat": False
        }
    return threat_detector.analyze_file(path, scan_id=scan_id, check_external=check_external)
