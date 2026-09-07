"""Small utility to validate the expected ACTIS directory structure.

This is intentionally lightweight and used by the Week 1 test suite.
It will not modify source artifacts, only create missing top-level directories used by ACTIS (logs, data, models).
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = [
    "data",
    "models",
    "scanners",
    "detection_engine",
    "threat_intelligence",
    "reports",
    "notifications",
    "dashboard",
    "assistant",
    "backend",
    "config",
    "tests",
    "logs",
]


def validate(create_missing: bool = True) -> bool:
    missing = []
    for d in REQUIRED:
        p = ROOT / d
        if not p.exists():
            missing.append(p)
            if create_missing:
                p.mkdir(parents=True, exist_ok=True)
    if missing:
        print("Created missing directories:" if create_missing else "Missing directories:")
        for m in missing:
            print(" -", m)
    else:
        print("All required ACTIS top-level directories present.")
    return len(missing) == 0


if __name__ == "__main__":
    ok = validate(create_missing=True)
    sys.exit(0 if ok else 1)
