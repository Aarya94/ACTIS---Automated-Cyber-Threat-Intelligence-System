"""
ACTIS Git Hook Setup Utility
Automated Cyber Threat Intelligence System

Installs or verifies the pre-commit hook that automatically runs
`python scripts/generate_docs.py` and stages `docs/generated/`
before each commit.
"""

import sys
from pathlib import Path

HOOK_CONTENT = """#!/bin/sh
# ACTIS Pre-Commit Hook: Auto-synchronize generated documentation
echo "[ACTIS Hook] Running documentation generator..."

if [ -f "venv/Scripts/python.exe" ]; then
    "venv/Scripts/python.exe" scripts/generate_docs.py
elif command -v python3 >/dev/null 2>&1; then
    python3 scripts/generate_docs.py
elif command -v python >/dev/null 2>&1; then
    python scripts/generate_docs.py
else
    echo "[ACTIS Hook] Warning: Python not found in path, skipping auto-doc generation."
    exit 0
fi

# Automatically stage the updated generated documentation
git add docs/generated/
"""


def install_hook() -> int:
    root_dir = Path(__file__).resolve().parent.parent
    hooks_dir = root_dir / ".git" / "hooks"

    if not hooks_dir.exists():
        print(f"Error: .git/hooks directory not found at {hooks_dir}")
        return 1

    pre_commit_file = hooks_dir / "pre-commit"
    try:
        pre_commit_file.write_text(HOOK_CONTENT, encoding="utf-8")
        print(f"Successfully installed ACTIS pre-commit hook at: {pre_commit_file}")
        return 0
    except Exception as err:
        print(f"Failed to write pre-commit hook: {err}")
        return 1


if __name__ == "__main__":
    sys.exit(install_hook())
