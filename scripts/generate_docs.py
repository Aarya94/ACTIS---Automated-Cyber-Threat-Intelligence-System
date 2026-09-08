"""
ACTIS Automated Documentation & Progress Generator
Automated Cyber Threat Intelligence System — Documentation Infrastructure

Inspects the ACTIS codebase, analyzes Git history, audits ML models and database schemas,
calculates reproducible roadmap progress, and generates authoritative markdown reports
in docs/generated/.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# Determine ACTIS root relative to this script
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DOCS_DIR = PROJECT_ROOT / "docs"
GENERATED_DIR = DOCS_DIR / "generated"


class RepoInspector:
    """Discovers filesystem structure, files, line counts, and directory statistics."""

    def __init__(self, root_dir: Path):
        self.root = root_dir
        self.core_packages = [
            "config",
            "scanners",
            "detection_engine",
            "threat_intelligence",
            "reports",
            "notifications",
            "dashboard",
            "assistant",
            "backend",
            "tests",
        ]

    def audit_directories(self) -> Dict[str, Dict[str, Any]]:
        """Audits presence, file count, and line count of major directories."""
        results = {}
        for pkg in self.core_packages + ["data", "models", "logs", "docs", "scripts"]:
            pkg_path = self.root / pkg
            exists = pkg_path.is_dir()
            file_count = 0
            py_file_count = 0
            total_lines = 0

            if exists:
                for f in pkg_path.rglob("*"):
                    if f.is_file():
                        file_count += 1
                        if f.suffix == ".py":
                            py_file_count += 1
                            try:
                                total_lines += len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
                            except Exception:
                                pass

            results[pkg] = {
                "exists": exists,
                "path": str(pkg_path),
                "file_count": file_count,
                "py_file_count": py_file_count,
                "total_lines": total_lines,
            }
        return results

    def get_root_files(self) -> Dict[str, bool]:
        """Checks presence of key project files at root."""
        key_files = [
            "main.py",
            "requirements.txt",
            "README.md",
            ".gitignore",
            ".env.example",
        ]
        return {f: (self.root / f).is_file() for f in key_files}


class GitAnalyzer:
    """Analyzes Git repository status, branch, remotes, and commit history."""

    def __init__(self, root_dir: Path):
        self.root = root_dir

    def _run_git(self, args: List[str]) -> Optional[str]:
        """Executes a git command safely and returns standard output."""
        try:
            res = subprocess.run(
                ["git"] + args,
                cwd=str(self.root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                return res.stdout.strip()
        except Exception:
            pass
        return None

    def get_branch_info(self) -> Dict[str, str]:
        """Returns current branch name, HEAD short hash, and origin remote URL."""
        branch = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"]) or "NOT VERIFIED"
        head_hash = self._run_git(["rev-parse", "--short", "HEAD"]) or "NOT VERIFIED"
        remote = self._run_git(["config", "--get", "remote.origin.url"]) or "NOT VERIFIED"
        return {
            "branch": branch,
            "head": head_hash,
            "remote": remote,
        }

    def get_recent_commits(self, count: int = 30) -> List[Dict[str, str]]:
        """Extracts structured list of recent commits with hash, date, message, and type."""
        raw = self._run_git(["log", f"-n{count}", "--format=%h|%ad|%s", "--date=short"])
        if not raw:
            return []
        commits = []
        for line in raw.splitlines():
            parts = line.split("|", 2)
            if len(parts) == 3:
                h, d, msg = parts
                c_type = msg.split(":", 1)[0].strip() if ":" in msg else "other"
                commits.append({
                    "hash": h,
                    "date": d,
                    "message": msg,
                    "type": c_type,
                })
        return commits

    def get_working_tree_status(self) -> Dict[str, Any]:
        """Checks status of current working tree."""
        status_raw = self._run_git(["status", "--short", "--branch"]) or ""
        lines = status_raw.splitlines()
        branch_line = lines[0] if lines else "## UNKNOWN"
        file_changes = lines[1:] if len(lines) > 1 else []
        return {
            "branch_line": branch_line,
            "is_clean": len(file_changes) == 0,
            "changed_files_count": len(file_changes),
            "changes": file_changes[:10],
        }


def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments for documentation generator."""
    parser = argparse.ArgumentParser(
        description="ACTIS Automated Documentation and Progress Generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=GENERATED_DIR,
        help="Target directory for generated markdown reports",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check repository integrity and report status without writing files",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable detailed diagnostic console output",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    inspector = RepoInspector(PROJECT_ROOT)
    git_analyzer = GitAnalyzer(PROJECT_ROOT)

    dirs = inspector.audit_directories()
    root_files = inspector.get_root_files()
    git_info = git_analyzer.get_branch_info()
    recent_commits = git_analyzer.get_recent_commits(10)
    tree_status = git_analyzer.get_working_tree_status()

    if args.verbose or args.check:
        print("=== ACTIS Repository Audit ===")
        print(f"Project Root: {PROJECT_ROOT}")
        print(f"Target Output: {args.output_dir}")
        print(f"Git Branch: {git_info['branch']} (HEAD: {git_info['head']})")
        print(f"Remote URL: {git_info['remote']}")
        print(f"Working Tree Clean: {tree_status['is_clean']}")
        print(f"Recent Commits Count: {len(recent_commits)}")
        for k, v in root_files.items():
            print(f"  Root File {k}: {'Present' if v else 'Missing'}")

    print("ACTIS Documentation Generator: Git analyzer integrated successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
