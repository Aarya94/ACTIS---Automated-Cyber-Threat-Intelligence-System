"""
Tests for ACTIS Automated Documentation and Progress Generator
Automated Cyber Threat Intelligence System — Quality Assurance

Validates RepoInspector, GitAnalyzer, CodebaseAnalyzer, MlModelAnalyzer,
DatabaseAnalyzer, TestSuiteAnalyzer, RoadmapCalculator, and MarkdownReportBuilder.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

# Ensure scripts directory is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from generate_docs import (
    CodebaseAnalyzer,
    DatabaseAnalyzer,
    GitAnalyzer,
    MarkdownReportBuilder,
    MlModelAnalyzer,
    RepoInspector,
    RoadmapCalculator,
    TestSuiteAnalyzer,
)


class TestRepoInspector:
    """Verifies filesystem discovery and directory statistics."""

    def test_audit_directories(self):
        inspector = RepoInspector(PROJECT_ROOT)
        dirs = inspector.audit_directories()
        assert isinstance(dirs, dict)
        assert "config" in dirs
        assert "tests" in dirs
        assert "docs" in dirs
        assert dirs["config"]["is_dir"] is True
        assert dirs["config"]["py_file_count"] >= 1

    def test_get_root_files(self):
        inspector = RepoInspector(PROJECT_ROOT)
        root_files = inspector.get_root_files()
        assert isinstance(root_files, list)
        assert "README.md" in root_files


class TestGitAnalyzer:
    """Verifies Git inspection capabilities."""

    def test_branch_info(self):
        git_analyzer = GitAnalyzer(PROJECT_ROOT)
        info = git_analyzer.get_branch_info()
        assert "branch" in info
        assert "head" in info
        assert info["branch"] != "UNKNOWN"
        assert len(info["head"]) >= 4

    def test_recent_commits(self):
        git_analyzer = GitAnalyzer(PROJECT_ROOT)
        commits = git_analyzer.get_recent_commits(limit=5)
        assert isinstance(commits, list)
        assert len(commits) >= 1
        first = commits[0]
        assert "hash" in first
        assert "author" in first
        assert "date" in first
        assert "type" in first
        assert "message" in first

    def test_working_tree_status(self):
        git_analyzer = GitAnalyzer(PROJECT_ROOT)
        status = git_analyzer.get_working_tree_status()
        assert isinstance(status, dict)
        assert "changed_files_count" in status


class TestCodebaseAnalyzer:
    """Verifies AST-based code analysis."""

    def test_inspect_python_file(self):
        analyzer = CodebaseAnalyzer(PROJECT_ROOT)
        config_file = PROJECT_ROOT / "config" / "settings.py"
        data = analyzer.inspect_file(config_file)
        assert data["loc"] > 50
        assert data["has_docstring"] is True
        class_names = [c["name"] for c in data["classes"]]
        assert "DatabaseConfig" in class_names
        assert "AppConfig" in class_names

    def test_inspect_package(self):
        analyzer = CodebaseAnalyzer(PROJECT_ROOT)
        pkg_data = analyzer.inspect_package("config")
        assert pkg_data["status"] == "IMPLEMENTED"
        assert pkg_data["exists"] is True
        assert pkg_data["total_classes"] >= 2
        assert pkg_data["total_loc"] > 50

    def test_inspect_scaffolded_package(self):
        analyzer = CodebaseAnalyzer(PROJECT_ROOT)
        pkg_data = analyzer.inspect_package("scanners")
        assert pkg_data["status"] == "PARTIALLY IMPLEMENTED"


class TestMlModelAnalyzer:
    """Verifies machine learning model and dataset auditing."""

    def test_audit_models(self):
        ml_analyzer = MlModelAnalyzer(PROJECT_ROOT)
        res = ml_analyzer.audit_models()
        assert res["exists"] is True
        assert "phishing_model.pkl" in res["models"]
        model = res["models"]["phishing_model.pkl"]
        assert model["size_bytes"] > 0
        assert model["has_metadata"] is True
        assert model["metadata_file"] == "phishing_model_metadata.json"

    def test_audit_datasets(self):
        ml_analyzer = MlModelAnalyzer(PROJECT_ROOT)
        res = ml_analyzer.audit_datasets()
        assert res["exists"] is True


class TestDatabaseAnalyzer:
    """Verifies database schema DDL parsing."""

    def test_audit_schema(self):
        db_analyzer = DatabaseAnalyzer(PROJECT_ROOT)
        res = db_analyzer.audit_schema()
        assert res["status"] == "IMPLEMENTED"
        table_names = [t["name"] for t in res["tables"]]
        assert "threats" in table_names
        assert "indicators" in table_names
        assert "scans" in table_names
        assert len(res["indices"]) >= 3


class TestTestSuiteAnalyzer:
    """Verifies test suite discovery."""

    def test_audit_test_files(self):
        test_analyzer = TestSuiteAnalyzer(PROJECT_ROOT)
        res = test_analyzer.audit_test_files()
        assert res["total_test_files"] >= 5
        assert res["total_tests"] >= 30
        assert "test_config_loading.py" in res["test_files"]
        assert "test_threat_database.py" in res["test_files"]


class TestRoadmapCalculator:
    """Verifies reproducible roadmap progress calculation."""

    def test_progress_metrics(self):
        calc = RoadmapCalculator(PROJECT_ROOT)
        prog = calc.calculate_progress()
        assert prog["completed_days"] == 2
        assert prog["total_roadmap_days"] == 112
        assert prog["month1_days"] == 28
        assert prog["estimated_overall_progress_pct"] == 1.79
        assert prog["estimated_month1_progress_pct"] == 7.14
        assert "Completed Roadmap Days / Total Defined Roadmap Days * 100" in prog["calculation_formula"]


class TestMarkdownReportBuilder:
    """Verifies markdown report generation completeness and truthfulness."""

    @pytest.fixture
    def context(self):
        inspector = RepoInspector(PROJECT_ROOT)
        git_analyzer = GitAnalyzer(PROJECT_ROOT)
        code_analyzer = CodebaseAnalyzer(PROJECT_ROOT)
        ml_analyzer = MlModelAnalyzer(PROJECT_ROOT)
        db_analyzer = DatabaseAnalyzer(PROJECT_ROOT)
        test_analyzer = TestSuiteAnalyzer(PROJECT_ROOT)
        roadmap_calc = RoadmapCalculator(PROJECT_ROOT)

        return {
            "project_root": PROJECT_ROOT,
            "dirs": inspector.audit_directories(),
            "root_files": inspector.get_root_files(),
            "git_info": git_analyzer.get_branch_info(),
            "recent_commits": git_analyzer.get_recent_commits(10),
            "tree_status": git_analyzer.get_working_tree_status(),
            "package_audits": {pkg: code_analyzer.inspect_package(pkg) for pkg in inspector.core_packages},
            "models": ml_analyzer.audit_models(),
            "datasets": ml_analyzer.audit_datasets(),
            "db_info": db_analyzer.audit_schema(),
            "test_info": test_analyzer.audit_test_files(),
            "progress": roadmap_calc.calculate_progress(),
        }

    def test_generate_project_status(self, context):
        builder = MarkdownReportBuilder(context)
        content = builder.generate_project_status()
        assert "# ACTIS Project Status" in content
        assert "## Overall Progress" in content
        assert "## Current Milestone" in content
        assert "## Current Week" in content
        assert "## Current Development Day" in content
        assert "## Repository Structure" in content
        assert "## Implemented Components" in content
        assert "## ML Status" in content
        assert "## Database Status" in content
        assert "## Test Status" in content
        assert "## Git Status" in content
        assert "## Recent Development Activity" in content

    def test_generate_module_status(self, context):
        builder = MarkdownReportBuilder(context)
        content = builder.generate_module_status()
        assert "# ACTIS Module Implementation Status" in content
        assert "## Module Status Overview" in content
        assert "| Module | Status | Files / LOC | Notes |" in content
        assert "`config/`" in content

    def test_generate_ml_reference(self, context):
        builder = MarkdownReportBuilder(context)
        content = builder.generate_ml_reference()
        assert "# ACTIS Machine Learning Reference" in content
        assert "## Model Inventory" in content
        assert "phishing_model.pkl" in content
        assert "malware_model.pkl" in content
        assert "## ML Safety Boundaries" in content

    def test_generate_database_reference(self, context):
        builder = MarkdownReportBuilder(context)
        content = builder.generate_database_reference()
        assert "# ACTIS Database Reference" in content
        assert "## Database Architecture" in content
        assert "threats" in content
        assert "indicators" in content
        assert "scans" in content

    def test_generate_test_status(self, context):
        builder = MarkdownReportBuilder(context)
        content = builder.generate_test_status()
        assert "# ACTIS Test Status & Verification Inventory" in content
        assert "## Test Suite Summary" in content
        assert "test_config_loading.py" in content

    def test_generate_changelog(self, context):
        builder = MarkdownReportBuilder(context)
        content = builder.generate_changelog()
        assert "# ACTIS Development Changelog" in content
        assert "| Date | Commit | Type | Description | Verification Status |" in content


class TestGeneratorCli:
    """Verifies that the generator script runs non-destructively via CLI."""

    def test_cli_check_mode(self):
        res = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "scripts" / "generate_docs.py"), "--check", "-v"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert res.returncode == 0
        assert "ACTIS Repository Audit" in res.stdout
        assert "Overall Progress" in res.stdout
