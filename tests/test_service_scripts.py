"""
Unit and Non-Privileged Integration Tests for ACTIS Windows Service PowerShell Scripts
Tests scripts/install_windows_service.ps1, status_windows_service.ps1, and uninstall_windows_service.ps1.
Uses -DryRun and read-only status checks; strictly avoids modifying system SCM.
"""

import json
import os
import subprocess
from pathlib import Path
import pytest

from notifications.windows_toast import get_powershell_executable

ACTIS_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ACTIS_ROOT / "scripts"


class TestServiceScriptsIntegrity:
    """Verifies script presence, safety invariants, and syntax."""

    def test_scripts_exist_and_readable(self):
        scripts = [
            SCRIPTS_DIR / "install_windows_service.ps1",
            SCRIPTS_DIR / "status_windows_service.ps1",
            SCRIPTS_DIR / "uninstall_windows_service.ps1",
        ]
        for script in scripts:
            assert script.exists(), f"Missing script: {script}"
            content = script.read_text(encoding="utf-8")
            assert len(content) > 100

    def test_scripts_contain_no_hardcoded_credentials(self):
        for script_name in ["install_windows_service.ps1", "status_windows_service.ps1", "uninstall_windows_service.ps1"]:
            content = (SCRIPTS_DIR / script_name).read_text(encoding="utf-8").lower()
            assert "password" not in content or "$env:" in content or "param" in content
            assert "api_key" not in content
            assert "secret" not in content

    def test_scripts_contain_no_defender_tampering(self):
        for script_name in ["install_windows_service.ps1", "status_windows_service.ps1", "uninstall_windows_service.ps1"]:
            content = (SCRIPTS_DIR / script_name).read_text(encoding="utf-8").lower()
            assert "set-mppreference" not in content
            assert "disablerealtimemonitoring" not in content
            assert "exclusionpath" not in content


class TestServiceScriptsExecution:
    """Tests execution of PowerShell scripts in non-privileged / DryRun modes."""

    @pytest.fixture(autouse=True)
    def check_powershell(self):
        self.ps_exe = get_powershell_executable()
        if not self.ps_exe:
            pytest.skip("powershell.exe not found on system")

    def test_install_script_dry_run(self):
        script = SCRIPTS_DIR / "install_windows_service.ps1"
        cmd = [
            self.ps_exe,
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", str(script),
            "-DryRun",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ACTIS_ROOT), timeout=10)
        assert result.returncode == 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        assert "[DRY-RUN] Validation Successful!" in result.stdout
        assert "ACTISProtectionService" in result.stdout
        assert "main.py" in result.stdout

    def test_status_script_json_output(self):
        script = SCRIPTS_DIR / "status_windows_service.ps1"
        cmd = [
            self.ps_exe,
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", str(script),
            "-AsJson",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ACTIS_ROOT), timeout=10)
        assert result.returncode == 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"

        # Parse JSON output
        data = json.loads(result.stdout)
        assert "ServiceName" in data
        assert data["ServiceName"] == "ACTISProtectionService"
        assert "Installed" in data
        assert "Status" in data
        assert isinstance(data["Installed"], bool)

    def test_uninstall_script_dry_run_or_uninstalled(self):
        script = SCRIPTS_DIR / "uninstall_windows_service.ps1"
        cmd = [
            self.ps_exe,
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", str(script),
            "-DryRun",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ACTIS_ROOT), timeout=10)
        assert result.returncode == 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        # Either reports not installed or dry-run pre-flight successful
        assert ("not installed in Windows SCM" in result.stdout) or ("[DRY-RUN]" in result.stdout)
