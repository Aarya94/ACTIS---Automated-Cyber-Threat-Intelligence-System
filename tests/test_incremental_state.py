"""
ACTIS Incremental Scan State Regression Tests
Tests file change classification (NEW, UNCHANGED, CHANGED, REMOVED),
cryptographic identity persistence in SQLite, version invalidation,
pruning, and end-to-end DeviceScanner incremental scan skip behavior.
"""

import os
import time
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch

from scanners.incremental_state import (
    IncrementalStateManager,
    FileScanState,
    FileChangeType,
    FileScanStatus,
    CURRENT_ANALYZER_VERSION,
    CURRENT_MODEL_VERSION,
    CURRENT_RULE_VERSION
)
from scanners.device_scanner import DeviceScanner
from reports.threat_database import (
    save_file_scan_state,
    get_file_scan_state,
    get_all_file_scan_states,
    delete_file_scan_state,
    clear_file_scan_states
)


class TestIncrementalScanState(unittest.TestCase):
    """Test suite for incremental scan state, change detection, and persistence."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temp_dir.name)
        clear_file_scan_states()
        self.manager = IncrementalStateManager(auto_load=False)

    def tearDown(self):
        clear_file_scan_states()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_file_scan_state_serialization_roundtrip(self):
        """FileScanState should serialize to dict and deserialize losslessly."""
        original = FileScanState(
            canonical_path=str(self.root_path / "app.exe"),
            file_size=2048,
            mtime=1690000000.5,
            sha256="abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            last_scanned_at="2026-10-09T10:00:00Z",
            scan_status=FileScanStatus.SUSPICIOUS.value,
            risk_score=75.5,
            risk_level="HIGH",
            analyzer_version=CURRENT_ANALYZER_VERSION,
            model_version=CURRENT_MODEL_VERSION,
            rule_version=CURRENT_RULE_VERSION,
            detection_reasons=["Heuristic alert", "Suspicious section"]
        )

        d = original.to_dict()
        reconstructed = FileScanState.from_dict(d)

        self.assertEqual(original.canonical_path, reconstructed.canonical_path)
        self.assertEqual(original.file_size, reconstructed.file_size)
        self.assertAlmostEqual(original.mtime, reconstructed.mtime, places=3)
        self.assertEqual(original.sha256, reconstructed.sha256)
        self.assertEqual(original.scan_status, reconstructed.scan_status)
        self.assertEqual(original.risk_score, reconstructed.risk_score)
        self.assertEqual(original.risk_level, reconstructed.risk_level)
        self.assertEqual(original.detection_reasons, reconstructed.detection_reasons)
        self.assertTrue(reconstructed.is_threat)
        self.assertTrue(reconstructed.is_version_compatible())

    def test_sqlite_persistence_crud(self):
        """Verify save, lookup, list, delete, and clear operations in SQLite threat database."""
        test_path = str((self.root_path / "persist_test.dll").resolve())
        state = FileScanState(
            canonical_path=test_path,
            file_size=4096,
            mtime=1700000000.0,
            sha256="1111222233334444555566667777888899990000aaaaabbbbccccddddeeeeffff",
            last_scanned_at="2026-10-09T12:00:00Z",
            scan_status="CLEAN",
            risk_score=5.0,
            risk_level="LOW",
            detection_reasons=["Known good"]
        )

        save_file_scan_state(state.to_dict())

        # Lookup by canonical path
        retrieved = get_file_scan_state(test_path)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["canonical_path"], test_path)
        self.assertEqual(retrieved["file_size"], 4096)
        self.assertEqual(retrieved["scan_status"], "CLEAN")

        # Get all
        all_states = get_all_file_scan_states()
        self.assertGreaterEqual(len(all_states), 1)
        self.assertTrue(any(s["canonical_path"] == test_path for s in all_states))

        # Delete
        self.assertTrue(delete_file_scan_state(test_path))
        self.assertIsNone(get_file_scan_state(test_path))

    def test_change_detection_new_vs_unchanged_vs_modified(self):
        """Test deterministic classification: NEW_FILE, UNCHANGED_FILE, CHANGED_FILE."""
        test_file = self.root_path / "target.exe"
        test_file.write_bytes(b"MZ initial executable payload")

        # 1. First inspection: should be NEW_FILE
        status, prev, meta = self.manager.check_file_status(test_file)
        self.assertEqual(status, FileChangeType.NEW_FILE)
        self.assertIsNone(prev)
        self.assertIsNotNone(meta)

        # Record state into manager
        now_str = datetime.now(timezone.utc).isoformat()
        state = FileScanState(
            canonical_path=meta.canonical_path,
            file_size=meta.file_size,
            mtime=meta.mtime,
            sha256="dummy_hash_1234",
            last_scanned_at=now_str,
            scan_status="CLEAN",
            risk_score=0.0
        )
        self.manager.record_state(state)

        # 2. Second inspection without changes: should be UNCHANGED_FILE
        status, prev, meta = self.manager.check_file_status(test_file)
        self.assertEqual(status, FileChangeType.UNCHANGED_FILE)
        self.assertIsNotNone(prev)

        # 3. Third inspection after modifying file content and size: should be CHANGED_FILE
        time.sleep(0.01)  # Ensure mtime advances if needed
        test_file.write_bytes(b"MZ modified executable with appended malicious payload bytes")
        status, prev, meta = self.manager.check_file_status(test_file)
        self.assertEqual(status, FileChangeType.CHANGED_FILE)

    def test_change_detection_removed_file(self):
        """Deleting a previously scanned file flags it as REMOVED_FILE."""
        test_file = self.root_path / "to_delete.exe"
        test_file.write_bytes(b"Temporary file")
        canonical = str(test_file.resolve())

        state = FileScanState(
            canonical_path=canonical,
            file_size=14,
            mtime=test_file.stat().st_mtime,
            sha256="hash_to_delete",
            last_scanned_at="2026-10-09T00:00:00Z"
        )
        self.manager.record_state(state)

        # Remove from disk
        test_file.unlink()

        status, prev, meta = self.manager.check_file_status(test_file)
        self.assertEqual(status, FileChangeType.REMOVED_FILE)
        self.assertIsNotNone(prev)

    def test_change_detection_version_incompatibility(self):
        """If analyzer, model, or rule version changes, cached state must be reanalyzed."""
        test_file = self.root_path / "versioned.exe"
        test_file.write_bytes(b"versioned test")
        meta = self.manager.check_file_status(test_file)[2]

        # Record with an older analyzer version
        old_state = FileScanState(
            canonical_path=meta.canonical_path,
            file_size=meta.file_size,
            mtime=meta.mtime,
            sha256="v_hash",
            last_scanned_at="2026-10-09T00:00:00Z",
            analyzer_version="0.9.0"  # Outdated version!
        )
        self.manager.record_state(old_state)

        status, prev, _ = self.manager.check_file_status(test_file)
        self.assertEqual(status, FileChangeType.CHANGED_FILE)

    def test_state_persistence_across_manager_instances(self):
        """States saved by one manager instance survive and load in a new instance."""
        test_path = str((self.root_path / "persist_across.exe").resolve())
        state = FileScanState(
            canonical_path=test_path,
            file_size=500,
            mtime=1695000000.0,
            sha256="survive_restart_sha256",
            last_scanned_at="2026-10-09T01:00:00Z",
            scan_status="CLEAN"
        )
        self.manager.record_state(state)

        # Instantiate a completely fresh manager with auto_load=True
        fresh_manager = IncrementalStateManager(auto_load=True)
        self.assertGreaterEqual(fresh_manager.get_cached_count(), 1)
        loaded = fresh_manager.get_state(test_path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.sha256, "survive_restart_sha256")

    def test_prune_missing_files(self):
        """Pruning removes records of files not present in the current discovered set."""
        p1 = str((self.root_path / "f1.exe").resolve())
        p2 = str((self.root_path / "f2.exe").resolve())

        self.manager.record_state(FileScanState(p1, 10, 100.0, "h1", "2026-10-09"))
        self.manager.record_state(FileScanState(p2, 20, 200.0, "h2", "2026-10-09"))
        self.assertEqual(self.manager.get_cached_count(), 2)

        # Prune keeping only p1
        pruned = self.manager.prune_missing_files({p1})
        self.assertEqual(pruned, 1)
        self.assertEqual(self.manager.get_cached_count(), 1)
        self.assertIsNotNone(self.manager.get_state(p1))
        self.assertIsNone(self.manager.get_state(p2))

    def test_device_scanner_incremental_integration_end_to_end(self):
        """
        Verify that DeviceScanner skips re-analysis for unchanged files
        and re-analyzes modified files across successive scans.
        """
        f1 = self.root_path / "sample1.txt"
        f2 = self.root_path / "sample2.txt"
        f1.write_text("file 1 content", encoding="utf-8")
        f2.write_text("file 2 content", encoding="utf-8")

        scanner = DeviceScanner(state_manager=self.manager)

        # Run 1: Both files are new -> files_scanned = 2, unchanged_count = 0
        res1 = scanner.custom_scan(self.root_path, use_incremental=True)
        self.assertEqual(res1.status, "completed")
        self.assertEqual(res1.files_scanned, 2)
        self.assertEqual(res1.unchanged_count, 0)

        # Run 2: Neither file changed -> files_scanned = 0, unchanged_count = 2
        res2 = scanner.custom_scan(self.root_path, use_incremental=True)
        self.assertEqual(res2.status, "completed")
        self.assertEqual(res2.files_scanned, 0)
        self.assertEqual(res2.unchanged_count, 2)

        # Modify f1
        time.sleep(0.01)
        f1.write_text("file 1 modified content with extra bytes", encoding="utf-8")

        # Run 3: f1 modified, f2 unchanged -> files_scanned = 1, unchanged_count = 1
        res3 = scanner.custom_scan(self.root_path, use_incremental=True)
        self.assertEqual(res3.status, "completed")
        self.assertEqual(res3.files_scanned, 1)
        self.assertEqual(res3.unchanged_count, 1)


if __name__ == "__main__":
    unittest.main()
