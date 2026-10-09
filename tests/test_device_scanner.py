"""
ACTIS Device Scanner Traversal & Safety Tests
Tests recursive filesystem traversal, symlink/reparse point safety,
oversized file policies, safe metadata collection, streaming fingerprinting,
and cooperative cancellation.
"""

import os
import sys
import time
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from scanners.device_scanner import (
    DeviceScanner,
    TraversalSafetyHelper,
    ScanCancellationToken,
    FileMetadata,
    FileFingerprint,
    DeviceScanResult,
    collect_file_metadata,
    compute_file_fingerprint
)


class TestDeviceScannerTraversalAndSafety(unittest.TestCase):
    """Test suite covering safe traversal, filtering, metadata, and cancellation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temp_dir.name)
        self.scanner = DeviceScanner()

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_traversal_empty_directory(self):
        """Scanning an empty directory should return zero files without error."""
        result = self.scanner.custom_scan(self.root_path)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.total_files_discovered, 0)
        self.assertEqual(result.files_scanned, 0)
        self.assertEqual(result.threats_found, 0)
        self.assertEqual(result.error_count, 0)

    def test_traversal_nested_directories(self):
        """Recursive traversal should discover files across nested subdirectories."""
        sub1 = self.root_path / "sub1"
        sub2 = sub1 / "sub2"
        sub2.mkdir(parents=True)

        f1 = self.root_path / "root_file.txt"
        f2 = sub1 / "level1.txt"
        f3 = sub2 / "level2.txt"

        f1.write_text("root file content", encoding="utf-8")
        f2.write_text("sub1 file content", encoding="utf-8")
        f3.write_text("sub2 file content", encoding="utf-8")

        discovered = self.scanner._discover_files(self.root_path)
        self.assertEqual(len(discovered), 3)
        discovered_names = {p.name for p in discovered}
        self.assertEqual(discovered_names, {"root_file.txt", "level1.txt", "level2.txt"})

    def test_traversal_missing_and_invalid_path(self):
        """Non-existent path should be handled gracefully without raising uncaught exceptions."""
        non_existent = self.root_path / "does_not_exist_dir"
        result = self.scanner.custom_scan(non_existent)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.total_files_discovered, 0)
        self.assertEqual(result.files_scanned, 0)

    def test_traversal_only_executables_filter(self):
        """When only_executables is enabled, non-executable files should be skipped."""
        f_txt = self.root_path / "readme.txt"
        f_doc = self.root_path / "document.pdf"
        f_bat = self.root_path / "script.bat"

        f_txt.write_text("plain text", encoding="utf-8")
        f_doc.write_bytes(b"%PDF-1.4 dummy")
        f_bat.write_text("@echo off\necho hello", encoding="utf-8")

        result = self.scanner.custom_scan(self.root_path, only_executables=True, use_incremental=False)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.total_files_discovered, 3)
        self.assertEqual(result.files_scanned, 1)  # only script.bat scanned
        self.assertEqual(result.skipped_count, 2)
        self.assertEqual(result.skipped_reasons.get("non_executable"), 2)

    def test_traversal_reparse_point_and_symlink_safety(self):
        """Reparse points and symlinks must be identified and skipped to prevent recursion loops."""
        sub = self.root_path / "target_folder"
        sub.mkdir()
        target_file = sub / "sample.txt"
        target_file.write_text("data", encoding="utf-8")

        # Verify TraversalSafetyHelper detection
        mock_path = MagicMock(spec=Path)
        mock_path.is_symlink.return_value = True
        self.assertTrue(TraversalSafetyHelper.is_reparse_point_or_symlink(mock_path))

        # Verify circular directory avoidance logic
        helper = TraversalSafetyHelper()
        self.assertFalse(helper.is_directory_already_visited(sub))
        # Second call for the same path should return True (already visited)
        self.assertTrue(helper.is_directory_already_visited(sub))

    def test_collect_file_metadata_safe(self):
        """Safe file metadata inspection without reading content into memory."""
        test_file = self.root_path / "metadata_test.bin"
        test_data = b"Safe file metadata payload"
        test_file.write_bytes(test_data)

        meta = collect_file_metadata(test_file)
        self.assertTrue(meta.is_accessible)
        self.assertEqual(meta.filename, "metadata_test.bin")
        self.assertEqual(meta.extension, ".bin")
        self.assertEqual(meta.file_size, len(test_data))
        self.assertGreater(meta.mtime, 0)
        self.assertFalse(meta.is_oversized)
        self.assertIsNone(meta.error)

        # Inaccessible/missing file
        missing_file = self.root_path / "ghost.bin"
        missing_meta = collect_file_metadata(missing_file)
        self.assertFalse(missing_meta.is_accessible)
        self.assertIsNotNone(missing_meta.error)

    def test_streaming_fingerprint_chunked(self):
        """Streaming chunked SHA-256 fingerprint matches standard cryptographic hash."""
        test_file = self.root_path / "hash_target.dat"
        data = b"A" * (128 * 1024)  # 128 KB
        test_file.write_bytes(data)

        expected_hash = hashlib.sha256(data).hexdigest()
        fp = compute_file_fingerprint(test_file, chunk_size=32768)

        self.assertEqual(fp.status, "OK")
        self.assertEqual(fp.sha256, expected_hash)
        self.assertIsNone(fp.error)

    def test_streaming_fingerprint_oversized(self):
        """Files exceeding max size limit should return SKIPPED_OVERSIZED."""
        test_file = self.root_path / "large_file.dat"
        test_file.write_bytes(b"0" * 1000)

        # Set max_size to 500 bytes
        fp = compute_file_fingerprint(test_file, max_size_bytes=500)
        self.assertEqual(fp.status, "SKIPPED_OVERSIZED")
        self.assertEqual(fp.sha256, "")
        self.assertIn("exceeds limit", fp.error)

    def test_streaming_fingerprint_changed_during_hash(self):
        """Detect when a file is modified/resized while being hashed."""
        test_file = self.root_path / "race_file.dat"
        test_file.write_bytes(b"initial data")

        orig_stat = test_file.stat()
        st_modified = os.stat_result((
            orig_stat.st_mode,
            orig_stat.st_ino,
            orig_stat.st_dev,
            orig_stat.st_nlink,
            orig_stat.st_uid,
            orig_stat.st_gid,
            orig_stat.st_size + 10,  # Size changed!
            orig_stat.st_atime,
            orig_stat.st_mtime + 5.0,  # Mtime changed!
            orig_stat.st_ctime
        ))

        # Mock second stat call to simulate concurrent modification
        stat_calls = [orig_stat, st_modified]

        def fake_stat():
            if stat_calls:
                return stat_calls.pop(0)
            return st_modified

        with patch.object(Path, "stat", side_effect=fake_stat):
            fp = compute_file_fingerprint(test_file)
            self.assertEqual(fp.status, "FILE_CHANGED_DURING_HASH")
            self.assertEqual(fp.sha256, "")
            self.assertIn("modified or resized", fp.error)

    def test_scan_cooperative_cancellation(self):
        """Cooperative cancellation token stops scan operation gracefully."""
        # Create multiple files
        for i in range(10):
            (self.root_path / f"file_{i}.txt").write_text(f"content {i}", encoding="utf-8")

        scanner = DeviceScanner()

        # Define progress callback that cancels scan on second file
        def cancel_callback(progress):
            if progress.get("files_scanned", 0) >= 1:
                scanner.cancel_current_scan()

        result = scanner.custom_scan(
            self.root_path,
            progress_callback=cancel_callback,
            use_incremental=False
        )

        self.assertEqual(result.status, "cancelled")
        self.assertTrue(result.is_cancelled)
        self.assertLess(result.files_scanned, 10)


if __name__ == "__main__":
    unittest.main()
