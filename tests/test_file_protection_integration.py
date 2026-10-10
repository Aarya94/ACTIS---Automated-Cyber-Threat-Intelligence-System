"""
ACTIS Day 10 Integration Tests: End-to-End Event-Driven File Protection
Proves the unified event flow:
OS Filesystem Event -> Watcher -> Protection Service -> Normalizer ->
Filter -> Debouncer -> Event Queue -> Worker -> Incremental Scan State ->
Shared Analysis Pipeline (ThreatDetector) -> Structured Result.

CRITICAL SAFETY BOUNDARIES:
- Synthetic safe files only.
- Read-only static analysis; ZERO binaries executed.
- Zero network activity.
"""

import time
from pathlib import Path
from typing import Dict, Any

import pytest

from scanners.file_feature_extractor import DOS_SIGNATURE
from scanners.incremental_state import (
    IncrementalStateManager,
    FileChangeType,
)
from service.events import (
    SecurityEvent,
    SecurityEventType,
)
from service.config import ServiceConfig
from service.protection_service import ProtectionService
from service.file_pipeline import (
    FileProtectionPipeline,
    EventProcessingStatus,
    EventProcessingResult,
)


class TestFileProtectionPipelineDirect:
    """Tests for FileProtectionPipeline race handling, incremental skip, and static analysis."""

    def test_pipeline_classifies_new_file_and_analyzes(self, tmp_path):
        state_mgr = IncrementalStateManager(auto_load=False)
        pipeline = FileProtectionPipeline(state_manager=state_mgr)

        safe_file = tmp_path / "target.exe"
        safe_file.write_bytes(DOS_SIGNATURE + b"\x00" * 256)

        event = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="filesystem_watcher",
            target=str(safe_file),
        )

        result = pipeline.process_file_event(event)

        assert result.status == EventProcessingStatus.ANALYZED
        assert result.change_type == FileChangeType.NEW_FILE
        assert result.target_path == str(safe_file.resolve())
        assert result.sha256 != ""
        assert state_mgr.get_cached_count() == 1

        # Re-evaluating unchanged file must skip analysis and mark UNCHANGED
        event_mod = SecurityEvent(
            event_type=SecurityEventType.FILE_MODIFIED,
            source="filesystem_watcher",
            target=str(safe_file),
        )
        second_result = pipeline.process_file_event(event_mod)

        assert second_result.status == EventProcessingStatus.UNCHANGED
        assert second_result.change_type == FileChangeType.UNCHANGED_FILE
        assert pipeline.get_stats()["unchanged_count"] == 1

    def test_pipeline_handles_disappearing_file(self, tmp_path):
        state_mgr = IncrementalStateManager(auto_load=False)
        pipeline = FileProtectionPipeline(state_manager=state_mgr)

        missing_target = tmp_path / "vanished.exe"
        event = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="filesystem_watcher",
            target=str(missing_target),
        )

        result = pipeline.process_file_event(event)
        assert result.status == EventProcessingStatus.DISAPPEARED
        assert result.change_type == FileChangeType.UNAVAILABLE_FILE
        assert pipeline.get_stats()["disappeared_count"] == 1

    def test_pipeline_handles_file_deletion_and_pruning(self, tmp_path):
        state_mgr = IncrementalStateManager(auto_load=False)
        pipeline = FileProtectionPipeline(state_manager=state_mgr)

        del_target = tmp_path / "deleted.exe"
        del_target.write_bytes(b"temp")

        # Ingest creation
        create_event = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="filesystem_watcher",
            target=str(del_target),
        )
        pipeline.process_file_event(create_event)
        canonical = str(del_target.resolve())
        assert state_mgr.get_state(canonical) is not None

        # Ingest deletion
        del_target.unlink()
        del_event = SecurityEvent(
            event_type=SecurityEventType.FILE_DELETED,
            source="filesystem_watcher",
            target=str(del_target),
        )
        result = pipeline.process_file_event(del_event)

        assert result.status == EventProcessingStatus.DELETED
        assert result.change_type == FileChangeType.REMOVED_FILE
        assert state_mgr.get_state(canonical) is None
        assert pipeline.get_stats()["deleted_count"] == 1

    def test_pipeline_handles_oversized_file(self, tmp_path):
        state_mgr = IncrementalStateManager(auto_load=False)
        # Limit max size to 50 bytes
        pipeline = FileProtectionPipeline(state_manager=state_mgr, max_file_size_bytes=50)

        oversized = tmp_path / "large.dat"
        oversized.write_bytes(b"A" * 128)

        event = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="filesystem_watcher",
            target=str(oversized),
        )

        result = pipeline.process_file_event(event)
        assert result.status == EventProcessingStatus.SKIPPED_OVERSIZED
        assert pipeline.get_stats()["oversized_count"] == 1

    def test_pipeline_unsupported_non_executables_filter(self, tmp_path):
        state_mgr = IncrementalStateManager(auto_load=False)
        pipeline = FileProtectionPipeline(
            state_manager=state_mgr,
            only_executables=True,
        )

        text_file = tmp_path / "notes.txt"
        text_file.write_text("plain text", encoding="utf-8")

        event = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="filesystem_watcher",
            target=str(text_file),
        )

        result = pipeline.process_file_event(event)
        assert result.status == EventProcessingStatus.SKIPPED_UNSUPPORTED
        assert pipeline.get_stats()["unsupported_count"] == 1

    def test_pipeline_race_condition_modification_during_analysis(self, tmp_path):
        state_mgr = IncrementalStateManager(auto_load=False)

        race_file = tmp_path / "racing.exe"
        race_file.write_bytes(DOS_SIGNATURE + b"\x00" * 100)

        def modifying_analyzer(p: Path) -> Dict[str, Any]:
            # Simulate external process modifying the file during analysis
            time.sleep(0.02)
            race_file.write_bytes(DOS_SIGNATURE + b"\xFF" * 200)
            return {"is_threat": False, "score": 0.0, "risk_level": "LOW"}

        pipeline = FileProtectionPipeline(
            state_manager=state_mgr,
            analysis_fn=modifying_analyzer,
        )

        event = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="filesystem_watcher",
            target=str(race_file),
        )

        result = pipeline.process_file_event(event)
        assert result.status == EventProcessingStatus.CHANGED_DURING_ANALYSIS
        assert pipeline.get_stats()["changed_during_analysis_count"] == 1


class TestEndToEndProtectionServiceIntegration:
    """
    End-to-end integration test proving the complete architectural chain:
    OS File Event -> Watcher -> Protection Service -> Queue -> Pipeline -> ThreatDetector
    """

    def test_full_filesystem_to_analysis_pipeline_integration(self, tmp_path):
        watch_dir = tmp_path / "actis_protected_dir"
        watch_dir.mkdir()

        state_mgr = IncrementalStateManager(auto_load=False)
        pipeline = FileProtectionPipeline(state_manager=state_mgr)

        cfg = ServiceConfig(
            service_name="E2EProtectionIntegration",
            worker_count=1,
            monitored_paths=[str(watch_dir)],
            debounce_delay_seconds=0.15,
            enable_file_monitoring=True,
            shutdown_timeout_seconds=2.0,
        )

        service = ProtectionService(config=cfg, orchestrator=pipeline)
        assert service.start() is True

        try:
            # 1. Create safe synthetic file in monitored directory
            safe_file = watch_dir / "safe_agent.exe"
            safe_file.write_bytes(DOS_SIGNATURE + b"\x00" * 300)

            # 2. Wait for watcher -> debouncer (0.15s) -> queue -> worker -> pipeline
            deadline = time.time() + 4.0
            while pipeline.get_stats()["analyzed_count"] == 0 and time.time() < deadline:
                time.sleep(0.05)

            stats = pipeline.get_stats()
            assert stats["events_processed"] >= 1
            assert stats["analyzed_count"] >= 1
            assert state_mgr.get_cached_count() >= 1

            # 3. Submit a follow-up event for the unchanged file (size and mtime identical)
            recheck_event = SecurityEvent(
                event_type=SecurityEventType.FILE_MODIFIED,
                source="filesystem_watcher",
                target=str(safe_file),
            )
            assert service.submit_event(recheck_event) is True

            # Wait for worker to consume and evaluate against incremental state
            deadline = time.time() + 2.0
            while pipeline.get_stats()["unchanged_count"] == 0 and time.time() < deadline:
                time.sleep(0.05)

            updated_stats = pipeline.get_stats()
            # The unchanged file must be identified and skipped
            assert updated_stats["unchanged_count"] >= 1

            # 4. Verify operational telemetry
            health = service.get_health()
            assert health.is_running is True
            assert health.is_healthy is True
            assert health.filesystem_monitoring is not None
            assert health.filesystem_monitoring["active"] is True

        finally:
            service.stop()
            assert service.is_running() is False
