"""
ACTIS Day 10 Unit Tests: Filesystem Event Source, Normalization, Filtering, and Debouncing
Validates read-only filesystem observation, normalization, temporary file suppression,
and rapid write debouncing using safe temporary directories and synthetic files.

CRITICAL SAFETY GUARANTEES:
- Uses strictly safe synthetic text files in pytest tmp_path.
- Operates strictly in read-only mode; does not execute or modify test binaries.
- Zero external network requests.
"""

import time
from pathlib import Path
from typing import List

import pytest

from scanners.file_watcher import (
    FilesystemEvent,
    FilesystemEventSource,
    wait_until_file_stable,
)
from service.file_normalizer import (
    FilesystemEventNormalizer,
    NormalizedFileEvent,
    normalize_filesystem_path,
)
from service.file_filter import (
    FileEventFilter,
    FileFilterPolicy,
    FilterReason,
)
from service.debouncer import FileEventDebouncer
from service.events import SecurityEventType


class TestFilesystemEventSource:
    """Tests for FilesystemEventSource lifecycle and observer management."""

    def test_initialization_valid_and_invalid_paths(self, tmp_path):
        valid_dir = tmp_path / "valid_watch"
        valid_dir.mkdir()
        non_existent = tmp_path / "does_not_exist"

        source = FilesystemEventSource(paths=[str(valid_dir), str(non_existent)])
        assert len(source.paths) == 1
        assert str(valid_dir.resolve()) in source.paths

    def test_start_and_stop_lifecycle(self, tmp_path):
        watch_dir = tmp_path / "lifecycle_watch"
        watch_dir.mkdir()

        source = FilesystemEventSource(paths=[str(watch_dir)])
        assert source.is_running is False

        assert source.start() is True
        assert source.is_running is True

        source.stop()
        assert source.is_running is False

    def test_repeated_start_stop_is_idempotent(self, tmp_path):
        watch_dir = tmp_path / "idempotent_watch"
        watch_dir.mkdir()

        source = FilesystemEventSource(paths=[str(watch_dir)])
        # Repeated start
        assert source.start() is True
        assert source.start() is True
        assert source.is_running is True

        # Repeated stop
        source.stop()
        source.stop()
        assert source.is_running is False

    def test_file_creation_event_detection(self, tmp_path):
        watch_dir = tmp_path / "create_watch"
        watch_dir.mkdir()

        captured_events: List[FilesystemEvent] = []
        source = FilesystemEventSource(
            paths=[str(watch_dir)],
            on_event=lambda e: captured_events.append(e),
        )
        assert source.start() is True

        try:
            # Create a safe synthetic test file
            test_file = watch_dir / "safe_file.txt"
            test_file.write_text("Safe ACTIS sample data", encoding="utf-8")

            # Allow watchdog thread to capture OS event
            time.sleep(0.3)

            assert len(captured_events) >= 1
            event_types = [e.event_type.lower() for e in captured_events]
            assert "created" in event_types or "modified" in event_types
        finally:
            source.stop()

    def test_file_modification_event_detection(self, tmp_path):
        watch_dir = tmp_path / "mod_watch"
        watch_dir.mkdir()
        test_file = watch_dir / "mod_target.txt"
        test_file.write_text("initial content", encoding="utf-8")

        captured_events: List[FilesystemEvent] = []
        source = FilesystemEventSource(
            paths=[str(watch_dir)],
            on_event=lambda e: captured_events.append(e),
        )
        assert source.start() is True

        try:
            time.sleep(0.1)
            # Modify safe file
            test_file.write_text("modified content update", encoding="utf-8")
            time.sleep(0.3)

            assert len(captured_events) >= 1
            mod_events = [e for e in captured_events if e.event_type.lower() == "modified"]
            assert len(mod_events) >= 1
        finally:
            source.stop()

    def test_file_deletion_event_detection(self, tmp_path):
        watch_dir = tmp_path / "del_watch"
        watch_dir.mkdir()
        test_file = watch_dir / "delete_target.txt"
        test_file.write_text("to be deleted", encoding="utf-8")

        captured_events: List[FilesystemEvent] = []
        source = FilesystemEventSource(
            paths=[str(watch_dir)],
            on_event=lambda e: captured_events.append(e),
        )
        assert source.start() is True

        try:
            time.sleep(0.1)
            test_file.unlink()
            time.sleep(0.3)

            del_events = [e for e in captured_events if e.event_type.lower() == "deleted"]
            assert len(del_events) >= 1
        finally:
            source.stop()


class TestFilesystemEventNormalizer:
    """Tests for path normalization and canonical event mapping."""

    def test_normalize_filesystem_path(self):
        raw = "C:/ACTIS/Data//Sample/../Sample/test.exe"
        norm = normalize_filesystem_path(raw)
        assert "/" not in norm
        assert "\\\\" not in norm
        assert norm.endswith("test.exe")

    def test_normalizer_mappings(self):
        normalizer = FilesystemEventNormalizer()

        raw_create = FilesystemEvent(event_type="created", src_path="C:\\test\\binary.exe")
        norm_create = normalizer.normalize(raw_create)
        assert norm_create is not None
        assert norm_create.event_type == SecurityEventType.FILE_CREATED
        assert norm_create.path.endswith("binary.exe")

        raw_mod = FilesystemEvent(event_type="modified", src_path="C:\\test\\binary.exe")
        norm_mod = normalizer.normalize(raw_mod)
        assert norm_mod.event_type == SecurityEventType.FILE_MODIFIED

        raw_move = FilesystemEvent(
            event_type="moved",
            src_path="C:\\test\\old.exe",
            dest_path="C:\\test\\new.exe",
        )
        norm_move = normalizer.normalize(raw_move)
        assert norm_move.event_type == SecurityEventType.FILE_RENAMED
        assert norm_move.path.endswith("new.exe")
        assert norm_move.previous_path.endswith("old.exe")

        raw_del = FilesystemEvent(event_type="deleted", src_path="C:\\test\\deleted.exe")
        norm_del = normalizer.normalize(raw_del)
        assert norm_del.event_type == SecurityEventType.FILE_DELETED

    def test_normalizer_converts_to_security_event(self):
        normalizer = FilesystemEventNormalizer()
        raw = FilesystemEvent(event_type="created", src_path="C:\\ACTIS\\test.exe")
        norm = normalizer.normalize(raw)
        sec_event = norm.to_security_event()

        assert sec_event.event_type == SecurityEventType.FILE_CREATED
        assert sec_event.source == "filesystem_watcher"
        assert sec_event.target.endswith("test.exe")
        sec_event.validate()


class TestFileEventFilter:
    """Tests for event filtering, exclusions, and temporary file suppression."""

    def test_filter_directories(self):
        filter_svc = FileEventFilter(policy=FileFilterPolicy(ignore_directories=True))
        event = NormalizedFileEvent(
            event_type=SecurityEventType.FILE_CREATED,
            path="C:\\ACTIS\\Folder",
            is_directory=True,
        )
        allowed, reason = filter_svc.filter_event(event)
        assert allowed is False
        assert reason == FilterReason.IGNORED_DIRECTORY

    def test_filter_temporary_files(self):
        filter_svc = FileEventFilter(policy=FileFilterPolicy(filter_temporary_files=True))
        temp_paths = [
            "C:\\ACTIS\\document.tmp",
            "C:\\ACTIS\\setup.temp",
            "C:\\ACTIS\\browser_download.crdownload",
            "C:\\ACTIS\\~$WordDoc.docx",
            "C:\\ACTIS\\file.swp",
            "C:\\ACTIS\\data.part",
        ]
        for p in temp_paths:
            event = NormalizedFileEvent(event_type=SecurityEventType.FILE_CREATED, path=p)
            allowed, reason = filter_svc.filter_event(event)
            assert allowed is False
            assert reason == FilterReason.TEMPORARY_FILE

    def test_temporary_files_allowed_when_policy_disabled(self):
        filter_svc = FileEventFilter(policy=FileFilterPolicy(filter_temporary_files=False))
        event = NormalizedFileEvent(event_type=SecurityEventType.FILE_CREATED, path="C:\\ACTIS\\temp_file.tmp")
        allowed, reason = filter_svc.filter_event(event)
        assert allowed is True
        assert reason == FilterReason.ACCEPTED

    def test_filter_excluded_segments(self):
        filter_svc = FileEventFilter()
        excluded_paths = [
            "C:\\ACTIS\\.git\\index",
            "C:\\ACTIS\\venv\\Scripts\\python.exe",
            "C:\\ACTIS\\node_modules\\package\\index.js",
            "C:\\ACTIS\\__pycache__\\code.cpython-313.pyc",
        ]
        for p in excluded_paths:
            event = NormalizedFileEvent(event_type=SecurityEventType.FILE_CREATED, path=p)
            allowed, reason = filter_svc.filter_event(event)
            assert allowed is False
            assert reason == FilterReason.EXCLUDED_DIRECTORY_PATTERN

    def test_filter_monitored_roots(self, tmp_path):
        root1 = str((tmp_path / "root1").resolve())
        root2 = str((tmp_path / "root2").resolve())
        outside = str((tmp_path / "outside").resolve())

        filter_svc = FileEventFilter(policy=FileFilterPolicy(monitored_roots=[root1, root2]))

        inside_event = NormalizedFileEvent(
            event_type=SecurityEventType.FILE_CREATED,
            path=str(Path(root1) / "file.exe"),
        )
        assert filter_svc.filter_event(inside_event)[0] is True

        outside_event = NormalizedFileEvent(
            event_type=SecurityEventType.FILE_CREATED,
            path=str(Path(outside) / "file.exe"),
        )
        allowed, reason = filter_svc.filter_event(outside_event)
        assert allowed is False
        assert reason == FilterReason.OUTSIDE_MONITORED_ROOT


class TestFileEventDebouncer:
    """Tests for event coalescing, timer debouncing, and deletion cancellations."""

    def test_debounce_coalesces_rapid_modifications(self, tmp_path):
        test_file = tmp_path / "rapid_mod.txt"
        test_file.write_text("initial", encoding="utf-8")

        emitted: List[NormalizedFileEvent] = []
        debouncer = FileEventDebouncer(
            debounce_seconds=0.15,
            stability_check=False,
            on_stable_event=lambda e: emitted.append(e),
        )

        try:
            # Submit 5 rapid modification events for the same path
            for i in range(5):
                event = NormalizedFileEvent(
                    event_type=SecurityEventType.FILE_MODIFIED,
                    path=str(test_file),
                )
                debouncer.submit(event)
                time.sleep(0.02)

            assert len(emitted) == 0  # Should be coalescing, not emitted yet
            time.sleep(0.3)  # Wait for debounce window to expire

            # Exactly one consolidated event should be emitted
            assert len(emitted) == 1
            assert emitted[0].metadata.get("coalesced_event_count") == 5
        finally:
            debouncer.stop()

    def test_file_deletion_cancels_pending_debounced_writes(self, tmp_path):
        test_file = tmp_path / "delete_race.txt"
        test_file.write_text("initial", encoding="utf-8")

        emitted: List[NormalizedFileEvent] = []
        debouncer = FileEventDebouncer(
            debounce_seconds=0.25,
            stability_check=False,
            on_stable_event=lambda e: emitted.append(e),
        )

        try:
            # Submit creation/mod
            event = NormalizedFileEvent(
                event_type=SecurityEventType.FILE_CREATED,
                path=str(test_file),
            )
            debouncer.submit(event)
            assert debouncer.pending_count() == 1

            # Submit deletion before debounce timer fires
            del_event = NormalizedFileEvent(
                event_type=SecurityEventType.FILE_DELETED,
                path=str(test_file),
            )
            debouncer.submit(del_event)

            # Pending creation should be cancelled, deletion emitted immediately
            assert debouncer.pending_count() == 0
            assert len(emitted) == 1
            assert emitted[0].event_type == SecurityEventType.FILE_DELETED

            time.sleep(0.35)
            # No spurious late creation event should fire
            assert len(emitted) == 1
        finally:
            debouncer.stop()

    def test_wait_until_file_stable_helper(self, tmp_path):
        test_file = tmp_path / "stable_check.txt"
        test_file.write_text("data", encoding="utf-8")

        assert wait_until_file_stable(test_file, timeout=1.0) is True

        missing_file = tmp_path / "missing.txt"
        assert wait_until_file_stable(missing_file, timeout=0.2) is False
