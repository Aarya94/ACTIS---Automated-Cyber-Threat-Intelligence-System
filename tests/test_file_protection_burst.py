"""
ACTIS Day 10 Unit Tests: Event Burst & Queue Stability
Validates bounded queue capacity, backpressure under heavy event bursts,
duplicate/rapid event reduction, cancellation, and graceful queue draining.

CRITICAL SAFETY GUARANTEES:
- Uses safe synthetic SecurityEvents in controlled in-memory environments.
- Enforces strict execution timeouts and thread safety.
- Zero network activity.
"""

import threading
import time
from typing import List

import pytest

from service.events import (
    SecurityEvent,
    SecurityEventQueue,
    SecurityEventType,
)
from service.debouncer import FileEventDebouncer
from service.file_normalizer import NormalizedFileEvent
from service.protection_service import ProtectionService
from service.config import ServiceConfig
from service.dispatcher import AnalysisOrchestrationStub


class TestQueueBurstAndBackpressure:
    """Tests for bounded SecurityEventQueue behavior under high event volume."""

    def test_bounded_queue_burst_drops_excess(self):
        q = SecurityEventQueue(maxsize=20)
        accepted = 0
        dropped = 0

        # Burst of 100 events
        for i in range(100):
            event = SecurityEvent(
                event_type=SecurityEventType.FILE_MODIFIED,
                source="burst_test",
                target=f"C:\\test\\file_{i}.txt",
            )
            if q.put(event, block=False):
                accepted += 1
            else:
                dropped += 1

        assert accepted == 20
        assert dropped == 80
        assert q.qsize() == 20
        assert q.is_full() is True

        stats = q.get_stats()
        assert stats["enqueued_count"] == 20
        assert stats["dropped_count"] == 80
        assert stats["peak_size"] == 20

    def test_queue_cancellation_and_safe_draining(self):
        q = SecurityEventQueue(maxsize=50)

        # Enqueue 15 events
        for i in range(15):
            event = SecurityEvent(
                event_type=SecurityEventType.FILE_CREATED,
                source="test",
                target=f"C:\\test\\item_{i}.exe",
            )
            assert q.put(event) is True

        assert q.qsize() == 15
        assert q.is_cancelled is False

        # Cancel queue
        q.cancel()
        assert q.is_cancelled is True

        # Subsequent put must be rejected
        new_event = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="test",
            target="C:\\test\\after_cancel.exe",
        )
        assert q.put(new_event) is False

        # Drain remaining events
        drained = q.drain()
        assert len(drained) == 15
        assert q.is_empty() is True
        assert q.qsize() == 0

    def test_queue_drain_partial_limit(self):
        q = SecurityEventQueue(maxsize=30)
        for i in range(20):
            event = SecurityEvent(
                event_type=SecurityEventType.FILE_MODIFIED,
                source="test",
                target=f"C:\\test\\item_{i}.txt",
            )
            q.put(event)

        drained_subset = q.drain(max_items=8)
        assert len(drained_subset) == 8
        assert q.qsize() == 12

        drained_rest = q.drain()
        assert len(drained_rest) == 12
        assert q.is_empty() is True


class TestDebouncerBurstReduction:
    """Tests for FileEventDebouncer coalescing under rapid write storms."""

    def test_debouncer_reduces_burst_on_multiple_paths(self):
        emitted: List[NormalizedFileEvent] = []
        debouncer = FileEventDebouncer(
            debounce_seconds=0.2,
            stability_check=False,
            on_stable_event=lambda e: emitted.append(e),
        )

        paths = [f"C:\\ACTIS\\burst_file_{i}.txt" for i in range(5)]

        try:
            # Simulate high-frequency writes: 20 modifications per path = 100 total events
            for _ in range(20):
                for p in paths:
                    ev = NormalizedFileEvent(
                        event_type=SecurityEventType.FILE_MODIFIED,
                        path=p,
                    )
                    debouncer.submit(ev)

            stats = debouncer.get_stats()
            assert stats["events_received"] == 100
            assert stats["events_coalesced"] == 95  # 100 - 5 unique paths

            # Wait for debounce window to fire
            time.sleep(0.4)

            # Exactly 5 coalesced events emitted
            assert len(emitted) == 5
            emitted_paths = {e.path for e in emitted}
            assert emitted_paths == set(paths)

            for e in emitted:
                assert e.metadata.get("coalesced_event_count") == 20
        finally:
            debouncer.stop()


class TestProtectionServiceBurstStability:
    """Tests for ProtectionService stability and worker pool behavior under concurrent bursts."""

    def test_concurrent_event_burst_dispatch(self):
        orchestrator = AnalysisOrchestrationStub(name="BurstTestOrchestrator")
        cfg = ServiceConfig(
            service_name="BurstServiceTest",
            worker_count=2,
            queue_max_size=200,
            shutdown_timeout_seconds=2.0,
        )
        service = ProtectionService(config=cfg, orchestrator=orchestrator)

        assert service.start() is True
        try:
            total_events = 60

            # Submit events across multiple threads
            def submitter(start_idx: int, count: int):
                for i in range(start_idx, start_idx + count):
                    e = SecurityEvent(
                        event_type=SecurityEventType.FILE_MODIFIED,
                        source="concurrent_tester",
                        target=f"C:\\test\\file_{i}.txt",
                    )
                    service.submit_event(e)

            threads = []
            for t in range(4):
                thread = threading.Thread(target=submitter, args=(t * 15, 15))
                threads.append(thread)
                thread.start()

            for t in threads:
                t.join(timeout=2.0)

            # Wait briefly for workers to consume and dispatch
            deadline = time.time() + 3.0
            while orchestrator.received_count < total_events and time.time() < deadline:
                time.sleep(0.05)

            assert orchestrator.received_count == total_events

            health = service.get_health()
            assert health.is_running is True
            assert health.is_healthy is True
            assert health.workers_alive == 2
            assert health.events_enqueued == total_events
            assert health.events_dispatched == total_events

        finally:
            assert service.stop() is True
            assert service.is_running() is False
