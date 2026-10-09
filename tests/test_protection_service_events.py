"""
ACTIS Security Event Boundary & Intake Test Suite
Validates the SecurityEvent contract, validation rules, queue operations,
event dispatching, and end-to-end orchestrator handoff.
"""

import time
import pytest
from unittest.mock import MagicMock

from service.lifecycle import ServiceState
from service.config import ServiceConfig
from service.events import (
    SecurityEvent,
    SecurityEventType,
    SecurityEventValidationError,
    SecurityEventQueue,
)
from service.dispatcher import (
    EventDispatcher,
    AnalysisOrchestrationStub,
)
from service.protection_service import ProtectionService


class TestSecurityEventContract:
    """Tests for SecurityEvent schema, validation rules, and serialization."""

    def test_valid_event_creation(self):
        event = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="test_source",
            target="C:\\test\\sample.exe",
            metadata={"file_size": 2048},
        )
        event.validate()
        assert event.event_id is not None
        assert event.timestamp is not None
        assert event.event_type == SecurityEventType.FILE_CREATED
        assert event.source == "test_source"
        assert event.target == "C:\\test\\sample.exe"
        assert event.metadata["file_size"] == 2048

    def test_string_type_conversion(self):
        event = SecurityEvent(
            event_type="URL_DETECTED",
            source="web_source",
            target="https://example.com/login",
        )
        assert event.event_type == SecurityEventType.URL_DETECTED
        event.validate()

    def test_invalid_type_raises_error(self):
        with pytest.raises(SecurityEventValidationError):
            SecurityEvent(
                event_type="NON_EXISTENT_TYPE",
                source="test",
            )

    def test_missing_source_rejected(self):
        event = SecurityEvent(
            event_type=SecurityEventType.MANUAL_SCAN,
            source="",
        )
        with pytest.raises(SecurityEventValidationError, match="source must be a non-empty string"):
            event.validate()

    def test_missing_target_for_file_events_rejected(self):
        event = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="test",
            target=None,
        )
        with pytest.raises(SecurityEventValidationError, match="requires a non-empty target"):
            event.validate()

    def test_system_events_allow_empty_target(self):
        event = SecurityEvent(
            event_type=SecurityEventType.SYSTEM_STARTUP,
            source="system",
            target=None,
        )
        event.validate()
        assert event.target is None

    def test_to_dict_and_from_dict_roundtrip(self):
        original = SecurityEvent(
            event_type=SecurityEventType.MESSAGE_RECEIVED,
            source="msg_scanner",
            target="Urgent account alert text",
            metadata={"origin_ip": "192.168.1.10"},
            correlation_id="corr-999",
        )
        d = original.to_dict()
        assert d["event_type"] == "MESSAGE_RECEIVED"
        assert d["correlation_id"] == "corr-999"

        restored = SecurityEvent.from_dict(d)
        assert restored.event_id == original.event_id
        assert restored.event_type == original.event_type
        assert restored.source == original.source
        assert restored.target == original.target
        assert restored.metadata == original.metadata
        assert restored.correlation_id == original.correlation_id

    def test_from_dict_invalid_data_rejected(self):
        with pytest.raises(SecurityEventValidationError):
            SecurityEvent.from_dict("not_a_dict")

        with pytest.raises(SecurityEventValidationError, match="Missing required field: 'event_type'"):
            SecurityEvent.from_dict({"source": "test"})


class TestSecurityEventQueue:
    """Tests for thread-safe bounded SecurityEventQueue operations."""

    def test_queue_put_and_get(self):
        q = SecurityEventQueue(maxsize=10)
        event = SecurityEvent(event_type=SecurityEventType.MANUAL_SCAN, source="unit_test")
        assert q.put(event) is True
        assert q.qsize() == 1
        assert q.is_empty() is False

        retrieved = q.get(timeout=0.1)
        assert retrieved is not None
        assert retrieved.event_id == event.event_id
        q.task_done()
        assert q.qsize() == 0

    def test_queue_capacity_drop(self):
        q = SecurityEventQueue(maxsize=10)  # Min capacity enforced is 10
        # Fill queue
        for i in range(10):
            e = SecurityEvent(event_type=SecurityEventType.MANUAL_SCAN, source=f"src_{i}")
            assert q.put(e, block=False) is True

        assert q.is_full() is True

        # Next put should drop
        overflow_event = SecurityEvent(event_type=SecurityEventType.MANUAL_SCAN, source="overflow")
        assert q.put(overflow_event, block=False) is False

        stats = q.get_stats()
        assert stats["enqueued_count"] == 10
        assert stats["dropped_count"] == 1

        # Clear queue
        cleared = q.clear()
        assert cleared == 10
        assert q.is_empty() is True


class TestEventDispatcher:
    """Tests for EventDispatcher subscriber routing and isolation."""

    def test_specific_and_wildcard_dispatch(self):
        dispatcher = EventDispatcher()
        specific_calls = []
        wildcard_calls = []

        dispatcher.register_handler(
            SecurityEventType.FILE_CREATED,
            lambda e: specific_calls.append(e.event_id)
        )
        dispatcher.register_wildcard_handler(
            lambda e: wildcard_calls.append(e.event_id)
        )

        event = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="test",
            target="C:\\path.exe"
        )
        handlers_executed = dispatcher.dispatch(event)
        assert handlers_executed == 2
        assert len(specific_calls) == 1
        assert len(wildcard_calls) == 1

    def test_handler_error_isolation(self):
        dispatcher = EventDispatcher()
        successful_calls = []

        def broken_handler(e):
            raise RuntimeError("Boom in handler")

        def healthy_handler(e):
            successful_calls.append(e.event_id)

        dispatcher.register_handler(SecurityEventType.MANUAL_SCAN, broken_handler)
        dispatcher.register_handler(SecurityEventType.MANUAL_SCAN, healthy_handler)

        event = SecurityEvent(event_type=SecurityEventType.MANUAL_SCAN, source="test")
        handlers_executed = dispatcher.dispatch(event)

        assert handlers_executed == 1
        assert len(successful_calls) == 1
        stats = dispatcher.get_stats()
        assert stats["dispatch_errors"] == 1

    def test_orchestrator_stub_integration(self):
        dispatcher = EventDispatcher()
        orchestrator = AnalysisOrchestrationStub(name="TestOrchestrator")
        dispatcher.connect_orchestrator(orchestrator)

        event = SecurityEvent(
            event_type=SecurityEventType.URL_DETECTED,
            source="test",
            target="http://malicious.example.com",
        )
        dispatcher.dispatch(event)

        assert orchestrator.received_count == 1
        received = orchestrator.get_received_events()
        assert received[0].target == "http://malicious.example.com"


class TestProtectionServiceEndToEndIntake:
    """End-to-end integration tests for ProtectionService event submission and dispatch."""

    def test_end_to_end_event_intake_flow(self):
        orchestrator = AnalysisOrchestrationStub(name="E2EOrchestrator")
        cfg = ServiceConfig(
            service_name="E2ETestService",
            worker_count=1,
            shutdown_timeout_seconds=2.0,
        )
        service = ProtectionService(config=cfg, orchestrator=orchestrator)
        try:
            assert service.start() is True

            event1 = SecurityEvent(
                event_type=SecurityEventType.FILE_CREATED,
                source="e2e_test",
                target="C:\\ACTIS\\test.exe",
            )
            event2 = SecurityEvent(
                event_type=SecurityEventType.URL_DETECTED,
                source="e2e_test",
                target="https://phish.example.com",
            )

            assert service.submit_event(event1) is True
            assert service.submit_event(event2) is True

            # Wait briefly for worker to consume and dispatch
            time.sleep(0.3)

            assert orchestrator.received_count == 2
            health = service.get_health()
            assert health.events_enqueued == 2
            assert health.events_dequeued == 2
            assert health.events_dispatched == 2
            assert health.events_dropped == 0
        finally:
            service.stop()

    def test_reject_event_submission_when_service_stopped(self):
        service = ProtectionService()
        event = SecurityEvent(event_type=SecurityEventType.MANUAL_SCAN, source="test")
        # Submitting while STOPPED must be rejected safely
        assert service.submit_event(event) is False
        assert service.event_queue.qsize() == 0
