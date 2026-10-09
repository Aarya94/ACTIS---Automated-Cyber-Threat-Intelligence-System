"""
ACTIS Protection Service Lifecycle Test Suite
Validates service state transitions, lifecycle contracts, idempotency,
pause/resume, and SCM host bridging.
"""

import threading
import time
import pytest
from unittest.mock import MagicMock, patch

from service.lifecycle import ServiceState, ServiceLifecycleError, IServiceLifecycle
from service.config import ServiceConfig, get_default_service_config
from service.state import ServiceStateManager, VALID_TRANSITIONS
from service.protection_service import ProtectionService
from service.windows_host import WindowsServiceHost, create_windows_host


class TestServiceStateManager:
    """Tests for ServiceStateManager deterministic state transitions."""

    def test_initial_state(self):
        manager = ServiceStateManager(initial_state=ServiceState.STOPPED)
        assert manager.current_state == ServiceState.STOPPED
        assert manager.last_error is None
        assert len(manager.get_history()) == 0

    def test_valid_transitions(self):
        manager = ServiceStateManager(initial_state=ServiceState.STOPPED)
        assert manager.can_transition(ServiceState.STARTING) is True
        assert manager.can_transition(ServiceState.RUNNING) is False

        assert manager.transition_to(ServiceState.STARTING, reason="starting up") is True
        assert manager.current_state == ServiceState.STARTING

        assert manager.transition_to(ServiceState.RUNNING, reason="started") is True
        assert manager.current_state == ServiceState.RUNNING

        assert manager.transition_to(ServiceState.STOPPING, reason="stopping") is True
        assert manager.current_state == ServiceState.STOPPING

        assert manager.transition_to(ServiceState.STOPPED, reason="stopped") is True
        assert manager.current_state == ServiceState.STOPPED

        history = manager.get_history()
        assert len(history) == 4
        assert history[0]["from_state"] == "STOPPED"
        assert history[0]["to_state"] == "STARTING"
        assert history[0]["success"] is True

    def test_invalid_transition_raises_error(self):
        manager = ServiceStateManager(initial_state=ServiceState.STOPPED)
        with pytest.raises(ServiceLifecycleError):
            manager.transition_to(ServiceState.RUNNING)

        assert manager.current_state == ServiceState.STOPPED
        history = manager.get_history()
        assert len(history) == 1
        assert history[0]["success"] is False

    def test_invalid_transition_without_raise(self):
        manager = ServiceStateManager(initial_state=ServiceState.STOPPED)
        success = manager.transition_to(ServiceState.PAUSED, raise_on_error=False)
        assert success is False
        assert manager.current_state == ServiceState.STOPPED

    def test_record_error_and_reset(self):
        manager = ServiceStateManager(initial_state=ServiceState.RUNNING)
        manager.record_error("Disk full error")
        assert manager.last_error == "Disk full error"

        manager.reset(initial_state=ServiceState.STOPPED)
        assert manager.current_state == ServiceState.STOPPED
        assert manager.last_error is None
        assert len(manager.get_history()) == 0


class TestProtectionServiceLifecycle:
    """Tests for ProtectionService lifecycle operations and idempotency."""

    @pytest.fixture
    def test_config(self):
        return ServiceConfig(
            service_name="TestProtectionService",
            worker_count=1,
            queue_max_size=50,
            shutdown_timeout_seconds=2.0,
            auto_restart_workers=False,
        )

    def test_initial_service_state(self, test_config):
        service = ProtectionService(config=test_config)
        assert service.get_state() == ServiceState.STOPPED
        assert service.is_running() is False

    def test_service_start_and_stop(self, test_config):
        service = ProtectionService(config=test_config)
        try:
            assert service.start() is True
            assert service.get_state() == ServiceState.RUNNING
            assert service.is_running() is True
        finally:
            assert service.stop() is True
            assert service.get_state() == ServiceState.STOPPED
            assert service.is_running() is False

    def test_repeated_start_is_idempotent(self, test_config):
        service = ProtectionService(config=test_config)
        try:
            assert service.start() is True
            assert service.start() is True  # Second call should safely succeed
            assert service.get_state() == ServiceState.RUNNING
            assert service.worker_manager.active_count() == 1
        finally:
            service.stop()

    def test_repeated_stop_is_idempotent(self, test_config):
        service = ProtectionService(config=test_config)
        service.start()
        assert service.stop() is True
        assert service.stop() is True  # Second call while already stopped
        assert service.get_state() == ServiceState.STOPPED

    def test_start_after_stop(self, test_config):
        service = ProtectionService(config=test_config)
        try:
            service.start()
            assert service.get_state() == ServiceState.RUNNING
            service.stop()
            assert service.get_state() == ServiceState.STOPPED

            # Restart cleanly
            service.start()
            assert service.get_state() == ServiceState.RUNNING
            assert service.worker_manager.active_count() == 1
        finally:
            service.stop()

    def test_pause_and_resume(self, test_config):
        service = ProtectionService(config=test_config)
        try:
            service.start()
            assert service.get_state() == ServiceState.RUNNING

            # Pause
            assert service.pause() is True
            assert service.get_state() == ServiceState.PAUSED
            assert service.is_running() is True  # Service is still active, just paused

            # Resume
            assert service.resume() is True
            assert service.get_state() == ServiceState.RUNNING

            # Cannot resume when already running
            assert service.resume() is False
        finally:
            service.stop()

    def test_pause_when_stopped_fails(self, test_config):
        service = ProtectionService(config=test_config)
        assert service.pause() is False
        assert service.get_state() == ServiceState.STOPPED

    def test_startup_failure_transitions_to_failed(self, test_config):
        service = ProtectionService(config=test_config)
        # Mock WorkerManager.start_workers to simulate failure
        with patch.object(service.worker_manager, "start_workers", return_value=False):
            assert service.start() is False
            assert service.get_state() == ServiceState.FAILED
            assert service.is_running() is False


class TestWindowsHostBridging:
    """Tests for WindowsServiceHost SCM control translation."""

    @pytest.fixture
    def host_fixture(self):
        cfg = ServiceConfig(
            service_name="TestSCMHost",
            worker_count=1,
            shutdown_timeout_seconds=1.0,
        )
        return create_windows_host(config=cfg)

    def test_scm_control_pause_continue_stop(self, host_fixture):
        host = host_fixture
        try:
            assert host.service.start() is True
            assert host.service.get_state() == ServiceState.RUNNING

            # SCM Pause
            assert host.handle_scm_control_pause() is True
            assert host.service.get_state() == ServiceState.PAUSED

            # SCM Continue
            assert host.handle_scm_control_continue() is True
            assert host.service.get_state() == ServiceState.RUNNING

            # SCM Interrogate
            status = host.handle_scm_control_interrogate()
            assert status["state"] == "RUNNING"
            assert status["is_running"] is True

            # SCM Stop
            assert host.handle_scm_control_stop() is True
            assert host.service.get_state() == ServiceState.STOPPED
        finally:
            host.service.stop()
