"""
Unit and Integration Tests for ACTIS Windows Service Host and CLI Entrypoint
Tests SCM control code bridging, standalone execution lifecycle, and service CLI flags.
Does NOT require Administrator privileges or native SCM service registration.
"""

import threading
import time
import pytest
from unittest.mock import MagicMock, patch

from service.lifecycle import ServiceState
from service.config import ServiceConfig
from service.windows_host import WindowsServiceHost, create_windows_host
from service.protection_service import ProtectionService


class TestWindowsServiceHostLifecycle:
    """Tests for WindowsServiceHost standalone execution and SCM bridging."""

    @pytest.fixture
    def test_host(self):
        cfg = ServiceConfig(
            service_name="TestACTISHost",
            worker_count=1,
            shutdown_timeout_seconds=1.0,
        )
        return create_windows_host(config=cfg)

    def test_host_initialization(self, test_host):
        assert test_host.service is not None
        assert test_host.config.service_name == "TestACTISHost"
        assert not test_host.is_stop_requested

    def test_request_stop_sets_event(self, test_host):
        assert not test_host.is_stop_requested
        test_host.request_stop()
        assert test_host.is_stop_requested

    def test_scm_control_handlers(self, test_host):
        host = test_host
        try:
            assert host.service.start() is True
            assert host.service.is_running() is True

            # Interrogate
            status = host.handle_scm_control_interrogate()
            assert isinstance(status, dict)
            assert status["state"] == "RUNNING"
            assert status["is_running"] is True

            # Pause
            assert host.handle_scm_control_pause() is True
            assert host.service.get_state() == ServiceState.PAUSED

            # Continue / Resume
            assert host.handle_scm_control_continue() is True
            assert host.service.get_state() == ServiceState.RUNNING

            # Stop
            assert host.handle_scm_control_stop() is True
            assert host.service.get_state() == ServiceState.STOPPED
            assert host.is_stop_requested
        finally:
            host.service.stop()

    def test_run_standalone_graceful_stop(self, test_host):
        """Validates that run_standalone starts the service and exits cleanly when stop requested."""
        host = test_host

        # Spawn a timer thread to request stop after 100ms
        def _delayed_stop():
            time.sleep(0.1)
            host.request_stop()

        stopper = threading.Thread(target=_delayed_stop)
        stopper.daemon = True
        stopper.start()

        exit_code = host.run_standalone(poll_interval=0.05)
        stopper.join(timeout=1.0)

        assert exit_code == 0
        assert host.service.get_state() == ServiceState.STOPPED
        assert not host.service.is_running()

    def test_run_standalone_startup_failure(self):
        """Validates that run_standalone returns exit code 1 if service.start() fails."""
        mock_service = MagicMock(spec=ProtectionService)
        mock_service.start.return_value = False
        mock_service.stop.return_value = True

        host = WindowsServiceHost(service=mock_service)
        exit_code = host.run_standalone(poll_interval=0.05)

        assert exit_code == 1
        mock_service.start.assert_called_once()
        mock_service.stop.assert_called_once()

    def test_run_standalone_fails_when_service_enters_failed_state(self):
        """Validates that run_standalone detects FAILED state and exits with code 1."""
        mock_service = MagicMock(spec=ProtectionService)
        mock_service.start.return_value = True
        mock_service.is_running.return_value = False
        mock_service.get_state.return_value = ServiceState.FAILED
        mock_service.stop.return_value = True

        host = WindowsServiceHost(service=mock_service)
        exit_code = host.run_standalone(poll_interval=0.05)

        assert exit_code == 1
        mock_service.stop.assert_called_once()


class TestServiceCliRouting:
    """Tests for main.py --service and --service-status argument routing."""

    def test_main_service_status_flag(self, capsys):
        import main
        test_args = ["main.py", "--service-status"]
        with patch("sys.argv", test_args):
            with pytest.raises(SystemExit) as exc_info:
                main.main()
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "is_running" in captured.out
        assert "STOPPED" in captured.out or "RUNNING" in captured.out

    def test_main_service_flag_dispatches_run_standalone(self):
        import main
        test_args = ["main.py", "--service"]
        with patch("sys.argv", test_args):
            with patch("service.windows_host.WindowsServiceHost.run_standalone", return_value=0) as mock_run:
                with pytest.raises(SystemExit) as exc_info:
                    main.main()
                assert exc_info.value.code == 0
                mock_run.assert_called_once()
