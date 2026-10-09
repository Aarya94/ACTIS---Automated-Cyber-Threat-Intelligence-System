"""
ACTIS Protection Service Worker & Failure Handling Test Suite
Validates worker lifecycle, cancellation, error capture, bounded recovery,
pool degradation, and graceful shutdown semantics.
"""

import threading
import time
import pytest
from unittest.mock import MagicMock

from service.lifecycle import ServiceState
from service.config import ServiceConfig
from service.workers import ServiceWorker, WorkerManager, WorkerState
from service.protection_service import ProtectionService


class TestServiceWorker:
    """Tests for single ServiceWorker thread behavior."""

    def test_worker_initial_status(self):
        worker = ServiceWorker(worker_id="w1", name="TestWorker-1")
        status = worker.get_status()
        assert status.worker_id == "w1"
        assert status.name == "TestWorker-1"
        assert status.state == WorkerState.STOPPED
        assert status.is_alive is False
        assert status.items_processed == 0
        assert status.errors_count == 0

    def test_worker_start_and_clean_stop(self):
        processed_count = 0
        def fake_work():
            nonlocal processed_count
            processed_count += 1
            return True

        worker = ServiceWorker(worker_id="w1", work_fn=fake_work, idle_sleep=0.01)
        worker.start()
        time.sleep(0.05)

        assert worker.is_alive() is True
        assert worker.state == WorkerState.RUNNING
        assert worker.get_status().items_processed > 0

        clean_stop = worker.stop(timeout=1.0)
        assert clean_stop is True
        assert worker.is_alive() is False
        assert worker.state == WorkerState.STOPPED

    def test_worker_pause_and_resume(self):
        cycles = 0
        def counting_work():
            nonlocal cycles
            cycles += 1
            return True

        worker = ServiceWorker(worker_id="w1", work_fn=counting_work, idle_sleep=0.01)
        worker.start()
        time.sleep(0.03)

        worker.pause()
        time.sleep(0.05)
        paused_cycles = cycles

        # While paused, cycles should not advance significantly
        time.sleep(0.05)
        assert cycles == paused_cycles

        worker.resume()
        time.sleep(0.05)
        assert cycles > paused_cycles

        worker.stop(timeout=1.0)

    def test_worker_failure_handling(self):
        error_callback = MagicMock()
        def failing_work():
            raise RuntimeError("Deliberate test failure")

        worker = ServiceWorker(
            worker_id="w1",
            work_fn=failing_work,
            on_error=error_callback,
            idle_sleep=0.01,
        )
        worker.start()
        time.sleep(0.1)

        # Worker should have exited and marked state FAILED
        assert worker.state == WorkerState.FAILED
        assert worker.get_status().errors_count == 1
        assert "Deliberate test failure" in worker.get_status().last_error
        error_callback.assert_called_once()
        assert error_callback.call_args[0][0] == "w1"


class TestWorkerManager:
    """Tests for WorkerManager multi-threaded pool coordination."""

    def test_manager_starts_and_stops_workers(self):
        manager = WorkerManager(worker_count=2, worker_name_prefix="ManagerTest")
        assert manager.active_count() == 0

        assert manager.start_workers() is True
        assert manager.active_count() == 2
        assert manager.total_count() == 2
        assert manager.all_alive() is True

        # Idempotent start: should not duplicate
        assert manager.start_workers() is False
        assert manager.active_count() == 2

        # Clean stop
        assert manager.stop_workers(timeout_per_worker=1.0) is True
        assert manager.active_count() == 0

    def test_manager_restart_failed_workers(self):
        fail_flag = True
        def flaky_work():
            if fail_flag:
                raise ValueError("Transient error")
            return False

        manager = WorkerManager(worker_count=1)
        manager.start_workers(work_fn=flaky_work)
        time.sleep(0.1)

        assert manager.is_any_failed() is True
        assert manager.active_count() == 0

        # Now fix condition and restart
        fail_flag = False
        restarted = manager.restart_failed_workers(work_fn=flaky_work)
        assert restarted == 1
        time.sleep(0.05)
        assert manager.all_alive() is True

        manager.stop_workers(timeout_per_worker=1.0)


class TestProtectionServiceFailureRecovery:
    """Tests for ProtectionService bounded recovery and degradation policy."""

    def test_service_degrades_when_single_worker_fails_in_pool(self):
        # Pool with 2 workers, 1 worker will fail
        call_counts = {"w1": 0, "w2": 0}
        def selective_work():
            curr = threading.current_thread().name
            if "Worker-1" in curr:
                raise RuntimeError("Worker 1 crashed")
            time.sleep(0.02)
            return False

        cfg = ServiceConfig(
            service_name="DegradeTest",
            worker_count=2,
            auto_restart_workers=False,  # Test degradation without auto-restart
        )
        service = ProtectionService(config=cfg, worker_task_override=selective_work)
        try:
            service.start()
            # Wait for worker 1 to crash and callback to fire
            time.sleep(0.2)

            health = service.get_health()
            assert health.state == "DEGRADED"
            assert health.workers_alive == 1
            assert health.workers_total == 2
            assert health.is_healthy is False
            assert "Worker 1 crashed" in str(health.last_error)
        finally:
            service.stop()

    def test_service_fails_when_all_workers_fail(self):
        def all_failing_work():
            raise RuntimeError("Fatal crash")

        cfg = ServiceConfig(
            service_name="CrashTest",
            worker_count=1,
            auto_restart_workers=False,
        )
        service = ProtectionService(config=cfg, worker_task_override=all_failing_work)
        try:
            service.start()
            time.sleep(0.15)

            health = service.get_health()
            assert health.state == "FAILED"
            assert health.workers_alive == 0
            assert health.is_running is False
        finally:
            service.stop()

    def test_service_bounded_recovery_policy(self):
        attempts = 0
        def recurring_failure():
            nonlocal attempts
            attempts += 1
            raise RuntimeError(f"Failure #{attempts}")

        cfg = ServiceConfig(
            service_name="BoundedRecoveryTest",
            worker_count=1,
            auto_restart_workers=True,
            max_restart_attempts=2,
            restart_cooldown_seconds=0.05,
        )
        service = ProtectionService(config=cfg, worker_task_override=recurring_failure)
        try:
            service.start()
            time.sleep(0.4)

            # Recovery attempts must be bounded to max_restart_attempts
            health = service.get_health()
            assert health.restart_count == 2
            # After max attempts exhausted, service transitions to FAILED
            assert health.state == "FAILED"
            assert health.workers_alive == 0
        finally:
            service.stop()
