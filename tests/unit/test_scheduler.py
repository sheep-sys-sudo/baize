"""Unit tests for scheduler module."""

import asyncio
import pytest

from baize.core.scheduler import (
    Scheduler,
    SchedulerState,
    TimeoutStrategy,
    SchedulerConfig,
)


@pytest.fixture
def scheduler():
    return Scheduler()


@pytest.fixture
def scheduler_config():
    return SchedulerConfig(
        progress_interval=5,
        timeout_strategy=TimeoutStrategy.WARN,
    )


class TestScheduler:
    def test_initial_state(self, scheduler):
        assert scheduler.state == SchedulerState.IDLE
        assert scheduler.progress == 0.0

    def test_start_build(self, scheduler):
        async def run():
            await scheduler.start_build(timeout=60)
            assert scheduler.state == SchedulerState.INITIALIZING
            await scheduler.complete_build(success=True)

        asyncio.run(run())

    def test_update_progress(self, scheduler):
        async def run():
            await scheduler.start_build(timeout=60)
            await scheduler.update_progress("building", 50.0, "Half done")
            assert scheduler.progress == 50.0
            assert scheduler.state == SchedulerState.BUILDING
            await scheduler.complete_build(success=True)

        asyncio.run(run())

    def test_complete_build_success(self, scheduler):
        async def run():
            await scheduler.start_build(timeout=60)
            await scheduler.complete_build(success=True)
            assert scheduler.state == SchedulerState.COMPLETED
            assert scheduler.progress == 100.0

        asyncio.run(run())

    def test_complete_build_failure(self, scheduler):
        async def run():
            await scheduler.start_build(timeout=60)
            await scheduler.complete_build(success=False)
            assert scheduler.state == SchedulerState.FAILED

        asyncio.run(run())

    def test_handle_timeout(self, scheduler):
        async def run():
            await scheduler.start_build(timeout=1)
            await asyncio.sleep(1.5)
            strategy = await scheduler.handle_timeout()
            assert strategy == TimeoutStrategy.WARN
            assert scheduler.state == SchedulerState.TIMEOUT

        asyncio.run(run())

    def test_reset(self, scheduler):
        async def run():
            await scheduler.start_build(timeout=60)
            await scheduler.reset()
            assert scheduler.state == SchedulerState.IDLE
            assert scheduler.progress == 0.0

        asyncio.run(run())


class TestSchedulerConfig:
    def test_default_config(self):
        config = SchedulerConfig()
        assert config.progress_interval == 10
        assert config.timeout_strategy == TimeoutStrategy.WARN

    def test_custom_config(self, scheduler_config):
        assert scheduler_config.progress_interval == 5
        assert scheduler_config.timeout_strategy == TimeoutStrategy.WARN