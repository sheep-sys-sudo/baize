"""Scheduler module for build timeout and progress monitoring."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from loguru import logger

from baize.utils.progress import BuildMetrics


class SchedulerState(str, Enum):
    """State machine for scheduler."""

    IDLE = "idle"
    INITIALIZING = "initializing"
    BUILDING = "building"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    FAILED = "failed"


class TimeoutStrategy(str, Enum):
    """Timeout handling strategies."""

    WARN = "warn"
    SKIP = "skip"
    PARTIAL = "partial"
    RETRY = "retry"
    ABORT = "abort"


@dataclass
class SchedulerConfig:
    """Configuration for scheduler."""

    progress_interval: int = 10
    timeout_strategy: TimeoutStrategy = TimeoutStrategy.WARN
    max_cpu_percent: int = 80
    max_memory_percent: int = 80
    max_disk_usage_gb: int = 10


@dataclass
class SchedulerEvent:
    """Events emitted by scheduler."""

    state: SchedulerState
    progress: float
    message: str
    metrics: Optional[BuildMetrics] = None
    warning: Optional[str] = None
    error: Optional[str] = None


class Scheduler:
    """Manages build scheduling, timeout, and progress monitoring."""

    def __init__(
        self,
        config: Optional[SchedulerConfig] = None,
        on_event: Optional[Callable[[SchedulerEvent], None]] = None,
        on_timeout: Optional[Callable[[TimeoutStrategy], None]] = None,
    ):
        self.config = config or SchedulerConfig()
        self._on_event = on_event
        self._on_timeout = on_timeout
        self._state = SchedulerState.IDLE
        self._progress = 0.0
        self._start_time = 0.0
        self._build_metrics = BuildMetrics()
        self._watchdog_task: Optional[asyncio.Task] = None
        self._should_stop = False

    @property
    def state(self) -> SchedulerState:
        return self._state

    @property
    def progress(self) -> float:
        return self._progress

    def _emit_event(
        self,
        state: Optional[SchedulerState] = None,
        progress: Optional[float] = None,
        message: str = "",
        **kwargs,
    ) -> None:
        event = SchedulerEvent(
            state=state or self._state,
            progress=progress if progress is not None else self._progress,
            message=message,
            **kwargs,
        )
        if self._on_event:
            self._on_event(event)

    async def start_build(self, timeout: int) -> None:
        """Start monitoring a build with the given timeout."""
        self._state = SchedulerState.INITIALIZING
        self._progress = 0.0
        now = time.time()
        self._start_time = now
        # Reset metrics so duration_seconds is accurate for this build
        self._build_metrics = BuildMetrics(start_time=now)
        self._should_stop = False
        self._emit_event(state=SchedulerState.INITIALIZING, progress=0.0, message="Initializing build")

        self._watchdog_task = asyncio.create_task(self._watchdog_loop(timeout))

    async def start_analysis(self, timeout: int) -> None:
        """Start monitoring an analysis phase with the given timeout."""
        self._state = SchedulerState.ANALYZING
        self._progress = 0.0
        now = time.time()
        self._start_time = now
        self._build_metrics = BuildMetrics(start_time=now)
        self._should_stop = False
        self._emit_event(state=SchedulerState.ANALYZING, progress=0.0, message="Starting analysis")

        self._watchdog_task = asyncio.create_task(self._watchdog_loop(timeout))

    async def update_progress(
        self,
        stage: str,
        progress: float,
        message: str = "",
    ) -> None:
        """Update the current build progress."""
        self._progress = min(progress, 100.0)

        if stage == "building" and self._state != SchedulerState.BUILDING:
            self._state = SchedulerState.BUILDING
            self._emit_event(state=SchedulerState.BUILDING, progress=self._progress, message=message)
        elif stage == "analyzing" and self._state != SchedulerState.ANALYZING:
            self._state = SchedulerState.ANALYZING
            self._emit_event(state=SchedulerState.ANALYZING, progress=self._progress, message=message)

    async def complete_build(self, success: bool = True) -> BuildMetrics:
        """Mark build as complete and return metrics."""
        self._should_stop = True
        self._build_metrics.end_time = time.time()

        if success:
            self._state = SchedulerState.COMPLETED
            self._progress = 100.0
            self._emit_event(state=SchedulerState.COMPLETED, progress=100.0, message="Build completed")
        else:
            self._state = SchedulerState.FAILED
            self._emit_event(state=SchedulerState.FAILED, progress=self._progress, message="Build failed")

        if self._watchdog_task:
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass

        return self._build_metrics

    async def handle_timeout(self) -> TimeoutStrategy:
        """Handle a build timeout based on configured strategy."""
        self._state = SchedulerState.TIMEOUT
        strategy = self.config.timeout_strategy
        logger.warning(f"Build timeout detected, applying strategy: {strategy.value}")

        self._build_metrics.warnings.append(
            f"Build timeout using strategy: {strategy.value}"
        )

        self._emit_event(
            state=SchedulerState.TIMEOUT,
            warning=f"Timeout occurred, applying {strategy.value} strategy",
        )

        # Notify the upper layer (builder/agent) so it can act on the strategy
        if self._on_timeout:
            self._on_timeout(strategy)

        return strategy

    async def _watchdog_loop(self, timeout: int) -> None:
        """Background task that monitors build progress and handles timeout."""
        check_interval = min(self.config.progress_interval, 30)
        start = time.time()

        try:
            while not self._should_stop:
                await asyncio.sleep(check_interval)
                elapsed = time.time() - start

                if elapsed >= timeout:
                    await self.handle_timeout()
                    self._should_stop = True
                    break

                remaining = timeout - elapsed
                if remaining < 60:
                    self._emit_event(
                        message=f"Warning: {int(remaining)}s remaining before timeout"
                    )

        except asyncio.CancelledError:
            pass

    def get_build_duration(self) -> float:
        """Get elapsed time since build started."""
        if self._start_time == 0:
            return 0.0
        return time.time() - self._start_time

    def report_resource_usage(
        self,
        cpu_percent: float,
        memory_mb: float,
    ) -> None:
        """Report current resource usage."""
        if memory_mb > self._build_metrics.peak_memory_mb:
            self._build_metrics.peak_memory_mb = memory_mb

        if cpu_percent > self._build_metrics.average_cpu_percent:
            self._build_metrics.average_cpu_percent = cpu_percent

        if memory_mb / 1024 > self.config.max_disk_usage_gb:
            self._build_metrics.warnings.append("High memory usage detected")

    async def reset(self) -> None:
        """Reset scheduler to idle state."""
        self._should_stop = True
        self._state = SchedulerState.IDLE
        self._progress = 0.0
        self._start_time = 0.0
        self._build_metrics = BuildMetrics()

        if self._watchdog_task:
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass
