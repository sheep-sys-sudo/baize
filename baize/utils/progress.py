"""Progress tracking utilities for build and analysis monitoring."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
)
from rich.table import Table


@dataclass
class ProgressUpdate:
    """Represents a progress update from a background task."""

    stage: str
    percent: float
    message: str
    elapsed_seconds: float
    resource_usage: dict = field(default_factory=dict)


@dataclass
class BuildMetrics:
    """Metrics collected during a build process."""

    start_time: float = 0.0
    end_time: float = 0.0
    peak_memory_mb: float = 0.0
    average_cpu_percent: float = 0.0
    disk_io_mb: float = 0.0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return self.end_time - self.start_time

    def to_dict(self) -> dict:
        return {
            "duration_seconds": self.duration_seconds,
            "peak_memory_mb": self.peak_memory_mb,
            "average_cpu_percent": self.average_cpu_percent,
            "disk_io_mb": self.disk_io_mb,
            "warnings": self.warnings,
            "errors": self.errors,
        }


class ProgressTracker:
    """Tracks progress of build and analysis operations."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self._progress: Optional[Progress] = None
        self._current_task: Optional[TaskID] = None
        self._start_time: float = 0.0
        self._stage: str = "initializing"
        self._metrics = BuildMetrics()

    def start(self, description: str = "Processing") -> None:
        """Start progress tracking with a main task."""
        self._progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
        )
        self._progress.start()
        self._current_task = self._progress.add_task(description, total=100)
        self._start_time = time.time()
        self._metrics.start_time = self._start_time

    def update(self, stage: str, percent: float, message: str = "") -> None:
        """Update progress with current stage information."""
        self._stage = stage
        if self._progress and self._current_task is not None:
            self._progress.update(
                self._current_task,
                advance=percent - self._progress.tasks[self._current_task].percentage,
                description=f"[bold blue]{stage}",
            )

    def stop(self, success: bool = True) -> BuildMetrics:
        """Stop progress tracking and return metrics."""
        self._metrics.end_time = time.time()
        if self._progress:
            self._progress.stop()
        return self._metrics

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self._start_time

    def report_resources(self, cpu_percent: float, memory_mb: float) -> None:
        """Report current resource usage."""
        if memory_mb > self._metrics.peak_memory_mb:
            self._metrics.peak_memory_mb = memory_mb
        if cpu_percent > self._metrics.average_cpu_percent:
            self._metrics.average_cpu_percent = cpu_percent

    def add_warning(self, warning: str) -> None:
        """Add a warning message."""
        self._metrics.warnings.append(warning)

    def add_error(self, error: str) -> None:
        """Add an error message."""
        self._metrics.errors.append(error)

    def create_summary_table(self) -> Table:
        """Create a summary table of build metrics."""
        table = Table(title="Build Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Duration", f"{self._metrics.duration_seconds:.1f}s")
        table.add_row("Peak Memory", f"{self._metrics.peak_memory_mb:.1f} MB")
        table.add_row("Avg CPU", f"{self._metrics.average_cpu_percent:.1f}%")

        if self._metrics.warnings:
            table.add_row("Warnings", str(len(self._metrics.warnings)))
        if self._metrics.errors:
            table.add_row("Errors", str(len(self._metrics.errors)))

        return table


class CallbackProgressTracker(ProgressTracker):
    """Progress tracker that also calls a callback function."""

    def __init__(
        self,
        callback: Optional[Callable[[ProgressUpdate], None]] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._callback = callback

    def update_with_callback(
        self, stage: str, percent: float, message: str = "", **kwargs
    ) -> None:
        """Update progress and call the callback function."""
        self.update(stage, percent, message)
        if self._callback:
            update = ProgressUpdate(
                stage=stage,
                percent=percent,
                message=message,
                elapsed_seconds=self.elapsed_seconds,
                resource_usage=kwargs,
            )
            self._callback(update)