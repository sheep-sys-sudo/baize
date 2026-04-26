"""CodeQL database builder with intelligent monitoring."""

from __future__ import annotations

import os
import psutil
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from loguru import logger

from baize.core.scheduler import Scheduler, TimeoutStrategy
from baize.core.build_plan import BuildPlan
from baize.utils.codeql import CodeQLCLI, detect_build_command, detect_language
from baize.utils.progress import BuildMetrics, ProgressTracker


@dataclass
class BuildStrategy:
    """Build strategy configuration."""

    incremental: bool = True
    threads: int = 4
    memory_limit: str = "auto"
    timeout: int = 1800
    fallback: str = "lightweight"
    use_disk_cache: bool = True
    reduce_concurrency: bool = False


@dataclass
class EnvironmentInfo:
    """Detected environment information."""

    is_wsl: bool = False
    wsl_version: int = 0
    available_memory_mb: int = 0
    cpu_cores: int = 0
    disk_space_gb: int = 0
    codeql_version: str = ""

    def is_memory_constrained(self) -> bool:
        return self.available_memory_mb < 8 * 1024


@dataclass
class ProjectInfo:
    """Analyzed project information."""

    language: str
    build_command: str
    lines_of_code: int = 0
    file_count: int = 0
    framework: list[str] = field(default_factory=list)


class CodeQLBuilder:
    """Builds CodeQL databases with intelligent monitoring and fallback."""

    def __init__(
        self,
        codeql_cli: Optional[CodeQLCLI] = None,
        scheduler: Optional[Scheduler] = None,
        on_timeout: Optional[Callable[[TimeoutStrategy], None]] = None,
    ):
        self.codeql = codeql_cli or CodeQLCLI()
        self.scheduler = scheduler or Scheduler()
        self._env_info: Optional[EnvironmentInfo] = None
        self._project_info: Optional[ProjectInfo] = None
        self._on_timeout = on_timeout

    async def detect_environment(self) -> EnvironmentInfo:
        """Detect the current environment (WSL, memory, CPU, etc.)."""
        if self._env_info:
            return self._env_info

        env = EnvironmentInfo()

        uname = os.uname()
        release_lower = uname.release.lower()
        is_wsl = "microsoft" in release_lower or "wsl" in release_lower
        env.is_wsl = is_wsl

        if is_wsl:
            try:
                with open("/proc/version", "r") as f:
                    version = f.read().lower()
                    if "microsoft-standard-wsl2" in version:
                        env.wsl_version = 2
                    elif "microsoft-standard-wsl1" in version or "microsoft-wsl" in version:
                        env.wsl_version = 1
            except Exception:
                pass

        memory = psutil.virtual_memory()
        env.available_memory_mb = int(memory.available / (1024 * 1024))

        env.cpu_cores = os.cpu_count() or 4

        try:
            disk = psutil.disk_usage("/")
            env.disk_space_gb = int(disk.free / (1024 * 1024 * 1024))
        except Exception:
            env.disk_space_gb = 100

        try:
            env.codeql_version = await self.codeql.version()
        except Exception as e:
            logger.warning(f"Could not detect CodeQL version: {e}")

        self._env_info = env
        logger.info(
            f"Environment detected: WSL={env.is_wsl} (v{env.wsl_version}), "
            f"Memory={env.available_memory_mb}MB, CPU cores={env.cpu_cores}"
        )

        return env

    async def analyze_project(self, project_path: Path) -> ProjectInfo:
        """Analyze a project to determine language and build requirements."""
        project_path = Path(project_path)

        # Cache per builder instance to avoid re-scanning for the same path
        if self._project_info is not None:
            return self._project_info

        language = await detect_language(project_path)
        build_cmd = await detect_build_command(project_path, language)

        total_lines = 0
        file_count = 0

        try:
            for ext in self._get_language_extensions(language):
                for f in project_path.rglob(f"*{ext}"):
                    if f.is_file():
                        file_count += 1
                        try:
                            with open(f, "r", encoding="utf-8", errors="ignore") as fp:
                                total_lines += sum(1 for _ in fp)
                        except Exception:
                            pass
        except Exception as e:
            logger.warning(f"Error counting lines: {e}")

        logger.info(
            f"Project analyzed: {language}, {file_count} files, "
            f"{total_lines} lines of code"
        )

        self._project_info = ProjectInfo(
            language=language,
            build_command=build_cmd,
            lines_of_code=total_lines,
            file_count=file_count,
        )
        return self._project_info

    def _get_language_extensions(self, language: str) -> list[str]:
        """Get file extensions for a language."""
        extensions = {
            "java": [".java"],
            "python": [".py"],
            "javascript": [".js", ".jsx", ".ts", ".tsx"],
            "go": [".go"],
            "cpp": [".cpp", ".hpp", ".cc", ".h"],
            "csharp": [".cs"],
        }
        return extensions.get(language, [".java"])

    async def decide_build_strategy(
        self,
        project_path: Path,
        force_strategy: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> BuildStrategy:
        """Decide on the optimal build strategy based on environment and project.

        Args:
            project_path:   Source root to analyse.
            force_strategy: ``"lightweight"`` bypasses all heuristics.
            timeout:        Override the strategy's default timeout (seconds).
                            When None, each branch picks a sensible default.
        """
        env = await self.detect_environment()
        project = await self.analyze_project(project_path)

        if force_strategy == "lightweight":
            return BuildStrategy(
                incremental=True,
                threads=2,
                memory_limit="2048",
                timeout=timeout or 1800,
                fallback="skip",
            )

        if env.is_memory_constrained():
            return BuildStrategy(
                incremental=True,
                threads=2,
                memory_limit="2048",
                timeout=timeout or 1800,
                fallback="lightweight",
                reduce_concurrency=True,
            )

        if project.lines_of_code > 1_000_000:
            return BuildStrategy(
                incremental=True,
                threads=min(env.cpu_cores // 2, 4),
                memory_limit="auto",
                timeout=timeout or 3600,
                fallback="partial",
            )

        return BuildStrategy(
            incremental=True,
            threads=min(env.cpu_cores // 2, 4),
            memory_limit="auto",
            timeout=timeout or 3600,
            fallback="warn",
        )

    async def build_database(
        self,
        project_path: Path,
        db_path: Optional[Path] = None,
        strategy: Optional[BuildStrategy] = None,
        build_plan: Optional["BuildPlan"] = None,
        progress_callback: Optional[Callable[[str, float, str], None]] = None,
    ) -> tuple[bool, BuildMetrics, Path]:
        """Build a CodeQL database with monitoring.

        Args:
            project_path:      Project source root.
            db_path:           Where to store the DB (default: project/.baize/db).
            strategy:          Build strategy; auto-detected when None.
            build_plan:       Build plan from BuildStrategyPlanner (recommended).
                              Contains build_mode, build_command, language, etc.
                              If provided, takes precedence over individual params.
            progress_callback: Called with (stage, percent, message) on progress.

        Returns:
            Tuple of (success, metrics, db_path)
        """
        project_path = Path(project_path)

        if strategy is None:
            strategy = await self.decide_build_strategy(project_path)

        if db_path is None:
            db_path = project_path / ".baize" / "db"

        db_path = Path(db_path)

        # Pass timeout callback so the scheduler can notify us on timeout
        self.scheduler._on_timeout = self._on_timeout

        await self.scheduler.start_build(strategy.timeout)

        tracker = ProgressTracker()
        tracker.start("Building CodeQL database")

        async def report_progress(stage: str, percent: float, msg: str = "") -> None:
            await self.scheduler.update_progress(stage, percent, msg)
            tracker.update(stage, percent, msg)
            if progress_callback:
                progress_callback(stage, percent, msg)

        env = await self.detect_environment()
        memory_limit = strategy.memory_limit
        if memory_limit == "auto":
            # Use at most half of available memory, capped at 4 GB
            memory_limit = str(min(env.available_memory_mb // 2, 4096))

        # Reuse cached project info; avoid a second full directory scan
        project_info = await self.analyze_project(project_path)

        # Use BuildPlan if provided, otherwise fall back to legacy behavior.
        # BuildPlan gives the planner/agent full control over build strategy.
        if build_plan is not None:
            effective_build_mode = build_plan.build_mode
            effective_build_command = build_plan.build_command
            effective_language = build_plan.language
            effective_java_home = build_plan.java_home
            logger.info(f"BuildPlan: {build_plan.reason}")
            for warning in build_plan.warnings:
                logger.warning(f"BuildPlan warning: {warning}")
        else:
            # Legacy fallback: replicate old auto-detection behavior
            effective_build_mode = None
            effective_build_command = project_info.build_command or None
            effective_language = project_info.language
            effective_java_home = None
            if effective_build_mode is None and effective_build_command is None:
                if env.is_wsl:
                    effective_build_mode = "none"
                    logger.info(
                        "WSL environment detected and no build command specified — "
                        "using --build-mode=none (source-only extraction, no compiler tracing)."
                    )

        # Pre-clean: if db_path exists but has no codeql-database.yml it is a
        # partial/broken database.  CodeQL refuses to --overwrite it in that
        # state, so remove it first.
        db_yml = db_path / "codeql-database.yml"
        if db_path.exists() and not db_yml.exists():
            logger.warning(
                f"Detected broken/partial CodeQL DB at {db_path} "
                "(codeql-database.yml missing) — removing before rebuild."
            )
            shutil.rmtree(db_path, ignore_errors=True)

        try:
            await report_progress("building", 5.0, "Starting database creation")

            result = await self.codeql.database_create(
                db_path=db_path,
                language=effective_language,
                source_root=project_path,
                build_command=effective_build_command,
                threads=strategy.threads,
                ram=memory_limit,
                timeout=strategy.timeout,
                overwrite=True,
                build_mode=effective_build_mode,
                java_home=effective_java_home,
            )

            if result.success:
                # Post-build health check: verify the DB is non-empty.
                # For --build-mode=none, source extraction may not produce files in src/
                # depending on project layout (e.g., Maven multi-module needs compilation).
                # We warn but don't fail for none mode.
                extracted = self._count_extracted_files(db_path, effective_language)
                if extracted == 0:
                    if effective_build_mode == "none":
                        logger.warning(
                            f"CodeQL DB built (exit 0) but 0 {effective_language} files "
                            "were extracted — source-only extraction found no files. "
                            "This may indicate the project needs compilation first, "
                            "or the source files are in a non-standard layout. "
                            "For complete analysis, provide an explicit build_command."
                        )
                        # Don't fail for none mode - the database is still usable
                        # for some queries, just less complete
                        await report_progress("completed", 100.0, "Build completed (source-only, files may be incomplete)")
                    else:
                        logger.error(
                            f"CodeQL DB built (exit 0) but 0 {effective_language} files "
                            "were extracted — the build tracer likely failed. "
                            "Consider using --build-mode=none or providing an explicit build command."
                        )
                        result.success = False
                        result.stderr += (
                            "\n[baize] Post-build health check failed: "
                            f"0 {effective_language} source files extracted."
                        )
                        await report_progress("failed", 0.0, "DB is empty after build")
                else:
                    logger.info(
                        f"Post-build health check passed: "
                        f"{extracted} {effective_language} file(s) extracted."
                    )
                    await report_progress("completed", 100.0, f"Build successful ({extracted} files extracted)")
            else:
                stderr_summary = result.stderr[:300]
                logger.error(f"Build failed: {stderr_summary}")

                # Suggest remediation based on common failure patterns
                suggestion = ""
                if "build-mode=none" in str(effective_build_mode) and "0 files" in str(stderr_summary):
                    suggestion = (
                        "Source-only extraction found no files. "
                        "Try providing a build command: --build-command='mvn compile -DskipTests'"
                    )
                elif "WSL" in str(stderr_summary) or env.is_wsl:
                    suggestion = "On WSL, try --build-mode=none for source-only analysis"
                elif "JAVA_HOME" in stderr_summary or "java" in stderr_summary.lower():
                    suggestion = "Check JAVA_HOME is set correctly for the required Java version"
                else:
                    suggestion = "Try --build-mode=none for source-only analysis, or check your build command"

                await report_progress(
                    "failed", 0.0,
                    f"Build failed: {result.stderr[:200]}. {suggestion}"
                )

            metrics = await self.scheduler.complete_build(success=result.success)
            tracker.stop(success=result.success)

            if not result.success:
                metrics.errors.append(result.stderr[:500])

            return result.success, metrics, db_path

        except Exception as e:
            logger.error(f"Build error: {e}")
            metrics = await self.scheduler.complete_build(success=False)
            tracker.stop(success=False)
            metrics.errors.append(str(e))
            raise

    def _count_extracted_files(self, db_path: Path, language: str) -> int:
        """Count how many source files were extracted into the CodeQL DB.

        For build-mode=none, CodeQL stores source in ``<db>/src.zip`` instead of <db>/src/.
        For traced builds, source goes into ``<db>/src/``.
        We check both locations as a health-check proxy.
        Returns 0 when no source files are found.
        """
        extensions = tuple(self._get_language_extensions(language))
        count = 0

        # Check src.zip (used by build-mode=none and some Java extractions)
        src_zip = db_path / "src.zip"
        if src_zip.exists():
            try:
                import zipfile
                with zipfile.ZipFile(src_zip, "r") as zf:
                    for name in zf.namelist():
                        if any(name.endswith(ext) for ext in extensions):
                            count += 1
                if count > 0:
                    return count
            except Exception as e:
                logger.debug(f"Health check src.zip count error: {e}")

        # Check src/ directory (used by traced builds)
        src_dir = db_path / "src"
        if src_dir.exists():
            try:
                for f in src_dir.rglob("*"):
                    if f.is_file() and f.suffix in extensions:
                        count += 1
            except Exception as e:
                logger.debug(f"Health check src dir count error: {e}")

        return count
