"""CodeQL CLI wrapper for database creation and query execution."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from baize.utils.progress import BuildMetrics


@dataclass
class CodeQLResult:
    """Result from a CodeQL CLI operation."""

    success: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    metrics: BuildMetrics = field(default_factory=BuildMetrics)
    db_path: Optional[Path] = None
    sarif_path: Optional[Path] = None


def _parse_ram_mb(ram: str) -> str:
    """Normalise RAM value to an integer MB string for the CodeQL CLI.

    CodeQL --ram flag expects a plain integer (megabytes).  Callers may
    pass strings like "4096MB", "4096mb", "4g", "4G" or just "4096".

    Returns:
        String containing an integer MB value, e.g. "4096".
    """
    ram = ram.strip()
    # e.g. "4096MB" or "4096mb"
    m = re.fullmatch(r"(\d+)\s*[Mm][Bb]?", ram)
    if m:
        return m.group(1)
    # e.g. "4G" or "4g"
    m = re.fullmatch(r"(\d+)\s*[Gg][Bb]?", ram)
    if m:
        return str(int(m.group(1)) * 1024)
    # plain integer
    if ram.isdigit():
        return ram
    logger.warning(f"Unrecognised RAM format '{ram}', using as-is")
    return ram


class CodeQLCLI:
    """Wrapper for CodeQL CLI operations."""

    def __init__(self, cli_path: Optional[str] = None):
        if cli_path:
            self.cli_path = Path(cli_path)
        else:
            self.cli_path = self._find_codeql()

        self._version: Optional[str] = None

    def _find_codeql(self) -> Path:
        """Find CodeQL CLI in PATH or common locations."""
        codeql = shutil.which("codeql")
        if codeql:
            return Path(codeql)

        common_paths = [
            Path.home() / "codeql" / "codeql",
            Path.home() / "Codeql" / "codeql" / "codeql",
            Path("/usr/local/bin/codeql"),
            Path("/opt/codeql/codeql"),
        ]
        for path in common_paths:
            if path.exists():
                return path

        raise RuntimeError(
            "CodeQL CLI not found.\n\n"
            "Installation options:\n"
            "  1. Download from: https://github.com/github/codeql-cli-binaries/releases\n"
            "  2. Extract and add to PATH: export PATH=$PATH:/path/to/codeql\n"
            "  3. Or set in baize.yaml: codeql.cli_path: /path/to/codeql/codeql\n"
            "\nSearched locations:\n"
            "  - PATH (via shutil.which)\n"
            "  - ~/codeql/codeql\n"
            "  - ~/Codeql/codeql/codeql\n"
            "  - /usr/local/bin/codeql\n"
            "  - /opt/codeql/codeql"
        )

    async def version(self) -> str:
        """Get CodeQL CLI version."""
        if self._version:
            return self._version

        result = await self._run(["version", "--format=json"])
        if result.success:
            try:
                data = json.loads(result.stdout)
                self._version = data.get("version", "unknown")
            except json.JSONDecodeError:
                self._version = "unknown"
        return self._version or "unknown"

    async def _run(
        self,
        args: list[str],
        cwd: Optional[Path] = None,
        timeout: Optional[int] = None,
        check: bool = True,
        env: Optional[dict[str, str]] = None,
    ) -> CodeQLResult:
        """Run a CodeQL CLI command."""
        cmd = [str(self.cli_path)] + args
        logger.debug(f"Running CodeQL: {' '.join(cmd)}")

        # Merge custom env with current environment
        full_env = None
        if env:
            import os
            full_env = {**os.environ, **env}

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=full_env,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )

            result = CodeQLResult(
                success=process.returncode == 0,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                returncode=process.returncode or 0,
            )

            if result.returncode != 0 and check:
                logger.warning(
                    f"CodeQL command failed (rc={result.returncode}): "
                    f"{result.stderr[:400]}"
                )

            return result

        except asyncio.TimeoutError:
            logger.error(f"CodeQL command timed out after {timeout}s")
            return CodeQLResult(success=False, returncode=-1, stderr="Timed out")

        except Exception as e:
            logger.error(f"CodeQL command error: {e}")
            return CodeQLResult(success=False, returncode=-1, stderr=str(e))

    async def database_create(
        self,
        db_path: Path,
        language: str,
        source_root: Path,
        build_command: Optional[str] = None,
        threads: int = 4,
        ram: str = "4096",
        timeout: int = 1800,
        overwrite: bool = True,
        build_mode: Optional[str] = None,
        java_home: Optional[str] = None,
    ) -> CodeQLResult:
        """Create a CodeQL database.

        Args:
            db_path: Path to create the database
            language: Language (java, python, javascript, etc.)
            source_root: Source code root directory
            build_command: Optional build command (ignored when build_mode='none')
            threads: Number of threads to use
            ram: RAM limit (e.g., "4096", "4096MB", "4g")
            timeout: Timeout in seconds
            overwrite: Overwrite existing database (required for rebuilds)
            build_mode: CodeQL build mode: 'none' (source-only, no compiler tracing),
                        'autobuild' (CodeQL auto-detects build system),
                        or None (use explicit build_command / default tracing).
                        'none' is strongly recommended for WSL environments.
            java_home: Optional path to Java home (e.g., "/usr/lib/jvm/java-17").
                       If set, will be passed as JAVA_HOME to the build subprocess.

        Returns:
            CodeQLResult with success status and metrics
        """
        db_path = Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        ram_mb = _parse_ram_mb(ram)

        args = [
            "database",
            "create",
            str(db_path),
            f"--language={language}",
            f"--source-root={source_root}",
            f"--threads={threads}",
            f"--ram={ram_mb}",
        ]

        # Always allow overwrite so incremental re-runs don't fail
        if overwrite or db_path.exists():
            args.append("--overwrite")

        if build_mode:
            args.append(f"--build-mode={build_mode}")
        elif build_command:
            args.extend(["--command", build_command])

        # When running a build command, inject JAVA_HOME if provided
        # This ensures Maven/Gradle use the correct Java version
        env = None
        if build_command and java_home:
            env = {"JAVA_HOME": java_home}

        result = await self._run(args, cwd=source_root, timeout=timeout, env=env)
        result.db_path = db_path
        return result

    async def database_analyze(
        self,
        db_path: Path,
        output_path: Path,
        queries: str = "security-extended",
        format: str = "sarif-latest",
        threads: int = 4,
        ram: str = "4096",
        timeout: int = 3600,
    ) -> CodeQLResult:
        """Run CodeQL analysis on a database.

        Args:
            db_path: Path to the CodeQL database
            output_path: Path to write SARIF results
            queries: Query suite or path to queries
            format: Output format (sarif-latest, json, csv)
            threads: Number of threads
            ram: RAM limit (e.g., "4096", "4096MB")
            timeout: Timeout in seconds

        Returns:
            CodeQLResult with success status and SARIF path
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        ram_mb = _parse_ram_mb(ram)

        args = [
            "database",
            "analyze",
            str(db_path),
            f"--format={format}",
            f"--output={output_path}",
            f"--threads={threads}",
            f"--ram={ram_mb}",
        ]

        if queries:
            args.append(queries)

        result = await self._run(args, timeout=timeout)
        result.sarif_path = output_path
        return result

    async def database_diagnostics(
        self,
        db_path: Path,
    ) -> dict[str, Any]:
        """Get diagnostics for a database."""
        result = await self._run(["database", "diagnostics", str(db_path)])
        if result.success:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"raw": result.stdout}
        return {}

    async def query_compile(
        self,
        query_path: Path,
    ) -> CodeQLResult:
        """Compile a query to check for syntax errors."""
        return await self._run(["query", "compile", str(query_path)])

    def parse_build_output(self, stderr: str) -> tuple[float, str]:
        """Parse build output to extract progress percentage.

        Returns:
            Tuple of (progress_percent, current_stage)
        """
        progress_patterns = [
            r"Building\s+(\d+)%",
            r"Progress:\s+(\d+)%",
            r"(\d+)%\s+complete",
            r"\[(\d+)/(\d+)\]",
        ]

        for pattern in progress_patterns:
            match = re.search(pattern, stderr)
            if match:
                if len(match.groups()) >= 2:
                    current, total = match.groups()
                    percent = (int(current) / int(total)) * 100
                else:
                    percent = float(match.group(1))
                return min(percent, 100.0), "building"

        if "finalizing" in stderr.lower():
            return 90.0, "finalizing"
        if "extraction" in stderr.lower():
            return 50.0, "extracting"

        return 0.0, "unknown"


async def detect_language(project_path: Path) -> str:
    """Auto-detect the primary language of a project.

    Each indicator is matched against the file *name* only (not the full path),
    so a project located at e.g. ``/home/user/java-project/`` does not
    artificially inflate the Java score for every file it contains.

    Indicators starting with ``'.'`` are treated as file-extension suffixes;
    all others must be an exact match of the file name.

    Returns:
        Language identifier (java, python, javascript, go, cpp, csharp)
    """
    files = list(project_path.rglob("*"))
    files = [f for f in files if f.is_file()]

    # Each value is a list of indicators:
    #   - starts with '.' → match as file extension (f.suffix)
    #   - otherwise       → exact filename match (f.name)
    language_indicators: dict[str, list[str]] = {
        "java": [".java", ".gradle", "pom.xml", "build.gradle"],
        "python": [".py", "setup.py", "pyproject.toml", "requirements.txt"],
        "javascript": [".js", ".ts", ".jsx", ".tsx", "package.json", "tsconfig.json"],
        "go": [".go", "go.mod", "go.sum"],
        "cpp": [".cpp", ".hpp", ".cc", ".h", "CMakeLists.txt"],
        "csharp": [".cs", ".csproj", ".sln"],
    }

    counts: dict[str, int] = {}
    for lang, indicators in language_indicators.items():
        count = 0
        for f in files:
            for indicator in indicators:
                if indicator.startswith("."):
                    if f.suffix == indicator:
                        count += 1
                else:
                    if f.name == indicator:
                        count += 1
        counts[lang] = count

    if not counts or max(counts.values()) == 0:
        return "java"

    return max(counts, key=lambda k: counts[k])


async def detect_build_command(project_path: Path, language: str) -> str:
    """Detect the appropriate build command for a project."""
    files = list(project_path.iterdir())
    filenames = {f.name for f in files}

    if language == "java":
        if "pom.xml" in filenames:
            return "mvn compile"
        if any("build.gradle" in f.name for f in files):
            return "./gradlew compileJava"

    elif language == "javascript":
        if "package.json" in filenames:
            return "npm install && npm run build"

    elif language == "python":
        if "pyproject.toml" in filenames:
            return "pip install -e ."

    return ""
