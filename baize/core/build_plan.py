"""Build planning: decides HOW to build, separate from execution."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from loguru import logger

from baize.utils.codeql import CodeQLCLI


@dataclass
class BuildPlan:
    """Structured plan for how to build a CodeQL database.

    Produced by BuildStrategyPlanner; consumed by CodeQLBuilder.
    Separating "what to do" from "how to execute" allows the planner
    to be overridden by an Agent for more intelligent decisions.
    """

    # Build approach
    build_mode: Optional[str] = None  # 'none', 'autobuild', or None
    build_command: Optional[str] = None  # e.g. "mvn compile -DskipTests"

    # Environment
    java_home: Optional[str] = None  # Path to Java home, e.g. "/usr/lib/jvm/java-17"

    # Project info
    language: str = "java"
    source_root: Path = field(default_factory=Path)

    # Reasoning (for audit/logging)
    reason: str = ""
    warnings: list[str] = field(default_factory=list)

    # Override options
    force_mode: bool = False  # If True, ignore subsequent validation


class BuildStrategyPlanner:
    """Analyzes a project and decides how to build it.

    This is the "decision layer" — it inspects the project structure,
    detects build tools and language version requirements, considers
    the runtime environment, and produces a BuildPlan.

    The planner can be replaced by an Agent-based implementation
    for more intelligent decision-making (e.g., using LLM to
    reason about build strategies).
    """

    def __init__(self, codeql_cli: Optional[CodeQLCLI] = None):
        self.codeql = codeql_cli or CodeQLCLI()

    async def create_plan(
        self,
        project_path: Path,
        explicit_build_command: Optional[str] = None,
        explicit_build_mode: Optional[str] = None,
        timeout: int = 3600,
    ) -> BuildPlan:
        """Analyze project and create a build plan.

        Args:
            project_path: Path to the project root
            explicit_build_command: CLI override, or None to auto-detect
            explicit_build_mode: CLI override ('none', 'autobuild'), or None to auto
            timeout: Build timeout in seconds

        Returns:
            BuildPlan describing how to build
        """
        logger.debug(
            f"create_plan called: explicit_build_command={explicit_build_command}, "
            f"explicit_build_mode={explicit_build_mode}"
        )
        project_path = Path(project_path)
        plan = BuildPlan(source_root=project_path)

        # Step 1: Analyze project structure
        project_info = await self._analyze_project(project_path)
        plan.language = project_info.language

        # Step 2: Detect environment
        env_info = await self._detect_environment()

        # Step 3: Decide build strategy based on all factors
        plan = self._decide_strategy(
            plan=plan,
            project_info=project_info,
            env_info=env_info,
            explicit_build_command=explicit_build_command,
            explicit_build_mode=explicit_build_mode,
            timeout=timeout,
        )

        return plan

    async def _analyze_project(self, project_path: Path):
        """Analyze project structure, detect language and build system."""
        # Simple analysis for now - can be enhanced with more detectors
        language = self._detect_language(project_path)
        build_system = self._detect_build_system(project_path)
        java_version = self._detect_java_version_requirement(project_path)
        is_multi_module = self._detect_multi_module(project_path)

        return ProjectInfo(
            language=language,
            build_system=build_system,
            java_version_required=java_version,
            is_multi_module=is_multi_module,
            build_command=self._suggest_build_command(project_path, build_system),
        )

    def _detect_language(self, project_path: Path) -> str:
        """Detect primary language from project structure."""
        if (project_path / "pom.xml").exists():
            return "java"
        if (project_path / "build.gradle").exists() or (project_path / "build.gradle.kts").exists():
            return "java"
        if (project_path / "package.json").exists():
            return "javascript"
        if (project_path / "go.mod").exists():
            return "go"
        return "java"  # default

    def _detect_build_system(self, project_path: Path) -> str:
        """Detect build system."""
        if (project_path / "pom.xml").exists():
            return "maven"
        if (project_path / "build.gradle").exists() or (project_path / "build.gradle.kts").exists():
            return "gradle"
        if (project_path / "requirements.txt").exists() or (project_path / "setup.py").exists():
            return "python"
        return "none"

    def _detect_java_version_requirement(self, project_path: Path) -> Optional[str]:
        """Detect required Java version from build config."""
        pom_xml = project_path / "pom.xml"
        if pom_xml.exists():
            try:
                content = pom_xml.read_text(encoding="utf-8")
                # Look for <java.version> or <maven.compiler.source>
                if "java.version>" in content:
                    import re
                    match = re.search(r'<java\.version>([^<]+)</java.version>', content)
                    if match:
                        return match.group(1)
                    match = re.search(r'<maven\.compiler\.source>([^<]+)</maven\.compiler\.source>', content)
                    if match:
                        return match.group(1)
            except Exception:
                pass
        return None

    def _detect_multi_module(self, project_path: Path) -> bool:
        """Check if this is a multi-module project."""
        pom_xml = project_path / "pom.xml"
        if pom_xml.exists():
            try:
                content = pom_xml.read_text(encoding="utf-8")
                return "<modules>" in content
            except Exception:
                pass
        return False

    def _suggest_build_command(self, project_path: Path, build_system: str) -> Optional[str]:
        """Suggest a build command based on build system."""
        if build_system == "maven":
            # For Maven multi-module, use install so cross-module deps resolve
            if self._detect_multi_module(project_path):
                return "mvn install -DskipTests"
            return "mvn compile -DskipTests"
        if build_system == "gradle":
            return "gradle compileJava"
        return None

    async def _detect_environment(self):
        """Detect runtime environment info."""
        import psutil

        env = EnvironmentInfo()
        uname = os.uname()
        release_lower = uname.release.lower()
        env.is_wsl = "microsoft" in release_lower or "wsl" in release_lower

        memory = psutil.virtual_memory()
        env.available_memory_mb = int(memory.available / (1024 * 1024))
        env.cpu_cores = os.cpu_count() or 4

        try:
            env.codeql_version = await self.codeql.version()
        except Exception:
            pass

        return env

    def _find_java_home(self, version: str) -> Optional[str]:
        """Find JAVA_HOME path for a given Java version.

        Args:
            version: Java version string (e.g., "17", "11", "8", "1.8")

        Returns:
            Path to JAVA_HOME if found, None otherwise
        """
        import re

        jvm_base = Path("/usr/lib/jvm")
        if not jvm_base.exists():
            return None

        # Normalize version: "1.8" -> "8", "11" -> "11"
        version_normalized = version
        if version.startswith("1."):
            version_normalized = version[2:]  # "1.8" -> "8", "1.7" -> "7"

        # Try both the normalized version and original version patterns
        version_patterns = [re.escape(version_normalized), re.escape(version)]

        try:
            for entry in jvm_base.iterdir():
                if not entry.is_dir():
                    continue
                for vp in version_patterns:
                    if re.match(rf"^java-{vp}(?:-|$)", entry.name):
                        if (entry / "bin" / "java").exists():
                            return str(entry)
        except Exception:
            pass

        return None

    def _decide_strategy(
        self,
        plan: BuildPlan,
        project_info,
        env_info,
        explicit_build_command: Optional[str],
        explicit_build_mode: Optional[str],
        timeout: int,
    ) -> BuildPlan:
        """Decide the final build strategy based on all factors.

        Priority:
        1. Explicit CLI overrides always win
        2. Auto-detected build_command → use autobuild-like approach
        3. WSL + no build command → source-only extraction
        """
        logger.debug(
            f"_decide_strategy: explicit_build_command={explicit_build_command}, "
            f"explicit_build_mode={explicit_build_mode}, "
            f"java_version_required={getattr(project_info, 'java_version_required', 'N/A')}"
        )

        # Priority 1: Explicit CLI overrides
        if explicit_build_mode is not None:
            plan.build_mode = explicit_build_mode
            plan.reason = f"CLI override: --build-mode={explicit_build_mode}"
            if explicit_build_command:
                plan.build_command = explicit_build_command
                plan.reason += f", --build-command={explicit_build_command}"
            else:
                plan.build_command = None
            return plan

        if explicit_build_command is not None:
            plan.build_command = explicit_build_command if explicit_build_command != "" else None
            plan.build_mode = None  # Let CodeQL auto-detect
            plan.reason = f"CLI override: build_command={'<empty>' if explicit_build_command == '' else explicit_build_command}"

            # Even with explicit build command, detect JAVA_HOME if needed for Maven/Gradle
            logger.debug(f"explicit_build_command path - java_version_required={project_info.java_version_required}")
            if project_info.java_version_required:
                java_home = self._find_java_home(project_info.java_version_required)
                logger.debug(f"java_home found: {java_home}")
                if java_home:
                    plan.java_home = java_home
                    plan.reason += f", JAVA_HOME={java_home}"
            return plan

        # Priority 2: Auto-detected build command
        if project_info.build_command:
            plan.build_command = project_info.build_command
            plan.build_mode = None  # CodeQL will use the command
            plan.reason = f"Auto-detected build system: {project_info.build_system}"
            if project_info.is_multi_module:
                plan.reason += " (multi-module)"
                plan.warnings.append(
                    "Multi-module project detected. Using 'mvn install' so "
                    "cross-module dependencies resolve. If some modules fail, "
                    "try: mvn install -DskipTests -pl <module> first."
                )
            plan.reason += f", command: {project_info.build_command}"

            # Check Java version compatibility and find correct JAVA_HOME
            if project_info.java_version_required:
                java_home = self._find_java_home(project_info.java_version_required)
                if java_home:
                    plan.java_home = java_home
                    plan.reason += f", JAVA_HOME={java_home}"
                else:
                    plan.warnings.append(
                        f"Project requires Java {project_info.java_version_required}, "
                        "but compatible JDK not found in /usr/lib/jvm/"
                    )
            return plan

        # Priority 3: WSL with no build command → source-only
        if env_info.is_wsl:
            plan.build_mode = "none"
            plan.build_command = None
            plan.reason = "WSL environment + no build command detected → source-only extraction"
            plan.warnings.append(
                "Source-only extraction may miss some code. "
                "For complete analysis, provide explicit build_command in baize.yaml"
            )
            return plan

        # Priority 4: Non-WSL, no build command → try autobuild
        plan.build_mode = "autobuild"
        plan.build_command = None
        plan.reason = "No build command, non-WSL environment → autobuild"
        return plan


@dataclass
class ProjectInfo:
    """Analyzed project information."""
    language: str = "java"
    build_system: str = "none"
    java_version_required: Optional[str] = None
    is_multi_module: bool = False
    build_command: Optional[str] = None


@dataclass
class EnvironmentInfo:
    """Detected environment information."""
    is_wsl: bool = False
    available_memory_mb: int = 0
    cpu_cores: int = 0
    codeql_version: str = ""
