"""Configuration management for Baize using Pydantic Settings."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _resolve_env_var(value: str | None) -> str | None:
    """Resolve environment variable references like ${OPENAI_API_KEY}."""
    if value is None:
        return None
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        env_var = value[2:-1]
        return os.environ.get(env_var)
    return value


def _make_serializable(obj: Any) -> Any:
    """Recursively convert non-YAML-serializable objects (e.g. Path) to plain types."""
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_make_serializable(v) for v in obj]
    return obj


class LLMConfig(BaseSettings):
    """LLM configuration for a single provider."""

    provider: Literal[
        "openai", "anthropic", "azure", "openrouter", "deepseek",
        "dashscope", "wenxin", "zhipu", "moonshot", "minimax", "ollama"
    ] = "openai"
    model: str = "gpt-4o"
    api_key: str | None = None
    base_url: str | None = None
    timeout: int = 60
    max_retries: int = 3
    temperature: float = 0.2

    model_config = SettingsConfigDict(env_prefix="", extra="ignore", populate_by_name=True)

    def model_post_init(self, __context: Any) -> None:
        # Resolve ${ENV_VAR} references passed as literal values
        self.api_key = _resolve_env_var(self.api_key)


class ProjectConfig(BaseSettings):
    """Project configuration."""

    name: str = Field(default="my-project")
    path: Path = Field(default=Path("."))
    languages: list[str] = Field(default_factory=lambda: ["java"])
    framework: list[str] = Field(default_factory=list)

    model_config = SettingsConfigDict(env_prefix="BAIZE_PROJECT_", extra="ignore", populate_by_name=True)


class CodeQLDatabaseConfig(BaseSettings):
    """CodeQL database configuration."""

    name: str = "baize-db"
    path: Path = Field(default=Path("./.baize/db"))
    build_command: str = ""
    timeout: int = Field(default=1800)
    threads: int = Field(default=4)
    incremental: bool = True

    model_config = SettingsConfigDict(env_prefix="BAIZE_CODEQL_DATABASE_", extra="ignore", populate_by_name=True)


class CodeQLQueriesConfig(BaseSettings):
    """CodeQL queries configuration."""

    builtin: list[str] = Field(default_factory=lambda: ["security-extended"])
    custom: list[Path] = Field(default_factory=list)

    model_config = SettingsConfigDict(env_prefix="BAIZE_CODEQL_QUERIES_", extra="ignore")


class CodeQLAnalysisConfig(BaseSettings):
    """CodeQL analysis configuration."""

    timeout: int = Field(default=3600, validation_alias="BAIZE_CODEQL_ANALYSIS_TIMEOUT")
    threads: int = Field(default=2, validation_alias="BAIZE_CODEQL_ANALYSIS_THREADS")
    # Store as plain string; normalisation happens in CodeQLCLI._parse_ram_mb
    ram: str = Field(default="8192", validation_alias="BAIZE_CODEQL_ANALYSIS_RAM")

    model_config = SettingsConfigDict(env_prefix="BAIZE_CODEQL_ANALYSIS_", extra="ignore")


class CodeQLConfig(BaseSettings):
    """CodeQL CLI configuration."""

    cli_path: str = Field(default="", validation_alias="BAIZE_CODEQL_CLI_PATH")
    database: CodeQLDatabaseConfig = Field(default_factory=CodeQLDatabaseConfig)
    queries: CodeQLQueriesConfig = Field(default_factory=CodeQLQueriesConfig)
    analysis: CodeQLAnalysisConfig = Field(default_factory=CodeQLAnalysisConfig)
    queries_path: str = Field(
        default="",
        validation_alias="BAIZE_CODEQL_QUERIES_PATH",
        description="Path to github/codeql clone with QL queries. "
                    "Empty = auto-detect (sibling dir then CodeQL CLI built-in). "
                    "Supports ${ENV_VAR} references.",
    )

    model_config = SettingsConfigDict(env_prefix="BAIZE_", extra="ignore")

    def get_resolved_queries_path(self) -> str:
        """Resolve the queries path, expanding env vars if present."""
        raw = _resolve_env_var(self.queries_path)
        return raw or ""


class VulnerabilitiesConfig(BaseSettings):
    """Vulnerability types configuration."""

    enabled: list[str] = Field(default_factory=lambda: [
        "sqli", "xss", "rce", "ssrf", "deserialization", "path-traversal"
    ])
    severity_filter: list[str] = Field(default_factory=lambda: ["high", "critical"])

    model_config = SettingsConfigDict(env_prefix="BAIZE_VULN_")


class DataFlowPatternConfig(BaseSettings):
    """Data flow pattern configuration."""

    type: str = ""
    patterns: list[str] = Field(default_factory=list)

    model_config = SettingsConfigDict(env_prefix="BAIZE_DATAFLOW_")


class DataFlowConfig(BaseSettings):
    """Data flow analysis configuration."""

    sources: list[DataFlowPatternConfig] = Field(default_factory=list)
    sinks: list[DataFlowPatternConfig] = Field(default_factory=list)
    sanitizers: list[DataFlowPatternConfig] = Field(default_factory=list)

    model_config = SettingsConfigDict(env_prefix="BAIZE_DATAFLOW_")


class ReportConfig(BaseSettings):
    """Report generation configuration."""

    formats: list[Literal["json", "markdown", "html", "sarif"]] = Field(
        default_factory=lambda: ["json", "markdown"]
    )
    output_dir: Path = Field(default=Path("./.baize/reports"))
    include_dataflow: bool = True
    include_fixes: bool = False
    max_findings: int = 100

    model_config = SettingsConfigDict(env_prefix="BAIZE_REPORT_")


class ResourceLimitsConfig(BaseSettings):
    """Resource limits for scheduler."""

    max_cpu_percent: int = 80
    max_memory_percent: int = 80
    max_disk_usage_gb: int = 10

    model_config = SettingsConfigDict(env_prefix="BAIZE_RESOURCE_")


class SchedulerConfig(BaseSettings):
    """Scheduler configuration for build timeout handling (settings layer).

    Runtime scheduling uses baize.core.scheduler.SchedulerConfig (dataclass).
    This class handles env-var / YAML loading; convert to the runtime type via
    ``to_runtime()`` when constructing a Scheduler instance.
    """

    progress_interval: int = 10
    timeout_strategy: Literal["warn", "skip", "partial", "retry", "abort"] = "warn"
    resource_limits: ResourceLimitsConfig = Field(default_factory=ResourceLimitsConfig)

    model_config = SettingsConfigDict(env_prefix="BAIZE_SCHEDULER_", populate_by_name=True)

    def to_runtime(self):  # -> baize.core.scheduler.SchedulerConfig
        """Convert to the runtime dataclass used by Scheduler."""
        from baize.core.scheduler import SchedulerConfig as _RuntimeCfg, TimeoutStrategy

        return _RuntimeCfg(
            progress_interval=self.progress_interval,
            timeout_strategy=TimeoutStrategy(self.timeout_strategy),
            max_cpu_percent=self.resource_limits.max_cpu_percent,
            max_memory_percent=self.resource_limits.max_memory_percent,
            max_disk_usage_gb=self.resource_limits.max_disk_usage_gb,
        )


class LLMConfigSet(BaseSettings):
    """Full LLM configuration set with primary/secondary/embedding."""

    primary: LLMConfig = Field(default_factory=LLMConfig)
    secondary: LLMConfig = Field(default_factory=lambda: LLMConfig(model="gpt-4o-mini"))
    embedding: LLMConfig = Field(
        default_factory=lambda: LLMConfig(model="text-embedding-3-small")
    )

    model_config = SettingsConfigDict(env_prefix="BAIZE_LLM_")


class MultiAgentConfig(BaseSettings):
    """Multi-agent system configuration."""

    enabled: bool = True
    agents: list[str] = Field(default_factory=lambda: [
        "auditor", "query_generator", "processor", "fix_suggester", "knowledge"
    ])

    model_config = SettingsConfigDict(env_prefix="BAIZE_MULTI_AGENT_", extra="ignore")


class KnowledgeBaseConfig(BaseSettings):
    """RAG knowledge base configuration."""

    enabled: bool = True
    path: Path = Field(default=Path("./.baize/kb"))
    retrieval_top_k: int = 5

    model_config = SettingsConfigDict(env_prefix="BAIZE_KB_", extra="ignore")


class AuditConfig(BaseSettings):
    """Audit pipeline configuration for ``baize audit``."""

    enable_triage: bool = True
    enable_db_cache: bool = True
    enable_delta: bool = False
    force_rebuild: bool = False
    output_path: Path = Field(default=Path("./.baize/result.json"))
    build_timeout: int = 1800

    model_config = SettingsConfigDict(env_prefix="BAIZE_AUDIT_", extra="ignore")


class FixesConfig(BaseSettings):
    """Fix suggestion configuration."""

    enabled: bool = True
    auto_apply: bool = False
    review_required: bool = True

    model_config = SettingsConfigDict(env_prefix="BAIZE_FIXES_", extra="ignore")


class BaizeConfig(BaseSettings):
    """Main Baize configuration.

    加载优先级：
    1. baize.yaml 配置文件（项目根目录或指定路径）
    2. 环境变量覆盖（BAIZE_{SECTION}_{KEY} 格式）
    3. 默认值
    """

    version: str = "2.0"
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    codeql: CodeQLConfig = Field(default_factory=CodeQLConfig)
    vulnerabilities: VulnerabilitiesConfig = Field(default_factory=VulnerabilitiesConfig)
    dataflow: DataFlowConfig = Field(default_factory=DataFlowConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    llm: LLMConfigSet = Field(default_factory=LLMConfigSet)
    multi_agent: MultiAgentConfig = Field(default_factory=MultiAgentConfig)
    knowledge_base: KnowledgeBaseConfig = Field(default_factory=KnowledgeBaseConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    fixes: FixesConfig = Field(default_factory=FixesConfig)

    model_config = SettingsConfigDict(
        env_prefix="BAIZE_",
        env_nested_delimiter="_",
        extra="ignore",
    )

    @classmethod
    def from_yaml(cls, path: Path | str) -> BaizeConfig:
        """Load configuration from a YAML file."""
        import yaml

        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path) as f:
            data = yaml.safe_load(f)

        return cls(**data)

    @classmethod
    def load(cls, config_path: Path | str | None = None) -> BaizeConfig:
        """Load configuration with proper precedence.

        1. 先从 baize.yaml 加载（如果存在）
        2. 环境变量覆盖
        3. 默认值
        """
        if config_path is None:
            config_path = Path("baize.yaml")
        else:
            config_path = Path(config_path)

        if config_path.exists():
            return cls.from_yaml(config_path)

        return cls()

    def to_yaml(self, path: Path | str) -> None:
        """Save configuration to a YAML file.

        Uses ``model_dump(mode='json')`` so that Path objects are serialised
        as plain strings before PyYAML processes them.
        """
        import yaml

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # mode='json' converts Path → str, datetime → ISO string, etc.
        data = self.model_dump(mode="json", exclude_none=True)

        with open(path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, allow_unicode=True)
