"""Unit tests for configuration module."""

import pytest
from pathlib import Path

from baize.config import (
    BaizeConfig,
    ProjectConfig,
    CodeQLConfig,
    LLMConfig,
    SchedulerConfig,
)


class TestBaizeConfig:
    def test_default_config(self):
        config = BaizeConfig()
        assert config.version == "2.0"
        assert config.project.name == "my-project"

    def test_config_from_dict(self):
        config = BaizeConfig(
            project=ProjectConfig(name="test"),
        )
        assert config.project.name == "test"

    def test_resolve_env_var(self):
        import os
        os.environ["TEST_API_KEY"] = "secret123"

        config = LLMConfig(api_key="${TEST_API_KEY}")
        assert config.api_key == "secret123"

        del os.environ["TEST_API_KEY"]


class TestProjectConfig:
    def test_default_values(self):
        config = ProjectConfig()
        assert config.name == "my-project"
        assert config.languages == ["java"]

    def test_custom_values(self):
        config = ProjectConfig(
            name="custom-project",
            languages=["python", "javascript"],
        )
        assert config.name == "custom-project"
        assert len(config.languages) == 2


class TestCodeQLConfig:
    def test_default_values(self):
        config = CodeQLConfig()
        assert config.database.timeout == 1800
        assert config.analysis.threads == 4

    def test_nested_config(self):
        from baize.config import CodeQLDatabaseConfig
        config = CodeQLConfig(database=CodeQLDatabaseConfig(timeout=3600))
        assert config.database.timeout == 3600


class TestLLMConfig:
    def test_provider_validation(self):
        config = LLMConfig(provider="openai", model="gpt-4o")
        assert config.provider == "openai"
        assert config.model == "gpt-4o"

    def test_env_var_resolution(self):
        import os
        os.environ["MY_API_KEY"] = "test-key"
        config = LLMConfig(api_key="${MY_API_KEY}")
        assert config.api_key == "test-key"
        del os.environ["MY_API_KEY"]


class TestSchedulerConfig:
    def test_timeout_strategies(self):
        from baize.core.scheduler import TimeoutStrategy

        config = SchedulerConfig(timeout_strategy=TimeoutStrategy.WARN)
        assert config.timeout_strategy == TimeoutStrategy.WARN