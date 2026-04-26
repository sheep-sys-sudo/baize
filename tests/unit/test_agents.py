"""Unit tests for agent module."""

import pytest

from baize.agents.base import AgentContext, AgentResult, AgentRegistry, agent


class TestAgentRegistry:
    """Tests for AgentRegistry."""

    def test_register_and_create(self):
        @agent("test_agent")
        class TestAgent:
            name = "test_agent"
            description = "Test agent"

            async def execute(self, context):
                return AgentResult(success=True)

        assert "test_agent" in AgentRegistry.list_agents()
        created = AgentRegistry.create("test_agent")
        assert created is not None


class TestAgentContext:
    """Tests for AgentContext."""

    def test_get_set(self):
        ctx = AgentContext()
        ctx.set("key", "value")
        assert ctx.get("key") == "value"

    def test_get_default(self):
        ctx = AgentContext()
        assert ctx.get("nonexistent", "default") == "default"

    def test_update(self):
        ctx = AgentContext()
        ctx.update(key1="value1", key2="value2")
        assert ctx.get("key1") == "value1"
        assert ctx.get("key2") == "value2"


class TestAgentResult:
    """Tests for AgentResult."""

    def test_to_dict(self):
        result = AgentResult(
            success=True,
            output={"data": "test"},
            metadata={"count": 1},
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["output"]["data"] == "test"
        assert d["metadata"]["count"] == 1