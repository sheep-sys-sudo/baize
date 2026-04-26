"""Base agent class and agent context for multi-agent orchestration."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from loguru import logger


class AgentStatus(str, Enum):
    """Status of an agent."""

    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    WAITING = "waiting"


@dataclass
class AgentContext:
    """Context passed to agents during execution.

    This contains all the shared state and data that agents need to operate.
    """

    project_path: str = ""
    config: dict = field(default_factory=dict)
    data: dict = field(default_factory=dict)
    state: dict = field(default_factory=dict)
    results: dict = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from context."""
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a value in context."""
        self.data[key] = value

    def update(self, **kwargs) -> None:
        """Update multiple values in context."""
        self.data.update(kwargs)


@dataclass
class AgentResult:
    """Result returned by an agent."""

    success: bool
    output: Any = None
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    status: AgentStatus = AgentStatus.COMPLETED

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "metadata": self.metadata,
            "status": self.status.value,
        }


class BaseAgent(ABC):
    """Base class for all agents in the system.

    Agents are specialized components that perform specific tasks
    in the code audit workflow. Each agent receives an AgentContext
    and produces an AgentResult.

    Subclasses must implement the `execute` method.
    """

    name: str = "base"
    description: str = "Base agent"

    def __init__(self):
        self._status = AgentStatus.IDLE
        self._current_context: Optional[AgentContext] = None

    @property
    def status(self) -> AgentStatus:
        """Get current agent status."""
        return self._status

    @abstractmethod
    async def execute(self, context: AgentContext) -> AgentResult:
        """Execute the agent's task.

        Args:
            context: Agent context with project information and shared data

        Returns:
            AgentResult with the execution outcome
        """
        pass

    async def run(self, context: AgentContext) -> AgentResult:
        """Run the agent with the given context.

        This method handles status tracking and error management.
        Subclasses should not override this method.

        Args:
            context: Agent context

        Returns:
            AgentResult
        """
        self._status = AgentStatus.RUNNING
        self._current_context = context

        try:
            logger.debug(f"Agent {self.name} starting execution")
            result = await self.execute(context)
            self._status = AgentStatus.COMPLETED if result.success else AgentStatus.FAILED
            return result
        except Exception as e:
            logger.error(f"Agent {self.name} failed: {e}")
            self._status = AgentStatus.FAILED
            return AgentResult(
                success=False,
                error=str(e),
                status=AgentStatus.FAILED,
            )
        finally:
            self._current_context = None

    def wait(self) -> None:
        """Wait for the agent to complete (for sync contexts)."""
        pass

    def cancel(self) -> None:
        """Cancel the agent's execution."""
        self._status = AgentStatus.FAILED
        logger.warning(f"Agent {self.name} cancelled")


class AgentRegistry:
    """Registry for managing available agents.

    This registry allows agents to be discovered and instantiated
    by name, enabling dynamic agent selection.
    """

    _agents: dict[str, type[BaseAgent]] = {}

    @classmethod
    def register(cls, name: str, agent_class: type[BaseAgent]) -> None:
        """Register an agent class.

        Args:
            name: Agent name
            agent_class: Agent class
        """
        cls._agents[name] = agent_class
        logger.debug(f"Registered agent: {name}")

    @classmethod
    def create(cls, name: str) -> Optional[BaseAgent]:
        """Create an agent instance by name.

        Args:
            name: Agent name

        Returns:
            Agent instance or None if not found
        """
        agent_class = cls._agents.get(name)
        if agent_class:
            return agent_class()
        return None

    @classmethod
    def list_agents(cls) -> list[str]:
        """List all registered agent names."""
        return list(cls._agents.keys())


def agent(name: str):
    """Decorator to register an agent class.

    Usage:
        @agent("my_agent")
        class MyAgent(BaseAgent):
            ...
    """
    def decorator(cls: type[BaseAgent]) -> type[BaseAgent]:
        AgentRegistry.register(name, cls)
        return cls
    return decorator