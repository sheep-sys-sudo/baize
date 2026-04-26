"""Agents module for multi-agent orchestration.

This module provides:
- Base agent classes and interfaces
- Specialized agents: auditor, query_generator, processor, fix_suggester, knowledge
- Agent orchestrator for workflow coordination
- Agent registry for dynamic agent discovery

Usage:
    from baize.agents import AgentRegistry, OrchestratorAgent

    # List available agents
    agents = AgentRegistry.list_agents()

    # Create and run an agent
    auditor = AgentRegistry.create("auditor")
    result = await auditor.run(context)
"""

from baize.agents.base import (
    AgentContext,
    AgentResult,
    AgentStatus,
    BaseAgent,
    AgentRegistry,
    agent,
)
from baize.agents.auditor import AuditorAgent
from baize.agents.query_agent import QueryGeneratorAgent
from baize.agents.processor_agent import ProcessorAgent
from baize.agents.fix_agent import FixSuggesterAgent
from baize.agents.knowledge_agent import KnowledgeAgent
from baize.agents.orchestrator import AgentOrchestrator, OrchestratorAgent

__all__ = [
    "AgentContext",
    "AgentResult",
    "AgentStatus",
    "BaseAgent",
    "AgentRegistry",
    "agent",
    "AuditorAgent",
    "QueryGeneratorAgent",
    "ProcessorAgent",
    "FixSuggesterAgent",
    "KnowledgeAgent",
    "AgentOrchestrator",
    "OrchestratorAgent",
]