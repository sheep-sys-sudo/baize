"""Orchestrator agent for coordinating multi-agent workflow."""

from __future__ import annotations

from typing import Optional

from loguru import logger

from baize.agents.base import AgentContext, AgentResult, AgentRegistry, BaseAgent, agent


@agent("orchestrator")
class OrchestratorAgent(BaseAgent):
    """Orchestrates the overall code audit workflow.

    The orchestrator is responsible for:
    - Planning the audit strategy
    - Coordinating sub-agents
    - Aggregating results
    - Reporting final output
    """

    name = "orchestrator"
    description = "Orchestrates the code audit workflow"

    async def execute(self, context: AgentContext) -> AgentResult:
        """Execute the orchestrator workflow.

        Args:
            context: Agent context with project info

        Returns:
            AgentResult with aggregated findings
        """
        project_path = context.project_path
        vuln_types = context.get("vuln_types", ["sqli", "xss", "rce"])

        logger.info(f"Orchestrator starting audit for {project_path}")

        results = []

        query_agent = AgentRegistry.create("query_generator")
        if query_agent:
            query_result = await query_agent.run(AgentContext(
                project_path=project_path,
                data={"vuln_types": vuln_types},
            ))
            results.append(("query_generator", query_result))

        auditor_agent = AgentRegistry.create("auditor")
        if auditor_agent:
            auditor_result = await auditor_agent.run(AgentContext(
                project_path=project_path,
                data=context.data,
            ))
            results.append(("auditor", auditor_result))

        processor_agent = AgentRegistry.create("processor")
        if processor_agent:
            processor_result = await processor_agent.run(AgentContext(
                project_path=project_path,
                data=context.data,
            ))
            results.append(("processor", processor_result))

        aggregated = {
            "total_agents": len(results),
            "successful": sum(1 for _, r in results if r.success),
            "failed": sum(1 for _, r in results if not r.success),
            "agent_results": {name: r.to_dict() for name, r in results},
        }

        return AgentResult(
            success=True,
            output=aggregated,
            metadata={"agents_executed": [n for n, _ in results]},
        )


class AgentOrchestrator:
    """Orchestrates multiple agents for a workflow.

    This class manages the execution of multiple agents in a coordinated manner,
    handling dependencies and result aggregation.
    """

    def __init__(self):
        self._agents: list[BaseAgent] = []
        self._context: Optional[AgentContext] = None

    def add_agent(self, agent: Optional[BaseAgent]) -> "AgentOrchestrator":
        """Add an agent to the workflow.

        Args:
            agent: Agent to add

        Returns:
            Self for chaining
        """
        if agent is not None:
            self._agents.append(agent)
        return self

    async def run(self, context: AgentContext) -> dict:
        """Run all agents in sequence.

        Args:
            context: Shared context for all agents

        Returns:
            Dict with aggregated results
        """
        self._context = context
        results = []

        for ag in self._agents:
            logger.info(f"Running agent: {ag.name}")
            result = await ag.run(context)
            results.append((ag.name, result))

            if not result.success and result.metadata.get("critical"):
                logger.warning(f"Critical failure in {ag.name}, stopping workflow")
                break

        return {
            "total_agents": len(self._agents),
            "results": {name: r.to_dict() for name, r in results},
        }

    def create_workflow(
        self,
        project_path: str,
        vuln_types: list[str],
    ) -> "AgentOrchestrator":
        """Create a standard audit workflow.

        Args:
            project_path: Path to project
            vuln_types: Vulnerability types to check

        Returns:
            Configured orchestrator
        """
        self.add_agent(AgentRegistry.create("auditor"))
        self.add_agent(AgentRegistry.create("query_generator"))
        self.add_agent(AgentRegistry.create("processor"))
        self.add_agent(AgentRegistry.create("fix_suggester"))

        return self