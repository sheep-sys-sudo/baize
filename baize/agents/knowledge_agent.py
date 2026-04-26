"""Knowledge agent for enriching findings with KB context."""

from __future__ import annotations

from typing import Any

from loguru import logger

from baize.agents.base import AgentContext, AgentResult, BaseAgent, agent


@agent("knowledge")
class KnowledgeAgent(BaseAgent):
    """Knowledge agent that enriches findings with vulnerability knowledge base context.

    This agent:
    - Retrieves CWE descriptions and fix guidance for each finding's vuln type
    - Provides free-form context retrieval for RAG-style augmentation
    - Degrades gracefully when ChromaDB / KB is not initialised
    """

    name = "knowledge"
    description = "Enriches findings with knowledge base context (CWE, fix hints)"

    async def execute(self, context: AgentContext) -> AgentResult:
        """Enrich findings with KB context.

        Context keys:
            findings: list[dict] or list[Finding] — findings to enrich
            query:    str — optional free-form query for context retrieval

        Returns:
            AgentResult with:
                output.enriched_findings: list of {finding, kb_context} dicts
                output.context:           free-form RAG context string
                output.kb_available:      bool
        """
        findings: list[Any] = context.get("findings", [])
        query: str = context.get("query", "")

        try:
            from baize.kb import VectorStore, create_retriever

            store = VectorStore()
            if not store.is_initialized:
                logger.warning("Knowledge base not initialised — skipping enrichment")
                return AgentResult(
                    success=True,
                    output={
                        "enriched_findings": [
                            {"finding": f, "kb_context": []} for f in findings
                        ],
                        "context": "",
                        "kb_available": False,
                    },
                    metadata={"kb_entries_used": 0},
                )

            retriever = create_retriever(store)
            enriched = []
            total_kb_entries = 0

            for finding in findings:
                # Support both dict and Finding objects
                if isinstance(finding, dict):
                    vuln_type = finding.get("vuln_type", "")
                    rule_id = finding.get("rule_id", "")
                else:
                    vuln_type = str(getattr(finding, "vuln_type", ""))
                    rule_id = getattr(finding, "rule_id", "")

                search_query = vuln_type or rule_id or "vulnerability"
                kb_results = retriever.retrieve_vulnerability_info(
                    search_query,
                    vuln_type=vuln_type if vuln_type else None,
                    top_k=2,
                )
                kb_ctx = [r.content for r in kb_results]
                total_kb_entries += len(kb_ctx)

                enriched.append({"finding": finding, "kb_context": kb_ctx})

            context_text = retriever.enrich_context(query) if query else ""

            logger.info(
                f"KnowledgeAgent enriched {len(enriched)} findings "
                f"with {total_kb_entries} KB entries"
            )

            return AgentResult(
                success=True,
                output={
                    "enriched_findings": enriched,
                    "context": context_text,
                    "kb_available": True,
                },
                metadata={"kb_entries_used": total_kb_entries},
            )

        except Exception as e:
            logger.error(f"KnowledgeAgent error: {e}")
            return AgentResult(
                success=False,
                error=str(e),
                output={
                    "enriched_findings": [
                        {"finding": f, "kb_context": []} for f in findings
                    ],
                    "context": "",
                    "kb_available": False,
                },
            )
