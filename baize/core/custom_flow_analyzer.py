"""Custom data-flow analyzer — LLM generates QL code from natural language spec.

User describes the source / sink / sanitizer in natural language;
this module asks the LLM to produce a complete, self-contained CodeQL query (.ql file),
saves it to the local codeql-queries repo, and executes it against the database.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from baize.utils.codeql import CodeQLCLI

# Path to cloned github/codeql repo
_LOCAL_QUERIES_BASE = Path(__file__).parent.parent.parent / "codeql-queries"


@dataclass
class FlowSpec:
    """User-supplied specification for a custom data-flow query."""

    source_description: str
    sink_description: str
    sanitizer_description: str = ""
    language: str = "java"
    query_description: str = ""
    extra_context: str = ""


@dataclass
class CustomFlowResult:
    """Result of a custom-flow analysis run."""

    success: bool
    generated_ql: str = ""
    output_path: Optional[Path] = None
    findings_count: int = 0
    error: str = ""


_SYSTEM_PROMPT = """\
You are an expert CodeQL query author. Write a complete, syntactically correct
CodeQL query (.ql file) that detects taint-flow vulnerabilities.

Rules:
- Output ONLY raw QL source — no markdown fences, no explanation.
- Include proper metadata comments (@name, @description, @kind, @problem.severity).
- Use DataFlow::Configuration or TaintTracking::Configuration for taint tracking.
- SELECT format: select sink, source, sink, "flow description"
- The @id should be unique (e.g., java/custom-xxx).\
"""

_USER_PROMPT_TEMPLATE = """\
Language: {language}

Query description: {query_description}

Source (taint entry points):
{source_description}

Sink (dangerous operations):
{sink_description}

{sanitizer_section}{extra_context_section}\
Write the complete CodeQL query now.\
"""


def _build_user_prompt(spec: FlowSpec) -> str:
    sanitizer_section = (
        f"Sanitizer (functions that clean/validate the taint):\n{spec.sanitizer_description}\n\n"
        if spec.sanitizer_description
        else ""
    )
    extra_section = (
        f"Additional context:\n{spec.extra_context}\n\n"
        if spec.extra_context
        else ""
    )
    return _USER_PROMPT_TEMPLATE.format(
        language=spec.language,
        query_description=spec.query_description or "Detect taint flow from source to sink",
        source_description=spec.source_description,
        sink_description=spec.sink_description,
        sanitizer_section=sanitizer_section,
        extra_context_section=extra_section,
    )


def _strip_markdown(text: str) -> str:
    """Remove ```ql ... ``` or ``` ... ``` fences from LLM output."""
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z]*\n?", "", text, flags=re.MULTILINE)
    text = re.sub(r"^```\s*$", "", text, flags=re.MULTILINE)
    return text.strip()


class CustomFlowAnalyzer:
    """Generates and executes AI-authored CodeQL queries for custom data flows.

    Workflow:
    1. Build prompt from FlowSpec.
    2. LLM generates QL code.
    3. Save to local codeql-queries repo (so imports resolve).
    4. Compile check (via CodeQLCLI, with one retry on failure).
    5. Execute via CodeQLCLI.database_analyze.
    """

    def __init__(
        self,
        llm_config: Any,
        context_provider: Any = None,
        codeql_cli: Optional[CodeQLCLI] = None,
    ) -> None:
        """Initialize the analyzer.

        Args:
            llm_config: LLMConfig instance for query generation.
            context_provider: Optional QL context provider for RAG.
            codeql_cli: Optional CodeQLCLI instance (created if not provided).
        """
        self._llm_config = llm_config
        self._context_provider = context_provider
        self.codeql = codeql_cli or CodeQLCLI()

    async def analyze(
        self,
        spec: FlowSpec,
        db_path: Path,
        output_path: Optional[Path] = None,
    ) -> CustomFlowResult:
        """Generate QL code from FlowSpec, compile, and execute against db.

        Args:
            spec: User-supplied FlowSpec describing source/sink/sanitizer.
            db_path: Path to the CodeQL database.
            output_path: Where to write the SARIF result; defaults to ./custom_flow.sarif.

        Returns:
            CustomFlowResult with findings count and diagnostics.
        """
        if output_path is None:
            output_path = Path("custom_flow.sarif")

        # Step 1: Generate QL
        logger.info("Generating QL query via LLM ...")
        ql_code, gen_error = await self._generate_ql(spec)
        if not ql_code:
            return CustomFlowResult(success=False, error=f"LLM failed: {gen_error}")

        # Step 2: Save to local codeql-queries dir so imports resolve
        lang_dir = _LOCAL_QUERIES_BASE / spec.language / "ql" / "src" / "Security" / "CWE" / "CustomFlow"
        lang_dir.mkdir(parents=True, exist_ok=True)
        ql_path = lang_dir / "CustomFlow.ql"
        ql_path.write_text(ql_code, encoding="utf-8")
        logger.info(f"Generated QL saved to: {ql_path}")

        # Step 3: Compile check (via CodeQLCLI, with one retry)
        ok, compile_error = await self._compile_with_retry(ql_path)
        if not ok:
            return CustomFlowResult(
                success=False,
                generated_ql=ql_code,
                output_path=ql_path,
                error=f"Compile error:\n{compile_error}",
            )

        # Step 4: Execute against database (via CodeQLCLI)
        logger.info(f"Executing against database: {db_path}")
        result = await self.codeql.database_analyze(
            db_path=db_path,
            output_path=output_path,
            queries=str(ql_path),
            threads=2,
        )

        if not result.success:
            return CustomFlowResult(
                success=False,
                generated_ql=ql_code,
                output_path=ql_path,
                error=f"Analysis failed:\n{result.stderr}",
            )

        # Count findings
        findings_count = 0
        if output_path.exists():
            import json
            try:
                sarif = json.loads(output_path.read_text())
                findings_count = len(sarif.get("runs", [{}])[0].get("results", []))
            except Exception:
                pass

        logger.info(f"Analysis complete. Findings: {findings_count}")
        return CustomFlowResult(
            success=True,
            generated_ql=ql_code,
            output_path=output_path,
            findings_count=findings_count,
        )

    async def _compile_with_retry(self, ql_path: Path, max_retries: int = 1) -> tuple[bool, str]:
        """Compile a QL query, with one retry on failure.

        Some LLM-generated queries have minor issues that a second attempt can fix.
        """
        for attempt in range(max_retries + 1):
            result = await self.codeql.query_compile(ql_path)
            if result.success:
                return True, ""
            if attempt < max_retries:
                logger.warning(
                    f"QL compile failed (attempt {attempt + 1}), retrying: {result.stderr[:200]}"
                )
            else:
                return False, result.stderr or result.stdout
        return False, "Unknown compile error"

    async def _generate_ql(self, spec: FlowSpec) -> tuple[str, str]:
        """Generate QL source from spec. Returns (ql_code, error_message)."""
        from baize.utils.llm import call_llm

        if self._context_provider is not None:
            query_for_retrieval = (
                f"{spec.query_description} {spec.source_description} {spec.sink_description}"
            )
            try:
                snippets = self._context_provider.retrieve(
                    query=query_for_retrieval,
                    language=spec.language,
                    top_k=3,
                )
                if snippets:
                    logger.info(f"Injecting {len(snippets)} QL example(s) into generation prompt")
            except Exception as exc:
                logger.warning(f"QL context retrieval failed (non-fatal): {exc}")

        prompt = _build_user_prompt(spec)
        try:
            raw = await call_llm(
                prompt,
                self._llm_config,
                system=_SYSTEM_PROMPT,
                caller="custom_flow_analyzer.generate",
            )
        except Exception as exc:
            return "", str(exc)

        ql_code = _strip_markdown(raw)
        if not ql_code:
            return "", "LLM returned empty content"
        return ql_code, ""
