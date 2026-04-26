"""MCP (Model Context Protocol) Server for Baize.

Exposes Baize tools to AI agents via HTTP API, enabling agents to:
- Run full audit pipelines (baize_audit)
- Triage projects before auditing (baize_triage)
- Check system status (baize_status)
- Build databases and run analysis as individual steps
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from loguru import logger

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    logger.warning("FastAPI not available. Install with: pip install fastapi uvicorn")


class BaizeMCPServer:
    """MCP Server that exposes Baize tools via HTTP API.

    Tools exposed:
    - baize_audit: Full audit pipeline (triage -> build -> analyze -> output)
    - baize_triage: Quick project viability assessment
    - baize_status: System status and CodeQL availability
    - baize_build: Build CodeQL database
    - baize_analyze: Run analysis on existing database
    - baize_report: Generate report from SARIF
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        config_path: Optional[Path] = None,
    ):
        self._host = host
        self._port = port
        self._config_path = config_path or Path("baize.yaml")
        self._app: Optional[FastAPI] = None
        self._server = None

        if FASTAPI_AVAILABLE:
            self._init_app()

    def _init_app(self) -> None:
        """Initialize the FastAPI application."""
        self._app = FastAPI(
            title="Baize MCP Server",
            description="AI Agent x CodeQL Intelligent Code Audit Orchestration Engine",
            version="0.2.0",
        )

        self._app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        self._register_routes()

    def _register_routes(self) -> None:
        """Register API routes."""
        if not self._app:
            return

        @self._app.get("/")
        async def root():
            return {
                "name": "Baize MCP Server",
                "version": "0.2.0",
                "status": "running",
                "tools": [
                    "/tools/baize_audit",
                    "/tools/baize_triage",
                    "/tools/baize_status",
                    "/tools/baize_build",
                    "/tools/baize_analyze",
                    "/tools/baize_report",
                    "/tools/baize_query_list",
                ],
            }

        @self._app.get("/health")
        async def health():
            return {"status": "healthy"}

        # ── baize_status ─────────────────────────────────────────────
        @self._app.get("/tools/baize_status")
        async def status():
            """Check system status: CodeQL availability, version, environment."""
            try:
                from baize.utils.codeql import CodeQLCLI

                codeql = CodeQLCLI()
                version = await codeql.version()
                codeql_ok = version not in ("unknown", "")

                import os, psutil
                uname = os.uname()
                is_wsl = "microsoft" in uname.release.lower()
                mem = psutil.virtual_memory()

                return {
                    "codeql_available": codeql_ok,
                    "codeql_version": version,
                    "codeql_path": str(codeql.cli_path),
                    "environment": {
                        "is_wsl": is_wsl,
                        "available_memory_mb": int(mem.available / (1024 * 1024)),
                        "cpu_cores": os.cpu_count() or 4,
                    },
                }
            except Exception as e:
                return {
                    "codeql_available": False,
                    "error": str(e),
                }

        # ── baize_triage ─────────────────────────────────────────────
        @self._app.post("/tools/baize_triage")
        async def triage(request: dict):
            """Quick project assessment — checks viability before full audit."""
            try:
                from baize.core.triage import TriageAssessor

                project_path = Path(request.get("project_path", ".")).resolve()
                if not project_path.exists():
                    raise HTTPException(status_code=400, detail="Project path does not exist")

                assessor = TriageAssessor(project_path)
                result = await assessor.assess()

                return {
                    "success": True,
                    "project_path": str(project_path),
                    "result": result.to_dict(),
                }
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Triage error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        # ── baize_audit ──────────────────────────────────────────────
        @self._app.post("/tools/baize_audit")
        async def audit(request: dict):
            """Run full audit pipeline on a project.

            Steps: triage -> (cached) build -> analyze -> structured output.

            Returns result.json content with all findings and dataflow paths.
            """
            try:
                from baize.config import BaizeConfig, ProjectConfig
                from baize.core import (
                    CodeQLBuilder,
                    Analyzer,
                    ResultProcessor,
                    Scheduler,
                    BuildStrategyPlanner,
                    DBCache,
                    TriageAssessor,
                )
                from baize.models.audit_result import AuditResult, TriageInfo
                from baize.utils.codeql import CodeQLCLI
                from baize.queries import get_template_manager
                from baize.models.finding import FindingSeverity, VulnerabilityType

                project_path = Path(request.get("project_path", ".")).resolve()
                vulns = request.get("vulns")
                severity = request.get("severity")
                force_rebuild = request.get("force_rebuild", False)
                delta_mode = request.get("delta", False)

                if not project_path.exists():
                    raise HTTPException(status_code=400, detail="Project path does not exist")

                config = BaizeConfig.load(self._config_path)
                config.project = ProjectConfig(
                    name=project_path.name,
                    path=project_path,
                    languages=config.project.languages,
                )

                result = AuditResult.create_empty(
                    project_name=project_path.name,
                    project_path=str(project_path),
                )

                # Triage
                triage_inst = TriageAssessor(project_path)
                triage_result = await triage_inst.assess()
                result.triage = TriageInfo(
                    viable=triage_result.viable,
                    score=triage_result.score,
                    language=triage_result.language,
                    file_count=triage_result.file_count,
                    lines_of_code=triage_result.lines_of_code,
                    build_system=triage_result.build_system,
                )
                result.language = triage_result.language

                # DB cache
                db_cache = DBCache(project_path)
                db_path = project_path / ".baize" / "db"
                config_section = {
                    "language": triage_result.language,
                    "build_system": triage_result.build_system,
                }
                current_hash = db_cache.compute_hash(config_section)

                # Build if needed
                if db_cache.should_rebuild(current_hash, force=force_rebuild):
                    codeql = CodeQLCLI(cli_path=config.codeql.cli_path or None)
                    scheduler_cfg = config.scheduler.to_runtime()
                    scheduler = Scheduler(config=scheduler_cfg)
                    builder = CodeQLBuilder(codeql, scheduler)
                    planner = BuildStrategyPlanner(codeql)

                    build_plan = await planner.create_plan(
                        project_path=project_path,
                        explicit_build_command=None,
                        explicit_build_mode=None,
                        timeout=config.codeql.database.timeout,
                    )

                    strategy = await builder.decide_build_strategy(project_path)
                    build_ok, metrics, _ = await builder.build_database(
                        project_path=project_path,
                        build_plan=build_plan,
                        strategy=strategy,
                    )

                    if not build_ok:
                        raise HTTPException(status_code=500, detail="CodeQL database build failed")

                    db_cache.write_cache_hash(current_hash)

                result.db_hash = current_hash
                result.build_info = {"cached": not db_cache.should_rebuild(current_hash, force_rebuild)}

                # Analyze
                codeql = CodeQLCLI(cli_path=config.codeql.cli_path or None)
                analyzer = Analyzer(codeql)
                processor = ResultProcessor()
                tm = get_template_manager(
                    queries_path=config.codeql.queries_path,
                    project_path=str(project_path),
                )

                if vulns:
                    vuln_list = [v.strip() for v in vulns.split(",")]
                    query_specs = tm.build_query_specs(triage_result.language, vuln_list)
                    if not query_specs:
                        query_specs = [tm.get_suite(triage_result.language)]
                else:
                    query_specs = [tm.get_suite(triage_result.language)]

                output_dir = project_path / ".baize" / "reports"
                output_dir.mkdir(parents=True, exist_ok=True)

                all_findings = []
                for spec in query_specs:
                    spec_sarif = output_dir / f"results_{abs(hash(spec)) % 10000}.sarif"
                    ok, sarif_path = await analyzer.execute_query(
                        db_path=db_path,
                        queries=spec,
                        output_path=spec_sarif,
                    )
                    if not ok:
                        continue

                    sev_filter = None
                    if severity:
                        sev_filter = [FindingSeverity(s.strip()) for s in severity.split(",")]
                    vuln_filter = None
                    if vulns:
                        vuln_filter = [VulnerabilityType(s.strip()) for s in vulns.split(",")]

                    findings = processor.process_results(
                        sarif_path,
                        severity_filter=sev_filter,
                        vuln_types_filter=vuln_filter,
                    )
                    all_findings.extend(findings)

                all_findings = await processor.deduplicate(all_findings)

                # Build result
                audit_result = AuditResult.from_findings(
                    findings=all_findings,
                    project_name=project_path.name,
                    project_path=str(project_path),
                    language=triage_result.language,
                    db_hash=current_hash,
                    triage=result.triage,
                )
                audit_result.build_info = result.build_info

                # Write result
                output_path = project_path / ".baize" / "result.json"
                audit_result.to_json(output_path)

                return {
                    "success": True,
                    "output_path": str(output_path),
                    "result": audit_result.to_dict(),
                }
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Audit error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        # ── baize_build ──────────────────────────────────────────────
        @self._app.post("/tools/baize_build")
        async def build_database(request: dict):
            """Build CodeQL database."""
            try:
                from baize.config import BaizeConfig
                from baize.core import CodeQLBuilder, Scheduler, BuildStrategyPlanner
                from baize.utils.codeql import CodeQLCLI

                project_path = Path(request.get("project_path", "."))
                build_mode = request.get("build_mode")

                config = BaizeConfig.load(self._config_path)
                codeql = CodeQLCLI(cli_path=config.codeql.cli_path or None)
                scheduler = Scheduler()
                builder = CodeQLBuilder(codeql, scheduler)
                planner = BuildStrategyPlanner(codeql)

                build_plan = await planner.create_plan(
                    project_path=project_path,
                    explicit_build_command=request.get("build_command"),
                    explicit_build_mode=build_mode,
                    timeout=request.get("timeout", 1800),
                )

                strategy = await builder.decide_build_strategy(project_path)
                success, metrics, db_path = await builder.build_database(
                    project_path=project_path,
                    build_plan=build_plan,
                    strategy=strategy,
                )

                return {
                    "success": success,
                    "db_path": str(db_path),
                    "duration_seconds": metrics.duration_seconds,
                    "peak_memory_mb": metrics.peak_memory_mb,
                    "warnings": metrics.warnings,
                    "errors": metrics.errors,
                }
            except Exception as e:
                logger.error(f"Build error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        # ── baize_analyze ────────────────────────────────────────────
        @self._app.post("/tools/baize_analyze")
        async def analyze(request: dict):
            """Run vulnerability analysis."""
            try:
                from baize.config import BaizeConfig
                from baize.core import Analyzer, ResultProcessor
                from baize.utils.codeql import CodeQLCLI

                project_path = Path(request.get("project_path", "."))

                db_path = project_path / ".baize" / "db"
                if not db_path.exists():
                    raise HTTPException(status_code=400, detail="Database not found. Run build first.")

                config = BaizeConfig.load(self._config_path)
                codeql = CodeQLCLI(cli_path=config.codeql.cli_path or None)
                analyzer = Analyzer(codeql)
                processor = ResultProcessor()

                output_path = project_path / ".baize" / "reports" / "results.sarif"
                output_path.parent.mkdir(parents=True, exist_ok=True)

                success, sarif_path = await analyzer.execute_query(
                    db_path=db_path,
                    output_path=output_path,
                    threads=config.codeql.analysis.threads,
                    ram=config.codeql.analysis.ram,
                    timeout=config.codeql.analysis.timeout,
                )

                findings = processor.process_results(sarif_path)

                return {
                    "success": success,
                    "sarif_path": str(sarif_path),
                    "total_findings": len(findings),
                    "findings_by_severity": {
                        "critical": len([f for f in findings if f.severity.value == "critical"]),
                        "high": len([f for f in findings if f.severity.value == "high"]),
                        "medium": len([f for f in findings if f.severity.value == "medium"]),
                        "low": len([f for f in findings if f.severity.value == "low"]),
                    },
                }
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Analyze error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        # ── baize_report ─────────────────────────────────────────────
        @self._app.post("/tools/baize_report")
        async def generate_report(request: dict):
            """Generate analysis report."""
            try:
                from baize.config import BaizeConfig
                from baize.core import ResultProcessor
                from baize.reports import generate_report

                input_path = Path(request.get("input_path", ".baize/reports/results.sarif"))
                output_format = request.get("format", "json")
                output_path = Path(request.get("output_path", f"baize-report.{output_format}"))

                if not input_path.exists():
                    raise HTTPException(status_code=400, detail="SARIF file not found.")

                config = BaizeConfig.load(self._config_path)
                processor = ResultProcessor()

                report_obj = processor.create_report(
                    input_path,
                    project_name=config.project.name,
                    project_path=str(config.project.path),
                )

                generate_report(report_obj, output_path, output_format)

                return {
                    "success": True,
                    "output_path": str(output_path),
                    "format": output_format,
                }
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Report error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        # ── baize_query_list ─────────────────────────────────────────
        @self._app.get("/tools/baize_query_list")
        async def list_queries():
            """List available query templates."""
            try:
                from baize.queries import get_template_manager

                manager = get_template_manager()
                templates = manager.list_templates()

                return {
                    "templates": templates,
                    "vuln_types": manager.get_all_vuln_types(),
                }
            except Exception as e:
                logger.error(f"List queries error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        # ── knowledge search ─────────────────────────────────────────
        @self._app.get("/knowledge/search")
        async def search_knowledge(q: str, top_k: int = 5):
            """Search the knowledge base."""
            try:
                from baize.kb import VectorStore, create_retriever, initialize_knowledge_base

                store = VectorStore()
                if not store.is_initialized:
                    initialize_knowledge_base(store)

                retriever = create_retriever(store)
                results = retriever.retrieve_vulnerability_info(q, top_k=top_k)

                return {
                    "query": q,
                    "results": [
                        {
                            "content": r.content,
                            "score": r.score,
                            "vuln_type": r.vuln_type,
                            "cwe": r.cwe,
                        }
                        for r in results
                    ],
                }
            except Exception as e:
                logger.error(f"Knowledge search error: {e}")
                raise HTTPException(status_code=500, detail=str(e))

    async def start(self) -> None:
        """Start the MCP server (async)."""
        if not FASTAPI_AVAILABLE:
            logger.error("FastAPI not available")
            return

        config = uvicorn.Config(
            self._app,
            host=self._host,
            port=self._port,
            log_level="info",
        )
        self._server = uvicorn.Server(config)
        await self._server.serve()

    def run(self) -> None:
        """Run the server synchronously."""
        if not FASTAPI_AVAILABLE:
            logger.error("FastAPI not available")
            return

        uvicorn.run(
            self._app,
            host=self._host,
            port=self._port,
            log_level="info",
        )


def create_mcp_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    config_path: Optional[Path] = None,
) -> BaizeMCPServer:
    """Create an MCP server instance.

    Args:
        host: Host to bind to.
        port: Port to listen on.
        config_path: Path to baize.yaml.

    Returns:
        BaizeMCPServer instance.
    """
    return BaizeMCPServer(host=host, port=port, config_path=config_path)
