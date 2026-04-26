"""CLI interface for Baize using Typer.

Usage:
    baize init --project ./myproject
    baize build
    baize analyze --vulns sqli,xss
    baize report --format markdown
    baize mcp --port 8080
    baize kb --init
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from baize import __version__
from baize.config import BaizeConfig, ProjectConfig
from baize.core import (
    CodeQLBuilder,
    Analyzer,
    ResultProcessor,
    Scheduler,
    BuildStrategyPlanner,
    DBCache,
    DeltaAnalyzer,
    TriageAssessor,
)
from baize.models.audit_result import AuditResult, TriageInfo
from baize.queries import get_template_manager
from baize.utils.logger import init_logger, logger
from baize.utils.codeql import CodeQLCLI
from baize.banner import print_banner

# Initialize logger early to avoid DEBUG spam during module imports
# The callback will re-initialize with appropriate level based on --verbose
init_logger(level="INFO")

app = typer.Typer(
    name="baize",
    help="白泽 - AI Agent × CodeQL 智能代码审计编排引擎",
    add_completion=False,
)

console = Console()


@app.command()
def init(
    project: Path = typer.Option(".", "--project", "-p", help="Project path"),
    language: Optional[str] = typer.Option(None, "--language", "-l", help="Project language"),
    build_command: Optional[str] = typer.Option(None, "--build-command", "-b", help="Build command"),
    config_path: Path = typer.Option("baize.yaml", "--config", "-c", help="Config file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Initialize a project for CodeQL analysis."""
    init_logger(level="DEBUG" if verbose else "INFO")

    project = project.resolve()

    if not project.exists():
        console.print(f"[red]Error: Project path does not exist: {project}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold blue]Initializing Baize for:[/bold blue] {project}")

    config = BaizeConfig.load(config_path)

    config.project = ProjectConfig(
        name=project.name,
        path=project,
        languages=[language] if language else ["java"],
    )

    if build_command:
        config.codeql.database.build_command = build_command

    codeql = CodeQLCLI(cli_path=config.codeql.cli_path or None)
    builder = CodeQLBuilder(codeql)

    try:
        import asyncio

        if not language:
            project_info = asyncio.run(builder.analyze_project(project))
            config.project.languages = [project_info.language]
            if project_info.build_command:
                config.codeql.database.build_command = project_info.build_command

            console.print(f"[green]Detected language:[/green] {project_info.language}")

    except Exception as e:
        console.print(f"[yellow]Warning: Could not detect environment: {e}[/yellow]")

    config.to_yaml(config_path)

    console.print(f"[bold green]Created configuration:[/bold green] {config_path}")
    console.print("[dim]Run 'baize build' to build the CodeQL database[/dim]")


@app.command()
def build(
    project: Path = typer.Option(".", "--project", "-p", help="Project path"),
    timeout: int = typer.Option(3600, "--timeout", "-t", help="Build timeout in seconds"),
    incremental: bool = typer.Option(True, "--incremental/--no-incremental", help="Use incremental build"),
    threads: int = typer.Option(4, "--threads", help="Number of threads"),
    build_mode: Optional[str] = typer.Option(
        None,
        "--build-mode",
        help="CodeQL build mode: 'none' (source-only, no compiler tracing), "
             "'autobuild' (CodeQL auto-detects). Defaults to 'none' on WSL.",
    ),
    config_path: Path = typer.Option("baize.yaml", "--config", "-c", help="Config file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Build CodeQL database for a project."""
    init_logger(level="DEBUG" if verbose else "INFO")

    project = project.resolve()

    config = BaizeConfig.load(config_path)

    console.print(f"[bold blue]Building CodeQL database for:[/bold blue] {project}")

    codeql = CodeQLCLI(cli_path=config.codeql.cli_path or None)
    # Honour the timeout_strategy configured in baize.yaml
    scheduler_cfg = config.scheduler.to_runtime()
    scheduler = Scheduler(config=scheduler_cfg)
    builder = CodeQLBuilder(codeql, scheduler)
    planner = BuildStrategyPlanner(codeql)

    async def do_build():
        try:
            # Step 1: Let the planner analyze the project and create a build plan
            # The planner considers project structure, build system, environment, etc.
            yaml_cmd = config.codeql.database.build_command  # str, may be ''
            # Empty string from yaml means "not configured" → auto-detect (None)
            # Only non-empty string is an explicit override
            explicit_cmd = yaml_cmd if yaml_cmd and yaml_cmd.strip() else None

            build_plan = await planner.create_plan(
                project_path=project,
                explicit_build_command=explicit_cmd,
                explicit_build_mode=build_mode,
                timeout=timeout,
            )

            console.print(f"[dim]Build strategy: {build_plan.reason}[/dim]")
            for warning in build_plan.warnings:
                console.print(f"[yellow]Warning: {warning}[/yellow]")

            # Step 2: Create execution strategy
            strategy = await builder.decide_build_strategy(project, timeout=timeout)
            strategy.incremental = incremental
            strategy.threads = threads

            # Step 3: Execute the plan
            success, metrics, db_path = await builder.build_database(
                project_path=project,
                build_plan=build_plan,
                strategy=strategy,
            )

            if success:
                console.print("[bold green]Build completed successfully![/bold green]")
                console.print(f"Database: {db_path}")
                console.print(f"Duration: {metrics.duration_seconds:.1f}s")
            else:
                console.print("[bold red]Build failed[/bold red]")
                if metrics.errors:
                    console.print(f"Errors: {metrics.errors[0][:200]}")
                raise typer.Exit(1)

        except typer.Exit:
            raise
        except Exception as e:
            console.print(f"[bold red]Build error: {e}[/bold red]")
            raise typer.Exit(1)

    import asyncio
    asyncio.run(do_build())


@app.command()
def analyze(
    project: Path = typer.Option(".", "--project", "-p", help="Project path"),
    vulns: Optional[str] = typer.Option(None, "--vulns", help="Vulnerability types (comma-separated)"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Severity filter (high,critical)"),
    dataflow_report: bool = typer.Option(False, "--dataflow-report", help="Include dataflow paths"),
    multi_agent: bool = typer.Option(False, "--multi-agent", help="Use multi-agent pipeline"),
    output: Path = typer.Option(".baize/reports", "--output", "-o", help="Output directory"),
    config_path: Path = typer.Option("baize.yaml", "--config", "-c", help="Config file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Run vulnerability analysis on a project."""
    init_logger(level="DEBUG" if verbose else "INFO")

    project = project.resolve()
    db_path = project / ".baize" / "db"

    if not db_path.exists():
        console.print("[red]Error: Database not found. Run 'baize build' first.[/red]")
        raise typer.Exit(1)

    config = BaizeConfig.load(config_path)

    # --multi-agent overrides config if explicitly requested
    use_multi_agent = multi_agent or config.multi_agent.enabled

    console.print(f"[bold blue]Analyzing project:[/bold blue] {project}")
    if use_multi_agent:
        console.print("[dim]Multi-agent pipeline enabled[/dim]")

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    sarif_path = output_dir / "results.sarif"

    async def do_analyze():
        try:
            from baize.models.finding import FindingSeverity, VulnerabilityType

            if use_multi_agent:
                await _do_analyze_multi_agent(
                    project=project,
                    db_path=db_path,
                    config=config,
                    vulns=vulns,
                    severity=severity,
                    sarif_path=sarif_path,
                )
                return

            # ── Single-pipeline path (default) ──────────────────────────────
            codeql = CodeQLCLI(cli_path=config.codeql.cli_path or None)
            analyzer = Analyzer(codeql)
            processor = ResultProcessor()

            language = config.project.languages[0] if config.project.languages else "java"
            tm = get_template_manager(
                queries_path=config.codeql.queries_path,
                project_path=str(project),
            )

            # Default: scan ALL security queries when --vulns not specified
            if vulns:
                vuln_list = [v.strip() for v in vulns.split(",")]
                query_specs = tm.build_query_specs(language, vuln_list)
                if not query_specs:
                    query_specs = [tm.get_suite(language)]
            else:
                # No vulns specified - use full security suite for the language
                query_specs = [tm.get_suite(language)]

            console.print(f"[dim]Using {len(query_specs)} query spec(s)[/dim]")

            all_findings = []
            for spec in query_specs:
                spec_sarif = sarif_path.parent / f"results_{abs(hash(spec)) % 10000}.sarif"
                console.print(f"[dim]  → {spec}[/dim]")

                success, result_path = await analyzer.execute_query(
                    db_path=db_path,
                    queries=spec,
                    output_path=spec_sarif,
                    threads=config.codeql.analysis.threads,
                    ram=config.codeql.analysis.ram,
                    timeout=config.codeql.analysis.timeout,
                )

                if not success:
                    console.print(f"[yellow]Warning: query spec '{spec}' failed[/yellow]")
                    continue

                severity_filter = None
                if severity:
                    severity_filter = [
                        FindingSeverity(s.strip()) for s in severity.split(",")
                    ]

                vuln_filter = None
                if vulns:
                    vuln_filter = [
                        VulnerabilityType(s.strip()) for s in vulns.split(",")
                    ]

                findings = processor.process_results(
                    result_path,
                    severity_filter=severity_filter,
                    vuln_types_filter=vuln_filter,
                )
                all_findings.extend(findings)

            all_findings = await processor.deduplicate(all_findings)

            console.print(f"[green]Found {len(all_findings)} vulnerabilities[/green]")
            for f in all_findings[:10]:
                console.print(
                    f"  [{f.severity.value.upper()}] {f.rule_id} "
                    f"at {f.location.file}:{f.location.line}"
                )
            if len(all_findings) > 10:
                console.print(f"  ... and {len(all_findings) - 10} more")

        except Exception as e:
            console.print(f"[bold red]Analysis error: {e}[/bold red]")
            raise typer.Exit(1)

    import asyncio
    asyncio.run(do_analyze())


async def _do_analyze_multi_agent(
    project: Path,
    db_path: Path,
    config: "BaizeConfig",
    vulns: Optional[str],
    severity: Optional[str],
    sarif_path: Path,
) -> None:
    """Run the multi-agent analysis pipeline.

    Pipeline: query_generator → auditor → processor → knowledge
    """
    from baize.agents import AgentContext, AgentRegistry

    vuln_list = [v.strip() for v in vulns.split(",")] if vulns else config.vulnerabilities.enabled
    language = config.project.languages[0] if config.project.languages else "java"

    ctx = AgentContext(
        project_path=str(project),
        config={
            "db_path": str(db_path),
            "vuln_types": vuln_list,
            "language": language,
            "severity_filter": [s.strip() for s in severity.split(",")] if severity else [],
            "sarif_output": str(sarif_path),
            "codeql_config": {
                "cli_path": config.codeql.cli_path or "",
                "threads": config.codeql.analysis.threads,
                "ram": config.codeql.analysis.ram,
                "timeout": config.codeql.analysis.timeout,
            },
        },
    )

    # Step 1: Query generation
    query_agent = AgentRegistry.create("query_generator")
    if query_agent:
        ctx.set("vuln_types", vuln_list)
        ctx.set("language", language)
        q_result = await query_agent.run(ctx)
        if q_result.success and q_result.output:
            ctx.set("query_specs", q_result.output.get("query_specs", []))
            console.print(
                f"[dim]Query agent: {len(q_result.output.get('query_specs', []))} spec(s)[/dim]"
            )

    # Step 2: Auditor runs CodeQL
    auditor = AgentRegistry.create("auditor")
    if auditor:
        a_result = await auditor.run(ctx)
        if a_result.success and a_result.output:
            ctx.set("sarif_path", a_result.output.get("sarif_path", ""))
            console.print(
                f"[dim]Auditor: found {a_result.output.get('total_findings', 0)} raw findings[/dim]"
            )
        else:
            console.print(f"[yellow]Auditor failed: {a_result.error}[/yellow]")
            return

    # Step 3: Processor deduplicates + enriches dataflow
    processor_agent = AgentRegistry.create("processor")
    findings_dicts: list = []
    if processor_agent:
        p_result = await processor_agent.run(ctx)
        if p_result.success and p_result.output:
            findings_dicts = p_result.output.get("all_findings", [])
            console.print(
                f"[dim]Processor: {p_result.output.get('total_findings', 0)} findings after dedup[/dim]"
            )

    # Step 4: Knowledge enrichment (optional, degrades gracefully)
    knowledge_agent = AgentRegistry.create("knowledge")
    if knowledge_agent and findings_dicts:
        ctx.set("findings", findings_dicts)
        k_result = await knowledge_agent.run(ctx)
        if k_result.success:
            console.print(
                f"[dim]Knowledge: enriched with "
                f"{k_result.metadata.get('kb_entries_used', 0)} KB entries[/dim]"
            )

    # Final summary
    total = len(findings_dicts)
    console.print(f"[green]Multi-agent pipeline complete: {total} vulnerabilities[/green]")
    for f in findings_dicts[:10]:
        sev = f.get("severity", "unknown").upper()
        rule = f.get("rule_id", "")
        loc = f.get("location", {})
        console.print(f"  [{sev}] {rule} at {loc.get('file', '')}:{loc.get('line', '')}")
    if total > 10:
        console.print(f"  ... and {total - 10} more")


@app.command()
def audit(
    project: Path = typer.Option(".", "--project", "-p", help="Project path"),
    vulns: Optional[str] = typer.Option(None, "--vulns", help="Vulnerability types (comma-separated)"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Severity filter (high,critical)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output result.json path (default: <project>/.baize/result.json)"),
    delta: bool = typer.Option(False, "--delta", help="Only show new findings since last audit"),
    force_rebuild: bool = typer.Option(False, "--force-rebuild", help="Force DB rebuild (skip cache)"),
    build_mode: Optional[str] = typer.Option(
        None,
        "--build-mode",
        help="CodeQL build mode: 'none' (source-only), 'autobuild'. "
             "Defaults to 'none' on WSL when no build command is configured.",
    ),
    build_timeout: int = typer.Option(1800, "--build-timeout", "-t", help="Build timeout in seconds"),
    analysis_timeout: int = typer.Option(
        3600, "--analysis-timeout", help="Analysis timeout in seconds (per query spec)"
    ),
    no_parallel: bool = typer.Option(
        False, "--no-parallel", help="Disable parallel query execution (use sequential instead)"
    ),
    config_path: Path = typer.Option("baize.yaml", "--config", "-c", help="Config file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Run full audit pipeline: init -> (cached) build -> analyze -> output.

    This is the main entry point for automated vulnerability discovery.
    Produces a structured result.json that AI agents consume directly.

    Examples:
        baize audit --project ./repo/myapp
        baize audit --project ./repo/myapp --vulns sqli,rce --delta
        baize audit --project ./repo/myapp --force-rebuild
    """
    init_logger(level="DEBUG" if verbose else "INFO")

    project = project.resolve()
    if not project.exists():
        console.print(f"[red]Error: Project path does not exist: {project}[/red]")
        raise typer.Exit(1)

    config = BaizeConfig.load(config_path)
    config.project = ProjectConfig(
        name=project.name,
        path=project,
        languages=config.project.languages,
    )

    console.print(f"[bold blue]Baize Audit:[/bold blue] {project}")

    async def do_audit():
        from baize.models.finding import FindingSeverity, VulnerabilityType

        result = AuditResult.create_empty(
            project_name=project.name,
            project_path=str(project),
        )
        errors: list[str] = []
        warnings: list[str] = []

        # ── Step 1: Triage ───────────────────────────────────────────
        console.print("[dim]Step 1/5: Triage assessment...[/dim]")
        triage = TriageAssessor(project)
        triage_result = await triage.assess()
        result.triage = TriageInfo(
            viable=triage_result.viable,
            score=triage_result.score,
            language=triage_result.language,
            file_count=triage_result.file_count,
            lines_of_code=triage_result.lines_of_code,
            build_system=triage_result.build_system,
        )
        result.language = triage_result.language
        warnings.extend(triage_result.warnings)

        if not triage_result.viable:
            console.print(f"[yellow]Triage: project scored {triage_result.score}/100 — low viability[/yellow]")
            for rec in triage_result.recommendations:
                console.print(f"  [dim]→ {rec}[/dim]")
        else:
            console.print(f"[green]Triage: score {triage_result.score}/100, {triage_result.language}, "
                         f"{triage_result.file_count} files[/green]")

        # ── Step 2: DB Cache Check ───────────────────────────────────
        console.print("[dim]Step 2/5: Database cache check...[/dim]")
        db_cache = DBCache(project)
        db_path = project / ".baize" / "db"

        config_section = {
            "language": triage_result.language,
            "build_system": triage_result.build_system,
        }
        current_hash = db_cache.compute_hash(config_section)

        needs_build = db_cache.should_rebuild(current_hash, force=force_rebuild)

        # ── Step 3: Build (if needed) ────────────────────────────────
        if needs_build:
            console.print("[dim]Step 3/5: Building CodeQL database...[/dim]")
            codeql = CodeQLCLI(cli_path=config.codeql.cli_path or None)
            scheduler_cfg = config.scheduler.to_runtime()
            scheduler = Scheduler(config=scheduler_cfg)
            builder = CodeQLBuilder(codeql, scheduler)
            planner = BuildStrategyPlanner(codeql)

            try:
                yaml_cmd = config.codeql.database.build_command
                explicit_cmd = yaml_cmd if yaml_cmd and yaml_cmd.strip() else None

                # On WSL without explicit build command, default to build-mode=none
                effective_build_mode = build_mode
                if effective_build_mode is None and explicit_cmd is None:
                    import os
                    uname = os.uname()
                    if "microsoft" in uname.release.lower() or "wsl" in uname.release.lower():
                        effective_build_mode = "none"
                        console.print("[dim]WSL detected — defaulting to --build-mode=none[/dim]")

                build_plan = await planner.create_plan(
                    project_path=project,
                    explicit_build_command=explicit_cmd,
                    explicit_build_mode=effective_build_mode,
                    timeout=build_timeout,
                )

                console.print(f"[dim]Build strategy: {build_plan.reason}[/dim]")
                for w in build_plan.warnings:
                    console.print(f"[yellow]Warning: {w}[/yellow]")

                strategy = await builder.decide_build_strategy(project, timeout=build_timeout)
                success, metrics, db_path = await builder.build_database(
                    project_path=project,
                    build_plan=build_plan,
                    strategy=strategy,
                )

                if not success:
                    console.print("[red]Build failed[/red]")
                    result.errors.append("CodeQL database build failed")
                    result.warnings = warnings
                    result.build_info = {"success": False, "duration_s": metrics.duration_seconds}
                    output_path = Path(output)
                    result.to_json(output_path)
                    console.print(f"[dim]Partial result written to: {output_path}[/dim]")
                    raise typer.Exit(1)

                console.print(f"[green]Build complete ({metrics.duration_seconds:.1f}s)[/green]")
                result.db_hash = current_hash
                result.build_info = {
                    "success": True,
                    "duration_s": metrics.duration_seconds,
                    "db_path": str(db_path),
                }
                db_cache.write_cache_hash(current_hash)

            except typer.Exit:
                raise
            except Exception as e:
                console.print(f"[red]Build error: {e}[/red]")
                result.errors.append(str(e))
                output_path = Path(output)
                result.to_json(output_path)
                raise typer.Exit(1)
        else:
            console.print("[dim]Step 3/5: Build skipped (database cached)[/dim]")
            result.db_hash = current_hash
            result.build_info = {"success": True, "cached": True, "db_path": str(db_path)}

        # ── Step 4: Analyze ──────────────────────────────────────────
        console.print("[dim]Step 4/5: Running security analysis...[/dim]")
        codeql = CodeQLCLI(cli_path=config.codeql.cli_path or None)
        scheduler_cfg = config.scheduler.to_runtime()
        analysis_scheduler = Scheduler(config=scheduler_cfg)
        analyzer = Analyzer(codeql, scheduler=analysis_scheduler)
        processor = ResultProcessor()

        language = triage_result.language
        tm = get_template_manager(
            queries_path=config.codeql.queries_path,
            project_path=str(project),
        )

        if vulns:
            vuln_list = [v.strip() for v in vulns.split(",")]
            query_specs = tm.build_query_specs(language, vuln_list)
            if not query_specs:
                query_specs = [tm.get_suite(language)]
        else:
            query_specs = [tm.get_suite(language)]

        console.print(f"[dim]Using {len(query_specs)} query spec(s)[/dim]")

        output_dir = project / ".baize" / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)

        analysis_start = time.time()
        all_findings = []
        timed_out_specs = []

        # Build per-spec analysis tasks
        async def _run_single_spec(index: int, spec: str):
            """Run analysis for a single query spec, returns (spec, sarif_path, success, metrics, error_msg)."""
            spec_sarif = output_dir / f"results_{abs(hash(spec)) % 10000}.sarif"
            console.print(f"[dim]  → {spec}[/dim]")
            try:
                success, result_path, q_metrics = await analyzer.execute_query(
                    db_path=db_path,
                    queries=spec,
                    output_path=spec_sarif,
                    threads=config.codeql.analysis.threads,
                    ram=config.codeql.analysis.ram,
                    timeout=analysis_timeout,
                    timeout_strategy="skip",
                )
                return (spec, result_path, success, q_metrics, None)
            except Exception as exc:
                return (spec, spec_sarif, False, {"success": False, "duration_s": 0, "error": str(exc)}, str(exc))

        # Execute: parallel or sequential
        use_parallel = len(query_specs) > 1 and not no_parallel
        if use_parallel:
            console.print(f"[dim]Running {len(query_specs)} query specs in parallel...[/dim]")
            tasks = [_run_single_spec(i, spec) for i, spec in enumerate(query_specs)]
            spec_results = await asyncio.gather(*tasks)
        else:
            spec_results = []
            for i, spec in enumerate(query_specs):
                spec_results.append(await _run_single_spec(i, spec))

        # Process results from all specs
        severity_filter = None
        if severity:
            severity_filter = [FindingSeverity(s.strip()) for s in severity.split(",")]
        vuln_filter = None
        if vulns:
            vuln_filter = [VulnerabilityType(s.strip()) for s in vulns.split(",")]

        for spec, result_path, success, q_metrics, error_msg in spec_results:
            if error_msg:
                console.print(f"[red]Analysis error for '{spec}': {error_msg}[/red]")
                errors.append(f"Analysis error: {error_msg}")
                continue

            if not success:
                if q_metrics.get("timed_out"):
                    console.print(f"[yellow]Query spec '{spec}' timed out ({q_metrics.get('duration_s', 0):.0f}s)[/yellow]")
                    timed_out_specs.append(str(spec))
                    warnings.append(f"Query spec timed out: {spec}")
                else:
                    console.print(f"[yellow]Warning: query spec '{spec}' failed[/yellow]")
                    warnings.append(f"Query spec failed: {spec}")
                if not result_path.exists():
                    continue

            findings = processor.process_results(
                result_path,
                severity_filter=severity_filter,
                vuln_types_filter=vuln_filter,
            )
            all_findings.extend(findings)

        all_findings = await processor.deduplicate(all_findings)
        analysis_elapsed = time.time() - analysis_start

        # ── Step 5: Output ───────────────────────────────────────────
        console.print(f"[dim]Step 5/5: Generating structured output... (analysis took {analysis_elapsed:.1f}s)[/dim]")

        # Delta analysis if requested
        delta_result = None
        if delta:
            delta_analyzer = DeltaAnalyzer(db_cache.result_file)
            findings_dicts = [f.to_dict() for f in all_findings]
            delta_data = delta_analyzer.analyze(findings_dicts)
            delta_result = delta_data.to_dict()
            console.print(
                f"[dim]Delta: {delta_data.new_count} new, "
                f"{delta_data.fixed_count} fixed, {delta_data.unchanged_count} unchanged[/dim]"
            )

        # Build AuditResult
        audit_result = AuditResult.from_findings(
            findings=all_findings,
            project_name=project.name,
            project_path=str(project),
            language=language,
            db_hash=current_hash,
            triage=result.triage,
        )
        audit_result.delta = delta_result
        audit_result.warnings = warnings
        audit_result.errors = errors
        audit_result.build_info = result.build_info
        audit_result.analysis_info = {
            "duration_s": round(analysis_elapsed, 1),
            "query_specs": len(query_specs),
            "timed_out_specs": timed_out_specs,
        }

        # Write result to project's .baize directory by default
        output_path = Path(output) if output else (project / ".baize" / "result.json")
        audit_result.to_json(output_path)
        console.print(f"[dim]Result: {output_path}[/dim]")
        sev = audit_result.findings_by_severity
        if sev:
            parts = " | ".join(f"{k}: {v}" for k, v in sorted(sev.items()))
            console.print(f"[dim]By severity: {parts}[/dim]")
        console.print(f"[dim]Result: {output_path}[/dim]")

        for f in audit_result.findings[:10]:
            console.print(
                f"  [{f.severity.upper()}] {f.rule_id} "
                f"at {f.location.get('file', '')}:{f.location.get('line', '')}"
            )
        if audit_result.total_findings > 10:
            console.print(f"  ... and {audit_result.total_findings - 10} more")

    asyncio.run(do_audit())


@app.command()
def clean(
    project: Path = typer.Option(".", "--project", "-p", help="Project path"),
    keep_db: bool = typer.Option(False, "--keep-db", help="Keep the CodeQL database (only clean reports/hash)"),
    keep_reports: bool = typer.Option(False, "--keep-reports", help="Keep SARIF reports (only clean database)"),
    all_baize: bool = typer.Option(False, "--all", help="Remove the entire .baize directory"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be removed without actually removing"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Clean Baize artifacts to reclaim disk space.

    Removes CodeQL databases (largest), SARIF reports, and cache files.

    Examples:
        baize clean --project ./repo/myapp
        baize clean --project ./repo/myapp --keep-db
        baize clean --project ./repo/myapp --all --dry-run
    """
    init_logger(level="DEBUG" if verbose else "INFO")

    project = project.resolve()
    baize_dir = project / ".baize"

    if not baize_dir.exists():
        console.print(f"[yellow]No .baize directory found in {project}[/yellow]")
        return

    if all_baize:
        _remove_tree(baize_dir, dry_run, "entire .baize directory")
        return

    total_freed = 0

    # Clean database (largest — typically 100MB-2GB)
    if not keep_db:
        db_path = baize_dir / "db"
        total_freed += _remove_tree(db_path, dry_run, "CodeQL database")

    # Clean reports (SARIF files)
    if not keep_reports:
        reports_path = baize_dir / "reports"
        total_freed += _remove_tree(reports_path, dry_run, "SARIF reports")

    # Clean cache files
    for fname in ["db_hash.txt", "result.json"]:
        fpath = baize_dir / fname
        if fpath.exists():
            size = fpath.stat().st_size
            total_freed += size
            if not dry_run:
                fpath.unlink()
                console.print(f"[dim]Removed {fname} ({_fmt_size(size)})[/dim]")
            else:
                console.print(f"[dim]Would remove {fname} ({_fmt_size(size)})[/dim]")

    if total_freed > 0:
        if dry_run:
            console.print(f"[bold blue]Would free: {_fmt_size(total_freed)}[/bold blue]")
        else:
            console.print(f"[bold green]Freed: {_fmt_size(total_freed)}[/bold green]")
    else:
        console.print("[dim]Nothing to clean.[/dim]")


def _fmt_size(size_bytes: int) -> str:
    """Format a byte count as a human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def _remove_tree(path: Path, dry_run: bool, label: str) -> int:
    """Remove a directory tree and return the total bytes freed.

    Args:
        path: Directory to remove.
        dry_run: If True, only print what would be done.
        label: Human label for logging.

    Returns:
        Total bytes that were (or would be) freed.
    """
    path = Path(path)
    if not path.exists():
        console.print(f"[dim]No {label} to clean.[/dim]")
        return 0

    total_size = _dir_size(path)
    if dry_run:
        console.print(f"[dim]Would remove {label}: {_fmt_size(total_size)}[/dim]")
    else:
        try:
            import shutil
            shutil.rmtree(path)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not remove {label}: {e}[/yellow]")
            return 0
        console.print(f"[dim]Removed {label}: {_fmt_size(total_size)}[/dim]")
    return total_size


def _dir_size(path: Path) -> int:
    """Calculate total size of a directory recursively."""
    total = 0
    try:
        for f in path.rglob("*"):
            if f.is_file():
                try:
                    total += f.stat().st_size
                except OSError:
                    pass
    except PermissionError:
        pass
    return total


@app.command()
def triage(
    project: Path = typer.Option(".", "--project", "-p", help="Project path"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write triage result to JSON file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Quick project triage — assess viability before full audit.

    Checks language, build system, code size, and security surface area.
    Returns a 0-100 viability score.

    Example:
        baize triage --project ./repo/myapp
    """
    init_logger(level="DEBUG" if verbose else "INFO")

    project = project.resolve()
    if not project.exists():
        console.print(f"[red]Error: Project path does not exist: {project}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold blue]Triaging:[/bold blue] {project}")

    async def do_triage():
        assessor = TriageAssessor(project)
        result = await assessor.assess()

        # Print summary table
        table = Table(title="Project Triage Assessment")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Language", result.language)
        table.add_row("Build System", result.build_system)
        table.add_row("Files", str(result.file_count))
        table.add_row("Lines of Code", str(result.lines_of_code))
        table.add_row("Has Controllers/API", str(result.has_controllers))
        table.add_row("Has DB Operations", str(result.has_db_operations))
        table.add_row("Has HTTP Client", str(result.has_http_client))
        table.add_row("Has Deserialization", str(result.has_deserialization))
        table.add_row("Viability Score", f"{result.score}/100")
        table.add_row("Viable for Audit", "[green]Yes[/green]" if result.viable else "[red]No[/red]")

        console.print(table)

        if result.warnings:
            console.print("\n[yellow]Warnings:[/yellow]")
            for w in result.warnings:
                console.print(f"  • {w}")

        if result.recommendations:
            console.print("\n[dim]Recommendations:[/dim]")
            for r in result.recommendations:
                console.print(f"  → {r}")

        if output:
            import json
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
            )
            console.print(f"\n[dim]Triage result written to: {out_path}[/dim]")

    import asyncio
    asyncio.run(do_triage())


@app.command()
def report(
    format: str = typer.Option("json", "--format", "-f", help="Report format (json, markdown, sarif)"),
    input: Path = typer.Option(".baize/reports/results.sarif", "--input", "-i", help="SARIF input path"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    include_dataflow: bool = typer.Option(False, "--include-dataflow", help="Include dataflow paths"),
    config_path: Path = typer.Option("baize.yaml", "--config", "-c", help="Config file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Generate analysis report."""
    init_logger(level="DEBUG" if verbose else "INFO")

    if not input.exists():
        console.print(f"[red]Error: Input file not found: {input}[/red]")
        raise typer.Exit(1)

    config = BaizeConfig.load(config_path)

    console.print(f"[bold blue]Generating {format} report...[/bold blue]")

    processor = ResultProcessor()
    report_obj = processor.create_report(
        input,
        project_name=config.project.name,
        project_path=str(config.project.path),
    )

    from baize.reports import generate_report

    if output is None:
        ext = {"json": ".json", "markdown": ".md", "md": ".md", "html": ".html", "sarif": ".sarif"}
        output = Path(f"baize-report{ext.get(format, '.txt')}")

    generate_report(report_obj, output, format)

    console.print(f"[bold green]Report saved to:[/bold green] {output}")


@app.command()
def mcp(
    host: str = typer.Option("127.0.0.1", "--host", help="Server host"),
    port: int = typer.Option(8080, "--port", help="Server port"),
    config_path: Path = typer.Option("baize.yaml", "--config", "-c", help="Config file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Start the MCP server for AI agent integration."""
    init_logger(level="DEBUG" if verbose else "INFO")

    console.print(f"[bold blue]Starting MCP server on {host}:{port}[/bold blue]")

    try:
        from baize.mcp_server import create_mcp_server

        server = create_mcp_server(
            host=host,
            port=port,
            config_path=config_path,
        )
        server.run()
    except ImportError:
        console.print("[red]Error: MCP server requires fastapi and uvicorn[/red]")
        console.print("[yellow]Install with: pip install fastapi uvicorn[/yellow]")
        raise typer.Exit(1)


@app.command()
def kb(
    action: str = typer.Option("list", "--action", help="Action: list, init, search, index-ql"),
    query: Optional[str] = typer.Option(None, "--query", "-q", help="Search query"),
    language: Optional[str] = typer.Option(None, "--language", "-l", help="Filter by language"),
    ql_dir: Optional[Path] = typer.Option(
        None,
        "--ql-dir",
        help="[index-ql] Directory of .ql files to index (e.g. a cloned learning-codeql repo)",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Manage the knowledge base."""
    init_logger(level="DEBUG" if verbose else "INFO")

    if action == "list":
        manager = get_template_manager()
        templates = manager.list_templates(language)

        table = Table(title="Available Query Templates")
        table.add_column("Language", style="cyan")
        table.add_column("Vulnerability Types", style="green")

        for lang, vulns in templates.items():
            table.add_row(lang, ", ".join(vulns))

        console.print(table)

    elif action == "init":
        console.print("[bold blue]Initializing knowledge base...[/bold blue]")

        try:
            from baize.kb import VectorStore, initialize_knowledge_base

            store = VectorStore()
            if store.is_initialized:
                initialize_knowledge_base(store)
                console.print(f"[bold green]Knowledge base initialized with {store.count()} entries[/bold green]")
            else:
                console.print("[yellow]ChromaDB not available, skipping initialization[/yellow]")

        except ImportError:
            console.print("[red]Error: Knowledge base requires chromadb[/red]")
            console.print("[yellow]Install with: pip install chromadb[/yellow]")

    elif action == "index-ql":
        if not ql_dir:
            console.print("[red]Error: --ql-dir is required for index-ql[/red]")
            console.print("[dim]Example: baize kb --action index-ql --ql-dir ~/learning-codeql[/dim]")
            raise typer.Exit(1)

        ql_dir = ql_dir.expanduser().resolve()
        if not ql_dir.exists():
            console.print(f"[red]Error: Directory not found: {ql_dir}[/red]")
            raise typer.Exit(1)

        console.print(f"[bold blue]Indexing .ql files from:[/bold blue] {ql_dir}")

        try:
            from baize.kb import VectorStore
            from baize.kb.ql_context import QLIndexer

            store = VectorStore()
            if not store.is_initialized:
                console.print("[red]Error: ChromaDB not available. Install with: pip install chromadb[/red]")
                raise typer.Exit(1)

            indexer = QLIndexer(store)
            count = indexer.index_directory(ql_dir)
            console.print(
                f"[bold green]Indexed {count} .ql file(s) into the knowledge base.[/bold green]"
            )
            console.print(
                "[dim]Now use 'baize flow --use-vector-kb' to retrieve examples during query generation.[/dim]"
            )

        except ImportError:
            console.print("[red]Error: Knowledge base requires chromadb[/red]")
            console.print("[yellow]Install with: pip install chromadb[/yellow]")

    elif action == "search":
        if not query:
            console.print("[red]Error: --query required for search[/red]")
            raise typer.Exit(1)

        try:
            from baize.kb import VectorStore, create_retriever

            store = VectorStore()
            if not store.is_initialized:
                console.print("[yellow]Knowledge base not initialized. Run 'baize kb --action init' first.[/yellow]")
                return

            retriever = create_retriever(store)
            results = retriever.retrieve_vulnerability_info(query, top_k=5)

            console.print(f"[bold blue]Search results for:[/bold blue] {query}")
            for i, r in enumerate(results, 1):
                console.print(f"\n[cyan]{i}. {r.metadata.get('title', 'Unknown')}[/cyan]")
                console.print(f"   Type: {r.vuln_type or 'N/A'}")
                console.print(f"   CWE: {r.cwe or 'N/A'}")
                console.print(f"   Score: {r.score:.2f}")

        except ImportError:
            console.print("[red]Error: Knowledge base requires chromadb[/red]")


@app.command()
def fix(
    input: Path = typer.Option(".baize/reports/results.sarif", "--input", "-i", help="SARIF input path"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter by severity (high,critical)"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format (markdown, json)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    config_path: Path = typer.Option("baize.yaml", "--config", "-c", help="Config file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Generate fix suggestions for discovered vulnerabilities."""
    init_logger(level="DEBUG" if verbose else "INFO")

    if not input.exists():
        console.print(f"[red]Error: SARIF file not found: {input}[/red]")
        console.print("[dim]Run 'baize analyze' first to produce results.[/dim]")
        raise typer.Exit(1)

    config = BaizeConfig.load(config_path)

    if not config.fixes.enabled:
        console.print("[yellow]Fix suggestions are disabled in config (fixes.enabled=false)[/yellow]")
        raise typer.Exit(0)

    console.print(f"[bold blue]Generating fix suggestions from:[/bold blue] {input}")

    from baize.core import ResultProcessor, FixSuggester
    from baize.models.finding import FindingSeverity

    processor = ResultProcessor()

    severity_filter = None
    if severity:
        severity_filter = [FindingSeverity(s.strip()) for s in severity.split(",")]

    findings = processor.process_results(input, severity_filter=severity_filter)

    if not findings:
        console.print("[yellow]No findings to generate fixes for.[/yellow]")
        raise typer.Exit(0)

    console.print(f"[dim]Processing {len(findings)} finding(s)...[/dim]")

    async def do_fix():
        llm_cfg = config.llm.primary if config.llm and config.llm.primary else None
        fixer = FixSuggester(llm_config=llm_cfg)
        fixes = await fixer.generate_fixes_for_findings(findings)

        if output is None:
            ext = ".md" if format in ("markdown", "md") else ".json"
            out_path = Path(f"baize-fixes{ext}")
        else:
            out_path = output

        if format in ("markdown", "md"):
            _write_fixes_markdown(fixes, findings, out_path)
        else:
            import json
            out_path.write_text(
                json.dumps(fixes, indent=2, ensure_ascii=False), encoding="utf-8"
            )

        console.print(f"[bold green]Fix suggestions saved to:[/bold green] {out_path}")

        if config.fixes.review_required:
            console.print(
                "[yellow]Note: review_required=true — please review suggestions before applying.[/yellow]"
            )

    import asyncio
    asyncio.run(do_fix())


def _write_fixes_markdown(fixes: list, findings: list, output_path: Path) -> None:
    """Write fix suggestions to a Markdown file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# 白泽 Fix Suggestions",
        "",
        f"Total findings: {len(findings)}  |  Fixes generated: {len(fixes)}",
        "",
    ]
    for i, (fix, finding) in enumerate(zip(fixes, findings), 1):
        lines.append(
            f"## {i}. [{finding.severity.value.upper()}] {finding.rule_id}"
        )
        lines.append(
            f"**Location**: `{finding.location.file}:{finding.location.line}`"
        )
        if isinstance(fix, dict):
            if fix.get("title"):
                lines.append(f"**Fix**: {fix['title']}")
            if fix.get("description"):
                lines.append(f"\n{fix['description']}")
            if fix.get("fix_snippet"):
                lines.append("\n```")
                lines.append(fix["fix_snippet"])
                lines.append("```")
        lines.append("")
    output_path.write_text("\n".join(lines), encoding="utf-8")


@app.command()
def query(
    vuln_type: str = typer.Option(..., "--vuln-type", "-t", help="Vulnerability type (sqli, xss, rce…)"),
    language: str = typer.Option("java", "--language", "-l", help="Target language"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write query spec to file"),
    config_path: Path = typer.Option("baize.yaml", "--config", "-c", help="Config file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Resolve or display a CodeQL query spec for a vulnerability type."""
    init_logger(level="DEBUG" if verbose else "INFO")

    config = BaizeConfig.load(config_path)
    tm = get_template_manager(
        queries_path=config.codeql.queries_path,
        project_path=str(config.project.path),
    )
    spec = tm.get_query_spec(language, vuln_type)

    if spec is None:
        # Try suite fallback
        suite = tm.get_suite(language)
        console.print(
            f"[yellow]No specific template for '{vuln_type}' in '{language}'.[/yellow]"
        )
        if suite:
            console.print(f"[dim]Fallback suite available: {suite}[/dim]")
        console.print(
            "[dim]Add a .ql file to baize/queries/templates/{language}/ to enable per-type queries.[/dim]"
        )
        if output:
            console.print("[red]Cannot write — no template found.[/red]")
            raise typer.Exit(1)
        raise typer.Exit(0)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(spec, encoding="utf-8")
        console.print(f"[bold green]Query spec written to:[/bold green] {output}")
    else:
        console.print(f"[bold blue]Query spec for {vuln_type} ({language}):[/bold blue]")
        console.print(spec)


@app.command()
def agents(
    list_all: bool = typer.Option(False, "--list", help="List all available agents"),
) -> None:
    """List available agents."""
    from baize.agents import AgentRegistry

    agents_list = AgentRegistry.list_agents()

    table = Table(title="Available Agents")
    table.add_column("Agent Name", style="cyan")
    table.add_column("Description", style="green")

    for name in agents_list:
        agent = AgentRegistry.create(name)
        if agent:
            table.add_row(name, getattr(agent, "description", ""))

    console.print(table)


@app.command()
def flow(
    project: Path = typer.Option(".", "--project", "-p", help="Project path"),
    source: str = typer.Option(..., "--source", "-s", help="Natural-language description of taint sources"),
    sink: str = typer.Option(..., "--sink", "-k", help="Natural-language description of dangerous sinks"),
    sanitizer: Optional[str] = typer.Option(None, "--sanitizer", help="Natural-language description of sanitizers"),
    language: str = typer.Option("java", "--language", "-l", help="Target language"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Human-readable query purpose"),
    extra_context: Optional[str] = typer.Option(None, "--extra", help="Additional context fed to the LLM"),
    ql_examples_dir: Optional[Path] = typer.Option(
        None,
        "--ql-examples-dir",
        help="Local directory of .ql files to use as few-shot examples "
             "(e.g. a clone of github.com/SummerSec/learning-codeql)",
    ),
    use_vector_kb: bool = typer.Option(
        False,
        "--use-vector-kb",
        help="Also retrieve QL examples from the ChromaDB knowledge base "
             "(requires prior indexing via 'baize kb --action index-ql')",
    ),
    output: Path = typer.Option(".baize/reports/custom_flow.sarif", "--output", "-o", help="SARIF output path"),
    show_ql: bool = typer.Option(False, "--show-ql", help="Print the generated QL query to stdout"),
    config_path: Path = typer.Option("baize.yaml", "--config", "-c", help="Config file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Mode-2 analysis: describe a source→sink data flow, AI writes the QL query.

    Optionally supply real .ql examples via --ql-examples-dir so the LLM can
    use them as few-shot structural references (highly recommended).

    Example:

      baize flow --project ./myapp \\
        --source "HTTP request parameters via getParameter()" \\
        --sink "SQL execution via executeQuery() or execute()" \\
        --sanitizer "PreparedStatement parameterised queries" \\
        --language java \\
        --description "Detect unsanitised SQL injection paths" \\
        --ql-examples-dir ~/learning-codeql \\
        --show-ql
    """
    init_logger(level="DEBUG" if verbose else "INFO")

    project = project.resolve()
    db_path = project / ".baize" / "db"

    if not db_path.exists():
        console.print("[red]Error: Database not found. Run 'baize build' first.[/red]")
        raise typer.Exit(1)

    config = BaizeConfig.load(config_path)

    if not config.llm or not config.llm.primary:
        console.print("[red]Error: LLM not configured. Set llm.primary in baize.yaml.[/red]")
        raise typer.Exit(1)

    from baize.core.custom_flow_analyzer import CustomFlowAnalyzer, FlowSpec
    from baize.kb.ql_context import build_context_provider

    spec = FlowSpec(
        source_description=source,
        sink_description=sink,
        sanitizer_description=sanitizer or "",
        language=language,
        query_description=description or "",
        extra_context=extra_context or "",
    )

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    console.print("[bold blue]Mode 2: AI-generated data-flow analysis[/bold blue]")
    console.print(f"  Source   : {source[:80]}")
    console.print(f"  Sink     : {sink[:80]}")
    if sanitizer:
        console.print(f"  Sanitizer: {sanitizer[:80]}")
    console.print(f"  Language : {language}")

    # ── Build QL context provider ─────────────────────────────────────────────
    vector_store = None
    if use_vector_kb:
        try:
            from baize.kb import VectorStore
            vector_store = VectorStore(persist_directory=str(config.knowledge_base.path))
            if not vector_store.is_initialized:
                console.print(
                    "[yellow]Warning: ChromaDB not available or empty; "
                    "--use-vector-kb will be skipped.[/yellow]"
                )
                vector_store = None
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load vector store: {e}[/yellow]")

    ctx_provider = build_context_provider(
        ql_examples_dir=ql_examples_dir,
        vector_store=vector_store,
    )

    if ctx_provider is not None:
        parts = []
        if ql_examples_dir:
            parts.append(f"local dir ({ql_examples_dir})")
        if vector_store:
            parts.append("vector KB")
        console.print(f"  Context  : RAG enabled — {', '.join(parts)}")
    else:
        console.print("  Context  : no QL examples (use --ql-examples-dir to add)")

    console.print("")

    async def do_flow() -> None:
        codeql = CodeQLCLI(cli_path=config.codeql.cli_path or None)
        analyzer = CustomFlowAnalyzer(
            llm_config=config.llm.primary,
            context_provider=ctx_provider,
            codeql_cli=codeql,
        )

        result = await analyzer.analyze(spec=spec, db_path=db_path, output_path=output_path)

        if show_ql and result.generated_ql:
            console.print("\n[bold cyan]Generated QL query:[/bold cyan]")
            console.print(result.generated_ql)
            console.print("")

        if not result.success:
            console.print(f"[bold red]Flow analysis failed:[/bold red] {result.error}")
            raise typer.Exit(1)

        console.print(f"[green]Found {result.findings_count} result(s)[/green]")
        console.print(f"[dim]SARIF output: {result.output_path}[/dim]")

    import asyncio
    asyncio.run(do_flow())


@app.command()
def version_cmd() -> None:
    """Show Baize version."""
    console.print(f"[bold blue]Baize[/bold blue] version [green]{__version__}[/green]")


@app.callback()
def main_callback(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """白泽 - AI Agent × CodeQL 智能代码审计编排引擎"""
    if verbose:
        init_logger(level="DEBUG")


def main() -> None:
    """Main entry point."""
    print_banner()
    app()


if __name__ == "__main__":
    main()
