"""Query executor for running CodeQL analysis."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from baize.core.scheduler import Scheduler
from baize.utils.codeql import CodeQLCLI


class Analyzer:
    """Executes CodeQL queries and collects results."""

    def __init__(
        self,
        codeql_cli: Optional[CodeQLCLI] = None,
        scheduler: Optional[Scheduler] = None,
    ):
        self.codeql = codeql_cli or CodeQLCLI()
        self.scheduler = scheduler or Scheduler()

    async def execute_query(
        self,
        db_path: Path,
        queries: str = "security-extended",
        output_path: Optional[Path] = None,
        threads: int = 4,
        ram: str = "4096MB",
        timeout: int = 3600,
        timeout_strategy: str = "skip",
    ) -> tuple[bool, Path, dict]:
        """Execute a query or query suite against a database.

        Args:
            db_path: Path to the CodeQL database
            queries: Query suite or path to queries
            output_path: Path to write SARIF results
            threads: Number of threads
            ram: RAM limit
            timeout: Timeout in seconds
            timeout_strategy: 'skip' (return partial), 'abort' (raise), 'warn' (log only)

        Returns:
            Tuple of (success, path_to_sarif_output, metrics_dict)
        """
        db_path = Path(db_path)

        if output_path is None:
            output_path = db_path.parent / "results.sarif"

        start_time = time.time()
        logger.info(f"Starting analysis on database: {db_path}")
        await self.scheduler.start_analysis(timeout)

        try:
            result = await asyncio.wait_for(
                self.codeql.database_analyze(
                    db_path=db_path,
                    output_path=output_path,
                    queries=queries,
                    format="sarif-latest",
                    threads=threads,
                    ram=ram,
                    timeout=timeout,
                ),
                timeout=timeout + 30,  # 30s grace period over the codeql-level timeout
            )
        except asyncio.TimeoutError:
            elapsed = time.time() - start_time
            logger.error(f"Analysis timed out after {elapsed:.1f}s (limit: {timeout}s)")
            await self.scheduler.complete_build(success=False)

            if timeout_strategy == "abort":
                raise
            # 'skip' or 'warn': return partial/failure gracefully
            return False, Path(output_path), {
                "success": False,
                "duration_s": elapsed,
                "timed_out": True,
            }

        elapsed = time.time() - start_time
        if result.success:
            logger.info(f"Analysis complete in {elapsed:.1f}s")
        else:
            logger.error(f"Analysis failed after {elapsed:.1f}s: {result.stderr}")

        await self.scheduler.complete_build(success=result.success)

        return result.success, Path(result.sarif_path or output_path), {
            "success": result.success,
            "duration_s": elapsed,
            "timed_out": False,
        }

    async def execute_multiple_queries(
        self,
        db_path: Path,
        query_specs: list[dict[str, Any]],
        output_dir: Optional[Path] = None,
        parallel: bool = True,
    ) -> list[tuple[bool, Path]]:
        """Execute multiple queries in parallel or sequential.

        Args:
            db_path: Path to the CodeQL database
            query_specs: List of dicts with 'queries' and 'output_name' keys
            output_dir: Directory for output files
            parallel: Whether to run queries in parallel

        Returns:
            List of (success, output_path) tuples
        """
        db_path = Path(db_path)
        if output_dir is None:
            output_dir = db_path.parent / "results"
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        results = []

        if parallel:
            tasks = []
            for spec in query_specs:
                queries = spec.get("queries", "security-extended")
                name = spec.get("output_name", "results")
                output_path = output_dir / f"{name}.sarif"
                tasks.append(self.execute_query(db_path, queries, output_path))

            raw_results = await asyncio.gather(*tasks, return_exceptions=True)
            for item in raw_results:
                if isinstance(item, Exception):
                    logger.error(f"Query execution exception: {item}")
                    results.append((False, Path(), {"success": False, "error": str(item)}))
                else:
                    success, path, metrics = item
                    results.append((success, path, metrics))
        else:
            for spec in query_specs:
                queries = spec.get("queries", "security-extended")
                name = spec.get("output_name", "results")
                output_path = output_dir / f"{name}.sarif"
                success, path, metrics = await self.execute_query(db_path, queries, output_path)
                results.append((success, path, metrics))

        return results

    async def get_database_info(self, db_path: Path) -> dict[str, Any]:
        """Get information about a CodeQL database."""
        return await self.codeql.database_diagnostics(db_path)