"""Database smart caching — hash-based DB reuse to avoid redundant rebuilds.

Computes a project fingerprint (git tree hash + config hash) and stores it
alongside the CodeQL database.  On subsequent ``baize audit`` runs the hash
is checked; if nothing changed the (expensive) DB build step is skipped.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Optional

from loguru import logger


class DBCache:
    """Manages the CodeQL database cache for a project.

    The cache key is a SHA-256 hash combining:
    * The git tree hash of the project (HEAD:)
    * A hash of the relevant baize config section

    The hash is stored in ``<project>/.baize/db_hash.txt`` alongside the
    CodeQL database at ``<project>/.baize/db/``.
    """

    def __init__(self, project_path: Path) -> None:
        self.project_path = Path(project_path).resolve()
        self.baize_dir = self.project_path / ".baize"
        self.db_path = self.baize_dir / "db"
        self.hash_file = self.baize_dir / "db_hash.txt"
        self.result_file = self.baize_dir / "result.json"

    def compute_hash(self, config_section: Optional[dict] = None) -> str:
        """Compute the cache key for the current project state.

        Args:
            config_section: Optional dict of relevant config values to include
                           in the hash (e.g. language, build_mode).

        Returns:
            64-character hex SHA-256 digest.
        """
        hasher = hashlib.sha256()

        # Git tree hash — captures all tracked file content
        git_hash = self._git_tree_hash()
        if git_hash:
            hasher.update(git_hash.encode())
        else:
            # Fall back to mtimes of source files
            logger.debug("No git tree hash available, falling back to file stat")
            hasher.update(self._file_stat_hash().encode())

        # Config section hash
        if config_section:
            config_str = json.dumps(config_section, sort_keys=True)
            hasher.update(config_str.encode())

        return hasher.hexdigest()

    def _git_tree_hash(self) -> Optional[str]:
        """Get the git tree hash of HEAD, or None if not a git repo."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD:"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            logger.debug(f"Git tree hash failed: {e}")
        return None

    def _file_stat_hash(self) -> str:
        """Fallback: hash based on mtimes of all source files."""
        hasher = hashlib.sha256()
        extensions = {".java", ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".cpp", ".cs"}
        try:
            files = sorted(
                [f for f in self.project_path.rglob("*") if f.is_file() and f.suffix in extensions],
                key=lambda f: str(f),
            )
            for f in files[:5000]:  # Cap to avoid excessive I/O
                stat = f.stat()
                hasher.update(f"{f.relative_to(self.project_path)}:{stat.st_mtime}:{stat.st_size}".encode())
        except Exception as e:
            logger.debug(f"File stat hash error: {e}")
        return hasher.hexdigest()

    def read_cached_hash(self) -> Optional[str]:
        """Read the stored hash from a previous build.

        Returns:
            The hash string, or None if no cache exists.
        """
        if not self.hash_file.exists():
            return None
        try:
            return self.hash_file.read_text().strip()
        except Exception:
            return None

    def write_cache_hash(self, hash_value: str) -> None:
        """Store a hash value after a successful build."""
        self.baize_dir.mkdir(parents=True, exist_ok=True)
        self.hash_file.write_text(hash_value)

    def is_db_valid(self, current_hash: str) -> bool:
        """Check whether the cached DB is still valid for the current hash.

        Returns True when:
        * The hash file exists and matches
        * The CodeQL database directory exists and looks healthy
        """
        cached = self.read_cached_hash()
        if cached != current_hash:
            cached_preview = cached[:16] if cached else "None"
            logger.info(f"DB cache miss: hash changed ({cached_preview}... -> {current_hash[:16]}...)")
            return False

        if not self.db_path.exists():
            logger.info("DB cache miss: database directory not found")
            return False

        db_yml = self.db_path / "codeql-database.yml"
        if not db_yml.exists():
            logger.info("DB cache miss: codeql-database.yml missing (database may be broken)")
            return False

        logger.info(f"DB cache hit: hash {current_hash[:16]}... — skipping build")
        return True

    def should_rebuild(self, current_hash: str, force: bool = False) -> bool:
        """Determine whether a rebuild is needed.

        Args:
            current_hash: The hash of the current project state.
            force: If True, always return True (force rebuild).

        Returns:
            True if a rebuild is needed.
        """
        if force:
            logger.info("Force rebuild requested")
            return True
        return not self.is_db_valid(current_hash)

    def get_cached_result(self) -> Optional[dict]:
        """Read the cached audit result if available."""
        if not self.result_file.exists():
            return None
        try:
            return json.loads(self.result_file.read_text())
        except Exception as e:
            logger.warning(f"Failed to read cached result: {e}")
            return None

    def write_result(self, result: dict) -> None:
        """Write audit result to cache."""
        self.baize_dir.mkdir(parents=True, exist_ok=True)
        self.result_file.write_text(json.dumps(result, indent=2, ensure_ascii=False))
