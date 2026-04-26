"""Project triage — quick viability assessment before full audit.

Runs a fast (2-5 min) assessment to determine whether a project is worth
a full CodeQL audit.  Checks language detection, build feasibility, and
estimates a security surface area score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from loguru import logger

from baize.utils.codeql import detect_language


@dataclass
class TriageResult:
    """Result of project triage assessment."""

    viable: bool = False
    score: int = 0  # 0-100 security surface area score
    language: str = "unknown"
    file_count: int = 0
    lines_of_code: int = 0
    build_system: str = "none"
    has_controllers: bool = False
    has_db_operations: bool = False
    has_http_client: bool = False
    has_deserialization: bool = False
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "viable": self.viable,
            "score": self.score,
            "language": self.language,
            "file_count": self.file_count,
            "lines_of_code": self.lines_of_code,
            "build_system": self.build_system,
            "has_controllers": self.has_controllers,
            "has_db_operations": self.has_db_operations,
            "has_http_client": self.has_http_client,
            "has_deserialization": self.has_deserialization,
            "warnings": self.warnings,
            "recommendations": self.recommendations,
        }


# Controller/route patterns by language
_CONTROLLER_PATTERNS = {
    "java": ["@Controller", "@RestController", "@RequestMapping", "@GetMapping", "@PostMapping",
              "@PutMapping", "@DeleteMapping", "@PatchMapping", "HttpServlet", "doGet", "doPost"],
    "python": ["@app.route", "@router", "def get(", "def post(", "Flask", "FastAPI", "Django",
               "APIView", "ViewSet"],
    "javascript": ["app.get(", "app.post(", "router.get(", "router.post(", "express.Router",
                   "@Get", "@Post", "@Controller", "NextApiHandler"],
    "go": ["http.HandleFunc", "gin.Context", "echo.Context", "fiber.Ctx", "mux.HandleFunc",
           "mux.NewRouter"],
}

# DB operation patterns by language
_DB_PATTERNS = {
    "java": ["JdbcTemplate", "EntityManager", "SessionFactory", "@Repository",
             "executeQuery", "prepareStatement", "MyBatis", "SqlSession",
             "MongoRepository", "JpaRepository", "CrudRepository"],
    "python": ["cursor.execute", "Session.query", "Model.objects", "db.session",
               "sqlalchemy", "pymongo", "psycopg2", "sqlite3"],
    "javascript": ["sequelize", "mongoose", "prisma", "typeorm", "knex",
                   "db.query", "pool.query"],
    "go": ["db.Query", "db.Exec", "gorm.DB", "sqlx.DB", "mongo.Collection"],
}

# HTTP client patterns
_HTTP_PATTERNS = {
    "java": ["RestTemplate", "WebClient", "HttpClient", "OkHttpClient", "URLConnection",
             "openConnection", "HttpURLConnection"],
    "python": ["requests.get", "requests.post", "httpx.get", "httpx.post",
               "urllib.request", "aiohttp.ClientSession"],
    "javascript": ["fetch(", "axios.get", "axios.post", "got(", "node-fetch",
                   "http.get", "http.request"],
    "go": ["http.Get", "http.Post", "http.Client", "http.NewRequest"],
}

# Deserialization patterns
_DESER_PATTERNS = {
    "java": ["ObjectInputStream", "readObject", "fastjson", "JSON.parseObject",
             "Yaml.load", "XmlMapper", "ObjectMapper.readValue"],
    "python": ["pickle.load", "yaml.load(", "marshal.load", "json.loads"],
    "javascript": ["JSON.parse", "serialize-javascript", "node-serialize"],
    "go": ["json.Unmarshal", "yaml.Unmarshal", "gob.Decoder", "xml.Unmarshal"],
}


class TriageAssessor:
    """Quick project viability assessor for pre-audit filtering."""

    def __init__(self, project_path: Path) -> None:
        self.project_path = Path(project_path).resolve()

    async def assess(self) -> TriageResult:
        """Run triage assessment on the project.

        Returns:
            TriageResult with viability, score, and surface area details.
        """
        result = TriageResult()

        # Step 1: Language detection
        result.language = await detect_language(self.project_path)
        logger.info(f"Detected language: {result.language}")

        # Step 2: Detect build system
        result.build_system = await self._detect_build_system()
        if result.build_system == "none":
            result.warnings.append("No recognized build system detected")
            result.recommendations.append("May need --build-mode=none for source-only analysis")

        # Step 3: Count files and lines
        result.file_count, result.lines_of_code = await self._count_files_and_lines(result.language)

        # Step 4: Security surface area scan
        await self._scan_surface_area(result)

        # Step 5: Compute viability score
        result.score = self._compute_score(result)
        result.viable = self._determine_viability(result)

        if not result.viable:
            result.recommendations.append("Low security surface area — consider skipping this project")

        return result

    async def _detect_build_system(self) -> str:
        """Detect the build system used by the project."""
        files = {f.name for f in self.project_path.iterdir()}
        if "pom.xml" in files:
            return "maven"
        if "build.gradle" in files or "build.gradle.kts" in files:
            return "gradle"
        if "package.json" in files:
            return "npm"
        if "go.mod" in files:
            return "go_modules"
        if "requirements.txt" in files or "setup.py" in files or "pyproject.toml" in files:
            return "pip"
        if "CMakeLists.txt" in files:
            return "cmake"
        return "none"

    async def _count_files_and_lines(self, language: str) -> tuple[int, int]:
        """Count source files and lines of code."""
        extensions = {
            "java": [".java"],
            "python": [".py"],
            "javascript": [".js", ".jsx", ".ts", ".tsx"],
            "go": [".go"],
            "cpp": [".cpp", ".hpp", ".cc", ".h"],
            "csharp": [".cs"],
        }.get(language, [".java"])

        file_count = 0
        total_lines = 0
        try:
            for ext in extensions:
                for f in self.project_path.rglob(f"*{ext}"):
                    if f.is_file() and "/test" not in str(f) and "/tests" not in str(f):
                        file_count += 1
                        try:
                            total_lines += sum(1 for _ in open(f, encoding="utf-8", errors="ignore"))
                        except Exception:
                            pass
        except Exception as e:
            logger.warning(f"Error counting files: {e}")

        return file_count, total_lines

    async def _scan_surface_area(self, result: TriageResult) -> None:
        """Scan project for security-relevant patterns."""
        language = result.language
        ctrl_patterns = _CONTROLLER_PATTERNS.get(language, [])
        db_patterns = _DB_PATTERNS.get(language, [])
        http_patterns = _HTTP_PATTERNS.get(language, [])
        deser_patterns = _DESER_PATTERNS.get(language, [])

        try:
            extensions = {
                "java": [".java"], "python": [".py"],
                "javascript": [".js", ".ts", ".jsx", ".tsx"], "go": [".go"],
                "cpp": [".cpp", ".hpp"], "csharp": [".cs"],
            }.get(language, [".java"])

            # Sample up to 500 files for speed
            files = []
            for ext in extensions:
                files.extend(list(self.project_path.rglob(f"*{ext}"))[:500])

            for f in files:
                if not f.is_file() or "test" in str(f).lower():
                    continue
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    for pat in ctrl_patterns:
                        if pat in content and not result.has_controllers:
                            result.has_controllers = True
                    for pat in db_patterns:
                        if pat in content and not result.has_db_operations:
                            result.has_db_operations = True
                    for pat in http_patterns:
                        if pat in content and not result.has_http_client:
                            result.has_http_client = True
                    for pat in deser_patterns:
                        if pat in content and not result.has_deserialization:
                            result.has_deserialization = True
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Surface area scan error: {e}")

    def _compute_score(self, result: TriageResult) -> int:
        """Compute a 0-100 security surface area score."""
        score = 0

        # File count: 0-20 points
        if result.file_count > 100:
            score += 20
        elif result.file_count > 20:
            score += 10
        elif result.file_count > 0:
            score += 5

        # Lines of code: 0-20 points
        if result.lines_of_code > 50_000:
            score += 20
        elif result.lines_of_code > 10_000:
            score += 15
        elif result.lines_of_code > 1_000:
            score += 10
        elif result.lines_of_code > 0:
            score += 5

        # Build system: 0-15 points
        build_scores = {"maven": 15, "gradle": 15, "npm": 10, "pip": 10, "go_modules": 10, "cmake": 5, "none": 5}
        score += build_scores.get(result.build_system, 5)

        # Surface area features: 0-45 points
        if result.has_controllers:
            score += 15
        if result.has_db_operations:
            score += 15
        if result.has_http_client:
            score += 10
        if result.has_deserialization:
            score += 5

        return min(score, 100)

    def _determine_viability(self, result: TriageResult) -> bool:
        """Determine whether a project is viable for full audit."""
        # Empty or near-empty projects
        if result.file_count < 5:
            return False
        if result.lines_of_code < 500:
            return False

        # No recognizable code structure
        if not result.has_controllers and not result.has_db_operations:
            if result.lines_of_code < 5_000:
                return False

        # Low score
        if result.score < 20:
            return False

        return True
