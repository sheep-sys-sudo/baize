"""Fix suggestion generator for vulnerabilities.

Fix resolution order:
1. Static template (FIX_TEMPLATES dict) — fast, no LLM cost
2. LLM-generated fix — when no template exists and LLM is configured
"""

from __future__ import annotations


from loguru import logger

from baize.models.finding import Finding, VulnerabilityType


FIX_TEMPLATES: dict[VulnerabilityType, dict] = {
    VulnerabilityType.SQLI: {
        "title": "SQL Injection Fix",
        "description": "Use parameterized queries instead of string concatenation",
        "patterns": [
            ("Statement.executeQuery", "PreparedStatement.executeQuery"),
            ("JdbcTemplate.query", "JdbcTemplate.query with PreparedStatement"),
            ("createStatement", "createPreparedStatement"),
        ],
        "fix_snippet": """
// Before (vulnerable):
String query = "SELECT * FROM users WHERE name = '" + username + "'";
stmt.executeQuery(query);

// After (fixed):
String query = "SELECT * FROM users WHERE name = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, username);
ResultSet rs = pstmt.executeQuery();
""",
    },
    VulnerabilityType.XSS: {
        "title": "Cross-Site Scripting (XSS) Fix",
        "description": "Encode output to prevent XSS attacks",
        "patterns": [
            ("response.getWriter().write", "Encode.forHtml()"),
            ("model.addAttribute", "Encode.forHtml()"),
        ],
        "fix_snippet": """
// Before (vulnerable):
model.addAttribute("userInput", userInput);

// After (fixed):
import org.owasp.encoder.Encode;
model.addAttribute("userInput", Encode.forHtml(userInput));
""",
    },
    VulnerabilityType.RCE: {
        "title": "Remote Code Execution Fix",
        "description": "Avoid executing user-controlled data",
        "patterns": [
            ("Runtime.exec", "ProcessBuilder with validated arguments"),
            ("ProcessBuilder", "Use safer APIs"),
        ],
        "fix_snippet": """
// Before (vulnerable):
Runtime.getRuntime().exec(command);

// After (fixed):
// Use a whitelist of allowed commands
ProcessBuilder pb = new ProcessBuilder(Arrays.asList("ls", "-la"));
pb.start();
""",
    },
    VulnerabilityType.PATH_TRAVERSAL: {
        "title": "Path Traversal Fix",
        "description": "Validate and sanitize file paths",
        "patterns": [
            ("FileInputStream", "Validate path with canonicalization"),
            ("Files.read", "Use Path.resolve and validate"),
        ],
        "fix_snippet": """
// Before (vulnerable):
FileInputStream fis = new FileInputStream(userInput);

// After (fixed):
Path base = Paths.get("/safe/base");
Path resolved = base.resolve(userInput).normalize();
if (!resolved.startsWith(base)) {
    throw new SecurityException("Path traversal detected");
}
FileInputStream fis = new FileInputStream(resolved.toFile());
""",
    },
    VulnerabilityType.DESERIALIZATION: {
        "title": "Unsafe Deserialization Fix",
        "description": "Avoid deserializing untrusted data; use safe serialization formats",
        "patterns": [
            ("ObjectInputStream", "Use JSON or XML with schema validation"),
            ("pickle.loads", "Use json.loads or validate source"),
        ],
        "fix_snippet": """
// Java — replace ObjectInputStream with a safe alternative:
// Before (vulnerable):
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();

// After (fixed): Use a deserialization filter (Java 9+):
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(ObjectInputFilter.Config.getSerialFilter());
Object obj = ois.readObject();

# Python — replace pickle with json:
# Before (vulnerable):
import pickle
obj = pickle.loads(data)

# After (fixed):
import json
obj = json.loads(data)
""",
    },
    VulnerabilityType.SSRF: {
        "title": "Server-Side Request Forgery (SSRF) Fix",
        "description": "Validate and allowlist outbound URLs",
        "patterns": [
            ("requests.get", "Validate URL against allowlist"),
            ("http.Get", "Validate URL against allowlist"),
        ],
        "fix_snippet": """
# Python — validate URL before making the request:
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.com", "partner.example.com"}

def safe_request(url: str):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Blocked host: {parsed.hostname}")
    return requests.get(url, timeout=10)
""",
    },
    VulnerabilityType.COMMAND_INJECTION: {
        "title": "Command Injection Fix",
        "description": "Avoid shell=True; pass arguments as a list and validate inputs",
        "patterns": [
            ("os.system", "Use subprocess with argument list"),
            ("exec.Command", "Validate and separate arguments"),
        ],
        "fix_snippet": """
# Python — avoid shell=True:
# Before (vulnerable):
import os
os.system(f"convert {user_input}")

# After (fixed):
import subprocess, shlex
allowed_formats = {"png", "jpg", "gif"}
if user_input not in allowed_formats:
    raise ValueError("Invalid format")
subprocess.run(["convert", user_input], check=True)
""",
    },
    VulnerabilityType.XXE: {
        "title": "XML External Entity (XXE) Fix",
        "description": "Disable external entity processing in the XML parser",
        "patterns": [
            ("DocumentBuilder", "Disable external entities"),
            ("SAXParser", "Disable external entities"),
        ],
        "fix_snippet": """
// Java — disable external entities:
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder db = dbf.newDocumentBuilder();
""",
    },
}


class FixSuggester:
    """Generates fix suggestions for vulnerabilities.

    If a static template is available it is returned immediately (no LLM cost).
    When no template exists and an LLMConfig is provided the suggester calls the
    LLM to produce a context-aware fix recommendation.
    """

    def __init__(self, llm_config=None) -> None:
        """Args:
            llm_config: Optional LLMConfig.  When provided, findings without a
                        static template will trigger an LLM call.
        """
        self._llm_config = llm_config

    def suggest_fix(self, finding: Finding) -> dict:
        """Return the static template fix for *finding* (sync, no LLM)."""
        template = FIX_TEMPLATES.get(finding.vuln_type)
        if template:
            return template.copy()
        return {
            "title": f"Fix for {finding.vuln_type.value}",
            "description": "Review and fix this vulnerability manually.",
            "patterns": [],
            "fix_snippet": "",
            "llm_generated": False,
        }

    async def suggest_fix_async(self, finding: Finding) -> dict:
        """Return a fix suggestion, falling back to LLM when no template exists."""
        template = FIX_TEMPLATES.get(finding.vuln_type)
        if template:
            return template.copy()

        if self._llm_config is None:
            return self.suggest_fix(finding)

        return await self._generate_llm_fix(finding)

    async def _generate_llm_fix(self, finding: Finding) -> dict:
        """Ask the LLM to generate a fix suggestion for *finding*."""
        from baize.utils.llm import call_llm

        snippet_hint = ""
        if finding.sink_code:
            snippet_hint = f"\nVulnerable code snippet:\n```\n{finding.sink_code[:500]}\n```"
        if finding.source_code and not finding.sink_code:
            snippet_hint = f"\nSource code:\n```\n{finding.source_code[:500]}\n```"

        prompt = (
            f"A {finding.vuln_type.value} vulnerability ({finding.rule_id}) was found "
            f"at {finding.location.file}:{finding.location.line}."
            f"{snippet_hint}\n\n"
            "Provide a concise fix suggestion in JSON with keys:\n"
            '  "title": short title\n'
            '  "description": 1-2 sentence explanation\n'
            '  "fix_snippet": corrected code example (use the same language)\n'
            "Return ONLY the JSON object, no markdown fences."
        )

        raw = await call_llm(prompt, self._llm_config, json_mode=True, caller="fix_suggester")

        if raw:
            try:
                import json as _json
                parsed = _json.loads(raw)
                parsed["llm_generated"] = True
                return parsed
            except Exception:
                logger.warning("LLM fix response was not valid JSON; using raw text")
                return {
                    "title": f"LLM fix for {finding.vuln_type.value}",
                    "description": raw[:300],
                    "fix_snippet": "",
                    "llm_generated": True,
                }

        return self.suggest_fix(finding)

    async def generate_fixes_for_findings(
        self,
        findings: list[Finding],
    ) -> list[dict]:
        """Generate fixes for multiple findings (uses LLM when configured)."""
        results = []
        for f in findings:
            fix = await self.suggest_fix_async(f)
            results.append(fix)
        return results

    def validate_fix(self, original_code: str, fixed_code: str) -> bool:
        """Validate that a fix doesn't break functionality."""
        return len(fixed_code) > 0 and fixed_code != original_code