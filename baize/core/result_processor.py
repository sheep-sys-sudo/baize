"""Enhanced result processor with denoising and ranking."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from loguru import logger

from baize.models.finding import Finding, FindingSeverity, VulnerabilityType
from baize.models.report import Report


RULE_ID_TO_TYPE: dict[str, VulnerabilityType] = {
    # ── SQL Injection ───────────────────────────────────────────────
    "java/sql-injection": VulnerabilityType.SQLI,
    "sql-injection": VulnerabilityType.SQLI,
    "py/sql-injection": VulnerabilityType.SQLI,
    "js/sql-injection": VulnerabilityType.SQLI,
    "python/sql-injection": VulnerabilityType.SQLI,
    "go/sql-injection": VulnerabilityType.SQLI,
    "java/sql-templates": VulnerabilityType.SQLI,
    "java/mybatis": VulnerabilityType.SQLI,
    "sqli": VulnerabilityType.SQLI,
    # ── XSS ─────────────────────────────────────────────────────────
    "java/xss": VulnerabilityType.XSS,
    "xss": VulnerabilityType.XSS,
    "py/xss": VulnerabilityType.XSS,
    "js/xss": VulnerabilityType.XSS,
    "python/xss": VulnerabilityType.XSS,
    "reflected-xss": VulnerabilityType.XSS,
    "stored-xss": VulnerabilityType.XSS,
    "dom-xss": VulnerabilityType.XSS,
    "java/xss-servlet": VulnerabilityType.XSS,
    "java/xss-jsp": VulnerabilityType.XSS,
    # ── RCE / Code Execution ────────────────────────────────────────
    "java/rce": VulnerabilityType.RCE,
    "remote-code-execution": VulnerabilityType.RCE,
    "py/rce": VulnerabilityType.RCE,
    "js/rce": VulnerabilityType.RCE,
    "python/rce": VulnerabilityType.RCE,
    "code-execution": VulnerabilityType.RCE,
    "java/command-injection": VulnerabilityType.COMMAND_INJECTION,
    "command-injection": VulnerabilityType.COMMAND_INJECTION,
    "java/process-builder": VulnerabilityType.COMMAND_INJECTION,
    "java/runtime-exec": VulnerabilityType.COMMAND_INJECTION,
    "java/groovy-injection": VulnerabilityType.RCE,
    "java/script-engine": VulnerabilityType.RCE,
    "java/spel-injection": VulnerabilityType.RCE,
    "java/ognl-injection": VulnerabilityType.RCE,
    "java/mvel-injection": VulnerabilityType.RCE,
    # ── SSRF ────────────────────────────────────────────────────────
    "java/ssrf": VulnerabilityType.SSRF,
    "ssrf": VulnerabilityType.SSRF,
    "py/ssrf": VulnerabilityType.SSRF,
    "java/untrusted-url": VulnerabilityType.SSRF,
    "java/url-rewriting": VulnerabilityType.SSRF,
    # ── Deserialization ─────────────────────────────────────────────
    "java/deserialization": VulnerabilityType.DESERIALIZATION,
    "deserialization": VulnerabilityType.DESERIALIZATION,
    "unsafe-deserialization": VulnerabilityType.DESERIALIZATION,
    "java/fastjson": VulnerabilityType.DESERIALIZATION,
    "java/jackson": VulnerabilityType.DESERIALIZATION,
    "java/readobject": VulnerabilityType.DESERIALIZATION,
    "java/objectinputstream": VulnerabilityType.DESERIALIZATION,
    "java/jndi-injection": VulnerabilityType.JNDI_INJECTION,
    "jndi-injection": VulnerabilityType.JNDI_INJECTION,
    "java/log4j": VulnerabilityType.JNDI_INJECTION,
    "log4shell": VulnerabilityType.JNDI_INJECTION,
    # ── Path Traversal ──────────────────────────────────────────────
    "java/path-traversal": VulnerabilityType.PATH_TRAVERSAL,
    "path-traversal": VulnerabilityType.PATH_TRAVERSAL,
    "py/path-injection": VulnerabilityType.PATH_TRAVERSAL,
    "java/zip-slip": VulnerabilityType.PATH_TRAVERSAL,
    "java/tainted-path": VulnerabilityType.PATH_TRAVERSAL,
    "java/file-upload": VulnerabilityType.PATH_TRAVERSAL,
    "java/arbitrary-file-write": VulnerabilityType.PATH_TRAVERSAL,
    "java/arbitrary-file-read": VulnerabilityType.PATH_TRAVERSAL,
    # ── XXE ─────────────────────────────────────────────────────────
    "java/xxe": VulnerabilityType.XXE,
    "xxe": VulnerabilityType.XXE,
    "java/xml-external-entity": VulnerabilityType.XXE,
    "java/documentbuilder-xxe": VulnerabilityType.XXE,
    "java/sax-xxe": VulnerabilityType.XXE,
    # ── Open Redirect ───────────────────────────────────────────────
    "java/open-redirect": VulnerabilityType.OPEN_REDIRECT,
    "open-redirect": VulnerabilityType.OPEN_REDIRECT,
    "java/unvalidated-redirect": VulnerabilityType.OPEN_REDIRECT,
    "java/url-redirect": VulnerabilityType.OPEN_REDIRECT,
    # ── Crypto (NEW) ────────────────────────────────────────────────
    "java/weak-cryptographic-algorithm": VulnerabilityType.CRYPTO,
    "java/weak-crypto": VulnerabilityType.CRYPTO,
    "java/insecure-cryptography": VulnerabilityType.CRYPTO,
    "weak-cryptographic-algorithm": VulnerabilityType.CRYPTO,
    "java/insufficient-key-size": VulnerabilityType.CRYPTO,
    "java/insecure-cipher": VulnerabilityType.CRYPTO,
    "java/padding-oracle": VulnerabilityType.CRYPTO,
    "java/cleartext-crypto": VulnerabilityType.CRYPTO,
    "java/weak-encryption": VulnerabilityType.CRYPTO,
    "crypto": VulnerabilityType.CRYPTO,
    # ── Log Injection (NEW) ─────────────────────────────────────────
    "java/log-injection": VulnerabilityType.LOG_INJECTION,
    "log-injection": VulnerabilityType.LOG_INJECTION,
    "java/log-forging": VulnerabilityType.LOG_INJECTION,
    "java/crlf-injection": VulnerabilityType.LOG_INJECTION,
    # ── Sensitive Data Exposure (NEW) ───────────────────────────────
    "java/sensitive-log": VulnerabilityType.SENSITIVE_DATA,
    "sensitive-log": VulnerabilityType.SENSITIVE_DATA,
    "java/cleartext-logging": VulnerabilityType.SENSITIVE_DATA,
    "java/cleartext-storage": VulnerabilityType.SENSITIVE_DATA,
    "java/cleartext-transmission": VulnerabilityType.SENSITIVE_DATA,
    "java/cleartext-credential": VulnerabilityType.SENSITIVE_DATA,
    "java/plaintext-credentials": VulnerabilityType.SENSITIVE_DATA,
    "java/plaintext-storage": VulnerabilityType.SENSITIVE_DATA,
    "java/insecure-protocol": VulnerabilityType.SENSITIVE_DATA,
    "java/unencrypted-socket": VulnerabilityType.SENSITIVE_DATA,
    "java/non-https": VulnerabilityType.SENSITIVE_DATA,
    "java/exposure-of-sensitive-information": VulnerabilityType.SENSITIVE_DATA,
    # ── Missing Auth (NEW) ──────────────────────────────────────────
    "java/missing-permission-check": VulnerabilityType.MISSING_AUTH,
    "missing-permission": VulnerabilityType.MISSING_AUTH,
    "java/spring-missing-authorization": VulnerabilityType.MISSING_AUTH,
    "java/spring-missing-authentication": VulnerabilityType.MISSING_AUTH,
    "java/android-missing-permission": VulnerabilityType.MISSING_AUTH,
    "java/missing-auth": VulnerabilityType.MISSING_AUTH,
    # ── Hardcoded Credentials (NEW) ─────────────────────────────────
    "java/hardcoded-credentials": VulnerabilityType.HARDCODED_CREDENTIALS,
    "hardcoded-credentials": VulnerabilityType.HARDCODED_CREDENTIALS,
    "java/hardcoded-password": VulnerabilityType.HARDCODED_CREDENTIALS,
    "java/hardcoded-key": VulnerabilityType.HARDCODED_CREDENTIALS,
    "java/password-in-configuration": VulnerabilityType.HARDCODED_CREDENTIALS,
    "java/hardcoded-secret": VulnerabilityType.HARDCODED_CREDENTIALS,
    "java/credentials-in-url": VulnerabilityType.HARDCODED_CREDENTIALS,
    # ── Unsafe Reflection (NEW) ─────────────────────────────────────
    "java/unsafe-reflection": VulnerabilityType.UNSAFE_REFLECTION,
    "java/reflective-injection": VulnerabilityType.UNSAFE_REFLECTION,
    "java/reflection-injection": VulnerabilityType.UNSAFE_REFLECTION,
    "java/dynamic-class-loading": VulnerabilityType.UNSAFE_REFLECTION,
    # ── SSTI (NEW) ──────────────────────────────────────────────────
    "java/ssti": VulnerabilityType.SSTI,
    "java/server-side-template-injection": VulnerabilityType.SSTI,
    "java/template-injection": VulnerabilityType.SSTI,
    "java/freemarker-injection": VulnerabilityType.SSTI,
    "java/velocity-injection": VulnerabilityType.SSTI,
    "java/thymeleaf-injection": VulnerabilityType.SSTI,
    # ── ReDoS (NEW) ─────────────────────────────────────────────────
    "java/regex-injection": VulnerabilityType.RE_DOS,
    "java/polynomial-regex": VulnerabilityType.RE_DOS,
    "java/polynomial-regular-expression-used": VulnerabilityType.RE_DOS,
    "java/re-dos": VulnerabilityType.RE_DOS,
    "regex-injection": VulnerabilityType.RE_DOS,
    # ── Info Leak (NEW) ─────────────────────────────────────────────
    "java/stack-trace-exposure": VulnerabilityType.INFO_LEAK,
    "java/exception-exposure": VulnerabilityType.INFO_LEAK,
    "java/system-information-leak": VulnerabilityType.INFO_LEAK,
    "java/error-message-exposure": VulnerabilityType.INFO_LEAK,
    "java/info-leak": VulnerabilityType.INFO_LEAK,
    # ── Misc ────────────────────────────────────────────────────────
    "java/insecure-random": VulnerabilityType.CRYPTO,
    "java/insecure-bean-validation": VulnerabilityType.MISSING_AUTH,
    "java/android-intent-redirect": VulnerabilityType.OPEN_REDIRECT,
    "java/android-webview": VulnerabilityType.XSS,
    "java/android-external-storage": VulnerabilityType.SENSITIVE_DATA,
    "java/android-broadcast": VulnerabilityType.MISSING_AUTH,
    "java/cross-site-request-forgery": VulnerabilityType.MISSING_AUTH,
    "java/request-dispatcher": VulnerabilityType.UNSAFE_REFLECTION,
    "java/signed-jar": VulnerabilityType.CRYPTO,
    "java/missing-jar-signature": VulnerabilityType.CRYPTO,
    "java/insecure-cookie": VulnerabilityType.SENSITIVE_DATA,
    "java/sensitive-cookie": VulnerabilityType.SENSITIVE_DATA,
    "java/cookie-persistence": VulnerabilityType.SENSITIVE_DATA,
    "java/http-response-splitting": VulnerabilityType.XSS,
    "java/header-injection": VulnerabilityType.XSS,
}


SEVERITY_MAP: dict[str, FindingSeverity] = {
    "error": FindingSeverity.HIGH,
    "warning": FindingSeverity.MEDIUM,
    "note": FindingSeverity.LOW,
    "none": FindingSeverity.INFO,
}


EXCLUSION_PATTERNS = [
    r"/test/",
    r"/tests/",
    r"\.test\.",
    r"\.tests\.",
    r"/mock/",
    r"/fixture/",
    r"/vendor/",
    r"/node_modules/",
    r"/\.git/",
    r"/__pycache__/",
    r"Test\.java$",
    r"Test\.py$",
    r"\.min\.js$",
    r"\.bundle\.js$",
    r"/generated/",
    r"/dist/",
    r"/build/",
]


HIGH_CONFIDENCE_PATTERNS = [
    r"executeQuery",
    r"exec\(",
    r"getParameter",
    r"innerHTML",
    r"eval\(",
    r"system\(",
    r"Runtime\.exec",
]


class ResultRanker:
    """Ranks findings by severity, confidence, and other factors."""

    SEVERITY_WEIGHTS = {
        FindingSeverity.CRITICAL: 10,
        FindingSeverity.HIGH: 7,
        FindingSeverity.MEDIUM: 4,
        FindingSeverity.LOW: 2,
        FindingSeverity.INFO: 1,
    }

    def __init__(self):
        self._confidence_cache: dict[str, float] = {}

    def calculate_confidence(self, finding: Finding) -> float:
        """Calculate confidence score for a finding.

        Args:
            finding: The finding to evaluate

        Returns:
            Confidence score between 0 and 1
        """
        cache_key = f"{finding.rule_id}:{finding.location.file}:{finding.location.line}"
        if cache_key in self._confidence_cache:
            return self._confidence_cache[cache_key]

        confidence = 0.5

        code = finding.location.snippet
        if code:
            for pattern in HIGH_CONFIDENCE_PATTERNS:
                if re.search(pattern, code, re.IGNORECASE):
                    confidence += 0.2

        if finding.dataflow_path and finding.dataflow_path.is_complete:
            confidence += 0.15

        if len(finding.related_locations) > 0:
            confidence += 0.1

        if finding.vuln_type != VulnerabilityType.UNKNOWN:
            confidence += 0.1

        confidence = min(confidence, 1.0)
        self._confidence_cache[cache_key] = confidence
        return confidence

    def rank_findings(
        self,
        findings: list[Finding],
        sort_by_confidence: bool = True,
    ) -> list[Finding]:
        """Rank findings by severity and confidence.

        Args:
            findings: List of findings to rank
            sort_by_confidence: Whether to also sort by confidence

        Returns:
            Sorted list of findings
        """
        def priority_key(f: Finding) -> tuple:
            severity_weight = self.SEVERITY_WEIGHTS.get(f.severity, 0)
            confidence = f.confidence
            return (
                -severity_weight,
                -confidence if sort_by_confidence else 0,
            )

        return sorted(findings, key=priority_key)


class ResultDenoiser:
    """Removes false positives and noisy findings."""

    NOISE_PATTERNS = [
        r"example\.com",
        r"localhost",
        r"127\.0\.0\.1",
        r"\.example\.",
        r"/demo/",
        r"/sample/",
    ]

    SAFE_METHODS = [
        r"ArrayList",
        r"HashMap",
        r"HashSet",
        r"List",
        r"Map",
        r"Set",
    ]

    def __init__(self):
        self._noise_patterns = [re.compile(p, re.IGNORECASE) for p in self.NOISE_PATTERNS]

    def is_likely_noise(self, finding: Finding) -> bool:
        """Check if a finding is likely a false positive.

        Args:
            finding: Finding to check

        Returns:
            True if likely noise
        """
        code = finding.location.snippet
        if not code:
            return False

        for pattern in self._noise_patterns:
            if pattern.search(code):
                return True

        if "test" in str(finding.location.file).lower():
            for safe in self.SAFE_METHODS:
                if safe in code:
                    return True

        return False

    def filter_noise(self, findings: list[Finding]) -> list[Finding]:
        """Filter out likely false positives.

        Args:
            findings: List of findings to filter

        Returns:
            Filtered list
        """
        return [f for f in findings if not self.is_likely_noise(f)]


class ResultProcessor:
    """Processes SARIF results into structured Finding objects with denoising and ranking."""

    def __init__(
        self,
        exclude_patterns: Optional[list[str]] = None,
        min_confidence: float = 0.0,
    ):
        """Initialize the processor.

        Args:
            exclude_patterns: Patterns for files to exclude
            min_confidence: Minimum confidence threshold
        """
        self._exclude_patterns = [
            re.compile(p) for p in (exclude_patterns or EXCLUSION_PATTERNS)
        ]
        self._min_confidence = min_confidence
        self._ranker = ResultRanker()
        self._denoiser = ResultDenoiser()

    def parse_sarif(self, sarif_path: Path) -> list[dict]:
        """Parse a SARIF file and return raw results."""
        sarif_path = Path(sarif_path)
        if not sarif_path.exists():
            raise FileNotFoundError(f"SARIF file not found: {sarif_path}")

        with open(sarif_path) as f:
            data = json.load(f)

        results = []
        for run in data.get("runs", []):
            for result in run.get("results", []):
                result["_run"] = run
            results.extend(run.get("results", []))

        logger.info(f"Parsed {len(results)} results from SARIF")
        return results

    def process_results(
        self,
        sarif_path: Path,
        severity_filter: Optional[list[FindingSeverity]] = None,
        vuln_types_filter: Optional[list[VulnerabilityType]] = None,
    ) -> list[Finding]:
        """Process SARIF results into Finding objects with filtering.

        Args:
            sarif_path: Path to SARIF file
            severity_filter: Only include findings with these severities
            vuln_types_filter: Only include findings of these types

        Returns:
            List of Finding objects
        """
        raw_results = self.parse_sarif(sarif_path)

        findings = []
        for raw in raw_results:
            finding = self._convert_result_to_finding(raw)
            if finding is None:
                continue

            if self._should_exclude(finding):
                continue

            if severity_filter and finding.severity not in severity_filter:
                continue

            if vuln_types_filter and finding.vuln_type not in vuln_types_filter:
                continue

            finding.confidence = self._ranker.calculate_confidence(finding)
            findings.append(finding)

        findings = self._denoiser.filter_noise(findings)
        findings = self._ranker.rank_findings(findings)

        logger.info(f"Processed {len(findings)} findings after filtering and ranking")
        return findings

    def _convert_result_to_finding(self, result: dict) -> Optional[Finding]:
        """Convert a single SARIF result to a Finding."""
        run = result.get("_run", {})
        rule_id = result.get("ruleId", "")

        vuln_type = self._determine_vuln_type(rule_id)
        severity = self._determine_severity(result)

        try:
            finding = Finding.from_sarif_result(
                result=result,
                sarif_run=run,
                vuln_type=vuln_type,
                severity=severity,
            )
            return finding
        except Exception as e:
            logger.warning(f"Error converting result {rule_id}: {e}")
            return None

    def _determine_vuln_type(self, rule_id: str) -> VulnerabilityType:
        """Determine vulnerability type from rule ID."""
        rule_lower = rule_id.lower()
        for pattern, vuln_type in RULE_ID_TO_TYPE.items():
            if pattern in rule_lower:
                return vuln_type
        return VulnerabilityType.UNKNOWN

    def _determine_severity(self, result: dict) -> FindingSeverity:
        """Determine severity from SARIF result."""
        level = result.get("level", "warning")
        return SEVERITY_MAP.get(level, FindingSeverity.MEDIUM)

    def _should_exclude(self, finding: Finding) -> bool:
        """Check if a finding should be excluded based on patterns."""
        file_path = str(finding.location.file)

        for pattern in self._exclude_patterns:
            if pattern.search(file_path):
                return True

        return False

    def create_report(
        self,
        sarif_path: Path,
        project_name: str = "",
        project_path: str = "",
        **kwargs,
    ) -> Report:
        """Create a Report from SARIF results."""
        findings = self.process_results(sarif_path, **kwargs)

        report = Report.create_empty(project_name, project_path)
        for finding in findings:
            report.add_finding(finding)

        report.dataflow_included = False
        report.fixes_included = False

        return report

    async def filter_by_confidence(
        self,
        findings: list[Finding],
        min_confidence: float = 0.5,
    ) -> list[Finding]:
        """Filter findings by confidence threshold."""
        return [f for f in findings if f.confidence >= min_confidence]

    async def deduplicate(
        self,
        findings: list[Finding],
    ) -> list[Finding]:
        """Remove duplicate findings based on location and rule."""
        seen: set[tuple] = set()
        unique = []

        for f in findings:
            key = (str(f.location.file), f.location.line, f.rule_id)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    async def rank_by_priority(
        self,
        findings: list[Finding],
    ) -> list[Finding]:
        """Rank findings by priority (severity + confidence).

        Args:
            findings: List of findings to rank

        Returns:
            Ranked list of findings
        """
        return self._ranker.rank_findings(findings)