"""Source-Sink detection for identifying vulnerability entry points and dangerous sinks.

This module provides automatic detection of:
- Sources: User input entry points (HTTP params, file reads, etc.)
- Sinks: Dangerous functions that can lead to vulnerabilities (SQL exec, command exec, etc.)
- Sanitizers: Functions that validate or escape data
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional



@dataclass
class Pattern:
    """A pattern for matching source/sink/sanitizer."""

    type: str
    patterns: list[str]
    language: str
    severity: str = "high"


@dataclass
class Source:
    """Represents a source (user input entry point)."""

    type: str
    pattern: str
    context: str
    examples: list[str] = field(default_factory=list)


@dataclass
class Sink:
    """Represents a sink (dangerous function)."""

    type: str
    pattern: str
    context: str
    vuln_type: str
    examples: list[str] = field(default_factory=list)


@dataclass
class Sanitizer:
    """Represents a sanitizer (input validation/escaping)."""

    type: str
    pattern: str
    context: str
    examples: list[str] = field(default_factory=list)


DEFAULT_SOURCES = {
    "java": [
        Source(
            type="http_parameter",
            pattern=r"(getParameter|getQueryString|getHeader|getCookies)\s*\(",
            context="HTTP request parameters",
            examples=["request.getParameter()", "request.getHeader()"],
        ),
        Source(
            type="file_input",
            pattern=r"(FileInputStream|BufferedReader|Scanner)\s*\(.*\)",
            context="File input operations",
            examples=["new FileInputStream(path)", "new Scanner(file)"],
        ),
        Source(
            type="network_input",
            pattern=r"(getInputStream|getReader|getBody)\s*\(",
            context="Network input",
            examples=["request.getInputStream()"],
        ),
        Source(
            type="environment",
            pattern=r"(getenv|System\.getProperty)\s*\(",
            context="Environment variables",
            examples=["System.getenv()", "System.getProperty()"],
        ),
    ],
    "python": [
        Source(
            type="http_parameter",
            pattern=r"(request\.(args|values|form|files)|flask\.request)",
            context="HTTP request parameters",
            examples=["request.args", "request.form", "flask.request"],
        ),
        Source(
            type="file_input",
            pattern=r"(open|file|io\.open|Path)\s*\(",
            context="File input operations",
            examples=["open(filename)", "Path(path)"],
        ),
        Source(
            type="stdin",
            pattern=r"(input|raw_input|sys\.stdin)\s*\(",
            context="Standard input",
            examples=["input()", "raw_input()"],
        ),
        Source(
            type="environment",
            pattern=r"(os\.environ|os\.getenv)\s*\(",
            context="Environment variables",
            examples=["os.environ", "os.getenv()"],
        ),
    ],
    "javascript": [
        Source(
            type="http_parameter",
            pattern=r"(req\.(body|params|query|headers)|request\.)",
            context="HTTP request parameters",
            examples=["req.body", "req.params", "request.query"],
        ),
        Source(
            type="user_input",
            pattern=r"(document\.cookie|localStorage|sessionStorage)",
            context="Browser storage",
            examples=["document.cookie", "localStorage.getItem()"],
        ),
        Source(
            type="network_input",
            pattern=r"(fetch|axios|XMLHttpRequest)",
            context="Network requests",
            examples=["fetch(url)", "axios.get()"],
        ),
    ],
    "go": [
        Source(
            type="http_parameter",
            pattern=r"(r\.FormValue|r\.PostFormValue|r\.URL\.Query|http\.Request)",
            context="HTTP request parameters",
            examples=["r.FormValue()", "r.PostFormValue()", "r.URL.Query()"],
        ),
        Source(
            type="environment",
            pattern=r"(os\.Getenv|os\.LookupEnv)",
            context="Environment variables",
            examples=["os.Getenv()", "os.LookupEnv()"],
        ),
        Source(
            type="file_input",
            pattern=r"(os\.Open|ioutil\.ReadFile|bufio\.NewReader)",
            context="File input operations",
            examples=["os.Open()", "ioutil.ReadFile()"],
        ),
    ],
}


DEFAULT_SINKS = {
    "java": [
        Sink(
            type="sql_execution",
            pattern=r"(?:(?:Statement|PreparedStatement|Connection|JdbcTemplate)\.|[a-z]\w*\.(?:execute|query|update|prepare))(?:Query|Update|Batch|Many|Proc|Statement)?\s*\(",
            context="SQL execution",
            vuln_type="sqli",
            examples=["stmt.executeQuery()", "pstmt.execute()", "jdbcTemplate.query()"],
        ),
        Sink(
            type="command_execution",
            pattern=r"(Runtime\.exec|ProcessBuilder|ProcessImpl)\s*\(",
            context="Command execution",
            vuln_type="rce",
            examples=["Runtime.exec()", "new ProcessBuilder()"],
        ),
        Sink(
            type="dynamic_code",
            pattern=r"(ClassLoader\.defineClass|MethodHandle\.invokeExact|System\.load)",
            context="Dynamic code loading",
            vuln_type="rce",
            examples=["classLoader.defineClass()", "methodHandle.invokeExact()"],
        ),
        Sink(
            type="file_operation",
            pattern=r"(FileInputStream|FileOutputStream|FileWriter|Paths\.get)\s*\(",
            context="File operations",
            vuln_type="path-traversal",
            examples=["new FileInputStream()", "Paths.get(userInput)"],
        ),
        Sink(
            type="reflection",
            pattern=r"(Class\.forName|Method\.invoke|Field\.get)\s*\(",
            context="Reflection APIs",
            vuln_type="rce",
            examples=["Class.forName()", "method.invoke()"],
        ),
        Sink(
            type="deserialization",
            pattern=r"(ObjectInputStream|XMLDecoder|JAXB\.unmarshal|JSON\.parse)\s*\(",
            context="Deserialization",
            vuln_type="deserialization",
            examples=["new ObjectInputStream()", "XMLDecoder()", "JSON.parse()"],
        ),
        Sink(
            type="network_request",
            pattern=r"(HttpURLConnection|OkHttpClient|JettyClient|WebClient)\.(open|get|post|newCall)",
            context="Network requests",
            vuln_type="ssrf",
            examples=["connection.getInputStream()", "client.newCall()"],
        ),
        Sink(
            type="html_output",
            pattern=r"(response\.getWriter|StringWriter|JspWriter)\.(write|print|append)",
            context="HTML output",
            vuln_type="xss",
            examples=["response.getWriter().write()", "out.print()"],
        ),
        Sink(
            type="el_output",
            pattern=r"(\$\{|\#\{|\.EL\s)",
            context="Expression Language output",
            vuln_type="xss",
            examples=["${userInput}", "#{userInput}"],
        ),
    ],
    "python": [
        Sink(
            type="sql_execution",
            pattern=r"(cursor\.execute|cursor\.executemany|cursor\.callproc|sqlalchemy\.text)",
            context="SQL execution",
            vuln_type="sqli",
            examples=["cursor.execute()", "cursor.executemany()"],
        ),
        Sink(
            type="command_execution",
            pattern=r"(os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen|eval|exec|compile)\s*\(",
            context="Command execution",
            vuln_type="rce",
            examples=["os.system()", "subprocess.run()", "eval()", "exec()"],
        ),
        Sink(
            type="file_operation",
            pattern=r"(open|file|io\.open|Path|os\.path)\s*\(",
            context="File operations",
            vuln_type="path-traversal",
            examples=["open(filename)", "Path(path)"],
        ),
        Sink(
            type="pickle_deserialization",
            pattern=r"(pickle\.load|pickle\.loads|marshal\.load|shelve\.open|yaml\.load)\s*\(",
            context="Deserialization",
            vuln_type="deserialization",
            examples=["pickle.loads()", "yaml.load()", "marshal.load()"],
        ),
        Sink(
            type="html_output",
            pattern=r"(Response|render_template|render|flask\.make_response|Markup)\.(write|Response|html)",
            context="HTML output",
            vuln_type="xss",
            examples=["response.write()", "render_template()"],
        ),
        Sink(
            type="network_request",
            pattern=r"(requests\.|urllib\.|http\.client\.|httpx\.)(get|post|put|delete|request)",
            context="Network requests",
            vuln_type="ssrf",
            examples=["requests.get()", "urllib.request.urlopen()"],
        ),
    ],
    "javascript": [
        Sink(
            type="sql_execution",
            pattern=r"(mysql|postgres|sqlite|mongoose|sequelize|query)\.(query|execute)",
            context="SQL execution",
            vuln_type="sqli",
            examples=["db.query()", "connection.execute()"],
        ),
        Sink(
            type="command_execution",
            pattern=r"(child_process|exec|execSync|spawn|promisify|vm\.runIn)",
            context="Command execution",
            vuln_type="rce",
            examples=["child_process.exec()", "eval()", "vm.runInContext()"],
        ),
        Sink(
            type="html_output",
            pattern=r"(innerHTML|outerHTML|insertAdjacentHTML|document\.write|jq|\$)\s*\(",
            context="HTML output",
            vuln_type="xss",
            examples=["element.innerHTML", "document.write()"],
        ),
        Sink(
            type="eval",
            pattern=r"(eval|Function|setTimeout|setInterval|new Function)\s*\(",
            context="Dynamic code execution",
            vuln_type="rce",
            examples=["eval()", "new Function()", "setTimeout(code, 0)"],
        ),
        Sink(
            type="network_request",
            pattern=r"(fetch|axios|XMLHttpRequest|request|http)\.(get|post|put|request)",
            context="Network requests",
            vuln_type="ssrf",
            examples=["fetch()", "axios.get()", "request(url)"],
        ),
    ],
    "go": [
        Sink(
            type="sql_execution",
            pattern=r"(db\.Query|db\.QueryRow|db\.Exec|sql\.Stmt)\.(Query|QueryRow|Exec)",
            context="SQL execution",
            vuln_type="sqli",
            examples=["db.Query()", "db.Exec()", "stmt.Query()"],
        ),
        Sink(
            type="command_execution",
            pattern=r"(exec\.Command|os/exec\.Command|exec\.LookPath)\s*\(",
            context="Command execution",
            vuln_type="rce",
            examples=["exec.Command()", "exec.Lookup()"],
        ),
        Sink(
            type="http_request",
            pattern=r"(http\.Get|http\.Post|http\.Client\.Do|NewRequest|DoWithClient)",
            context="HTTP requests",
            vuln_type="ssrf",
            examples=["http.Get()", "client.Do()", "http.NewRequest()"],
        ),
        Sink(
            type="template_execution",
            pattern=r"(template\.Execute|text/template|html/template)\.",
            context="Template execution",
            vuln_type="xss",
            examples=["template.Execute()", "tmpl.Execute()"],
        ),
        Sink(
            type="file_operation",
            pattern=r"(os\.Open|os\.Create|os\.WriteFile|io\.Copy|ioutil\.ReadFile)\s*\(",
            context="File operations",
            vuln_type="path-traversal",
            examples=["os.Open()", "ioutil.ReadFile()"],
        ),
    ],
}


DEFAULT_SANITIZERS = {
    "java": [
        Sanitizer(
            type="sql_escape",
            pattern=r"(PreparedStatement|Statement\.escape|StringEscapeUtils\.escapeSql)",
            context="SQL escaping",
            examples=["PreparedStatement", "escapeSql()"],
        ),
        Sanitizer(
            type="html_encode",
            pattern=r"(Encoder\.forHtml|StringEscapeUtils\.escapeHtml4|HtmlEncoder\.encode)",
            context="HTML encoding",
            examples=["Encode.forHtml()", "StringEscapeUtils.escapeHtml4()"],
        ),
        Sanitizer(
            type="url_encode",
            pattern=r"(URLEncoder\.encode|Uri\.encode)",
            context="URL encoding",
            examples=["URLEncoder.encode()", "Uri.encode()"],
        ),
        Sanitizer(
            type="path_validation",
            pattern=r"(Path\.normalize|File\.getCanonicalPath|Paths\.get\.resolve)",
            context="Path validation",
            examples=["path.normalize()", "file.getCanonicalPath()"],
        ),
        Sanitizer(
            type="regex_validation",
            pattern=r"(Pattern\.matches|RegexValidator|String\.matches)",
            context="Regex validation",
            examples=["Pattern.matches()", "validator.matches()"],
        ),
    ],
    "python": [
        Sanitizer(
            type="sql_escape",
            pattern=r"(psycopg2\.extras\.RealDictCursor|safe|string\.escape|mysql\.connector)",
            context="SQL escaping",
            examples=["cursor.mogrify()", "psycopg2.escape()"],
        ),
        Sanitizer(
            type="html_encode",
            pattern=r"(markup|bleach\.clean|html\.escape|cgi\.escape|jinja2\.escape|Markup\.escape)",
            context="HTML encoding",
            examples=["markup.escape()", "bleach.clean()", "html.escape()"],
        ),
        Sanitizer(
            type="url_encode",
            pattern=r"(urllib\.quote|urllib\.parse\.quote|quote_plus)",
            context="URL encoding",
            examples=["urllib.parse.quote()", "quote_plus()"],
        ),
        Sanitizer(
            type="input_validation",
            pattern=r"(re\.match|re\.fullmatch|validate|check|assert)",
            context="Input validation",
            examples=["re.match()", "validate()", "assert"],
        ),
    ],
    "javascript": [
        Sanitizer(
            type="html_encode",
            pattern=r"(DOMPurify\.sanitize|he\.encode|textContent|createTextNode)",
            context="HTML encoding",
            examples=["DOMPurify.sanitize()", "document.createTextNode()"],
        ),
        Sanitizer(
            type="url_encode",
            pattern=r"(encodeURIComponent|encodeURI|urlencode)",
            context="URL encoding",
            examples=["encodeURIComponent()", "encodeURI()"],
        ),
        Sanitizer(
            type="json_encode",
            pattern=r"(JSON\.stringify|json\.stringify)",
            context="JSON encoding",
            examples=["JSON.stringify()"],
        ),
    ],
    "go": [
        Sanitizer(
            type="sql_escape",
            pattern=r"(sql\.Stmt|PreparedStmt|html\.EscapeString|url\.QueryEscape)",
            context="SQL escaping",
            examples=["html.EscapeString()", "url.QueryEscape()"],
        ),
        Sanitizer(
            type="html_encode",
            pattern=r"(template\.HTML|html\.template\.HTML|template\.HTMLEscape)",
            context="HTML encoding",
            examples=["template.HTML()", "template.HTMLEscapeString()"],
        ),
        Sanitizer(
            type="path_validation",
            pattern=r"(filepath\.Clean|filepath\.FromSlash|path\.Clean)",
            context="Path validation",
            examples=["filepath.Clean()", "path.Clean()"],
        ),
    ],
}


class SourceSinkDetector:
    """Detects sources, sinks, and sanitizers in source code."""

    def __init__(
        self,
        language: str,
        custom_sources: Optional[list[Source]] = None,
        custom_sinks: Optional[list[Sink]] = None,
        custom_sanitizers: Optional[list[Sanitizer]] = None,
    ):
        self._language = language.lower()
        self._sources = custom_sources or DEFAULT_SOURCES.get(self._language, [])
        self._sinks = custom_sinks or DEFAULT_SINKS.get(self._language, [])
        self._sanitizers = custom_sanitizers or DEFAULT_SANITIZERS.get(self._language, [])

        # Pre-compile patterns for performance
        self._compiled_sources = [
            (s, re.compile(s.pattern, re.IGNORECASE)) for s in self._sources
        ]
        self._compiled_sinks = [
            (s, re.compile(s.pattern, re.IGNORECASE)) for s in self._sinks
        ]
        self._compiled_sanitizers = [
            (s, re.compile(s.pattern, re.IGNORECASE)) for s in self._sanitizers
        ]

    def find_sources(self, code: str) -> list[tuple[str, int]]:
        """Find all sources in the given code.

        Returns:
            List of (source_type, line_number) tuples
        """
        findings = []
        lines = code.split("\n")
        for source, compiled in self._compiled_sources:
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    findings.append((source.type, i))
        return findings

    def find_sinks(self, code: str) -> list[tuple[str, str, int]]:
        """Find all sinks in the given code.

        Returns:
            List of (sink_type, vuln_type, line_number) tuples
        """
        findings = []
        lines = code.split("\n")
        for sink, compiled in self._compiled_sinks:
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    findings.append((sink.type, sink.vuln_type, i))
        return findings

    def find_sanitizers(self, code: str) -> list[tuple[str, int]]:
        """Find all sanitizers in the given code.

        Returns:
            List of (sanitizer_type, line_number) tuples
        """
        findings = []
        lines = code.split("\n")
        for sanitizer, compiled in self._compiled_sanitizers:
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    findings.append((sanitizer.type, i))
        return findings

    def analyze_potential_vulns(self, code: str) -> dict:
        """Analyze code for potential vulnerabilities.

        Returns:
            Dict with sources, sinks, sanitizers, and potential_vulns.
            potential_vulns lists sinks that are near a source and not
            protected by a sanitizer on the same or adjacent lines.
        """
        sources = self.find_sources(code)
        sinks = self.find_sinks(code)
        sanitizers = self.find_sanitizers(code)

        sanitizer_lines = {line for _, line in sanitizers}
        source_lines = {line for _, line in sources}

        potential_vulns = []
        for sink_type, vuln_type, sink_line in sinks:
            # Skip sinks that have a sanitizer on the same line
            if sink_line in sanitizer_lines:
                continue

            # Check for an unsanitized source within a 10-line window
            nearby_unsanitized_source = any(
                abs(sink_line - src_line) < 10 and src_line not in sanitizer_lines
                for src_line in source_lines
            )
            if nearby_unsanitized_source:
                potential_vulns.append({
                    "type": vuln_type,
                    "sink_type": sink_type,
                    "line": sink_line,
                    "confidence": "high",
                })

        return {
            "sources": sources,
            "sinks": sinks,
            "sanitizers": sanitizers,
            "potential_vulns": potential_vulns,
        }

    def get_sources(self) -> list[Source]:
        return self._sources

    def get_sinks(self) -> list[Sink]:
        return self._sinks

    def get_sanitizers(self) -> list[Sanitizer]:
        return self._sanitizers


def create_detector(language: str) -> SourceSinkDetector:
    """Create a source-sink detector for the given language."""
    return SourceSinkDetector(language=language)
