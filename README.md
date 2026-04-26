# Baize (白泽)

**AI Agent × CodeQL Intelligent Code Audit Orchestration Engine**

Baize acts as an orchestration layer between AI agents and CodeQL static analysis, providing:

- Intelligent CodeQL database build scheduling (timeout handling, resource control)
- Automatic CodeQL query generation/optimization (RAG + templates)
- SARIF result processing: denoising, priority ranking, Source-Sink dataflow path reconstruction
- Actionable fix suggestions via LLM
- Skill/MCP interface for external agent integration

## Quick Start

```bash
# Install dependencies
uv sync  # or: pip install -e .[dev]

# Initialize project
baize init --project ./my-java-project

# Build CodeQL database
baize build

# Run analysis
baize analyze --vulns sqli,xss,rce

# Generate report
baize report --format markdown

# Generate fix suggestions
baize fix
```

## Requirements

- Python 3.10–3.12 (recommended: 3.11)
- CodeQL CLI ≥ 2.15.0
- uv or pip

## Documentation

See `白泽_Baize_开发文档_v2.md` for full design documentation.
