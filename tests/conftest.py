"""Pytest configuration and fixtures."""

from __future__ import annotations

import pytest
from pathlib import Path


@pytest.fixture
def project_path(tmp_path) -> Path:
    """Create a temporary project path for testing."""
    project = tmp_path / "test-project"
    project.mkdir()

    (project / "src").mkdir()
    (project / "src" / "Main.java").write_text("""
public class Main {
    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
""")

    (project / "pom.xml").write_text("""
<?xml version="1.0"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>test</groupId>
    <artifactId>test</artifactId>
    <version>1.0</version>
</project>
""")

    return project


@pytest.fixture
def sarif_sample() -> dict:
    """Sample SARIF data for testing."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "version": "2.15.0"
                    }
                },
                "results": [
                    {
                        "ruleId": "java/sql-injection",
                        "level": "error",
                        "message": {
                            "text": "Potential SQL injection"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "src/main/java/Example.java"
                                    },
                                    "region": {
                                        "startLine": 42,
                                        "startColumn": 12,
                                        "snippet": {
                                            "text": "stmt.executeQuery(query)"
                                        }
                                    }
                                }
                            }
                        ]
                    },
                    {
                        "ruleId": "java/xss",
                        "level": "warning",
                        "message": {
                            "text": "Potential XSS"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "src/Controller.java"
                                    },
                                    "region": {
                                        "startLine": 15,
                                        "startColumn": 5,
                                        "snippet": {
                                            "text": "response.getWriter().write(input)"
                                        }
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }


@pytest.fixture
def config_dict() -> dict:
    """Sample configuration dictionary."""
    return {
        "version": "2.0",
        "project": {
            "name": "test-project",
            "path": ".",
            "languages": ["java"],
        },
        "codeql": {
            "cli_path": "",
            "database": {
                "name": "test-db",
                "timeout": 1800,
            },
        },
        "vulnerabilities": {
            "enabled": ["sqli", "xss"],
            "severity_filter": ["high", "critical"],
        },
    }