"""MCP Server module for Baize.

Provides an HTTP API for AI agents to invoke Baize functionality.

Usage:
    from baize.mcp_server import create_mcp_server

    server = create_mcp_server(host="127.0.0.1", port=8080)
    server.run()  # Starts the server

Endpoints:
    POST /tools/baize_init    - Initialize a project
    POST /tools/baize_build   - Build CodeQL database
    POST /tools/baize_analyze - Run vulnerability analysis
    POST /tools/baize_report - Generate report
    GET  /tools/baize_query_list - List available queries
    GET  /knowledge/search    - Search knowledge base
"""

from baize.mcp_server.server import BaizeMCPServer, create_mcp_server

__all__ = ["BaizeMCPServer", "create_mcp_server"]