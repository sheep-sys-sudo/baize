"""ASCII art banner for Baize CLI."""

from rich.console import Console
from rich.style import Style
from rich.text import Text

BANNER = r"""
__________        .__               
\______   \_____  |__|_______ ____  
 |    |  _/\__  \ |  \___   // __ \ 
 |    |   \ / __ \|  |/    /\  ___/ 
 |______  /(____  /__/_____ \\___  >
        \/      \/         \/    \/ 
"""

SUBTITLE = "  AI Agent x CodeQL 智能代码审计编排引擎  "
VERSION_LINE = "  v0.1.0"


def print_banner() -> None:
    """Print the Baize ASCII art banner to stdout."""
    console = Console()

    colors = ["cyan", "blue", "magenta", "green", "yellow", "red"]

    lines = BANNER.strip().split("\n")
    for i, line in enumerate(lines):
        color = colors[i % len(colors)]
        console.print(Text(line, style=Style(color=color, bold=True)))

    console.print(
        Text(SUBTITLE, style=Style(color="white", dim=True)),
        justify="center",
    )
    console.print(
        Text(VERSION_LINE, style=Style(dim=True)),
        justify="center",
    )
    console.print()
