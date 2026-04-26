"""Logger configuration using loguru."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from loguru import logger

from baize import __version__


def init_logger(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    format_string: Optional[str] = None,
) -> None:
    """Initialize loguru logger with Baize defaults.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional file path to write logs to
        format_string: Custom log format string
    """
    logger.remove()

    default_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
        "<level>{message}</level>"
    )

    logger.add(
        sys.stderr,
        level=level,
        format=format_string or default_format,
        colorize=True,
    )

    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        logger.add(
            log_file,
            level=level,
            format=format_string or default_format,
            rotation="10 MB",
            retention="7 days",
            compression="gz",
        )

    logger.info(f"Baize v{__version__} initialized")


def get_logger(name: str) -> logger:
    """Get a logger instance with the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    return logger.bind(name=name)