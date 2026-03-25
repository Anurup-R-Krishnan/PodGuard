"""
Structured logging utilities for the EPSS Framework.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

console = Console()

_logger: Optional[logging.Logger] = None


def get_logger(name: str = "epss_framework", level: str = "INFO") -> logging.Logger:
    """Get or create a structured logger."""
    global _logger

    if _logger is not None:
        return _logger

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not logger.handlers:
        # Rich console handler for pretty terminal output
        rich_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        rich_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(rich_handler)

    _logger = logger
    return logger


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Initialize logging for the framework."""
    return get_logger(level=level)
