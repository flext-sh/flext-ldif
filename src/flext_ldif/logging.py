"""FLEXT-LDIF Logging Utilities - Redirects to flext-core.

This module provides compatibility wrappers that redirect to flext-core
logging patterns, eliminating duplication while maintaining API compatibility.
"""

from __future__ import annotations

import logging
from enum import Enum


class LogLevel(Enum):
    """Log level enumeration."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


def configure_ldif_logging(level: LogLevel = LogLevel.INFO) -> None:
    """Configure LDIF logging - delegated to flext-core."""
    # flext-core handles logging configuration globally


def get_ldif_logger(name: str = __name__) -> object:
    """Get LDIF logger - delegates to flext-core."""
    return logging.getLogger(name)
