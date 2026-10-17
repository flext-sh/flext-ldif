"""LDIF string enumerations for conversion and logging flows.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum, unique


class FlextLdifConstantsStrEnums:
    """LDIF string enumerations composed into ``c.Ldif``."""

    @unique
    class SchemaItemKind(StrEnum):
        """Schema item discriminator used in conversion flows."""

        ATTRIBUTE = "attribute"
        OBJECTCLASS = "objectclass"

    @unique
    class NormalizeFallback(StrEnum):
        """Fallback strategy when DN normalization fails."""

        LOWER = "lower"
        UPPER = "upper"
        ORIGINAL = "original"

    @unique
    class LogLevelLower(StrEnum):
        """Lowercase log-level names for logger dispatch comparisons."""

        DEBUG = "debug"
        INFO = "info"
        WARNING = "warning"
        ERROR = "error"
        CRITICAL = "critical"


__all__: list[str] = [
    "FlextLdifConstantsStrEnums",
    "LogLevelLower",
    "NormalizeFallback",
    "SchemaItemKind",
]
