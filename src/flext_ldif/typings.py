"""FLEXT LDIF Types.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Literal, NewType, TypeVar

from flext_core import FlextResult, FlextTypes


class FlextLdifTypes(FlextTypes):
    """LDIF-specific type definitions extending flext-core FlextTypes.

    Contains ONLY type definitions, no implementations.
    """

    # =============================================================================
    # CORE LDIF TYPES
    # =============================================================================

    class Core(FlextTypes.Core):
        """Core LDIF type definitions."""

        # Domain-specific typed strings
        DistinguishedNameString = NewType("DistinguishedNameString", str)
        AttributeNameString = NewType("AttributeNameString", str)
        AttributeValueString = NewType("AttributeValueString", str)
        LdifContentString = NewType("LdifContentString", str)

        # File handling types
        LdifFilePath = NewType("LdifFilePath", str)
        LdifFileContent = NewType("LdifFileContent", str)

        # Data structure types
        LdifEntryDict = dict[str, object]
        LdifAttributeDict = dict[str, FlextTypes.Core.StringList]
        LdifStatistics = dict[str, int | float | FlextTypes.Core.StringList]

        # Literal types for compile-time validation
        HealthStatus = Literal["healthy", "degraded", "unhealthy"]
        ProcessingStage = Literal["parsing", "validation", "analytics", "writing"]
        EntryModificationType = Literal["add", "modify", "delete", "modrdn"]

    # =============================================================================
    # GENERIC TYPE VARIABLES
    # =============================================================================

    class Processing:
        """Generic type variables for LDIF processing."""

        # Generic type variables
        T_Entry = TypeVar("T_Entry")
        T_Result = TypeVar("T_Result")
        T_Config = TypeVar("T_Config")
        T_Statistics = TypeVar("T_Statistics")

        # Function type aliases
        EntryProcessor = Callable[[T_Entry], FlextResult[T_Result]]
        EntryFilter = Callable[[T_Entry], bool]
        EntryTransformer = Callable[[T_Entry], FlextResult[T_Entry]]
        ValidationRule = Callable[[T_Entry], FlextResult[bool]]

    # =============================================================================
    # I/O OPERATION TYPES
    # =============================================================================

    class IO:
        """I/O operation type definitions."""

        # File operation types
        FileReader = Callable[["FlextLdifTypes.Core.LdifFilePath"], FlextResult[str]]
        FileWriter = Callable[
            ["FlextLdifTypes.Core.LdifFilePath", str], FlextResult[bool]
        ]
        StreamReader = Callable[["FlextLdifTypes.Core.LdifFilePath"], Iterator[str]]
        StreamWriter = Callable[
            ["FlextLdifTypes.Core.LdifFilePath"], Callable[[str], FlextResult[bool]]
        ]

        # Batch processing types
        BatchProcessor = Callable[
            [list["FlextLdifTypes.Processing.T_Entry"]],
            FlextResult[list["FlextLdifTypes.Processing.T_Entry"]],
        ]


__all__ = ["FlextLdifTypes"]
