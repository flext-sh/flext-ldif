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
    Uses flext-core SOURCE OF TRUTH for type patterns.
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
        LdifEntryDict = dict[str, str | list[str] | dict[str, str | list[str]]]
        LdifAttributeDict = dict[str, FlextTypes.Core.StringList]
        LdifStatistics = dict[
            str, int | float | str | FlextTypes.Core.StringList | dict[str, int]
        ]
        HealthStatusDict = dict[
            str, int | float | str | FlextTypes.Core.StringList | dict[str, int]
        ]

        # Literal types for compile-time validation
        HealthStatus = Literal["healthy", "degraded", "unhealthy"]
        ProcessingStage = Literal["parsing", "validation", "analytics", "writing"]
        EntryModificationType = Literal["add", "modify", "delete", "modrdn"]

        # RFC 2849 specific types
        LdifVersion = Literal["1"]
        EncodingType = Literal[
            "utf-8", "latin-1", "ascii", "utf-16", "utf-32", "cp1252", "iso-8859-1"
        ]
        LdapServerType = Literal[
            "active_directory",
            "openldap",
            "apache_directory",
            "novell_edirectory",
            "ibm_tivoli",
            "generic",
        ]
        ComplianceLevel = Literal["strict", "moderate", "lenient"]

        # Advanced LDIF types
        Base64String = NewType("Base64String", str)
        LdifUrl = NewType("LdifUrl", str)
        AttributeOption = NewType("AttributeOption", str)
        LanguageTag = NewType("LanguageTag", str)

        # Change record types
        ChangeRecordDict = dict[str, str | list[str] | dict[str, str | list[str]]]
        ModificationOperation = Literal["add", "delete", "replace"]

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
