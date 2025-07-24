"""FlextLdif Domain Interfaces - Abstract Contracts.

🏗️ CLEAN ARCHITECTURE: Domain Interfaces
Built on flext-core foundation patterns.

Interfaces define contracts for infrastructure implementations.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports

if TYPE_CHECKING:
    from pathlib import Path

    from flext_core import FlextResult

    from flext_ldif.domain.entities import FlextLdifEntry
    from flext_ldif.domain.values import LDIFContent


class FlextLdifParserInterface(ABC):
    """Abstract interface for FlextLdif parsing."""

    @abstractmethod
    def parse_content(self, content: LDIFContent) -> FlextResult[Any]:
        """Parse LDIF content into entries.

        Args:
            content: LDIF content to parse

        Returns:
            FlextResult containing list of FlextLdif entries

        """

    @abstractmethod
    def parse_file(self, file_path: Path) -> FlextResult[Any]:
        """Parse LDIF file into entries.

        Args:
            file_path: Path to LDIF file

        Returns:
            FlextResult containing list of FlextLdif entries

        """


class FlextLdifValidatorInterface(ABC):
    """Abstract interface for FlextLdif validation."""

    @abstractmethod
    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[Any]:
        """Validate single LDIF entry.

        Args:
            entry: FlextLdif entry to validate

        Returns:
            FlextResult indicating validation success

        """

    @abstractmethod
    def validate_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[Any]:
        """Validate multiple LDIF entries.

        Args:
            entries: List of FlextLdif entries to validate

        Returns:
            FlextResult indicating validation success

        """


class FlextLdifWriterInterface(ABC):
    """Abstract interface for FlextLdif writing."""

    @abstractmethod
    def write_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[Any]:
        """Write entries to LDIF format.

        Args:
            entries: List of FlextLdif entries to write

        Returns:
            FlextResult containing LDIF string

        """

    @abstractmethod
    def write_to_file(
        self,
        entries: list[FlextLdifEntry],
        file_path: Path,
    ) -> FlextResult[Any]:
        """Write entries to LDIF file.

        Args:
            entries: List of FlextLdif entries to write
            file_path: Output file path

        Returns:
            FlextResult indicating success

        """


class FlextLdifTransformerInterface(ABC):
    """Abstract interface for FlextLdif transformation."""

    @abstractmethod
    def transform_entries(
        self,
        entries: list[FlextLdifEntry],
        transformation_rules: dict[str, Any],
    ) -> FlextResult[Any]:
        """Transform entries using rules.

        Args:
            entries: List of FlextLdif entries to transform
            transformation_rules: Transformation rules

        Returns:
            FlextResult containing transformed entries

        """


class FlextLdifFilterInterface(ABC):
    """Abstract interface for FlextLdif filtering."""

    @abstractmethod
    def filter_entries(
        self,
        entries: list[FlextLdifEntry],
        criteria: dict[str, Any],
    ) -> FlextResult[Any]:
        """Filter entries by criteria.

        Args:
            entries: List of FlextLdif entries to filter
            criteria: Filter criteria

        Returns:
            FlextResult containing filtered entries

        """

    @abstractmethod
    def filter_by_objectclass(
        self,
        entries: list[FlextLdifEntry],
        object_class: str,
    ) -> FlextResult[Any]:
        """Filter entries by object class.

        Args:
            entries: List of FlextLdif entries to filter
            object_class: Object class to filter by

        Returns:
            FlextResult containing filtered entries

        """


__all__ = [
    "FlextLdifFilterInterface",
    "FlextLdifParserInterface",
    "FlextLdifTransformerInterface",
    "FlextLdifValidatorInterface",
    "FlextLdifWriterInterface",
]
