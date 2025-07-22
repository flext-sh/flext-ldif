"""LDIF Domain Interfaces - Abstract Contracts.

🏗️ CLEAN ARCHITECTURE: Domain Interfaces
Built on flext-core foundation patterns.

Interfaces define contracts for infrastructure implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from flext_core.domain.shared_types import ServiceResult

    from flext_ldif.domain.entities import LDIFEntry
    from flext_ldif.domain.values import LDIFContent


class LDIFParser(ABC):
    """Abstract interface for LDIF parsing."""

    @abstractmethod
    def parse_content(self, content: LDIFContent) -> ServiceResult[Any]:
        """Parse LDIF content into entries.

        Args:
            content: LDIF content to parse

        Returns:
            ServiceResult containing list of LDIF entries

        """

    @abstractmethod
    def parse_file(self, file_path: Path) -> ServiceResult[Any]:
        """Parse LDIF file into entries.

        Args:
            file_path: Path to LDIF file

        Returns:
            ServiceResult containing list of LDIF entries

        """

    @abstractmethod
    def parse_lines(self, lines: list[str]) -> ServiceResult[Any]:
        """Parse LDIF lines into entries.

        Args:
            lines: List of LDIF lines

        Returns:
            ServiceResult containing list of LDIF entries

        """


class LDIFValidator(ABC):
    """Abstract interface for LDIF validation."""

    @abstractmethod
    def validate_entry(self, entry: LDIFEntry) -> ServiceResult[Any]:
        """Validate a single LDIF entry.

        Args:
            entry: LDIF entry to validate

        Returns:
            ServiceResult indicating validation success

        """

    @abstractmethod
    def validate_entries(self, entries: list[LDIFEntry]) -> ServiceResult[Any]:
        """Validate multiple LDIF entries.

        Args:
            entries: List of LDIF entries to validate

        Returns:
            ServiceResult indicating validation success

        """

    @abstractmethod
    def validate_dn(self, dn: str) -> ServiceResult[Any]:
        """Validate distinguished name format.

        Args:
            dn: Distinguished name to validate

        Returns:
            ServiceResult indicating validation success

        """

    @abstractmethod
    def validate_attribute_syntax(
        self,
        attribute_name: str,
        value: str,
    ) -> ServiceResult[Any]:
        """Validate attribute value syntax.

        Args:
            attribute_name: Name of the attribute
            value: Value to validate

        Returns:
            ServiceResult indicating validation success

        """


class LDIFWriter(ABC):
    """Abstract interface for LDIF writing."""

    @abstractmethod
    def write_entries(self, entries: list[LDIFEntry]) -> ServiceResult[Any]:
        """Write entries to LDIF format.

        Args:
            entries: List of LDIF entries to write

        Returns:
            ServiceResult containing LDIF content string

        """

    @abstractmethod
    def write_to_file(
        self,
        entries: list[LDIFEntry],
        file_path: Path,
    ) -> ServiceResult[Any]:
        """Write entries to LDIF file.

        Args:
            entries: List of LDIF entries to write
            file_path: Output file path

        Returns:
            ServiceResult indicating success

        """

    @abstractmethod
    def format_entry(self, entry: LDIFEntry) -> ServiceResult[Any]:
        """Format single entry as LDIF.

        Args:
            entry: LDIF entry to format

        Returns:
            ServiceResult containing formatted LDIF string

        """


class LDIFTransformer(ABC):
    """Abstract interface for LDIF transformation."""

    @abstractmethod
    def transform_entries(
        self,
        entries: list[LDIFEntry],
        transformation_rules: dict[str, Any],
    ) -> ServiceResult[Any]:
        """Transform LDIF entries according to rules.

        Args:
            entries: List of LDIF entries to transform
            transformation_rules: Transformation rules to apply

        Returns:
            ServiceResult containing transformed entries

        """

    @abstractmethod
    def apply_attribute_mapping(
        self,
        entry: LDIFEntry,
        attribute_mapping: dict[str, str],
    ) -> ServiceResult[Any]:
        """Apply attribute name mapping to entry.

        Args:
            entry: LDIF entry to transform
            attribute_mapping: Mapping from old to new attribute names

        Returns:
            ServiceResult containing transformed entry

        """


class LDIFFilter(ABC):
    """Abstract interface for LDIF filtering."""

    @abstractmethod
    def filter_entries(
        self,
        entries: list[LDIFEntry],
        filter_criteria: str,
    ) -> ServiceResult[Any]:
        """Filter entries based on criteria.

        Args:
            entries: List of LDIF entries to filter
            filter_criteria: Filter criteria

        Returns:
            ServiceResult containing filtered entries

        """

    @abstractmethod
    def filter_by_objectclass(
        self,
        entries: list[LDIFEntry],
        object_class: str,
    ) -> ServiceResult[Any]:
        """Filter entries by object class.

        Args:
            entries: List of LDIF entries to filter
            object_class: Object class to filter by

        Returns:
            ServiceResult containing filtered entries

        """

    @abstractmethod
    def filter_by_dn_pattern(
        self,
        entries: list[LDIFEntry],
        dn_pattern: str,
    ) -> ServiceResult[Any]:
        """Filter entries by DN pattern.

        Args:
            entries: List of LDIF entries to filter
            dn_pattern: DN pattern to match

        Returns:
            ServiceResult containing filtered entries

        """
