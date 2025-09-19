"""FLEXT LDIF Protocols - Unified protocol definitions for LDIF operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import IO, Protocol, runtime_checkable

from flext_core import FlextProtocols, FlextResult


class FlextLdifProtocols(FlextProtocols):
    """LDIF-specific protocols extending flext-core FlextProtocols.

    Single unified class containing all LDIF protocol definitions
    following SOLID principles and FLEXT ecosystem patterns.

    Uses FlextProtocols inheritance to reduce code duplication and ensure
    consistent protocol patterns across the FLEXT ecosystem.
    """

    # =============================================================================
    # LDIF DOMAIN PROTOCOLS (extending FlextProtocols patterns)
    # =============================================================================

    @runtime_checkable
    class LdifParserProtocol(Protocol):
        """Protocol for LDIF parser implementations."""

        def parse_content(self, content: str) -> FlextResult[list[object]]:
            """Parse LDIF content string into entries."""
            ...

        def parse_file(self, file_path: str) -> FlextResult[list[object]]:
            """Parse LDIF file into entries."""
            ...

        def parse_stream(self, stream: IO[str]) -> FlextResult[list[object]]:
            """Parse LDIF stream into entries."""
            ...

    @runtime_checkable
    class LdifValidatorProtocol(Protocol):
        """Protocol for LDIF validator implementations."""

        def validate_entry(self, entry: object) -> FlextResult[None]:
            """Validate single LDIF entry."""
            ...

        def validate_entries(self, entries: list[object]) -> FlextResult[None]:
            """Validate multiple LDIF entries."""
            ...

        def validate_syntax(self, content: str) -> FlextResult[None]:
            """Validate LDIF syntax."""
            ...

    @runtime_checkable
    class LdifWriterProtocol(Protocol):
        """Protocol for LDIF writer implementations."""

        def write_entries_to_string(self, entries: list[object]) -> FlextResult[str]:
            """Write entries to LDIF string."""
            ...

        def write_entries_to_file(
            self, entries: list[object], file_path: str,
        ) -> FlextResult[None]:
            """Write entries to LDIF file."""
            ...

        def write_entries_to_stream(
            self, entries: list[object], stream: IO[str],
        ) -> FlextResult[None]:
            """Write entries to LDIF stream."""
            ...

    @runtime_checkable
    class LdifRepositoryProtocol(Protocol):
        """Protocol for LDIF repository implementations."""

        def store_entries(self, entries: list[object]) -> FlextResult[None]:
            """Store LDIF entries."""
            ...

        def retrieve_entries(
            self, filter_criteria: dict[str, object],
        ) -> FlextResult[list[object]]:
            """Retrieve LDIF entries by criteria."""
            ...

        def count_entries(
            self, filter_criteria: dict[str, object] | None = None,
        ) -> FlextResult[int]:
            """Count LDIF entries."""
            ...

    @runtime_checkable
    class LdifAnalyticsProtocol(Protocol):
        """Protocol for LDIF analytics implementations."""

        def calculate_statistics(
            self, entries: list[object],
        ) -> FlextResult[dict[str, object]]:
            """Calculate LDIF statistics."""
            ...

        def generate_report(self, statistics: dict[str, object]) -> FlextResult[str]:
            """Generate analytics report."""
            ...

        def get_entry_distribution(
            self, entries: list[object],
        ) -> FlextResult[dict[str, int]]:
            """Get entry type distribution."""
            ...

    @runtime_checkable
    class LdifTransformerProtocol(Protocol):
        """Protocol for LDIF transformer implementations."""

        def transform_entries(self, entries: list[object]) -> FlextResult[list[object]]:
            """Transform LDIF entries."""
            ...

        def apply_transformations(
            self, transformations: list[object],
        ) -> FlextResult[None]:
            """Apply transformation rules."""
            ...

        def normalize_entries(self, entries: list[object]) -> FlextResult[list[object]]:
            """Normalize LDIF entries."""
            ...

    @runtime_checkable
    class LdifFormatHandlerProtocol(Protocol):
        """Protocol for LDIF format handlers."""

        def can_handle(self, source: str) -> bool:
            """Check if handler can process source."""
            ...

        def read_content(self, source: str) -> FlextResult[str]:
            """Read content from source."""
            ...

        def validate_source(self, source: str) -> FlextResult[None]:
            """Validate source format."""
            ...

    @runtime_checkable
    class LdifDispatcherProtocol(Protocol):
        """Protocol for LDIF service dispatchers."""

        def dispatch_operation(
            self, operation: str, **kwargs: object,
        ) -> FlextResult[object]:
            """Dispatch LDIF operation."""
            ...

        def supports_operation(self, operation: str) -> bool:
            """Check if operation is supported."""
            ...

    @runtime_checkable
    class LdifServiceProtocol(Protocol):
        """Base protocol for all LDIF services."""

        def initialize(self) -> FlextResult[None]:
            """Initialize the service."""
            ...

        def is_healthy(self) -> bool:
            """Check service health."""
            ...

        def cleanup(self) -> FlextResult[None]:
            """Cleanup service resources."""
            ...

    @runtime_checkable
    class ServiceContainerProtocol(Protocol):
        """Protocol describing the services required by dispatcher handlers.

        Moved from dispatcher.py to maintain unified protocol definitions.
        """

        parser: FlextLdifProtocols.LdifParserProtocol
        validator: FlextLdifProtocols.LdifValidatorProtocol
        writer: FlextLdifProtocols.LdifWriterProtocol

    # =============================================================================
    # LDIF PROTOCOL VALIDATORS (using flext-core patterns)
    # =============================================================================

    @classmethod
    def validate_ldif_parser(cls, obj: object) -> bool:
        """Validate object implements LdifParserProtocol."""
        return isinstance(obj, cls.LdifParserProtocol)

    @classmethod
    def validate_ldif_validator(cls, obj: object) -> bool:
        """Validate object implements LdifValidatorProtocol."""
        return isinstance(obj, cls.LdifValidatorProtocol)

    @classmethod
    def validate_ldif_writer(cls, obj: object) -> bool:
        """Validate object implements LdifWriterProtocol."""
        return isinstance(obj, cls.LdifWriterProtocol)

    @classmethod
    def validate_ldif_repository(cls, obj: object) -> bool:
        """Validate object implements LdifRepositoryProtocol."""
        return isinstance(obj, cls.LdifRepositoryProtocol)

    @classmethod
    def validate_ldif_analytics(cls, obj: object) -> bool:
        """Validate object implements LdifAnalyticsProtocol."""
        return isinstance(obj, cls.LdifAnalyticsProtocol)

    @classmethod
    def validate_ldif_transformer(cls, obj: object) -> bool:
        """Validate object implements LdifTransformerProtocol."""
        return isinstance(obj, cls.LdifTransformerProtocol)

    @classmethod
    def validate_ldif_service(cls, obj: object) -> bool:
        """Validate object implements LdifServiceProtocol."""
        return isinstance(obj, cls.LdifServiceProtocol)


__all__ = ["FlextLdifProtocols"]
