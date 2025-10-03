"""FLEXT LDIF Protocols.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_core import FlextProtocols, FlextResult, FlextTypes

if TYPE_CHECKING:
    from flext_ldif.models import FlextLdifModels


class FlextLdifProtocols:
    """Unified LDIF protocols following FLEXT domain extension pattern.

    This class consolidates LDIF processing protocols while explicitly
    re-exporting foundation protocols for backward compatibility and clean access.

    Architecture:
        - RE-EXPORTS: Foundation protocols from flext-core for unified access
        - EXTENDS: LDIF-specific protocols in Ldif namespace
        - MAINTAINS: Zero breaking changes through explicit re-export pattern

    Usage:
        from flext_ldif.protocols import FlextLdifProtocols

        # Foundation access (re-exported)
        FlextLdifProtocols.Foundation.ResultProtocol

        # LDIF-specific access
        FlextLdifProtocols.Ldif.EntryProtocol
    """

    # =========================================================================
    # FOUNDATION PROTOCOL RE-EXPORTS (from flext-core)
    # =========================================================================
    # Explicitly re-export foundation protocols for unified access.
    # This maintains backward compatibility while providing clean namespace access.

    Foundation = FlextProtocols.Foundation
    Domain = FlextProtocols.Domain
    Application = FlextProtocols.Application
    Infrastructure = FlextProtocols.Infrastructure
    Extensions = FlextProtocols.Extensions
    Commands = FlextProtocols.Commands

    # =========================================================================
    # LDIF-SPECIFIC PROTOCOLS
    # =========================================================================
    # Domain-specific protocols for LDIF processing and directory operations.

    class Ldif:
        """LDIF domain-specific protocols.

        Provides protocols for LDIF entry processing, parsing, validation,
        writing, analytics, and extensibility patterns.
        """

        @runtime_checkable
        class EntryProtocol(Protocol):
            """Protocol for LDIF entry objects."""

            @property
            def dn(self: object) -> str:
                """Get the distinguished name of the entry."""
                ...

            @property
            def attributes(self: object) -> dict[str, FlextTypes.StringList]:
                """Get the attributes of the entry."""
                ...

            def get_attribute(self, name: str) -> FlextTypes.StringList | None:
                """Get attribute values by name."""
                ...

            def has_attribute(self, name: str) -> bool:
                """Check if entry has specified attribute."""
                ...

            def has_object_class(self, object_class: str) -> bool:
                """Check if entry has specified object class."""
                ...

            def is_person_entry(self: object) -> bool:
                """Check if entry is a person entry."""
                ...

            def validate_business_rules(self: object) -> FlextResult[bool]:
                """Validate entry against business rules."""
                ...

        @runtime_checkable
        class ProcessorProtocol(Protocol):
            """Protocol for LDIF processors with file and content parsing."""

            def parse_ldif_file(
                self, path: Path, encoding: str = "utf-8"
            ) -> FlextResult[list[FlextLdifModels.Entry]]:
                """Parse LDIF file into entries."""
                ...

            def parse_content(
                self, content: str
            ) -> FlextResult[list[FlextLdifModels.Entry]]:
                """Parse LDIF content string into entries."""
                ...

            def parse(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
                """Parse LDIF content string into entries (alias for parse_content)."""
                ...

            def validate_entries(
                self, entries: list[FlextLdifModels.Entry]
            ) -> FlextResult[list[FlextLdifModels.Entry]]:
                """Validate LDIF entries and return validated entries."""
                ...

            def write(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
                """Write entries to LDIF string."""
                ...

            def transform_entries(
                self,
                entries: list[FlextLdifModels.Entry],
                transformer: Callable[[FlextLdifModels.Entry], FlextLdifModels.Entry],
            ) -> FlextResult[list[FlextLdifModels.Entry]]:
                """Transform entries using transformer function."""
                ...

            def analyze_entries(
                self, entries: list[FlextLdifModels.Entry]
            ) -> FlextResult[FlextTypes.Dict]:
                """Analyze entries and provide statistics."""
                ...

        @runtime_checkable
        class ValidatorProtocol(Protocol):
            """Protocol for LDIF validators with strict mode support."""

            def validate_entry(self, entry: FlextLdifModels.Entry) -> FlextResult[bool]:
                """Validate a single LDIF entry."""
                ...

            def validate_entries(
                self, entries: list[FlextLdifModels.Entry], *, strict: bool = False
            ) -> FlextResult[FlextLdifModels.LdifValidationResult]:
                """Validate multiple LDIF entries with optional strict mode."""
                ...

            def get_validation_errors(self: object) -> FlextTypes.StringList:
                """Get list of validation errors."""
                ...

        @runtime_checkable
        class WriterProtocol(Protocol):
            """Protocol for LDIF writers."""

            def write_entries_to_string(
                self, entries: list[FlextLdifModels.Entry]
            ) -> FlextResult[str]:
                """Write entries to LDIF format string."""
                ...

            def write_entries_to_file(
                self, entries: list[FlextLdifModels.Entry], file_path: str
            ) -> FlextResult[bool]:
                """Write entries to LDIF file."""
                ...

        @runtime_checkable
        class AnalyticsProtocol(Protocol):
            """Protocol for LDIF analytics."""

            def analyze_entries(
                self, entries: list[FlextLdifModels.Entry]
            ) -> FlextResult[FlextTypes.Dict]:
                """Analyze LDIF entries and generate analytics."""
                ...

            def get_statistics(self: object) -> dict[str, int | float]:
                """Get analytics statistics."""
                ...

            def detect_patterns(
                self, entries: list[FlextLdifModels.Entry]
            ) -> FlextTypes.Dict:
                """Detect patterns in LDIF entries."""
                ...

        # =====================================================================
        # EXTENSIBILITY PROTOCOLS (SOLID PATTERNS)
        # =====================================================================

        @runtime_checkable
        class ParserStrategyProtocol(Protocol):
            """Protocol for parser encoding detection strategies."""

            def detect(self, content: bytes) -> FlextResult[str]:
                """Detect encoding from content."""
                ...

            def supports(self, encoding: str) -> bool:
                """Check if strategy supports given encoding."""
                ...

        @runtime_checkable
        class SchemaBuilderProtocol(Protocol):
            """Protocol for schema builders."""

            def add_object_class(self, object_class: object) -> object:
                """Add object class to schema."""
                ...

            def add_attribute(self, attr: object) -> object:
                """Add attribute to schema."""
                ...

            def build(self: object) -> FlextResult[object]:
                """Build final schema."""
                ...

        @runtime_checkable
        class AclRuleProtocol(Protocol):
            """Protocol for ACL rules (Composite pattern)."""

            def evaluate(self, context: FlextTypes.Dict) -> FlextResult[bool]:
                """Evaluate ACL rule against context."""
                ...

            def add_rule(self, rule: object) -> None:
                """Add sub-rule (for composite rules)."""
                ...

        @runtime_checkable
        class ServerAdapterProtocol(Protocol):
            """Protocol for server-specific adapters."""

            def adapt(self, entry: object) -> FlextResult[object]:
                """Adapt entry for specific server type."""
                ...

            def supports_server(self, server_type: str) -> bool:
                """Check if adapter supports server type."""
                ...

        @runtime_checkable
        class ValidatorPluginProtocol(Protocol):
            """Protocol for custom validator plugins."""

            def validate(self, data: object) -> FlextResult[bool]:
                """Validate data against custom rules."""
                ...

            def get_error_messages(self: object) -> FlextTypes.StringList:
                """Get validation error messages."""
                ...

        @runtime_checkable
        class MigrationPipelineProtocol(Protocol):
            """Protocol for LDIF migration pipeline."""

            def migrate_entries(
                self,
                entries: list[FlextLdifModels.Entry],
                source_format: str,
                target_format: str,
                quirks: FlextTypes.List,
            ) -> FlextResult[list[FlextLdifModels.Entry]]:
                """Migrate LDIF entries between formats."""
                ...

        @runtime_checkable
        class QuirkRegistryProtocol(Protocol):
            """Protocol for quirk registry."""

        def register_schema_quirk(self, quirk: object) -> FlextResult[None]: ...

        def register_acl_quirk(self, quirk: object) -> FlextResult[None]: ...

        def register_entry_quirk(self, quirk: object) -> FlextResult[None]: ...

    # =========================================================================
    # BACKWARD COMPATIBILITY ALIASES
    # =========================================================================
    # Maintain existing attribute names for zero breaking changes.

    LdifEntryProtocol = Ldif.EntryProtocol
    LdifProcessorProtocol = Ldif.ProcessorProtocol
    LdifValidatorProtocol = Ldif.ValidatorProtocol
    LdifWriterProtocol = Ldif.WriterProtocol
    LdifAnalyticsProtocol = Ldif.AnalyticsProtocol
    ParserStrategyProtocol = Ldif.ParserStrategyProtocol
    SchemaBuilderProtocol = Ldif.SchemaBuilderProtocol
    AclRuleProtocol = Ldif.AclRuleProtocol
    ServerAdapterProtocol = Ldif.ServerAdapterProtocol
    ValidatorPluginProtocol = Ldif.ValidatorPluginProtocol
    MigrationPipelineProtocol = Ldif.MigrationPipelineProtocol
    QuirkRegistryProtocol = Ldif.QuirkRegistryProtocol


__all__ = ["FlextLdifProtocols"]
