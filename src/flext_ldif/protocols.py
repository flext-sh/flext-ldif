"""LDIF protocol definitions for flext-ldif domain.

Protocol interfaces for LDIF processing quirks and operations.
All protocols organized per FLEXT standardization with maximum 2 levels of nesting.

Defines strict structural typing contracts for:
- Schema quirks (attribute and objectClass processing)
- ACL quirks (access control processing)
- Entry quirks (LDAP entry processing)
- Conversion operations (server-to-server transformations)
- Registry operations (quirk discovery and management)

ARCHITECTURE NOTE:
Protocols are defined at module level or 1 level deep to ensure mypy recognizes
them as valid types. Deeper nesting (3+ levels) causes mypy [valid-type] errors.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, Self, runtime_checkable

from flext_core import FlextProtocols, FlextResult

from flext_ldif.typings import t

# =========================================================================
# NAMESPACE CLASS
# =========================================================================


class FlextLdifProtocols(FlextProtocols):
    """Unified LDIF protocol definitions extending FlextProtocols.

    Protocols are defined at module level and referenced here for
    organized namespace access following FLEXT patterns.

    Usage:
        from flext_ldif.protocols import FlextLdifProtocols

        # Access via namespace
        entry: "FlextLdifProtocols.Ldif.EntryProtocol"  # p.Ldif.Entry.EntryProtocol
        acl: "FlextLdifProtocols.Ldif.AclProtocol"      # AclProtocol
    """

    class Ldif:
        """LDIF-specific protocol namespace."""

        # =========================================================================
        # MODULE-LEVEL PROTOCOL DEFINITIONS
        # =========================================================================
        # Define protocols at module level for mypy compatibility.
        # Then reference them in the FlextLdifProtocols class for namespace access.

        @runtime_checkable
        class EntryProtocol(Protocol):
            """Protocol for LDIF Entry models.

            LDIF entries that all Entry implementations must satisfy.
            """

            @property
            def dn(self) -> str | object | None:
                """Distinguished Name (str, DN model, or None)."""
                ...

            @property
            def attributes(self) -> Mapping[str, Sequence[str]] | object | None:
                """Entry attributes (Mapping, Attributes model, or None)."""
                ...

            @property
            def metadata(self) -> t.Ldif.MetadataType | object | None:
                """Optional metadata for processing context."""
                ...

            def get_objectclass_names(self) -> Sequence[str]:
                """Get list of objectClass values from entry."""
                ...

            def model_copy(
                self,
                *,
                deep: bool = False,
                update: t.Ldif.MetadataType | None = None,
            ) -> Self:
                """Create a copy of the entry with optional updates."""
                ...

        @runtime_checkable
        class EntryWithDnProtocol(Protocol):
            """Protocol for objects that have a DN attribute."""

            @property
            def dn(self) -> str | object | None:
                """DN - str, DN model, or None."""
                ...

        @runtime_checkable
        class AttributeValueProtocol(Protocol):
            """Protocol for objects that have attribute values."""

            values: list[str] | str

        @runtime_checkable
        class AclProtocol(Protocol):
            """Protocol for LDIF ACL models."""

            name: str
            target: Mapping[str, str]
            subject: Mapping[str, str]
            permissions: Mapping[str, bool]
            metadata: t.Ldif.MetadataType | None

        @runtime_checkable
        class SchemaAttributeProtocol(Protocol):
            """Protocol for LDIF SchemaAttribute models."""

            name: str
            oid: str
            syntax: str | None
            single_valued: bool
            description: str | None

        @runtime_checkable
        class SchemaObjectClassProtocol(Protocol):
            """Protocol for LDIF SchemaObjectClass models."""

            name: str
            oid: str
            type: str
            must_attributes: Sequence[str]
            may_attributes: Sequence[str]
            description: str | None

        @runtime_checkable
        class WriteFormatOptionsProtocol(Protocol):
            """Protocol for write format options."""

            line_width: int
            respect_attribute_order: bool
            sort_attributes: bool
            write_hidden_attributes_as_comments: bool
            write_metadata_as_comments: bool
            include_version_header: bool
            include_timestamps: bool
            base64_encode_binary: bool
            fold_long_lines: bool
            restore_original_format: bool
            write_empty_values: bool
            normalize_attribute_names: bool
            include_dn_comments: bool
            write_removed_attributes_as_comments: bool
            write_migration_header: bool
            migration_header_template: str | None
            write_rejection_reasons: bool
            include_removal_statistics: bool
            ldif_changetype: str | None
            ldif_modify_operation: str

        @runtime_checkable
        class AclWriteMetadataProtocol(Protocol):
            """Protocol for ACL write metadata."""

            source_subject_type: str | None

        # =========================================================================
        # SERVICE PROTOCOLS
        # =========================================================================

        @runtime_checkable
        class HasParseMethodProtocol(Protocol):
            """Protocol for objects with parse method."""

            def parse(
                self,
                ldif_input: str | Path,
                server_type: str | None = None,
            ) -> FlextResult[Sequence[FlextLdifProtocols.Ldif.EntryProtocol]]:
                """Parse LDIF content."""
                ...

        @runtime_checkable
        class HasWriteMethodProtocol(Protocol):
            """Protocol for objects with write method."""

            def write(
                self,
                entries: Sequence[FlextLdifProtocols.Ldif.EntryProtocol]
                | FlextLdifProtocols.Ldif.EntryProtocol,
            ) -> FlextResult[str]:
                """Write entries to LDIF."""
                ...

        @runtime_checkable
        class HasEntryWriteMethodProtocol(Protocol):
            """Protocol for entry quirk instances with write method."""

            def write(
                self,
                entries: Sequence[FlextLdifProtocols.Ldif.EntryProtocol],
            ) -> FlextResult[str]:
                """Write entries to LDIF."""
                ...

        @runtime_checkable
        class HasEntriesProtocol(Protocol):
            """Protocol for objects that have an entries attribute."""

            @property
            def entries(self) -> Sequence[FlextLdifProtocols.Ldif.EntryProtocol]:
                """Get list of entries."""
                ...

        @runtime_checkable
        class HasContentProtocol(Protocol):
            """Protocol for objects that have a content attribute."""

            content: str | None

        @runtime_checkable
        class UnifiedParseResultProtocol(Protocol):
            """Unified protocol for all parse result types."""

            @property
            def entries(
                self,
            ) -> Sequence[
                FlextLdifProtocols.Ldif.EntryProtocol
                | FlextLdifProtocols.Ldif.SchemaAttributeProtocol
                | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
                | FlextLdifProtocols.Ldif.AclProtocol
            ]:
                """Get all entries."""
                ...

        @runtime_checkable
        class UnifiedWriteResultProtocol(Protocol):
            """Unified protocol for all write result types."""

            content: str | None

        @runtime_checkable
        class FilterEventProtocol(Protocol):
            """Protocol for filter event objects."""

            unique_id: str
            event_type: str
            aggregate_id: str
            filter_operation: str
            entries_before: int
            entries_after: int
            filter_criteria: Sequence[
                Mapping[str, str | int | bool | Sequence[str] | None]
            ]
            filter_duration_ms: float

        @runtime_checkable
        class EntryResultProtocol(Protocol):
            """Protocol for EntryResult model."""

            @property
            def entries(self) -> Sequence[FlextLdifProtocols.Ldif.EntryProtocol]:
                """Get all entries."""
                ...

            @property
            def content(self) -> Sequence[FlextLdifProtocols.Ldif.EntryProtocol]:
                """Alias for entries property."""
                ...

            def __len__(self) -> int:
                """Return the number of entries."""
                ...

        @runtime_checkable
        class FilterServiceProtocol(Protocol):
            """Protocol for filtering service implementations."""

            def execute(
                self,
            ) -> FlextResult[
                FlextLdifProtocols.Ldif.UnifiedParseResultProtocol
                | FlextLdifProtocols.Ldif.HasEntriesProtocol
                | Sequence[FlextLdifProtocols.Ldif.EntryProtocol]
                | str
            ]:
                """Execute filtering."""
                ...

            @classmethod
            def filter(
                cls,
                entries: Sequence[FlextLdifProtocols.Ldif.EntryProtocol],
                *,
                criteria: str = "dn",
                pattern: str | None = None,
                objectclass: str | None = None,
                required_attributes: Sequence[str] | None = None,
                attributes: Sequence[str] | None = None,
                base_dn: str | None = None,
                mode: str = "include",
                match_all: bool = False,
                mark_excluded: bool = False,
            ) -> FlextResult[
                FlextLdifProtocols.Ldif.UnifiedParseResultProtocol
                | FlextLdifProtocols.Ldif.HasEntriesProtocol
                | Sequence[FlextLdifProtocols.Ldif.EntryProtocol]
                | str
            ]:
                """Quick filter."""
                ...

            def get_last_event(
                self,
            ) -> FlextLdifProtocols.Ldif.FilterEventProtocol | None:
                """Get last emitted FilterEvent."""
                ...

        @runtime_checkable
        class FlexibleCategoriesProtocol(Protocol):
            """Protocol for flexible entry categorization."""

            def __getitem__(
                self, key: str
            ) -> Sequence[FlextLdifProtocols.Ldif.EntryProtocol]:
                """Get entries for a category by key."""
                ...

            def get(
                self,
                key: str,
                default: Sequence[FlextLdifProtocols.Ldif.EntryProtocol] | None = None,
            ) -> Sequence[FlextLdifProtocols.Ldif.EntryProtocol] | None:
                """Get entries for a category with fallback."""
                ...

            def keys(self) -> Sequence[str]:
                """Get all category keys."""
                ...

            def values(
                self,
            ) -> Sequence[Sequence[FlextLdifProtocols.Ldif.EntryProtocol]]:
                """Get all category entry lists."""
                ...

            def items(
                self,
            ) -> Sequence[tuple[str, Sequence[FlextLdifProtocols.Ldif.EntryProtocol]]]:
                """Get all category key-value pairs."""
                ...

        @runtime_checkable
        class CategoryRulesProtocol(Protocol):
            """Protocol for category rules configuration."""

            @property
            def user_dn_patterns(self) -> list[str]:
                """DN patterns to match user entries."""
                ...

            @property
            def group_dn_patterns(self) -> list[str]:
                """DN patterns to match group entries."""
                ...

            @property
            def hierarchy_dn_patterns(self) -> list[str]:
                """DN patterns to match hierarchy entries."""
                ...

            @property
            def schema_dn_patterns(self) -> list[str]:
                """DN patterns to match schema entries."""
                ...

            @property
            def user_objectclasses(self) -> list[str]:
                """ObjectClass names that identify user entries."""
                ...

            @property
            def group_objectclasses(self) -> list[str]:
                """ObjectClass names that identify group entries."""
                ...

            @property
            def hierarchy_objectclasses(self) -> list[str]:
                """ObjectClass names that identify hierarchy entries."""
                ...

            @property
            def acl_attributes(self) -> list[str]:
                """Attribute names that identify ACL entries."""
                ...

        @runtime_checkable
        class CategorizationServiceProtocol(Protocol):
            """Protocol for entry categorization service."""

            def execute(
                self,
            ) -> FlextResult[FlextLdifProtocols.Ldif.FlexibleCategoriesProtocol]:
                """Execute categorization."""
                ...

            def validate_dns(
                self,
                entries: Sequence[FlextLdifProtocols.Ldif.EntryProtocol],
            ) -> FlextResult[Sequence[FlextLdifProtocols.Ldif.EntryProtocol]]:
                """Validate entry DNs."""
                ...

            def categorize_entries(
                self,
                entries: Sequence[FlextLdifProtocols.Ldif.EntryProtocol],
            ) -> FlextResult[FlextLdifProtocols.Ldif.FlexibleCategoriesProtocol]:
                """Categorize all entries."""
                ...

            def categorize_entry(
                self,
                entry: FlextLdifProtocols.Ldif.EntryProtocol,
                rules: FlextLdifProtocols.Ldif.CategoryRulesProtocol
                | Mapping[str, Sequence[str]]
                | None = None,
                server_type: str | None = None,
            ) -> tuple[str, str | None]:
                """Categorize single entry."""
                ...

            def filter_by_base_dn(
                self, base_dn: str
            ) -> FlextLdifProtocols.Ldif.FlexibleCategoriesProtocol:
                """Filter categories by base DN."""
                ...

            def filter_schema_by_oids(
                self,
                allowed_oids: Sequence[str],
            ) -> FlextLdifProtocols.Ldif.FlexibleCategoriesProtocol:
                """Filter schema entries by allowed OIDs."""
                ...

        # =========================================================================
        # QUIRK PROTOCOLS
        # =========================================================================

        @runtime_checkable
        class ParentQuirkProtocol(Protocol):
            """Protocol for parent quirk (FlextLdifServersBase) instances."""

            @property
            def server_type(self) -> str:
                """Server type identifier."""
                ...

            class Constants:
                """Nested Constants class protocol."""

                PRIORITY: int

        @runtime_checkable
        class SchemaQuirkProtocol(Protocol):
            """Protocol for Schema quirk implementations."""

            def parse(
                self,
                attr_definition: str,
            ) -> FlextResult[
                FlextLdifProtocols.Ldif.SchemaAttributeProtocol
                | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
            ]:
                """Parse schema definition."""
                ...

            def write(
                self,
                model: FlextLdifProtocols.Ldif.SchemaAttributeProtocol
                | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol,
            ) -> FlextResult[str]:
                """Write schema definition."""
                ...

        @runtime_checkable
        class AclQuirkProtocol(Protocol):
            """Protocol for ACL quirk implementations."""

            def parse(
                self, acl_line: str
            ) -> FlextResult[FlextLdifProtocols.Ldif.AclProtocol]:
                """Parse ACL definition."""
                ...

            def write(
                self, acl_data: FlextLdifProtocols.Ldif.AclProtocol
            ) -> FlextResult[str]:
                """Write ACL definition."""
                ...

        @runtime_checkable
        class EntryQuirkProtocol(Protocol):
            """Protocol for Entry quirk implementations."""

            def parse(
                self, entry_lines: Sequence[str]
            ) -> FlextResult[FlextLdifProtocols.Ldif.EntryProtocol]:
                """Parse entry definition."""
                ...

            def parse_entry(
                self,
                entry_dn: str,
                entry_attrs: Mapping[str, Sequence[str]],
            ) -> FlextResult[FlextLdifProtocols.Ldif.EntryProtocol]:
                """Parse single entry from DN and attributes."""
                ...

            def write(
                self,
                entries: FlextLdifProtocols.Ldif.EntryProtocol
                | Sequence[FlextLdifProtocols.Ldif.EntryProtocol],
                format_options: FlextLdifProtocols.Ldif.WriteFormatOptionsProtocol
                | None = None,
            ) -> FlextResult[str]:
                """Write entries to LDIF."""
                ...

        @runtime_checkable
        class QuirksPortProtocol(Protocol):
            """Protocol for unified quirks interface."""

            def execute(
                self,
                model: FlextLdifProtocols.Ldif.SchemaAttributeProtocol
                | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
                | FlextLdifProtocols.Ldif.AclProtocol
                | FlextLdifProtocols.Ldif.EntryProtocol
                | str,
            ) -> FlextResult[str]:
                """Execute quirk operation on any model type."""
                ...

        @runtime_checkable
        class QuirkRegistryProtocol(Protocol):
            """Protocol for quirk registry implementations."""

            def get_quirk(
                self, server_type: str
            ) -> FlextLdifProtocols.Ldif.SchemaQuirkProtocol | None:
                """Get quirk for server type."""
                ...

            def register_quirk(
                self,
                server_type: str,
                quirk: FlextLdifProtocols.Ldif.SchemaQuirkProtocol,
            ) -> None:
                """Register a quirk for server type."""
                ...

        # =========================================================================
        # SERVER CONSTANTS PROTOCOLS
        # =========================================================================

        @runtime_checkable
        class ServerConstantsProtocol(Protocol):
            """Protocol for server Constants classes."""

            DETECTION_OID_PATTERN: str | None
            DETECTION_ATTRIBUTE_PREFIXES: frozenset[str] | None
            DETECTION_OBJECTCLASS_NAMES: frozenset[str] | None
            DETECTION_DN_MARKERS: frozenset[str] | None
            ACL_ATTRIBUTE_NAME: str | None

        @runtime_checkable
        class ModelWithValidationMetadataProtocol(Protocol):
            """Protocol for models with validation_metadata attribute."""

            validation_metadata: t.Ldif.MetadataType | None

        # =========================================================================
        # UTILITY PROTOCOLS
        # =========================================================================

        @runtime_checkable
        class TransformerProtocol[T](Protocol):
            """Protocol for transformers in pipelines."""

            def apply(self, item: T) -> T | FlextResult[T]:
                """Apply the transformation."""
                ...

        @runtime_checkable
        class BatchTransformerProtocol[T](Protocol):
            """Protocol for batch transformers."""

            def apply_batch(self, items: Sequence[T]) -> FlextResult[list[T]]:
                """Apply transformation to batch."""
                ...

        @runtime_checkable
        class FilterProtocol[T](Protocol):
            """Protocol for filters in pipelines."""

            def matches(self, item: T) -> bool:
                """Check if item matches filter criteria."""
                ...

            def __and__(
                self, other: FlextLdifProtocols.Ldif.FilterProtocol[T]
            ) -> FlextLdifProtocols.Ldif.FilterProtocol[T]:
                """AND combination."""
                ...

            def __or__(
                self, other: FlextLdifProtocols.Ldif.FilterProtocol[T]
            ) -> FlextLdifProtocols.Ldif.FilterProtocol[T]:
                """OR combination."""
                ...

            def __invert__(self) -> FlextLdifProtocols.Ldif.FilterProtocol[T]:
                """NOT negation."""
                ...

        @runtime_checkable
        class ValidationReportProtocol(Protocol):
            """Protocol for validation reports."""

            @property
            def is_valid(self) -> bool:
                """Check if validation passed."""
                ...

            @property
            def errors(self) -> list[str]:
                """Get error messages."""
                ...

            @property
            def warnings(self) -> list[str]:
                """Get warning messages."""
                ...

        @runtime_checkable
        class ValidatorProtocol[T](Protocol):
            """Protocol for validators."""

            def validate(
                self, item: T
            ) -> FlextResult[FlextLdifProtocols.Ldif.ValidationReportProtocol]:
                """Validate an item."""
                ...

        @runtime_checkable
        class ValidationRuleProtocol[T](Protocol):
            """Protocol for validation rules."""

            @property
            def name(self) -> str:
                """Get the rule name."""
                ...

            def check(self, item: T) -> tuple[bool, str | None]:
                """Check an item against this rule."""
                ...

        @runtime_checkable
        class PipelineStepProtocol[TIn, TOut](Protocol):
            """Protocol for pipeline steps."""

            @property
            def name(self) -> str:
                """Get step name."""
                ...

            def execute(self, input_data: TIn) -> FlextResult[TOut]:
                """Execute pipeline step."""
                ...

        @runtime_checkable
        class FluentBuilderProtocol[TConfig](Protocol):
            """Protocol for fluent builders."""

            def build(self) -> TConfig:
                """Build the final configuration object."""
                ...

        @runtime_checkable
        class FluentOpsProtocol[T](Protocol):
            """Protocol for fluent operation chains."""

            def build(self) -> FlextResult[T]:
                """Build/finalize and return the result."""
                ...

        @runtime_checkable
        class LoadableProtocol[T](Protocol):
            """Protocol for loadable data sources."""

            def load(self) -> FlextResult[T]:
                """Load and return the data."""
                ...

        @runtime_checkable
        class WritableProtocol(Protocol):
            """Protocol for writable output targets."""

            def write(self, content: str) -> FlextResult[str]:
                """Write content to the target."""
                ...

        # =========================================================================
        # NAMESPACE ALIASES (for FlextLdifProtocols.Ldif.* access)
        # =========================================================================

        # Access protocols directly via composition - no aliases needed

        # Nested constants class (for compatibility)
        class Constants:
            """Constants namespace for protocol access."""

        # Quirks namespace for backward compatibility with tests
        # Note: Protocol aliases must be added after class definition
        # because nested class can't reference sibling protocols directly
        class Quirks:
            """Quirks namespace containing quirk protocol aliases."""


# Define Quirks protocol aliases after class definition
# These are added to Quirks namespace for test compatibility
FlextLdifProtocols.Ldif.Quirks.SchemaProtocol = FlextLdifProtocols.Ldif.SchemaQuirkProtocol
FlextLdifProtocols.Ldif.Quirks.AclProtocol = FlextLdifProtocols.Ldif.AclQuirkProtocol
FlextLdifProtocols.Ldif.Quirks.EntryProtocol = FlextLdifProtocols.Ldif.EntryQuirkProtocol
FlextLdifProtocols.Ldif.Quirks.QuirksPort = FlextLdifProtocols.Ldif.QuirksPortProtocol

# Add direct Quirks alias for test compatibility
FlextLdifProtocols.Quirks = FlextLdifProtocols.Ldif.Quirks

# Short name aliases for Schema protocols (without Protocol suffix)
# These provide backward compatibility for tests using p.Ldif.SchemaAttribute
FlextLdifProtocols.Ldif.SchemaAttribute = FlextLdifProtocols.Ldif.SchemaAttributeProtocol
FlextLdifProtocols.Ldif.SchemaObjectClass = FlextLdifProtocols.Ldif.SchemaObjectClassProtocol

# Runtime aliases
p = FlextLdifProtocols
fldif = FlextLdifProtocols

__all__ = ["FlextLdifProtocols", "fldif", "p"]
