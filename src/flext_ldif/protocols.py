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

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Protocol, Self, runtime_checkable

from flext_core import FlextProtocols, FlextResult

from flext_ldif.constants import c
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
            Uses plain attributes (not @property) for Pydantic 2 structural typing.
            """

            dn: str | None
            """Distinguished Name."""

            attributes: Mapping[str, Sequence[str]] | None
            """Entry attributes (Mapping, Attributes model, or None)."""

            metadata: FlextLdifProtocols.Ldif.QuirkMetadataProtocol | None
            """Optional metadata for processing context."""

            def get_objectclass_names(self) -> Sequence[str]:
                """Get list of objectClass values from entry."""
                ...

            def model_copy(
                self,
                *,
                deep: bool = False,
                update: Mapping[str, str | int | float | bool | Sequence[str] | None]
                | None = None,
            ) -> Self:
                """Create a copy of the entry with optional updates."""
                ...

        @runtime_checkable
        class EntryWithDnProtocol(Protocol):
            """Protocol for objects that have a DN attribute."""

            dn: str | None
            """Distinguished Name."""

        @runtime_checkable
        class AttributeValueProtocol(Protocol):
            """Protocol for objects that have attribute values."""

            values: list[str] | str

        # =========================================================================
        # METADATA PROTOCOLS (for QuirkMetadata and related classes)
        # =========================================================================

        @runtime_checkable
        class DynamicMetadataProtocol(Protocol):
            """Protocol for DynamicMetadata model with extra="allow"."""

            transformations: list[object] | None
            model_extra: dict[str, str | int | float | bool | list[str] | None] | None

            def get(
                self, key: str, default: str | float | bool | list[str] | None = None
            ) -> str | int | float | bool | list[str] | None:
                """Get value from model_extra dict with type safety."""
                ...

        @runtime_checkable
        class EntryMetadataProtocol(Protocol):
            """Protocol for EntryMetadata model with extra="allow"."""

            model_extra: (
                dict[
                    str,
                    str
                    | int
                    | float
                    | bool
                    | list[str]
                    | dict[str, str | int | float | bool | list[str] | None]
                    | None,
                ]
                | None
            )

            def get(
                self, key: str, default: str | float | bool | list[str] | None = None
            ) -> str | int | float | bool | list[str] | None:
                """Get value from model_extra dict with type safety."""
                ...

        @runtime_checkable
        class AttributeTransformationProtocol(Protocol):
            """Protocol for AttributeTransformation model."""

            original_name: str
            target_name: str | None
            original_values: Sequence[str]
            target_values: Sequence[str] | None
            transformation_type: str
            reason: str

        @runtime_checkable
        class QuirkMetadataProtocol(Protocol):
            """Protocol for QuirkMetadata model.

            Matches all fields in FlextLdifModelsDomains.QuirkMetadata.
            Uses exact types matching the Model for Protocol invariance.
            """

            # quirk_type can be ServerTypes enum or Literal string - use str for Protocol
            quirk_type: str
            # Use list[str] to match Model exactly (Protocol attributes are invariant)
            rfc_violations: list[str]
            rfc_warnings: list[str]
            original_server_type: str | None
            target_server_type: str | None
            validation_violations: list[str]

        # =========================================================================
        # ACL PROTOCOLS
        # =========================================================================

        @runtime_checkable
        class AclTargetProtocol(Protocol):
            """Protocol for ACL target specification.

            Uses list[str] to match Model exactly (Protocol attributes are invariant).
            """

            target_dn: str
            attributes: list[str]

        @runtime_checkable
        class AclSubjectProtocol(Protocol):
            """Protocol for ACL subject specification."""

            subject_type: str
            subject_value: str

        @runtime_checkable
        class AclPermissionsProtocol(Protocol):
            """Protocol for ACL permissions."""

            read: bool
            write: bool
            add: bool
            delete: bool
            search: bool

        @runtime_checkable
        class AclProtocol(Protocol):
            """Protocol for LDIF ACL models.

            Minimal structural protocol for ACL write operations.
            Avoids nested Protocol types to prevent pyrefly invariance issues.
            Uses scalar types only for reliable structural typing.
            """

            name: str
            """ACL name."""

            raw_acl: str
            """Original ACL string from LDIF."""

            server_type: c.Ldif.LiteralTypes.ServerTypeLiteral
            """LDAP server type using exact Literal type for invariance."""

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
            """Protocol for write format options.

            All attributes are read-only properties to match Pydantic model behavior.
            """

            @property
            def line_width(self) -> int: ...
            @property
            def respect_attribute_order(self) -> bool: ...
            @property
            def sort_attributes(self) -> bool: ...
            @property
            def write_hidden_attributes_as_comments(self) -> bool:
                """Whether to write hidden attributes as comments."""
                ...

            @property
            def write_metadata_as_comments(self) -> bool:
                """Whether to write metadata as comments."""
                ...

            @property
            def include_version_header(self) -> bool:
                """Whether to include version header."""
                ...

            @property
            def include_timestamps(self) -> bool:
                """Whether to include timestamps."""
                ...

            @property
            def base64_encode_binary(self) -> bool:
                """Whether to base64 encode binary data."""
                ...
            @property
            def fold_long_lines(self) -> bool:
                """Whether to fold long lines."""
                ...
            @property
            def restore_original_format(self) -> bool: ...
            @property
            def write_empty_values(self) -> bool: ...
            @property
            def normalize_attribute_names(self) -> bool: ...
            @property
            def include_dn_comments(self) -> bool: ...
            @property
            def write_removed_attributes_as_comments(self) -> bool: ...
            @property
            def write_migration_header(self) -> bool: ...
            @property
            def migration_header_template(self) -> str | None: ...
            @property
            def write_rejection_reasons(self) -> bool: ...
            @property
            def include_removal_statistics(self) -> bool: ...
            @property
            def ldif_changetype(self) -> str | None: ...
            @property
            def ldif_modify_operation(self) -> str: ...

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

            entries: Sequence[FlextLdifProtocols.Ldif.EntryProtocol]
            """List of entries."""

        @runtime_checkable
        class HasContentProtocol(Protocol):
            """Protocol for objects that have a content attribute."""

            content: str | None

        @runtime_checkable
        class SchemaConversionPipelineConfigProtocol(Protocol):
            """Protocol for schema conversion pipeline configuration objects.

            All attributes are read-only properties to match Pydantic model behavior.
            """

            @property
            def write_method(self) -> Callable[..., FlextResult[str]]:
                """Method to write schema object to LDIF."""
                ...

            @property
            def source_schema(
                self,
            ) -> (
                FlextLdifProtocols.Ldif.SchemaAttributeProtocol
                | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
            ):
                """Source schema object to convert."""
                ...

            @property
            def parse_method(self) -> Callable[..., FlextResult[object]]:
                """Method to parse LDIF into schema object."""
                ...

            @property
            def target_schema(
                self,
            ) -> (
                FlextLdifProtocols.Ldif.SchemaAttributeProtocol
                | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
            ):
                """Target schema object template."""
                ...

            @property
            def item_name(self) -> str:
                """Name of the schema item being converted."""
                ...

        @runtime_checkable
        class UnifiedParseResultProtocol(Protocol):
            """Unified protocol for all parse result types."""

            entries: Sequence[
                FlextLdifProtocols.Ldif.EntryProtocol
                | FlextLdifProtocols.Ldif.SchemaAttributeProtocol
                | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
                | FlextLdifProtocols.Ldif.AclProtocol
            ]
            """All entries."""

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

            entries: Sequence[FlextLdifProtocols.Ldif.EntryProtocol]
            """All entries."""

            content: Sequence[FlextLdifProtocols.Ldif.EntryProtocol]
            """Alias for entries."""

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
                self,
                key: str,
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

            user_dn_patterns: list[str]
            """DN patterns to match user entries."""

            group_dn_patterns: list[str]
            """DN patterns to match group entries."""

            hierarchy_dn_patterns: list[str]
            """DN patterns to match hierarchy entries."""

            schema_dn_patterns: list[str]
            """DN patterns to match schema entries."""

            user_objectclasses: list[str]
            """ObjectClass names that identify user entries."""

            group_objectclasses: list[str]
            """ObjectClass names that identify group entries."""

            hierarchy_objectclasses: list[str]
            """ObjectClass names that identify hierarchy entries."""

            acl_attributes: list[str]
            """Attribute names that identify ACL entries."""

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
                self,
                base_dn: str,
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

            server_type: str
            """Server type identifier."""

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

            def parse_attribute(
                self,
                attr_definition: str,
            ) -> FlextResult[object]:
                """Parse individual attribute definition."""
                ...

            def write_attribute(
                self,
                attribute: object,
            ) -> FlextResult[str]:
                """Write individual attribute definition."""
                ...

            def parse_objectclass(
                self,
                oc_definition: str,
            ) -> FlextResult[object]:
                """Parse individual objectClass definition."""
                ...

            def write_objectclass(
                self,
                objectclass: object,
            ) -> FlextResult[str]:
                """Write individual objectClass definition."""
                ...

        @runtime_checkable
        class AclQuirkProtocol(Protocol):
            """Protocol for ACL quirk implementations."""

            def parse(
                self,
                acl_line: str,
            ) -> FlextResult[FlextLdifProtocols.Ldif.AclProtocol]:
                """Parse ACL definition."""
                ...

            def write(
                self,
                acl_data: FlextLdifProtocols.Ldif.AclProtocol,
            ) -> FlextResult[str]:
                """Write ACL definition."""
                ...

        @runtime_checkable
        class EntryQuirkProtocol(Protocol):
            """Protocol for Entry quirk implementations."""

            def parse(
                self,
                entry_lines: Sequence[str],
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
                self,
                server_type: str,
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
                self,
                other: FlextLdifProtocols.Ldif.FilterProtocol[T],
            ) -> FlextLdifProtocols.Ldif.FilterProtocol[T]:
                """AND combination."""
                ...

            def __or__(
                self,
                other: FlextLdifProtocols.Ldif.FilterProtocol[T],
            ) -> FlextLdifProtocols.Ldif.FilterProtocol[T]:
                """OR combination."""
                ...

            def __invert__(self) -> FlextLdifProtocols.Ldif.FilterProtocol[T]:
                """NOT negation."""
                ...

        @runtime_checkable
        class ValidationReportProtocol(Protocol):
            """Protocol for validation reports."""

            is_valid: bool
            """Check if validation passed."""

            errors: list[str]
            """Error messages."""

            warnings: list[str]
            """Warning messages."""

        @runtime_checkable
        class ValidatorProtocol[T](Protocol):
            """Protocol for validators."""

            def validate(
                self,
                item: T,
            ) -> FlextResult[FlextLdifProtocols.Ldif.ValidationReportProtocol]:
                """Validate an item."""
                ...

        @runtime_checkable
        class ValidationRuleProtocol[T](Protocol):
            """Protocol for validation rules."""

            name: str
            """Rule name."""

            def check(self, item: T) -> tuple[bool, str | None]:
                """Check an item against this rule."""
                ...

        @runtime_checkable
        class PipelineStepProtocol[TIn, TOut](Protocol):
            """Protocol for pipeline steps."""

            name: str
            """Step name."""

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


# Runtime type compatibility: add protocol aliases to namespaces
# These assignments work at runtime; mypy warnings are expected for dynamic assignments
# Accessing via full names (e.g., p.Ldif.SchemaQuirkProtocol) is mypy-compatible

# Runtime aliases
p = FlextLdifProtocols
fldif = FlextLdifProtocols

__all__ = ["FlextLdifProtocols", "fldif", "p"]
