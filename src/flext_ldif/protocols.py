"""LDIF protocol definitions for flext-ldif domain.

Protocol interfaces for LDIF processing quirks and operations.
All protocols organized under single FlextLdifProtocols class per
FLEXT standardization.

Defines strict structural typing contracts for:
- Schema quirks (attribute and objectClass processing)
- ACL quirks (access control processing)
- Entry quirks (LDAP entry processing)
- Conversion operations (server-to-server transformations)
- Registry operations (quirk discovery and management)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal, Protocol, Self, runtime_checkable

from flext_core import FlextProtocols, FlextResult

# =========================================================================
# INLINE TYPE DEFINITIONS - Metadata structures for protocols
# =========================================================================
# These types are defined here (not imported) to allow protocols to remain
# independent of typings.py and constants.py, following FLEXT protocol-models
# separation rule. Protocols can only import other Protocols.
# Uses ONLY structural types (Mapping, Sequence) from collections.abc.
# Uses Literal types inline (not imported from constants) to maintain independence.

type FlextLdifMetadataValue = (
    str
    | int
    | float
    | bool
    | Sequence[str | int | Mapping[str, str | Sequence[str]]]
    | Mapping[str, str | int | Sequence[str] | Mapping[str, str | Sequence[str]]]
    | None
)
"""Structural type for metadata values (supports nested structures).

Represents:
- Primitives: str, int, float, bool, None
- Lists: Sequence[str], Sequence[int], Sequence[Mapping[...]]
- Dicts: Mapping[str, primitives | sequences | nested mappings]
"""

type FlextLdifMetadata = Mapping[str, FlextLdifMetadataValue]
"""Structural type for metadata dictionaries using Mapping (read-only interface).

Represents flexible metadata containers without importing typings.py.
Used in protocol definitions where metadata must be stored or passed.
"""

# =========================================================================
# INLINE LITERAL TYPE DEFINITIONS - For protocol method signatures
# =========================================================================
# These Literal types are defined inline to maintain protocol independence
# per FLEXT architecture rules (Protocols cannot import Constants).
# They MUST match exactly the Literal types in constants.py.LiteralTypes
# to ensure consistency across the codebase.
#
# IMPORTANT: When updating these, also update constants.py.LiteralTypes
# to keep them synchronized.

type CategoryLiteral = Literal[
    "all",
    "users",
    "groups",
    "hierarchy",
    "schema",
    "acl",
    "rejected",
]
"""Category literals for entry categorization.
Must match FlextLdifConstants.LiteralTypes.CategoryLiteral exactly."""

type ServerTypeLiteral = Literal[
    "oid",
    "oud",
    "openldap",
    "openldap1",
    "openldap2",
    "active_directory",
    "apache_directory",
    "generic",
    "rfc",
    "389ds",
    "relaxed",
    "novell_edirectory",
    "ibm_tivoli",
    "oracle_oid",
    "oracle_oud",
]
"""Server type literals for server identification.
Must match FlextLdifConstants.LiteralTypes.ServerTypeLiteral exactly."""


class FlextLdifProtocols(FlextProtocols):
    """Unified LDIF protocol definitions extending FlextProtocols.

    This class extends the base FlextProtocols with LDIF-specific protocol
    definitions for the minimal, streamlined public interfaces of quirks.

    **Protocol Compliance Strategy:**
    1. All quirk classes inherit from ABC base classes (Schema, Acl, Entry)
    2. All base classes satisfy protocols through structural typing (duck typing)
    3. isinstance() checks validate protocol compliance at runtime
    4. All methods use "FlextResult[T]" for railway-oriented error handling
    5. execute() method provides polymorphic type-based routing

    **Minimal Public Interface:**
    - Schema: parse(), write()
    - ACL: parse(), write()
    - Entry: parse(), write()
    - execute() method provides automatic type-detection routing for all operations

    **Private Methods (NOT in protocols):**
    - can_handle_* methods for internal detection logic
    - _hook_* methods for customization points
    - process_entry, convert_entry (handled via hooks or conversion)
    """

    class Models:
        """Protocol definitions for LDIF domain models.

        These protocols define the minimal interface that models must satisfy.
        Models implement these protocols, not the other way around.
        """

        @runtime_checkable
        class EntryProtocol(Protocol):
            """Protocol for LDIF Entry models.

            Defines structural interface that Entry models must satisfy.
            Uses abstract types for all attributes.
            """

            dn: str
            attributes: Mapping[str, Sequence[str]]
            metadata: FlextLdifMetadata | None

            def get_objectclass_names(self) -> Sequence[str]:
                """Get list of objectClass values."""
                ...

            def model_copy(
                self,
                *,
                deep: bool = False,
                update: FlextLdifMetadata | None = None,
            ) -> Self:
                """Create a copy of the entry."""
                ...

        @runtime_checkable
        class AclProtocol(Protocol):
            """Protocol for LDIF ACL models.

            Defines minimal structural interface for ACL objects.
            """

            name: str
            target: Mapping[str, str]
            subject: Mapping[str, str]
            permissions: Mapping[str, bool]
            metadata: FlextLdifMetadata | None

        @runtime_checkable
        class SchemaAttributeProtocol(Protocol):
            """Protocol for LDIF SchemaAttribute models.

            Defines minimal structural interface for schema attributes.
            """

            name: str
            oid: str
            syntax: str | None
            single_valued: bool
            description: str | None

        @runtime_checkable
        class SchemaObjectClassProtocol(Protocol):
            """Protocol for LDIF SchemaObjectClass models.

            Defines minimal structural interface for schema object classes.
            """

            name: str
            oid: str
            type: str
            must_attributes: Sequence[str]
            may_attributes: Sequence[str]
            description: str | None

        @runtime_checkable
        class WriteFormatOptionsProtocol(Protocol):
            """Protocol for write format options.

            Defines minimal interface for LDIF write format configuration.
            """

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
            """Protocol for ACL write metadata.

            Defines minimal structural interface for ACL metadata.
            """

            source_subject_type: str | None

        @runtime_checkable
        class CategoryRulesProtocol(Protocol):
            """Protocol for category rules configuration.

            Defines structural interface that CategoryRules models must satisfy.
            """

            user_dn_patterns: Sequence[str]
            group_dn_patterns: Sequence[str]
            hierarchy_dn_patterns: Sequence[str]
            schema_dn_patterns: Sequence[str]
            user_objectclasses: Sequence[str]
            group_objectclasses: Sequence[str]
            hierarchy_objectclasses: Sequence[str]
            acl_attributes: Sequence[str]

    class Services:
        """Service interface protocols for LDIF operations."""

        @runtime_checkable
        class HasParseMethodProtocol(Protocol):
            """Protocol for objects with parse method."""

            def parse(
                self,
                ldif_input: str | Path,
                server_type: str | None = None,
            ) -> FlextResult[Sequence[FlextLdifProtocols.Models.EntryProtocol]]:
                """Parse LDIF content."""
                ...

        @runtime_checkable
        class HasWriteMethodProtocol(Protocol):
            """Protocol for objects with write method."""

            def write(
                self,
                entries: Sequence[FlextLdifProtocols.Models.EntryProtocol]
                | FlextLdifProtocols.Models.EntryProtocol,
            ) -> FlextResult[str]:
                """Write entries to LDIF."""
                ...

        @runtime_checkable
        class HasEntryWriteMethodProtocol(Protocol):
            """Protocol for entry quirk instances with write method."""

            def write(
                self,
                entries: Sequence[FlextLdifProtocols.Models.EntryProtocol],
            ) -> FlextResult[str]:
                """Write entries to LDIF."""
                ...

        @runtime_checkable
        class HasEntriesProtocol(Protocol):
            """Protocol for objects that have an entries attribute.

            Used by EntryResult and similar result containers.
            """

            @property
            def entries(self) -> Sequence[FlextLdifProtocols.Models.EntryProtocol]:
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
                FlextLdifProtocols.Models.EntryProtocol
                | FlextLdifProtocols.Models.SchemaAttributeProtocol
                | FlextLdifProtocols.Models.SchemaObjectClassProtocol
                | FlextLdifProtocols.Models.AclProtocol
            ]:
                """Get all entries (works for any result type)."""
                ...

        @runtime_checkable
        class UnifiedWriteResultProtocol(Protocol):
            """Unified protocol for all write result types."""

            content: str | None

        @runtime_checkable
        class FilterEventProtocol(Protocol):
            """Protocol for filter event objects.

            Defines structural interface for event tracking during filtering operations.
            """

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
        class FlexibleCategoriesProtocol(Protocol):
            """Protocol for flexible entry categorization.

            Defines structural interface for categorized entry collections.
            Uses dict-like access (e.g., categories["schema"], categories["users"]).
            """

            def __getitem__(
                self, key: str
            ) -> Sequence[FlextLdifProtocols.Models.EntryProtocol]:
                """Get entries for a category by key."""
                ...

            def get(
                self,
                key: str,
                default: Sequence[FlextLdifProtocols.Models.EntryProtocol]
                | None = None,
            ) -> Sequence[FlextLdifProtocols.Models.EntryProtocol] | None:
                """Get entries for a category with fallback."""
                ...

            def keys(self) -> Sequence[str]:
                """Get all category keys."""
                ...

            def values(
                self,
            ) -> Sequence[Sequence[FlextLdifProtocols.Models.EntryProtocol]]:
                """Get all category entry lists."""
                ...

            def items(
                self,
            ) -> Sequence[
                tuple[str, Sequence[FlextLdifProtocols.Models.EntryProtocol]]
            ]:
                """Get all category key-value pairs."""
                ...

        @runtime_checkable
        class FilterServiceProtocol(Protocol):
            """Protocol for filtering service implementations."""

            def execute(
                self,
            ) -> FlextResult[
                FlextLdifProtocols.Services.UnifiedParseResultProtocol
                | FlextLdifProtocols.Services.HasEntriesProtocol
                | Sequence[FlextLdifProtocols.Models.EntryProtocol]
                | str
            ]:
                """Execute filtering based on configured criteria."""
                ...

            @classmethod
            def filter(
                cls,
                entries: Sequence[FlextLdifProtocols.Models.EntryProtocol],
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
                FlextLdifProtocols.Services.UnifiedParseResultProtocol
                | FlextLdifProtocols.Services.HasEntriesProtocol
                | Sequence[FlextLdifProtocols.Models.EntryProtocol]
                | str
            ]:
                """Quick filter with FlextResult for composable operations."""
                ...

            def get_last_event(
                self,
            ) -> FlextLdifProtocols.Services.FilterEventProtocol | None:
                """Get last emitted FilterEvent."""
                ...

        @runtime_checkable
        class CategorizationServiceProtocol(Protocol):
            """Protocol for entry categorization service implementations."""

            def execute(
                self,
            ) -> FlextResult[FlextLdifProtocols.Services.FlexibleCategoriesProtocol]:
                """Execute categorization based on configured rules."""
                ...

            def validate_dns(
                self,
                entries: Sequence[FlextLdifProtocols.Models.EntryProtocol],
            ) -> FlextResult[Sequence[FlextLdifProtocols.Models.EntryProtocol]]:
                """Validate entry DNs according to RFC 4514."""
                ...

            def categorize_entries(
                self,
                entries: Sequence[FlextLdifProtocols.Models.EntryProtocol],
            ) -> FlextResult[FlextLdifProtocols.Services.FlexibleCategoriesProtocol]:
                """Categorize all entries into categories."""
                ...

            def categorize_entry(
                self,
                entry: FlextLdifProtocols.Models.EntryProtocol,
                rules: (
                    FlextLdifProtocols.Models.CategoryRulesProtocol
                    | Mapping[str, Sequence[str]]
                    | None
                ) = None,
                server_type: str | None = None,
            ) -> tuple[
                CategoryLiteral,
                str | None,
            ]:
                """Categorize single entry, return (category, reason)."""
                ...

            def filter_by_base_dn(
                self,
                base_dn: str,
            ) -> FlextLdifProtocols.Services.FlexibleCategoriesProtocol:
                """Filter categories by base DN."""
                ...

            def filter_schema_by_oids(
                self,
                allowed_oids: Sequence[str],
            ) -> FlextLdifProtocols.Services.FlexibleCategoriesProtocol:
                """Filter schema entries by allowed OIDs."""
                ...

    class Quirks:
        """Protocol definitions for quirk implementations."""

        @runtime_checkable
        class SchemaProtocol(Protocol):
            """Protocol for Schema quirk implementations."""

            def parse(
                self,
                attr_definition: str,
            ) -> FlextResult[
                FlextLdifProtocols.Models.SchemaAttributeProtocol
                | FlextLdifProtocols.Models.SchemaObjectClassProtocol
            ]:
                """Parse schema definition."""
                ...

            def write(
                self,
                model: FlextLdifProtocols.Models.SchemaAttributeProtocol
                | FlextLdifProtocols.Models.SchemaObjectClassProtocol,
            ) -> FlextResult[str]:
                """Write schema definition."""
                ...

        @runtime_checkable
        class AclProtocol(Protocol):
            """Protocol for ACL quirk implementations."""

            def parse(
                self,
                acl_line: str,
            ) -> FlextResult[FlextLdifProtocols.Models.AclProtocol]:
                """Parse ACL definition."""
                ...

            def write(
                self,
                acl_data: FlextLdifProtocols.Models.AclProtocol,
            ) -> FlextResult[str]:
                """Write ACL definition."""
                ...

        @runtime_checkable
        class EntryProtocol(Protocol):
            """Protocol for Entry quirk implementations."""

            def parse(
                self,
                entry_lines: Sequence[str],
            ) -> FlextResult[FlextLdifProtocols.Models.EntryProtocol]:
                """Parse entry definition."""
                ...

            def parse_entry(
                self,
                entry_dn: str,
                entry_attrs: Mapping[str, Sequence[str]],
            ) -> FlextResult[FlextLdifProtocols.Models.EntryProtocol]:
                """Parse single entry from DN and attributes."""
                ...

            def write(
                self,
                entries: FlextLdifProtocols.Models.EntryProtocol
                | Sequence[FlextLdifProtocols.Models.EntryProtocol],
                format_options: FlextLdifProtocols.Models.WriteFormatOptionsProtocol
                | None = None,
            ) -> FlextResult[str]:
                """Write entries to LDIF."""
                ...

        @runtime_checkable
        class QuirksPort(Protocol):
            """Protocol for unified quirks interface.

            Gateway interface that supports Schema, ACL, and Entry quirks.
            """

            def execute(
                self,
                model: FlextLdifProtocols.Models.SchemaAttributeProtocol
                | FlextLdifProtocols.Models.SchemaObjectClassProtocol
                | FlextLdifProtocols.Models.AclProtocol
                | FlextLdifProtocols.Models.EntryProtocol
                | str,
            ) -> FlextResult[str]:
                """Execute quirk operation on any model type."""
                ...

    class Registry:
        """Protocol definitions for quirk registry operations."""

        @runtime_checkable
        class QuirkRegistryProtocol(Protocol):
            """Protocol for quirk registry implementations."""

            def get_quirk(
                self,
                server_type: ServerTypeLiteral | str,
            ) -> FlextLdifProtocols.Quirks.SchemaProtocol | None:
                """Get quirk for server type."""
                ...

            def register_quirk(
                self,
                server_type: ServerTypeLiteral | str,
                quirk: FlextLdifProtocols.Quirks.SchemaProtocol,
            ) -> None:
                """Register a quirk for server type."""
                ...
