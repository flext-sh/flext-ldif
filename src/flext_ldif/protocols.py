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

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Protocol, Self, TypeVar, runtime_checkable

from flext_core import FlextProtocols, FlextResult

if TYPE_CHECKING:
    from flext_ldif._models.domain import FlextLdifModelsDomains
    from flext_ldif._models.metadata import FlextLdifModelsMetadata

TResult = TypeVar("TResult")


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
            Uses union types to support both str/dict and DistinguishedName/LdifAttributes variants.
            """

            dn: str | FlextLdifModelsDomains.DistinguishedName
            attributes: dict[str, list[str]] | FlextLdifModelsDomains.LdifAttributes
            metadata: FlextLdifModelsMetadata.EntryMetadata | None

            def get_objectclass_names(self) -> list[str]:
                """Get list of objectClass values."""
                ...

            def model_copy(self, *, deep: bool = False, update: dict[str, str | list[str] | dict[str, str]] | None = None) -> Self:
                """Create a copy of the entry."""
                ...

        @runtime_checkable
        class AclProtocol(Protocol):
            """Protocol for LDIF ACL models."""

        @runtime_checkable
        class SchemaAttributeProtocol(Protocol):
            """Protocol for LDIF SchemaAttribute models."""

        @runtime_checkable
        class SchemaObjectClassProtocol(Protocol):
            """Protocol for LDIF SchemaObjectClass models."""

        @runtime_checkable
        class WriteFormatOptionsProtocol(Protocol):
            """Protocol for write format options."""

        @runtime_checkable
        class AclWriteMetadataProtocol(Protocol):
            """Protocol for ACL write metadata."""

    class Services:
        """Service interface protocols for LDIF operations."""

        @runtime_checkable
        class HasParseMethodProtocol(Protocol):
            """Protocol for objects with parse method."""

            def parse(
                self,
                ldif_input: str | Path,
                server_type: str | None = None,
            ) -> FlextResult[list[FlextLdifProtocols.Models.EntryProtocol]]:
                """Parse LDIF content."""
                ...

        @runtime_checkable
        class HasWriteMethodProtocol(Protocol):
            """Protocol for objects with write method."""

            def write(
                self,
                entries: list[FlextLdifProtocols.Models.EntryProtocol]
                | FlextLdifProtocols.Models.EntryProtocol,
            ) -> FlextResult[str]:
                """Write entries to LDIF."""
                ...

        @runtime_checkable
        class HasEntryWriteMethodProtocol(Protocol):
            """Protocol for entry quirk instances with write method."""

            def write(
                self,
                entries: list[FlextLdifProtocols.Models.EntryProtocol],
            ) -> FlextResult[str]:
                """Write entries to LDIF."""
                ...

        @runtime_checkable
        class HasEntriesProtocol(Protocol):
            """Protocol for objects that have an entries attribute."""

            entries: list[FlextLdifProtocols.Models.EntryProtocol]

        @runtime_checkable
        class HasContentProtocol(Protocol):
            """Protocol for objects that have a content attribute."""

            content: str | None

        @runtime_checkable
        class UnifiedParseResultProtocol(Protocol):
            """Unified protocol for all parse result types."""

            def get_entries(self) -> list[FlextLdifProtocols.Models.EntryProtocol]:
                """Get parsed entries."""
                ...

        @runtime_checkable
        class UnifiedWriteResultProtocol(Protocol):
            """Unified protocol for all write result types."""

            def get_content(self) -> str:
                """Get written content."""
                ...

        @runtime_checkable
        class ServiceWithExecuteProtocol(Protocol[TResult]):
            """Protocol for services with execute method."""

            def execute(self, **_kwargs: str | int | bool) -> FlextResult[TResult]:
                """Execute service operation."""
                ...

        @runtime_checkable
        class ObjectWithMetadataProtocol(Protocol):
            """Protocol for objects with metadata."""

            metadata: dict[str, str | int | bool | list[str]]

        @runtime_checkable
        class ConstantsClassProtocol(Protocol):
            """Protocol for classes with constants."""

            SERVER_TYPE: ClassVar[str]
            PRIORITY: ClassVar[int]

        @runtime_checkable
        class FixtureLoaderProtocol(Protocol):
            """Protocol for fixture loaders."""

            def load_fixture(self, name: str) -> str | dict[str, str]:
                """Load fixture by name."""
                ...

            def get_fixture_path(self, server_type: str, fixture_name: str) -> Path:
                """Get fixture path for server type and name."""
                ...

        @runtime_checkable
        class QuirkInstanceProtocol(Protocol):
            """Protocol for quirk instances."""

            server_type: str
            priority: int

        @runtime_checkable
        class ServiceInstanceProtocol(Protocol[TResult]):
            """Protocol for service instances."""

            def parse(self, data: str | dict[str, str]) -> FlextResult[TResult]:
                """Parse data."""
                ...

        @runtime_checkable
        class CategorizationServiceProtocol(Protocol):
            """Protocol for categorization services.

            Defines the interface for entry categorization without circular imports.
            Used to break circular dependency between filters and categorization services.
            """

            def categorize_entry(
                self,
                entry: FlextLdifProtocols.Models.EntryProtocol,
                rules: dict[str, object],
                server_type: str,
            ) -> tuple[str, str]:
                """Categorize an entry into categories (schema, hierarchy, users, groups, acl, rejected).

                Args:
                    entry: Entry to categorize
                    rules: Categorization rules configuration
                    server_type: LDAP server type

                Returns:
                    Tuple of (category, reason) where category is one of the 6 categories

                """
                ...

        @runtime_checkable
        class FilterServiceProtocol(Protocol):
            """Protocol for filter services.

            Defines the interface for entry filtering without circular imports.
            Used to break circular dependency between categorization and filter services.
            """

            def filter_schema_by_oids(
                self,
                entries: list[FlextLdifProtocols.Models.EntryProtocol],
                allowed_oids: dict[str, list[str]],
            ) -> FlextResult[list[FlextLdifProtocols.Models.EntryProtocol]]:
                """Filter schema entries by allowed OIDs.

                Args:
                    entries: Schema entries to filter
                    allowed_oids: Dict of allowed OIDs by type

                Returns:
                    FlextResult with filtered entries

                """
                ...

    class Quirks:
        """LDIF quirk protocols for server-specific extensions."""

        @runtime_checkable
        class SchemaProtocol(Protocol):
            """Protocol for schema-level quirks - minimal public interface.

            Schema quirks handle RFC 4512 schema parsing with server-specific
            extensions for attributeTypes and objectClasses.

            Implemented by:
            - FlextLdifServersOid (Oracle OID)
            - FlextLdifServersOud (Oracle OUD)
            - FlextLdifServersOpenldap (OpenLDAP)
            - FlextLdifServersRfc (RFC baseline)

            **PUBLIC INTERFACE** (protocol-required):
            1. parse(str) -> "FlextResult[SchemaAttribute | SchemaObjectClass]"
            2. write(SchemaAttribute | SchemaObjectClass) -> "FlextResult[str]"
            3. execute(data, operation) ->
              "FlextResult[SchemaAttribute | SchemaObjectClass | str]"

            **Private Methods** (NOT in protocol, internal only):
            - can_handle_attribute() - Detection logic
            - can_handle_objectclass() - Detection logic
            - _hook_post_parse_attribute() - Customization hook
            - _hook_post_parse_objectclass() - Customization hook
            - _detect_schema_type() - Helper for attribute vs objectClass detection
            """

            server_type: str
            """Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc')."""

            priority: int
            """Quirk priority (lower number = higher priority)."""

            def parse(
                self,
                definition: str,
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
                """Write schema model."""
                ...

            def parse_attribute(
                self,
                attr_definition: str,
            ) -> FlextResult[FlextLdifProtocols.Models.SchemaAttributeProtocol]:
                """Parse attribute definition."""
                ...

            def write_attribute(
                self,
                attr_data: FlextLdifProtocols.Models.SchemaAttributeProtocol,
            ) -> FlextResult[str]:
                """Write attribute model."""
                ...

            def parse_objectclass(
                self,
                oc_definition: str,
            ) -> FlextResult[FlextLdifProtocols.Models.SchemaObjectClassProtocol]:
                """Parse objectclass definition."""
                ...

            def write_objectclass(
                self,
                oc_data: FlextLdifProtocols.Models.SchemaObjectClassProtocol,
            ) -> FlextResult[str]:
                """Write objectclass model."""
                ...

            def execute(
                self,
                **kwargs: str | int | bool | dict[str, str],
            ) -> FlextResult[
                FlextLdifProtocols.Models.SchemaAttributeProtocol
                | FlextLdifProtocols.Models.SchemaObjectClassProtocol
                | str
            ]:
                """Execute operation with automatic type detection and routing.

                Polymorphic dispatch based on kwargs:
                - definition (str) -> parse -> SchemaAttribute | SchemaObjectClass
                - model (SchemaAttribute | SchemaObjectClass) -> write -> str

                Args:
                    **kwargs: definition (str) OR model (SchemaAttribute | SchemaObjectClass)

                Returns:
                    FlextResult[SchemaAttribute | SchemaObjectClass | str]

                """
                ...

        @runtime_checkable
        class AclProtocol(Protocol):
            """Protocol for ACL-level quirks - minimal public interface.

            ACL quirks handle server-specific access control list processing
            for orclaci, orclentrylevelaci, olcAccess, and other ACL formats.

            Implemented by:
            - FlextLdifServersOid (Oracle OID ACL format)
            - FlextLdifServersOud (Oracle OUD ACL format)
            - FlextLdifServersOpenldap (OpenLDAP olcAccess format)
            - FlextLdifServersRfc (RFC-based ACL handling)

            **PUBLIC INTERFACE** (protocol-required):
            1. parse(str) -> "FlextResult[Acl]"
            2. write(Acl) -> "FlextResult[str]"
            3. execute(data, operation) -> "FlextResult[Acl | str]"

            **Private Methods** (NOT in protocol, internal only):
            - __can_handle() - Detection logic
            - _hook_post_parse() - Customization hook
            - Conversion handled via conversion service
            """

            server_type: str
            """Server type identifier."""

            priority: int
            """Quirk priority (lower number = higher priority)."""

            def parse(
                self, acl_line: str
            ) -> FlextResult[FlextLdifProtocols.Models.AclProtocol]:
                """Parse ACL line to Acl model.

                Args:
                    acl_line: ACL definition line (e.g., orclaci, olcAccess)

                Returns:
                    "FlextResult[FlextLdifProtocols.Models.AclProtocol]"

                """
                ...

            def write(
                self, acl_data: FlextLdifProtocols.Models.AclProtocol
            ) -> FlextResult[str]:
                """Write Acl model to string format.

                Args:
                    acl_data: FlextLdifProtocols.Models.AclProtocol

                Returns:
                    "FlextResult[str]" with ACL line

                """
                ...

            def execute(
                self,
                **_kwargs: str | int | bool | dict[str, str],
            ) -> FlextResult[FlextLdifProtocols.Models.AclProtocol | str]:
                """Execute with automatic type detection and routing.

                Polymorphic dispatch based on kwargs:
                - acl_line (str) -> parse -> Acl
                - acl_model (Acl) -> write -> str

                Args:
                    **_kwargs: acl_line (str) OR acl_model (Acl)

                Returns:
                    FlextResult[Acl | str]

                """
                ...

            def convert_rfc_acl_to_aci(
                self,
                rfc_acl_attrs: dict[str, list[str]],
                target_server: str,
            ) -> FlextResult[dict[str, list[str]]]:
                """Convert RFC ACL format to server-specific ACI format.

                Args:
                    rfc_acl_attrs: ACL attributes in RFC format
                    target_server: Target server type identifier

                Returns:
                    "FlextResult[dict[str, list[str]]]" with server-specific ACL attributes

                """
                ...

            def format_acl_value(
                self,
                acl_value: str,
                acl_metadata: FlextLdifProtocols.Models.AclWriteMetadataProtocol,
                *,
                use_original_format_as_name: bool = False,
            ) -> FlextResult[str]:
                """Format ACL value for writing, optionally using original format as name.

                This method handles ACL-specific formatting during LDIF writing,
                replacing generated ACL names with the original ACL format when requested.
                Follows SRP by moving ACL formatting logic from Writer to ACL quirks.

                Args:
                    acl_value: The ACL string value to format (e.g., ACI attribute value).
                    acl_metadata: AclWriteMetadata extracted from entry metadata.
                    use_original_format_as_name: If True, replace acl "name" with
                        sanitized original format from metadata.

                Returns:
                    FlextResult[str] with formatted ACL value, or unchanged value
                    if formatting not applicable.

                Example:
                    >>> metadata = AclWriteMetadata.from_extensions(
                    ...     entry.metadata.extensions
                    ... )
                    >>> result = acl_quirk.format_acl_value(
                    ...     aci_value, metadata, use_original_format_as_name=True
                    ... )

                """
                ...

        @runtime_checkable
        class EntryProtocol(Protocol):
            """Protocol for entry-level quirks - minimal public interface.

            Entry quirks handle LDAP entry processing with server-specific
            attribute handling, DN normalization, and operational attributes.

            Implemented by:
            - FlextLdifServersOid (Oracle OID entry handling)
            - FlextLdifServersOud (Oracle OUD entry handling)
            - FlextLdifServersOpenldap (OpenLDAP entry handling)
            - FlextLdifServersRfc (RFC baseline)

            **PUBLIC INTERFACE** (protocol-required):
            1. parse(str) -> "FlextResult[list[Entry]]"
            2. write(Entry) -> "FlextResult[str]"
            3. execute(data, operation) -> "FlextResult[list[Entry] | str]"

            **Private Methods** (NOT in protocol, internal only):
            - can_handle(dn, attributes) - Entry detection logic
            - can_handle_entry(entry) - Entry-level validation
            - Hooks: _hook_validate_entry_raw(), _hook_post_parse_entry(), _hook_pre_write_entry()
            - process_entry, convert_entry handled via hooks or conversion

            NOTE: can_handle_attribute() and can_handle_objectclass() are Schema-level
            methods only, not used at Entry level.
            """

            server_type: str
            """Server type identifier."""

            priority: int
            """Quirk priority (lower number = higher priority)."""

            def parse(
                self,
                ldif_content: str,
            ) -> FlextResult[list[FlextLdifProtocols.Models.EntryProtocol]]:
                """Parse LDIF content string into Entry models.

                Args:
                    ldif_content: Raw LDIF content as string

                Returns:
                    "FlextResult[list[FlextLdifProtocols.Models.EntryProtocol]]"

                """
                ...

            def write(
                self,
                entry_data: FlextLdifProtocols.Models.EntryProtocol
                | list[FlextLdifProtocols.Models.EntryProtocol],
                write_options: FlextLdifProtocols.Models.WriteFormatOptionsProtocol
                | None = None,
            ) -> FlextResult[str]:
                """Write Entry model to RFC-compliant LDIF string.

                Args:
                    entry_data: FlextLdifProtocols.Models.EntryProtocol or list[FlextLdifProtocols.Models.EntryProtocol]
                    write_options: Optional WriteFormatOptions for controlling output format
                        - ldif_changetype: 'add' (default), 'modify', 'delete', 'modrdn'
                        - ldif_modify_operation: 'add', 'replace', 'delete' (for changetype=modify)

                Returns:
                    "FlextResult[str]" with LDIF string

                """
                ...

            def parse_entry(
                self,
                entry_dn: str,
                entry_attrs: Mapping[str, str | list[str]],
            ) -> FlextResult[FlextLdifProtocols.Models.EntryProtocol]:
                """Parse a single entry from DN and attributes.

                Args:
                    entry_dn: Entry distinguished name
                    entry_attrs: Entry attributes mapping

                Returns:
                    FlextResult[Entry] with parsed entry model

                """
                ...

            def execute(
                self,
                **_kwargs: str | int | bool | dict[str, str],
            ) -> FlextResult[FlextLdifProtocols.Models.EntryProtocol | str]:
                """Execute with automatic type detection and routing.

                Polymorphic dispatch based on kwargs:
                - ldif_content (str) -> parse -> Entry
                - entry_model (Entry) -> write -> str

                Args:
                    **_kwargs: ldif_content (str) OR entry_model (Entry)

                Returns:
                    FlextResult[Entry | str]

                """
                ...

        @runtime_checkable
        class QuirksPort(Protocol):
            """A universal, model-driven port for handling server-specific LDIF quirks.

            All communication with services (parser, writer, migration, etc.) should happen
            through this interface using the Entry, SchemaAttribute, SchemaObjectClass,
            and Acl models. This ensures a standardized, type-safe contract between
            the services layer and the server-specific implementation layer.

            The port is responsible for two main categories of operations:
            1.  **Model-to-Model Transformation**: Converting models between the canonical
                RFC representation and a server-specific representation. This is used by
                services like the migration pipeline.
            2.  **Raw-to-Model Parsing & Model-to-Raw Writing**: Encapsulating the logic
                of parsing raw data (LDIF strings, dictionaries) into standardized models
                and writing those models back to LDIF strings. This is used by the
                Parser and Writer services.
            """

            server_type: str
            """Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc').
            Must match a value from `FlextLdifConstants.ServerTypes`.
            """

            priority: int
            """Quirk priority (lower number = higher priority). Used by the registry
            to select the most specific quirk available.
            """

            def parse(
                self,
                ldif_text: str,
            ) -> FlextResult[list[FlextLdifProtocols.Models.EntryProtocol]]:
                """Parse LDIF text to Entry models.

                Args:
                    ldif_text: LDIF content as string.

                Returns:
                    "FlextResult" with list of Entry models.

                """
                ...

            def write(
                self,
                entries: list[FlextLdifProtocols.Models.EntryProtocol],
            ) -> FlextResult[str]:
                """Write Entry models to LDIF text.

                Args:
                    entries: List of Entry models to write.

                Returns:
                    "FlextResult" with LDIF text as string.

                """
                ...

        @runtime_checkable
        class ConversionMatrixProtocol(Protocol):
            """Protocol for conversion matrix operations.

            Handles NxN server conversions using RFC as intermediate format:
            Source Server -> RFC Format -> Target Server

            Responsibilities:
            1. Convert schema elements between servers
            2. Convert entries between servers
            3. Convert ACLs between servers
            4. Track DN case registry for OUD compatibility
            """

            def convert(
                self,
                source: FlextLdifProtocols.Quirks.QuirksPort,
                target: FlextLdifProtocols.Quirks.QuirksPort,
                model_instance: FlextLdifProtocols.Models.EntryProtocol
                | FlextLdifProtocols.Models.SchemaAttributeProtocol
                | FlextLdifProtocols.Models.SchemaObjectClassProtocol
                | FlextLdifProtocols.Models.AclProtocol,
            ) -> FlextResult[
                FlextLdifProtocols.Models.EntryProtocol
                | FlextLdifProtocols.Models.SchemaAttributeProtocol
                | FlextLdifProtocols.Models.SchemaObjectClassProtocol
                | FlextLdifProtocols.Models.AclProtocol
            ]:
                """Convert a model from a source server format to a target server format.

                This is the core method for all transformations. It orchestrates the
                two-step conversion process (Source -> RFC -> Target) by delegating
                to the appropriate `normalize_*_to_rfc` and `denormalize_*_from_rfc`
                methods on the provided quirk ports.

                Args:
                    source: The quirk port implementation for the source server.
                    target: The quirk port implementation for the target server.
                    model_instance: The Pydantic model instance to convert.

                Returns:
                    A "FlextResult" containing the converted Pydantic model in the
                    target server's format.

                """
                ...

        @runtime_checkable
        class QuirkRegistryProtocol(Protocol):
            """Protocol for quirk registry operations.

            Manages discovery, registration, and retrieval of quirks.

            Responsibilities:
            1. Register quirks when classes are defined
            2. Retrieve quirks by server type
            3. Find best-fit quirk by priority
            4. Manage global registry singleton
            """

            def get_best_schema(
                self,
                server_type: str,
            ) -> FlextResult[FlextLdifProtocols.Quirks.SchemaProtocol]:
                """Get best-fit schema quirk for server type.

                Args:
                    server_type: Server type identifier

                Returns:
                    "FlextResult" with highest-priority schema quirk

                """
                ...

            @staticmethod
            def get_global_instance() -> (
                FlextLdifProtocols.Quirks.QuirkRegistryProtocol
            ):
                """Get global registry singleton instance.

                Returns:
                    Global QuirkRegistry instance

                """
                ...

    class Entry:
        """General entry processing protocols for LDIF operations."""

        @runtime_checkable
        class EntryWithDnProtocol(Protocol):
            """Protocol for objects that have a DN and attributes."""

            dn: str
            attributes: dict[str, list[str]]

        @runtime_checkable
        class LdifAttributesProtocol(Protocol):
            """Protocol for LDIF attributes container.

            Defines the interface for attribute storage with metadata.
            """

            attributes: dict[str, list[str]]
            """Attribute name to values list."""

            attribute_metadata: dict[str, dict[str, str | list[str]]]
            """Per-attribute metadata (status, deleted_at, etc.)."""

            def get_active_attributes(self) -> dict[str, list[str]]:
                """Get only active attributes (exclude deleted/hidden)."""
                ...

            def get_deleted_attributes(
                self,
            ) -> dict[str, dict[str, str | list[str]]]:
                """Get soft-deleted attributes with metadata."""
                ...

            def to_ldap3(
                self, exclude: list[str] | None = None
            ) -> dict[str, list[str]]:
                """Convert to ldap3-compatible dict."""
                ...

    @runtime_checkable
    class AttributeValueProtocol(Protocol):
        """Protocol for objects that contain attribute values.

        This protocol defines the minimal interface for attribute value objects
        that can be processed by the LDIF API. Objects satisfying this protocol
        have a .values property or can be iterated directly.

        Used by:
        - FlextLdif.get_attribute_values() for extracting values from various formats
        - Entry processing operations
        - Attribute transformation operations

        Implementation:
        Any object with 'values' attribute or that is iterable/list/string
        satisfies this protocol through structural typing.
        """

        values: list[str] | str
        """Attribute values as list or single string value."""

    @runtime_checkable
    class ServerAclProtocol(Protocol):
        """Protocol for LDAP server ACL attribute handling.

        Defines interface for servers to customize ACL attributes.
        RFC Foundation is base for all servers, customization per server type.

        Each server implementation (OID, OUD, OpenLDAP, etc.) provides:
        1. RFC_ACL_ATTRIBUTES - Standard LDAP ACL attributes (RFC foundation)
        2. Server-specific extensions (e.g., OID_ACL_ATTRIBUTES, OUD_ACL_ATTRIBUTES)
        3. get_acl_attributes() - Returns RFC + server-specific attributes
        4. is_acl_attribute() - Checks if attribute is ACL (case-insensitive)

        Usage:
        >>> from flext_ldif.servers.oid import FlextLdifServersOid
        >>> acl = FlextLdifServersOid.Acl()
        >>> attrs = acl.get_acl_attributes()
        >>> # Returns RFC + OID-specific ACL attributes
        >>> assert "aci" in attrs  # RFC foundation
        >>> assert "orclaci" in attrs  # OID-specific
        >>> assert acl.is_acl_attribute("ACI")  # Case-insensitive
        """

        RFC_ACL_ATTRIBUTES: ClassVar[list[str]]
        """RFC Foundation - Standard LDAP attributes (all servers start here)."""

        def get_acl_attributes(self) -> list[str]:
            """Get ACL attributes for this server.

            Returns RFC foundation + server-specific customizations/expansions.
            Each server implements to return appropriate attributes.

            Returns:
                List of ACL attribute names (lowercase)

            """
            ...

        def is_acl_attribute(self, attribute_name: str) -> bool:
            """Check if attribute is ACL attribute for this server.

            Args:
                attribute_name: Attribute name to check (case-insensitive)

            Returns:
                True if attribute is ACL attribute, False otherwise

            """
            ...


__all__ = [
    "FlextLdifProtocols",
]
