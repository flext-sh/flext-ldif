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

from typing import Any, Protocol, runtime_checkable

from flext_core import FlextProtocols, FlextResult


class FlextLdifProtocols(FlextProtocols):
    """Unified LDIF protocol definitions extending FlextProtocols.

    This class extends the base FlextProtocols with LDIF-specific protocol
    definitions, using Python's typing.Protocol for structural subtyping
    (duck typing).

    Provides strict interface contracts for:
    1. Schema Processing Quirks (attributes, objectClasses)
    2. ACL Processing Quirks (access control lists)
    3. Entry Processing Quirks (LDAP entries)
    4. Conversion Operations (format conversions)
    5. Registry Operations (quirk management)

    Architecture:
    - All protocols use @runtime_checkable for isinstance() validation
    - All methods return FlextResult[T] for railway-oriented error handling
    - All quirks must satisfy corresponding protocol for type safety
    - Inheritance hierarchy allows shared method signatures

    Usage Pattern:
        >>> class MySchema:
        ...     def can_handle_attribute(self, attr: str) -> bool:
        ...         return "MY_" in attr
        ...
        ...     def parse_attribute(self, attr: str) -> FlextResult:
        ...         # Parse logic
        ...         return FlextResult.ok({})
        >>> quirk = MySchema()
        >>> isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol)
        True  # Satisfies protocol through structural typing
    """

    # =========================================================================
    # INHERIT FOUNDATION PROTOCOLS - Available through inheritance
    # =========================================================================

    # Foundation, Domain, Application, Infrastructure, Extensions, Commands
    # are all inherited from FlextProtocols - no need to re-export

    # =========================================================================
    # LDIF-SPECIFIC PROTOCOLS - Domain extension for LDIF operations
    # =========================================================================

    class Quirks:
        """LDIF quirk protocols for server-specific extensions."""

        # =====================================================================
        # SCHEMA QUIRK PROTOCOLS - For attribute and objectClass processing
        # =====================================================================

        @runtime_checkable
        class SchemaProtocol(Protocol):
            """Protocol for schema-level quirks.

            Schema quirks handle RFC 4512 schema parsing with server-specific
            extensions for attributeTypes and objectClasses.

            Implemented by:
            - FlextLdifServersOid (Oracle OID)
            - FlextLdifServersOud (Oracle OUD)
            - FlextLdifServersOpenldap (OpenLDAP)
            - FlextLdifServersRfc (RFC baseline)

            Responsibilities:
            1. Determine if can handle an attribute/objectClass (can_handle_*)
            2. Parse attribute/objectClass definitions (parse_*)
            3. Convert to/from RFC format (convert_*_to_rfc, convert_*_from_rfc)
            4. Write back to RFC-compliant format (write_*_to_rfc)
            """

            server_type: str
            """Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc')."""

            priority: int
            """Quirk priority (lower number = higher priority)."""

            # -----------------------------------------------------------------
            # ATTRIBUTE PROCESSING METHODS
            # -----------------------------------------------------------------

            def can_handle_attribute(self, attr_definition: str) -> bool:
                """Check if this quirk can handle the attribute definition.

                Args:
                    attr_definition: AttributeType definition string

                Returns:
                    True if this quirk should process this attribute

                """
                ...

            def parse_attribute(
                self,
                attr_definition: str,
            ) -> FlextResult[dict[str, object]]:
                """Parse server-specific attribute definition.

                Extracts attribute metadata (OID, NAME, DESC, SYNTAX, etc.)
                from RFC 4512 format and applies server-specific enhancements.

                Args:
                    attr_definition: AttributeType definition string

                Returns:
                    FlextResult with parsed attribute data as dictionary

                """
                ...

            def convert_attribute_to_rfc(
                self,
                attr_data: dict[str, object],
            ) -> FlextResult[dict[str, object]]:
                """Convert server-specific attribute to RFC-compliant format.

                Transforms server-specific attribute extensions to standard
                RFC 4512 format for universal compatibility.

                Args:
                    attr_data: Server-specific attribute data dictionary

                Returns:
                    FlextResult with RFC-compliant attribute data

                """
                ...

            def convert_attribute_from_rfc(
                self,
                rfc_data: dict[str, object],
            ) -> FlextResult[dict[str, object]]:
                """Convert RFC-compliant attribute to server-specific format.

                Enhances standard RFC attribute with server-specific extensions.

                Args:
                    rfc_data: RFC-compliant attribute data dictionary

                Returns:
                    FlextResult with server-specific attribute data

                """
                ...

            def write_attribute_to_rfc(
                self,
                attr_data: dict[str, object],
            ) -> FlextResult[str]:
                """Write attribute data to RFC-compliant string format.

                Serializes attribute data back to RFC 4512 string representation.

                Args:
                    attr_data: Attribute data dictionary

                Returns:
                    FlextResult with RFC-compliant attribute string

                """
                ...

            # -----------------------------------------------------------------
            # OBJECTCLASS PROCESSING METHODS
            # -----------------------------------------------------------------

            def can_handle_objectclass(self, oc_definition: str) -> bool:
                """Check if this quirk can handle the objectClass definition.

                Args:
                    oc_definition: ObjectClass definition string

                Returns:
                    True if this quirk should process this objectClass

                """
                ...

            def parse_objectclass(
                self,
                oc_definition: str,
            ) -> FlextResult[dict[str, object]]:
                """Parse server-specific objectClass definition.

                Extracts objectClass metadata (OID, NAME, SUP, MUST, MAY, etc.)
                from RFC 4512 format and applies server-specific enhancements.

                Args:
                    oc_definition: ObjectClass definition string

                Returns:
                    FlextResult with parsed objectClass data as dictionary

                """
                ...

            def convert_objectclass_to_rfc(
                self,
                oc_data: dict[str, object],
            ) -> FlextResult[dict[str, object]]:
                """Convert server-specific objectClass to RFC-compliant format.

                Transforms server-specific objectClass extensions to standard
                RFC 4512 format for universal compatibility.

                Args:
                    oc_data: Server-specific objectClass data dictionary

                Returns:
                    FlextResult with RFC-compliant objectClass data

                """
                ...

            def convert_objectclass_from_rfc(
                self,
                rfc_data: dict[str, object],
            ) -> FlextResult[dict[str, object]]:
                """Convert RFC-compliant objectClass to server-specific format.

                Enhances standard RFC objectClass with server-specific extensions.

                Args:
                    rfc_data: RFC-compliant objectClass data dictionary

                Returns:
                    FlextResult with server-specific objectClass data

                """
                ...

            def write_objectclass_to_rfc(
                self,
                oc_data: dict[str, object],
            ) -> FlextResult[str]:
                """Write objectClass data to RFC-compliant string format.

                Serializes objectClass data back to RFC 4512 string representation.

                Args:
                    oc_data: ObjectClass data dictionary

                Returns:
                    FlextResult with RFC-compliant objectClass string

                """
                ...

        # =====================================================================
        # ACL QUIRK PROTOCOLS - For access control processing
        # =====================================================================

        @runtime_checkable
        class AclProtocol(Protocol):
            """Protocol for ACL-level quirks.

            ACL quirks handle server-specific access control list processing
            for orclaci, orclentrylevelaci, olcAccess, and other ACL formats.

            Implemented by:
            - FlextLdifServersOid (Oracle OID ACL format)
            - FlextLdifServersOud (Oracle OUD ACL format)
            - FlextLdifServersOpenldap (OpenLDAP olcAccess format)
            - FlextLdifServersRfc (RFC-based ACL handling)

            Responsibilities:
            1. Determine if can handle an ACL definition (can_handle_acl)
            2. Parse ACL definitions (parse_acl)
            3. Convert to/from RFC format (convert_acl_to_rfc, convert_acl_from_rfc)
            4. Write back to RFC-compliant format (write_acl_to_rfc)
            """

            server_type: str
            """Server type identifier."""

            priority: int
            """Quirk priority (lower number = higher priority)."""

            def can_handle_acl(self, acl_line: str) -> bool:
                """Check if this quirk can handle the ACL definition.

                Args:
                    acl_line: ACL definition line

                Returns:
                    True if this quirk should process this ACL

                """
                ...

            def parse_acl(self, acl_line: str) -> FlextResult[dict[str, object]]:
                """Parse server-specific ACL definition.

                Extracts ACL metadata and permissions from server-specific format.

                Args:
                    acl_line: ACL definition line

                Returns:
                    FlextResult with parsed ACL data as dictionary

                """
                ...

            def convert_acl_to_rfc(
                self,
                acl_data: dict[str, object],
            ) -> FlextResult[dict[str, object]]:
                """Convert server-specific ACL to RFC-compliant format.

                Transforms server-specific ACL extensions to standard format.

                Args:
                    acl_data: Server-specific ACL data dictionary

                Returns:
                    FlextResult with RFC-compliant ACL data

                """
                ...

            def convert_acl_from_rfc(
                self,
                acl_data: dict[str, object],
            ) -> FlextResult[dict[str, object]]:
                """Convert RFC-compliant ACL to server-specific format.

                Enhances standard RFC ACL with server-specific extensions.

                Args:
                    acl_data: RFC-compliant ACL data dictionary

                Returns:
                    FlextResult with server-specific ACL data

                """
                ...

            def write_acl_to_rfc(self, acl_data: dict[str, object]) -> FlextResult[str]:
                """Write ACL data to RFC-compliant string format.

                Serializes ACL data back to RFC-based string representation.

                Args:
                    acl_data: ACL data dictionary

                Returns:
                    FlextResult with RFC-compliant ACL string

                """
                ...

        # =====================================================================
        # ENTRY QUIRK PROTOCOLS - For entry processing
        # =====================================================================

        @runtime_checkable
        class EntryProtocol(Protocol):
            """Protocol for entry-level quirks.

            Entry quirks handle LDAP entry processing with server-specific
            attribute handling, DN normalization, and operational attributes.

            Implemented by:
            - FlextLdifServersOid (Oracle OID entry handling)
            - FlextLdifServersOud (Oracle OUD entry handling)
            - FlextLdifServersOpenldap (OpenLDAP entry handling)
            - FlextLdifServersRfc (RFC baseline)

            Responsibilities:
            1. Determine if can handle an entry (can_handle_entry)
            2. Process entries with server logic (process_entry)
            3. Convert to/from RFC format (convert_entry_to_rfc, etc.)
            """

            server_type: str
            """Server type identifier."""

            priority: int
            """Quirk priority (lower number = higher priority)."""

            def can_handle_entry(
                self,
                entry_dn: str,
                attributes: dict[str, object],
            ) -> bool:
                """Check if this quirk can handle the entry.

                Args:
                    entry_dn: Entry distinguished name
                    attributes: Entry attributes dictionary

                Returns:
                    True if this quirk should process this entry

                """
                ...

            def process_entry(
                self,
                entry_dn: str,
                attributes: dict[str, object],
            ) -> FlextResult[dict[str, object]]:
                """Process entry with server-specific logic.

                Applies server-specific transformations to entry data
                (DN normalization, attribute filtering, etc.).

                Args:
                    entry_dn: Entry distinguished name
                    attributes: Entry attributes dictionary

                Returns:
                    FlextResult with processed entry data

                """
                ...

            def convert_entry_to_rfc(
                self,
                entry_data: dict[str, object],
            ) -> FlextResult[dict[str, object]]:
                """Convert server-specific entry to RFC-compliant format.

                Transforms server-specific entry format to RFC 2849 standard.

                Args:
                    entry_data: Server-specific entry data dictionary

                Returns:
                    FlextResult with RFC-compliant entry data

                """
                ...

            def convert_entry_from_rfc(
                self,
                rfc_data: dict[str, object],
            ) -> FlextResult[dict[str, object]]:
                """Convert RFC-compliant entry to server-specific format.

                Enhances standard RFC entry with server-specific extensions.

                Args:
                    rfc_data: RFC-compliant entry data dictionary

                Returns:
                    FlextResult with server-specific entry data

                """
                ...

        # =====================================================================
        # CONVERSION MATRIX PROTOCOLS - For server-to-server conversions
        # =====================================================================

        @runtime_checkable
        class ConversionMatrixProtocol(Protocol):
            """Protocol for conversion matrix operations.

            Handles N×N server conversions using RFC as intermediate format:
            Source Server → RFC Format → Target Server

            Responsibilities:
            1. Convert schema elements between servers
            2. Convert entries between servers
            3. Convert ACLs between servers
            4. Track DN case registry for OUD compatibility
            """

            def convert(
                self,
                source_quirk: FlextLdifProtocols.Quirks.SchemaProtocol,
                target_quirk: FlextLdifProtocols.Quirks.SchemaProtocol,
                _element_type: str,
                _element_data: str | dict[str, object],
            ) -> FlextResult[str | dict[str, object]]:
                """Convert schema element between two servers via RFC format.

                Performs: Source → RFC → Target conversion with automatic
                DN case registry management for OUD compatibility.

                Args:
                    source_quirk: Source server quirk implementation
                    target_quirk: Target server quirk implementation
                    _element_type: Type of element ('attribute', 'objectclass', 'entry', 'acl')
                    _element_data: Element data to convert (string or dict)

                Returns:
                    FlextResult with converted element data

                """
                ...

        # =====================================================================
        # REGISTRY PROTOCOLS - For quirk discovery and management
        # =====================================================================

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

            def register_schema_quirk(
                self,
                quirk: FlextLdifProtocols.Quirks.SchemaProtocol,
            ) -> FlextResult[None]:
                """Register a schema quirk.

                Args:
                    quirk: Schema quirk to register

                Returns:
                    FlextResult[None]: Registration success

                """
                ...

            def register_acl_quirk(
                self,
                quirk: FlextLdifProtocols.Quirks.AclProtocol,
            ) -> FlextResult[None]:
                """Register an ACL quirk.

                Args:
                    quirk: ACL quirk to register

                Returns:
                    FlextResult[None]: Registration success

                """
                ...

            def register_entry_quirk(
                self,
                quirk: FlextLdifProtocols.Quirks.EntryProtocol,
            ) -> FlextResult[None]:
                """Register an entry quirk.

                Args:
                    quirk: Entry quirk to register

                Returns:
                    FlextResult[None]: Registration success

                """
                ...

            def get_schema_quirks(self, server_type: str) -> FlextResult[list[object]]:
                """Get schema quirks for server type.

                Args:
                    server_type: Server type identifier

                Returns:
                    FlextResult with list of schema quirks ordered by priority

                """
                ...

            def get_best_schema_quirk(
                self,
                server_type: str,
            ) -> FlextResult[FlextLdifProtocols.Quirks.SchemaProtocol]:
                """Get best-fit schema quirk for server type.

                Args:
                    server_type: Server type identifier

                Returns:
                    FlextResult with highest-priority schema quirk

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

    # =========================================================================
    # ENTRY PROTOCOLS - General entry processing protocols
    # =========================================================================

    class Entry:
        """General entry processing protocols for LDIF operations."""

        @runtime_checkable
        class EntryWithDnProtocol(Protocol):
            """Protocol for objects that have a DN and attributes.

            This protocol defines the minimal interface for LDAP entries
            that can be processed by the LDIF API. Objects satisfying this
            protocol have a DN (distinguished name) and attributes dictionary.

            Used by:
            - FlextLdif API methods for entry processing
            - Migration operations between servers
            - Entry validation and transformation

            Implementation:
            Any object with 'dn' and 'attributes' attributes satisfies this
            protocol through structural typing (duck typing).
            """

            dn: Any  # Can be str or object with .value property
            """Entry distinguished name (DN). Can be string or object with .value."""

            attributes: Any  # Entry attributes dictionary
            """Entry attributes as dictionary mapping attribute names to values."""


__all__ = [
    "FlextLdifProtocols",
]
