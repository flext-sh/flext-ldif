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

from typing import ClassVar, Protocol, runtime_checkable

from flext_core import FlextProtocols, FlextResult

from flext_ldif.models import FlextLdifModels


class FlextLdifProtocols(FlextProtocols):
    r"""Unified LDIF protocol definitions extending FlextProtocols.

    This class extends the base FlextProtocols with LDIF-specific protocol
    definitions for the minimal, streamlined public interfaces of quirks.

    **Protocol Compliance Strategy:**
    1. All quirk classes inherit from ABC base classes (Schema, Acl, Entry)
    2. All base classes satisfy protocols through structural typing (duck typing)
    3. isinstance() checks validate protocol compliance at runtime
    4. All methods use FlextResult[T] for railway-oriented error handling
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

    **Usage Pattern - Maximum Automation:**
        >>> from flext_ldif.servers.base import FlextLdifServersBase
        >>> from flext_ldif.models import FlextLdifModels
        >>>
        >>> # Entry: auto-routes based on data type
        >>> entry = FlextLdifServersRfc.Entry()
        >>> entries = entry.execute("dn: cn=test\\n...")  # Parse
        >>> ldif = entry.execute([entry1, entry2])  # Write
        >>>
        >>> # Schema: auto-routes based on data type
        >>> schema = FlextLdifServersRfc.Schema()
        >>> attr = schema.execute("( 1.3... )")  # Parse attribute
        >>> text = schema.execute(attr)  # Write attribute
        >>>
        >>> # ACL: auto-routes based on data type
        >>> acl = FlextLdifServersRfc.Acl()
        >>> model = acl.execute("(target=...)")  # Parse
        >>> line = acl.execute(model)  # Write

    **Registration and Validation:**
        The FlextLdifServer validates protocol compliance automatically when quirks are:
        1. Auto-discovered during initialization
        2. Registered manually via registry.register(quirk)

        This happens at REGISTRATION TIME, not at type-checking time, ensuring all
        quirks satisfy their protocols before being used by the framework.
    """

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
            """Protocol for schema-level quirks - minimal public interface.

            Schema quirks handle RFC 4512 schema parsing with server-specific
            extensions for attributeTypes and objectClasses.

            Implemented by:
            - FlextLdifServersOid (Oracle OID)
            - FlextLdifServersOud (Oracle OUD)
            - FlextLdifServersOpenldap (OpenLDAP)
            - FlextLdifServersRfc (RFC baseline)

            **PUBLIC INTERFACE** (protocol-required):
            1. parse(str) → FlextResult[SchemaAttribute | SchemaObjectClass]
            2. write(SchemaAttribute | SchemaObjectClass) → FlextResult[str]
            3. execute(data, operation) → FlextResult[SchemaAttribute | SchemaObjectClass | str]

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

            # -----------------------------------------------------------------
            # PUBLIC METHODS - Required
            # -----------------------------------------------------------------

            def parse(
                self,
                definition: str,
            ) -> FlextResult[object]:
                """Parse schema definition (attribute or objectClass).

                Auto-detects type from content and routes appropriately.

                Args:
                    definition: RFC 4512 AttributeType or ObjectClass definition string

                Returns:
                    FlextResult[SchemaAttribute | SchemaObjectClass]

                """
                ...

            def write(
                self,
                model: object,
            ) -> FlextResult[object]:
                """Write schema model to RFC-compliant string.

                Auto-detects model type and routes to appropriate writer.

                Args:
                    model: SchemaAttribute or SchemaObjectClass model

                Returns:
                    FlextResult[str] with RFC 4512 schema definition

                """
                ...

            def execute(
                self,
                data: str | object | None = None,
                operation: str | None = None,
            ) -> FlextResult[object]:
                """Execute with automatic type detection and routing.

                Polymorphic dispatch based on data type:
                - str → auto-detect attribute vs OC → parse()
                - SchemaAttribute → write()
                - SchemaObjectClass → write()

                Args:
                    data: Schema definition string OR SchemaAttribute OR SchemaObjectClass
                    operation: Force operation ('parse' or 'write'), optional

                Returns:
                    FlextResult[SchemaAttribute | SchemaObjectClass | str]

                """
                ...

        # =====================================================================
        # ACL QUIRK PROTOCOLS - For access control processing
        # =====================================================================

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
            1. parse(str) → FlextResult[Acl]
            2. write(Acl) → FlextResult[str]
            3. execute(data, operation) → FlextResult[Acl | str]

            **Private Methods** (NOT in protocol, internal only):
            - __can_handle() - Detection logic
            - _hook_post_parse() - Customization hook
            - Conversion handled via conversion service
            """

            server_type: str
            """Server type identifier."""

            priority: int
            """Quirk priority (lower number = higher priority)."""

            def parse(self, acl_line: str) -> FlextResult[object]:
                """Parse ACL line to Acl model.

                Args:
                    acl_line: ACL definition line (e.g., orclaci, olcAccess)

                Returns:
                    FlextResult[FlextLdifModels.Acl]

                """
                ...

            def write(self, acl_data: object) -> FlextResult[object]:
                """Write Acl model to string format.

                Args:
                    acl_data: FlextLdifModels.Acl

                Returns:
                    FlextResult[str] with ACL line

                """
                ...

            def execute(
                self,
                data: str | object | None = None,
                operation: str | None = None,
            ) -> FlextResult[object]:
                """Execute with automatic type detection and routing.

                Polymorphic dispatch based on data type:
                - str → parse
                - Acl → write

                Args:
                    data: ACL line string OR Acl model
                    operation: Force operation ('parse' or 'write'), optional

                Returns:
                    FlextResult[Acl | str]

                """
                ...

        # =====================================================================
        # ENTRY QUIRK PROTOCOLS - For entry processing
        # =====================================================================

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
            1. parse(str) → FlextResult[list[Entry]]
            2. write(Entry) → FlextResult[str]
            3. execute(data, operation) → FlextResult[list[Entry] | str]

            **Private Methods** (NOT in protocol, internal only):
            - can_handle() - Detection logic
            - can_handle_attribute() - Detection logic
            - can_handle_objectclass() - Detection logic
            - Hooks: _hook_validate_entry_raw(), _hook_post_parse_entry(), _hook_pre_write_entry()
            - process_entry, convert_entry handled via hooks or conversion
            """

            server_type: str
            """Server type identifier."""

            priority: int
            """Quirk priority (lower number = higher priority)."""

            def parse(
                self,
                ldif_content: str,
            ) -> FlextResult[object]:
                """Parse LDIF content string into Entry models.

                Args:
                    ldif_content: Raw LDIF content as string

                Returns:
                    FlextResult[list[FlextLdifModels.Entry]]

                """
                ...

            def write(
                self,
                entry_data: object,
            ) -> FlextResult[object]:
                """Write Entry model to RFC-compliant LDIF string.

                Args:
                    entry_data: FlextLdifModels.Entry or list[Entry]

                Returns:
                    FlextResult[str] with LDIF string

                """
                ...

            def execute(
                self,
                data: str | list[object] | object | None = None,
                operation: str | None = None,
            ) -> FlextResult[object]:
                """Execute with automatic type detection and routing.

                Polymorphic dispatch based on data type:
                - str → parse → list[Entry]
                - list[Entry] → write → str

                Args:
                    data: LDIF content string OR list of Entry models
                    operation: Force operation ('parse' or 'write'), optional

                Returns:
                    FlextResult[list[Entry] | str]

                """
                ...

        # =====================================================================
        # UNIVERSAL QUIRK PROTOCOL - For all server-specific conversions
        # =====================================================================

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

            # =====================================================================
            # Generalized Quirk Methods - Entry-by-Entry Routing Only
            # =====================================================================
            # Only entry-by-entry routing methods are defined in the protocol.
            # Individual item methods should be called directly on the quirk subclasses
            # (entry, schema, acl) instead of through the base port.
            # These methods route each entry to the appropriate quirk based on its type.

            def parse(self, ldif_text: str) -> FlextResult[list[FlextLdifModels.Entry]]:
                """Parse LDIF text to Entry models.

                Args:
                    ldif_text: LDIF content as string.

                Returns:
                    FlextResult with list of Entry models.

                """
                ...

            def write(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
                """Write Entry models to LDIF text.

                Args:
                    entries: List of Entry models to write.

                Returns:
                    FlextResult with LDIF text as string.

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
                source: FlextLdifProtocols.Quirks.QuirksPort,
                target: FlextLdifProtocols.Quirks.QuirksPort,
                model_instance: FlextLdifModels.Entry
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | FlextLdifModels.Acl,
            ) -> FlextResult[
                FlextLdifModels.Entry
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | FlextLdifModels.Acl
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
                    A FlextResult containing the converted Pydantic model in the
                    target server's format.

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

            def get_best_schema(
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

            dn: str | object  # Can be str or object with .value property
            """Entry distinguished name (DN). Can be string or object with .value."""

            attributes: dict[str, list[str]] | object  # Entry attributes dictionary
            """Entry attributes as dictionary mapping attribute names to values."""

    # =========================================================================
    # SERVER ACL PROTOCOLS - For server-specific ACL attribute handling
    # =========================================================================

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

        Implementation Pattern:
            class FlextLdifServerOidAcl:
                RFC_ACL_ATTRIBUTES: ClassVar[list[str]] = [
                    "aci", "acl", "olcAccess", "aclRights", "aclEntry"
                ]
                OID_ACL_ATTRIBUTES: ClassVar[list[str]] = [
                    "orclaci", "orclentrylevelaci"
                ]

                def get_acl_attributes(self) -> list[str]:
                    return self.RFC_ACL_ATTRIBUTES + self.OID_ACL_ATTRIBUTES

                def is_acl_attribute(self, attribute_name: str) -> bool:
                    all_attrs = self.get_acl_attributes()
                    return attribute_name.lower() in [a.lower() for a in all_attrs]
        """

        # RFC Foundation - Standard LDAP attributes (all servers start here)
        RFC_ACL_ATTRIBUTES: ClassVar[list[str]]

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
