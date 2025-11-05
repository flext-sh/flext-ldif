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
    - _can_handle_* methods for internal detection logic
    - _hook_* methods for customization points
    - process_entry, convert_entry (handled via hooks or conversion_matrix)

    **Usage Pattern - Maximum Automation:**
        >>> from flext_ldif.servers.base import FlextLdifServersBase
        >>> from flext_ldif.models import FlextLdifModels
        >>>
        >>> # Entry: auto-routes based on data type
        >>> entry_quirk = FlextLdifServersRfc.Entry()
        >>> entries = entry_quirk.execute("dn: cn=test\\n...")  # Parse
        >>> ldif = entry_quirk.execute([entry1, entry2])  # Write
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
        The FlextLdifRegistry validates protocol compliance automatically when quirks are:
        1. Auto-discovered during initialization
        2. Registered manually via registry.register(quirk)

        This happens at REGISTRATION TIME, not at type-checking time, ensuring all
        quirks satisfy their protocols before being used by the framework.
    """

    # Define a type alias for any model that can be converted by the matrix.
    # This is defined here, alongside the protocol that uses it, to avoid
    # circular dependencies between models.py and typings.py.
    ConvertibleModel = (
        FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl
    )
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
            - _can_handle_attribute() - Detection logic
            - _can_handle_objectclass() - Detection logic
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
            ) -> FlextResult:
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
            ) -> FlextResult:
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
            ) -> FlextResult:
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
            - Conversion handled via conversion_matrix service
            """

            server_type: str
            """Server type identifier."""

            priority: int
            """Quirk priority (lower number = higher priority)."""

            def parse(self, acl_line: str) -> FlextResult:
                """Parse ACL line to Acl model.

                Args:
                    acl_line: ACL definition line (e.g., orclaci, olcAccess)

                Returns:
                    FlextResult[FlextLdifModels.Acl]

                """
                ...

            def write(self, acl_data: object) -> FlextResult:
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
            ) -> FlextResult:
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
            - _can_handle_entry() - Detection logic
            - _can_handle_attribute() - Detection logic
            - _can_handle_objectclass() - Detection logic
            - Hooks: _hook_validate_entry_raw(), _hook_post_parse_entry(), _hook_pre_write_entry()
            - process_entry, convert_entry handled via hooks or conversion_matrix
            """

            server_type: str
            """Server type identifier."""

            priority: int
            """Quirk priority (lower number = higher priority)."""

            def parse(
                self,
                ldif_content: str,
            ) -> FlextResult:
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
            ) -> FlextResult:
                """Write Entry model to RFC-compliant LDIF string.

                Args:
                    entry_data: FlextLdifModels.Entry or list[Entry]

                Returns:
                    FlextResult[str] with LDIF string

                """
                ...

            def execute(
                self,
                data: str | list | object | None = None,
                operation: str | None = None,
            ) -> FlextResult:
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
                source_quirk: FlextLdifProtocols.Quirks.QuirksPort,
                target_quirk: FlextLdifProtocols.Quirks.QuirksPort,
                model_instance: FlextLdifProtocols.ConvertibleModel,
            ) -> FlextResult[FlextLdifProtocols.ConvertibleModel]:
                """Convert a model from a source server format to a target server format.

                This is the core method for all transformations. It orchestrates the
                two-step conversion process (Source -> RFC -> Target) by delegating
                to the appropriate `normalize_*_to_rfc` and `denormalize_*_from_rfc`
                methods on the provided quirk ports.

                Args:
                    source_quirk: The quirk port implementation for the source server.
                    target_quirk: The quirk port implementation for the target server.
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
