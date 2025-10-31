"""Base Quirk Classes for LDIF/LDAP Server Extensions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Defines base classes for implementing server-specific quirks that extend
RFC-compliant LDIF/LDAP parsing with vendor-specific features.

Quirks allow extending the RFC base without modifying core parser logic.

ARCHITECTURE:
    Base classes use Python 3.13+ abstract base classes (ABC) with @abstractmethod
    decorators for explicit inheritance contracts, while also implementing all
    methods required by FlextLdifProtocols for structural typing validation.

    This dual approach provides:
    - Explicit inheritance contracts through ABC
    - Structural typing validation through protocols
    - isinstance() checks for protocol compliance
    - Type safety at development and runtime

PROTOCOL COMPLIANCE:
    All base classes and implementations MUST satisfy corresponding protocols:
    - FlextLdifServersBase.Schema → FlextLdifProtocols.Quirks.SchemaProtocol
    - FlextLdifServersBase.Acl → FlextLdifProtocols.Quirks.AclProtocol
    - FlextLdifServersBase.Entry → FlextLdifProtocols.Quirks.EntryProtocol

    All method signatures must match protocol definitions exactly for type safety.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import ClassVar

from flext_core import FlextLogger, FlextResult

from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols

logger = FlextLogger(__name__)


class FlextLdifServersBase(ABC, FlextLdifProtocols.Quirks.QuirksPort):
    """Abstract base class for LDIF/LDAP server quirks.

    This class defines the complete contract for a server quirk implementation
    by inheriting from `FlextLdifProtocols.Quirks.QuirksPort`. It uses the
    `ABC` helper class to define all methods from the port as abstract,
    ensuring that any concrete subclass must implement the full interface.

    It also preserves the nested abstract base classes for `Schema`, `Acl`, and
    `Entry` quirks. These nested classes define the internal implementation
    contracts that concrete server classes use to structure their specialized logic.
    """

    # =========================================================================
    # QuirksPort Protocol Implementation (Abstract Methods)
    # =========================================================================

    @abstractmethod
    def normalize_entry_to_rfc(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Convert a server-specific Entry model to the canonical RFC model."""
        ...

    @abstractmethod
    def denormalize_entry_from_rfc(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Convert a canonical RFC Entry model to a server-specific model."""
        ...

    @abstractmethod
    def normalize_attribute_to_rfc(
        self, attribute: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert a server-specific SchemaAttribute to the canonical RFC model."""
        ...

    @abstractmethod
    def denormalize_attribute_from_rfc(
        self, attribute: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert a canonical RFC SchemaAttribute to a server-specific model."""
        ...

    @abstractmethod
    def normalize_objectclass_to_rfc(
        self, objectclass: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert a server-specific SchemaObjectClass to the canonical RFC model."""
        ...

    @abstractmethod
    def denormalize_objectclass_from_rfc(
        self, objectclass: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert a canonical RFC SchemaObjectClass to a server-specific model."""
        ...

    @abstractmethod
    def normalize_acl_to_rfc(
        self, acl: FlextLdifModels.Acl
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Convert a server-specific Acl to the canonical RFC model."""
        ...

    @abstractmethod
    def denormalize_acl_from_rfc(
        self, acl: FlextLdifModels.Acl
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Convert a canonical RFC Acl to a server-specific model."""
        ...

    @abstractmethod
    def parse_ldif_content(
        self, content: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse a raw LDIF string into a list of Entry models."""
        ...

    # =========================================================================
    # Nested Abstract Base Classes for Internal Implementation
    # =========================================================================
    class Schema(ABC):
        """Base class for schema quirks - satisfies FlextLdifProtocols.Quirks.SchemaProtocol.

        NOTE: This is an implementation detail - DO NOT import directly.
        Use FlextLdifServersBase.Schema instead.

        Schema quirks extend RFC 4512 schema parsing with server-specific features
        for attribute and objectClass processing.

        **Protocol Compliance**: All implementations MUST satisfy
        FlextLdifProtocols.Quirks.SchemaProtocol through structural typing.
        This means all public methods must match protocol signatures exactly.

        **Validation**: Use isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol)
        to check protocol compliance at runtime.

        Example vendors:
        - Oracle OID: orclOID prefix, Oracle-specific syntaxes
        - Oracle OUD: Enhanced schema features
        - OpenLDAP: olc* configuration attributes
        - Active Directory: AD-specific schema extensions
        - RFC: RFC 4512 compliant baseline (no extensions)
        """

        # Registry method for DI-based automatic registration
        _REGISTRY_METHOD: ClassVar[str] = "register_schema_quirk"

        # Base configuration defaults - subclasses CAN override
        # These are class-level attributes, not instance attributes
        server_type: ClassVar[str] = "generic"
        priority: ClassVar[int] = 100

        @abstractmethod
        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize schema quirk with optional server_type and priority."""
            # Note: server_type and priority are ClassVar attributes
            # They cannot be assigned per-instance
            # Explicit pass to satisfy linter

        @abstractmethod
        @abstractmethod
        def can_handle_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Check if this quirk can handle the attribute definition.

            Args:
            attribute: AttributeType definition model

            Returns:
            True if this quirk can parse this attribute

            """

        @abstractmethod
        @abstractmethod
        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse server-specific attribute definition.

            Args:
            attr_definition: AttributeType definition string

            Returns:
            FlextResult with SchemaAttribute model

            """

        @abstractmethod
        @abstractmethod
        def can_handle_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Check if this quirk can handle the objectClass definition.

            Args:
            objectclass: ObjectClass definition model

            Returns:
            True if this quirk can parse this objectClass

            """

        @abstractmethod
        @abstractmethod
        def parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse server-specific objectClass definition.

            Args:
            oc_definition: ObjectClass definition string

            Returns:
            FlextResult with SchemaObjectClass model

            """

        @abstractmethod
        def convert_attribute_to_rfc(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert server-specific attribute to RFC-compliant format.

            Args:
                attr_data: Server-specific SchemaAttribute

            Returns:
                FlextResult with RFC-compliant SchemaAttribute

            """

        @abstractmethod
        def convert_objectclass_to_rfc(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert server-specific objectClass to RFC-compliant format.

            Args:
                oc_data: Server-specific SchemaObjectClass

            Returns:
                FlextResult with RFC-compliant SchemaObjectClass

            """

        @abstractmethod
        def convert_attribute_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert RFC-compliant attribute to server-specific format.

            Args:
                rfc_data: RFC-compliant SchemaAttribute

            Returns:
                FlextResult with server-specific SchemaAttribute

            """

        @abstractmethod
        def convert_objectclass_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert RFC-compliant objectClass to server-specific format.

            Args:
                rfc_data: RFC-compliant SchemaObjectClass

            Returns:
                FlextResult with server-specific SchemaObjectClass

            """

        def create_quirk_metadata(
            self,
            original_format: str,
            extensions: dict[str, object] | None = None,
        ) -> FlextLdifModels.QuirkMetadata:
            """Create quirk metadata with consistent server-specific extensions.

            Helper method to consolidate metadata creation across server quirks.
            Reduces code duplication in server-specific parse_attribute/parse_objectclass methods.

            Args:
                original_format: Original text format of the parsed element
                extensions: Optional dict of server-specific extensions/metadata

            Returns:
                FlextLdifModels.QuirkMetadata with quirk_type from server_type ClassVar

            """
            return FlextLdifModels.QuirkMetadata(
                quirk_type=self.server_type,
                original_format=original_format,
                extensions=extensions or {},
            )

        @abstractmethod
        def write_attribute_to_rfc(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write attribute data to RFC-compliant string format.

            Args:
            attr_data: SchemaAttribute model

            Returns:
            FlextResult with RFC-compliant attribute string

            """

        @abstractmethod
        def write_objectclass_to_rfc(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write objectClass data to RFC-compliant string format.

            Args:
                oc_data: SchemaObjectClass model

            Returns:
                FlextResult with RFC-compliant objectClass string

            """

        @abstractmethod
        def should_filter_out_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Check if an attribute should be filtered out during export.

            Schema quirks typically don't filter attributes, so default False.
            Subclasses can override if they implement attribute filtering.

            Args:
                attribute: SchemaAttribute model to check

            Returns:
                True if this attribute should be filtered out (removed from output)

            """

        @abstractmethod
        def should_filter_out_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Check if an objectClass should be filtered out during export.

            Schema quirks may filter objectClasses during export operations.

            Args:
                objectclass: SchemaObjectClass model to check

            Returns:
                True if the objectClass should be filtered out

            """

    class Acl(ABC):
        """Base class for ACL quirks - satisfies FlextLdifProtocols.Quirks.AclProtocol.

        NOTE: This is an implementation detail - DO NOT import directly.
        Use FlextLdifServersBase.Acl instead.

        ACL quirks extend RFC 4516 ACL parsing with server-specific formats
        for access control list processing.

        **Protocol Compliance**: All implementations MUST satisfy
        FlextLdifProtocols.Quirks.AclProtocol through structural typing.
        This means all public methods must match protocol signatures exactly.

        **Validation**: Use isinstance(quirk, FlextLdifProtocols.Quirks.AclProtocol)
        to check protocol compliance at runtime.

        Example vendors:
        - Oracle OID: orclaci, orclentrylevelaci
        - Oracle OUD: Enhanced ACI format
        - OpenLDAP: olcAccess directives
        - Active Directory: NT Security Descriptors
        - RFC: RFC 4516 compliant baseline
        """

        # Registry method for DI-based automatic registration
        _REGISTRY_METHOD: ClassVar[str] = "register_acl_quirk"

        # Default ACL attribute name (RFC baseline). Override in subclass for server-specific name.
        acl_attribute_name: ClassVar[str] = "acl"

        # Server type and priority defaults - Subclasses override via ClassVar declarations
        server_type: ClassVar[str] = "generic"
        priority: ClassVar[int] = 100

        @abstractmethod
        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize ACL quirk with optional server_type and priority."""
            # Note: server_type and priority are ClassVar attributes, not instance attributes
            # Explicit pass to satisfy linter
            # They are overridden in subclasses via ClassVar declarations

        @abstractmethod
        def can_handle_acl(self, acl: FlextLdifModels.Acl) -> bool:
            """Check if this quirk can handle the ACL definition.

            Args:
                acl: Acl model

            Returns:
                True if this quirk can handle this ACL

            """

        @abstractmethod
        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse server-specific ACL definition.

            Args:
            acl_line: ACL definition line

            Returns:
            FlextResult with Acl model

            """

        @abstractmethod
        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert server-specific ACL to RFC-compliant format.

            Args:
            acl_data: Server-specific Acl model

            Returns:
            FlextResult with RFC-compliant Acl model

            """

        @abstractmethod
        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert RFC-compliant ACL to server-specific format.

            Args:
            acl_data: RFC-compliant Acl model

            Returns:
            FlextResult with server-specific Acl model

            """

        @abstractmethod
        def get_acl_attribute_name(self) -> str:
            """Get the server-specific ACL attribute name.

            Returns the LDAP attribute name for ACL definitions in this server.
            Different servers use different attribute names:
            - OUD: "aci" (RFC 4876 compliant)
            - OID: "orclaci" or "orclentrylevelaci"
            - RFC baseline: "acl"

            Returns the class attribute `acl_attribute_name` which can be overridden in subclasses.

            Returns:
                Server-specific ACL attribute name

            """

        @abstractmethod
        def can_handle_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific attribute definition.

            ACL quirks may need to evaluate rules based on attribute schema properties
            (e.g., sensitivity, usage). This method allows the quirk to indicate
            if it has special handling for a given attribute model.

            Args:
                attribute: The SchemaAttribute model to check.

            Returns:
                True if this quirk has specific logic related to this attribute.

            """

        @abstractmethod
        def can_handle_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific objectClass definition.

            ACL quirks may need to evaluate rules based on objectClass properties.

            Args:
                objectclass: The SchemaObjectClass model to check.

            Returns:
                True if this quirk has specific logic related to this objectClass.

            """

        @abstractmethod
        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            Args:
                acl_data: Acl model

            Returns:
                FlextResult with RFC-compliant ACL string

            """

    class Entry(ABC):
        """Base class for entry processing quirks - satisfies FlextLdifProtocols.Quirks.EntryProtocol.

        NOTE: This is an implementation detail - DO NOT import directly.
        Use FlextLdifServersBase.Entry instead.

        Entry quirks handle server-specific entry attributes and transformations
        for LDAP entry processing.

        **Protocol Compliance**: All implementations MUST satisfy
        FlextLdifProtocols.Quirks.EntryProtocol through structural typing.
        This means all public methods must match protocol signatures exactly.

        **Validation**: Use isinstance(quirk, FlextLdifProtocols.Quirks.EntryProtocol)
        to check protocol compliance at runtime.

        Example use cases:
        - Oracle operational attributes
        - OpenLDAP configuration entries (cn=config)
        - Active Directory specific attributes
        - Server-specific DN formats
        - RFC baseline entry handling
        """

        # Registry method for DI-based automatic registration
        _REGISTRY_METHOD: ClassVar[str] = "register_entry_quirk"

        # Server type and priority defaults - Subclasses override via ClassVar declarations
        server_type: ClassVar[str] = "generic"
        priority: ClassVar[int] = 100

        @abstractmethod
        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize entry quirk with optional server_type and priority."""
            # Note: server_type and priority are ClassVar attributes, not instance attributes
            # Explicit pass to satisfy linter
            # They are overridden in subclasses via ClassVar declarations

        @abstractmethod
        def can_handle_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> bool:
            """Check if this quirk can handle the entry.

            Args:
                entry: Entry model to check

            Returns:
                True if this quirk should process this entry

            """

        @abstractmethod
        def parse_content(
            self,
            ldif_content: str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse raw LDIF content string into Entry models.

            This is the PRIMARY interface - parser.py calls this with raw LDIF content.
            Quirk internally uses ldif3 to iterate and parse all entries.

            Implementation must:
            1. Use ldif3.LDIFParser to parse LDIF content
            2. For each (dn, attrs) pair from ldif3:
               a. Call parse_entry() to transform into Entry model
            3. Return list of all parsed entries

            This is where ldif3 lives - NOT in parser.py.

            Args:
                ldif_content: Raw LDIF content as string

            Returns:
                FlextResult with list of parsed Entry objects

            """

        @abstractmethod
        def parse_entry(
            self,
            entry_dn: str,
            entry_attrs: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse individual LDIF entry data into Entry model.

            Called internally by parse_content() for each entry.

            Parsing steps:
            1. Clean/normalize DN (server-specific format)
            2. Convert raw attributes to proper format
            3. Create Entry model with validated attributes
            4. Apply server-specific post-processing via process_entry()

            Args:
                entry_dn: Raw DN string from LDIF parser
                entry_attrs: Raw attributes mapping from LDIF parser (may contain bytes values).
                           This is a Mapping (read-only) to accept dict, dict[str, list[bytes]], etc.

            Returns:
                FlextResult with parsed Entry object (fully validated and processed)

            """

        @abstractmethod
        def process_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Process entry with server-specific logic.

            Applies server-specific transformations to an Entry model, such as:
            - Attribute name normalization
            - Boolean value conversion (0/1 to TRUE/FALSE)
            - Telephone number validation
            - Metadata preservation and updates

            Args:
                entry: Entry model to process

            Returns:
                FlextResult with processed Entry model

            """

        @abstractmethod
        def convert_entry_to_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Convert server-specific entry to RFC-compliant format.

            Args:
                entry_data: Server-specific Entry model

            Returns:
                FlextResult with RFC-compliant Entry model

            """

        @abstractmethod
        def convert_entry_from_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Convert RFC-compliant entry to server-specific format.

            Args:
                entry_data: RFC-compliant Entry model

            Returns:
                FlextResult with server-specific Entry model

            """

        @abstractmethod
        def can_handle_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Check if this Entry quirk has special handling for an attribute definition.

            Entry processing logic might change based on an attribute's schema
            (e.g., handling operational attributes differently).

            Args:
                attribute: The SchemaAttribute model to check.

            Returns:
                True if this quirk has specific processing logic for this attribute.

            """

        @abstractmethod
        def can_handle_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Check if this Entry quirk has special handling for an objectClass definition.

            Entry processing logic might change based on an entry's objectClasses.

            Args:
                objectclass: The SchemaObjectClass model to check.

            Returns:
                True if this quirk has specific processing logic for this objectClass.

            """


__all__ = [
    "FlextLdifServersBase",
]
