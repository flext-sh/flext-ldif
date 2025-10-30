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
from typing import ClassVar

from flext_core import FlextLogger, FlextResult

from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes

logger = FlextLogger(__name__)


class FlextLdifServersBase(ABC):
    """Abstract base class for LDIF/LDAP server quirks.

    Provides nested abstract base classes for Schema, Acl, and Entry quirks.
    Each nested class defines contracts for server-specific implementations.
    """

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

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize schema quirk with optional server_type and priority."""
            # Note: server_type and priority are ClassVar attributes
            # They cannot be assigned per-instance
            pass  # Explicit pass to satisfy linter

        @abstractmethod
        def can_handle_attribute(self, attr_definition: str) -> bool:
            """Check if this quirk can handle the attribute definition.

            Args:
            attr_definition: AttributeType definition string

            Returns:
            True if this quirk can parse this attribute

            """

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
        def can_handle_objectclass(self, oc_definition: str) -> bool:
            """Check if this quirk can handle the objectClass definition.

            Args:
            oc_definition: ObjectClass definition string

            Returns:
            True if this quirk can parse this objectClass

            """

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

        def should_filter_out_attribute(self, _attr_definition: str) -> bool:
            """Check if an attribute should be filtered out during export.

            Schema quirks typically don't filter attributes, so default False.
            Subclasses can override if they implement attribute filtering.

            Args:
                _attr_definition: Attribute definition string

            Returns:
                True if this attribute should be filtered out (removed from output)

            """
            return False

        def should_filter_out_objectclass(self, _oc_definition: str) -> bool:
            """Check if an objectClass should be filtered out during export.

            Default implementation returns False (no filtering).
            Subclasses can override to filter out server-specific objectClasses.

            Args:
                _oc_definition: ObjectClass definition string

            Returns:
                True if the objectClass should be filtered out

            """
            return False

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

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize ACL quirk with optional server_type and priority."""
            # Note: server_type and priority are ClassVar attributes, not instance attributes
            pass  # Explicit pass to satisfy linter
            # They are overridden in subclasses via ClassVar declarations

        @abstractmethod
        def can_handle_acl(self, acl_line: str) -> bool:
            """Check if this quirk can handle the ACL definition.

            Args:
            acl_line: ACL definition line

            Returns:
            True if this quirk can parse this ACL

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
            return self.acl_attribute_name

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

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize entry quirk with optional server_type and priority."""
            # Note: server_type and priority are ClassVar attributes, not instance attributes
            pass  # Explicit pass to satisfy linter
            # They are overridden in subclasses via ClassVar declarations

        @abstractmethod
        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> bool:
            """Check if this quirk can handle the entry.

            Args:
            entry_dn: Entry distinguished name
            attributes: Entry attributes dict

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
            entry_attrs: dict[str, object],
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
                entry_attrs: Raw attributes dict from LDIF parser (may contain bytes values)

            Returns:
                FlextResult with parsed Entry object (fully validated and processed)

            """

        @abstractmethod
        def process_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Process entry with server-specific logic.

            Args:
            entry_dn: Entry distinguished name
            attributes: Entry attributes dict

            Returns:
            FlextResult with processed entry attributes

            """

        @abstractmethod
        def convert_entry_to_rfc(
            self,
            entry_data: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert server-specific entry to RFC-compliant format.

            Args:
                entry_data: Server-specific entry attributes dict

            Returns:
                FlextResult with RFC-compliant entry attributes

            """

        @abstractmethod
        def convert_entry_from_rfc(
            self,
            entry_data: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert RFC-compliant entry to server-specific format.

            Args:
                entry_data: RFC-compliant entry attributes dict

            Returns:
                FlextResult with server-specific entry attributes

            """

        @abstractmethod
        def write_entry_to_ldif(
            self,
            entry_data: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[str]:
            """Write entry to LDIF text format.

            Args:
                entry_data: Entry attributes dict

            Returns:
                FlextResult with LDIF text for the entry

            """


__all__ = [
    "FlextLdifServersBase",
]
