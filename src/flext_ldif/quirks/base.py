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
    - FlextLdifQuirksBaseSchemaQuirk → FlextLdifProtocols.Quirks.SchemaQuirkProtocol
    - FlextLdifQuirksBaseAclQuirk → FlextLdifProtocols.Quirks.AclQuirkProtocol
    - FlextLdifQuirksBaseEntryQuirk → FlextLdifProtocols.Quirks.EntryQuirkProtocol

    All method signatures must match protocol definitions exactly for type safety.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from types import ModuleType
from typing import TYPE_CHECKING

from flext_core import FlextModels, FlextResult
from pydantic import Field

from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes

# Import protocols for validation and type hints

# Deferred import to avoid circular dependency with registry
# This is an intentional pattern - FlextLdifQuirksRegistry imports from this module
if TYPE_CHECKING:
    import flext_ldif.quirks.registry as quirks_registry_module
else:
    quirks_registry_module: ModuleType | None
    try:
        import flext_ldif.quirks.registry as quirks_registry_module

        _QUIRKS_REGISTRY_AVAILABLE = True
    except ImportError:
        quirks_registry_module = None
        _QUIRKS_REGISTRY_AVAILABLE = False

logger = logging.getLogger(__name__)


class FlextLdifQuirksBaseSchemaQuirk(ABC, FlextModels.Value):
    """Base class for schema quirks - satisfies FlextLdifProtocols.Quirks.SchemaQuirkProtocol.

    Schema quirks extend RFC 4512 schema parsing with server-specific features
    for attribute and objectClass processing.

    **Protocol Compliance**: All implementations MUST satisfy
    FlextLdifProtocols.Quirks.SchemaQuirkProtocol through structural typing.
    This means all public methods must match protocol signatures exactly.

    **Validation**: Use isinstance(quirk, FlextLdifProtocols.Quirks.SchemaQuirkProtocol)
    to check protocol compliance at runtime.

    Example vendors:
    - Oracle OID: orclOID prefix, Oracle-specific syntaxes
    - Oracle OUD: Enhanced schema features
    - OpenLDAP: olc* configuration attributes
    - Active Directory: AD-specific schema extensions
    - RFC: RFC 4512 compliant baseline (no extensions)
    """

    server_type: str = Field(
        default="generic",
        description="Server type this quirk applies to (e.g., 'oid', 'oud', 'openldap')",
    )
    priority: int = Field(
        default=100, description="Quirk priority (lower = higher priority)"
    )

    def __init_subclass__(cls) -> None:
        """Automatic quirk registration - pure Python 3.13+ pattern.

        Pure Python 3.13+ pattern - no wrappers, no helpers, no boilerplate.
        Schema quirks transparently register in global registry when class is defined.

        Example:
            >>> class MyServerQuirk(FlextLdifQuirksBaseSchemaQuirk):
            ...     server_type: str = "myserver"
            ...     # Automatically registered in global FlextLdifQuirksRegistry

        """
        super().__init_subclass__()

        # Only register concrete classes (not base classes or nested abstract classes)
        if not hasattr(cls, "__abstractmethods__") or not cls.__abstractmethods__:
            try:
                # Check if cls has all required fields with defaults
                # Pydantic models can only be instantiated if all required fields have defaults
                try:
                    quirk_instance = cls()
                except TypeError:
                    # Missing required fields (like server_type) - skip registration
                    # This happens for abstract base classes
                    return

                if quirks_registry_module is not None:
                    registry = quirks_registry_module.FlextLdifQuirksRegistry.get_global_instance()
                else:
                    return
                registry.register_schema_quirk(quirk_instance)
            except Exception as e:
                # Registration failures are non-critical during class creation
                # Log at debug level to avoid noise during module import
                logger.debug(
                    f"Failed to register schema quirk {cls.__name__}: {e}",
                    exc_info=False,
                )

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
        self, attr_definition: str
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
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse server-specific objectClass definition.

        Args:
        oc_definition: ObjectClass definition string

        Returns:
        FlextResult with SchemaObjectClass model

        """

    @abstractmethod
    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert server-specific attribute to RFC-compliant format.

        Args:
        attr_data: Server-specific SchemaAttribute

        Returns:
        FlextResult with RFC-compliant SchemaAttribute

        """

    @abstractmethod
    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert server-specific objectClass to RFC-compliant format.

        Args:
        oc_data: Server-specific SchemaObjectClass

        Returns:
        FlextResult with RFC-compliant SchemaObjectClass

        """

    @abstractmethod
    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert RFC-compliant attribute to server-specific format.

        Args:
        rfc_data: RFC-compliant SchemaAttribute

        Returns:
        FlextResult with server-specific SchemaAttribute

        """

    @abstractmethod
    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert RFC-compliant objectClass to server-specific format.

        Args:
        rfc_data: RFC-compliant SchemaObjectClass

        Returns:
        FlextResult with server-specific SchemaObjectClass

        """

    @abstractmethod
    def write_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        """Write attribute data to RFC-compliant string format.

        Args:
        attr_data: SchemaAttribute model

        Returns:
        FlextResult with RFC-compliant attribute string

        """

    @abstractmethod
    def write_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
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

    def can_handle_acl(self, _acl_line: str) -> bool:
        """Check if this quirk can handle the ACL definition.

        Schema quirks typically don't handle ACLs, so default False.
        Subclasses can override if they handle both schema and ACLs.

        Args:
            _acl_line: ACL definition line

        Returns:
            True if this quirk can parse this ACL

        """
        return False


class FlextLdifQuirksBaseAclQuirk(ABC, FlextModels.Value):
    """Base class for ACL quirks - satisfies FlextLdifProtocols.Quirks.AclQuirkProtocol.

    ACL quirks extend RFC 4516 ACL parsing with server-specific formats
    for access control list processing.

    **Protocol Compliance**: All implementations MUST satisfy
    FlextLdifProtocols.Quirks.AclQuirkProtocol through structural typing.
    This means all public methods must match protocol signatures exactly.

    **Validation**: Use isinstance(quirk, FlextLdifProtocols.Quirks.AclQuirkProtocol)
    to check protocol compliance at runtime.

    Example vendors:
    - Oracle OID: orclaci, orclentrylevelaci
    - Oracle OUD: Enhanced ACI format
    - OpenLDAP: olcAccess directives
    - Active Directory: NT Security Descriptors
    - RFC: RFC 4516 compliant baseline
    """

    server_type: str = Field(
        default="generic", description="Server type this quirk applies to"
    )
    priority: int = Field(default=100, description="Quirk priority")

    def __init_subclass__(cls) -> None:
        """Automatic quirk registration - pure Python 3.13+ pattern.

        Pure Python 3.13+ pattern - no wrappers, no helpers, no boilerplate.
        ACL quirks transparently register in global registry when class is defined.

        Example:
            >>> class MyServerAclQuirk(FlextLdifQuirksBaseAclQuirk):
            ...     server_type: str = "myserver"
            ...     # Automatically registered in global FlextLdifQuirksRegistry

        """
        super().__init_subclass__()

        # Only register concrete classes (not base classes or nested abstract classes)
        if not hasattr(cls, "__abstractmethods__") or not cls.__abstractmethods__:
            try:
                # Check if cls has all required fields with defaults
                # Pydantic models can only be instantiated if all required fields have defaults
                try:
                    quirk_instance = cls()
                except TypeError:
                    # Missing required fields (like server_type) - skip registration
                    # This happens for abstract base classes
                    return

                if quirks_registry_module is not None:
                    registry = quirks_registry_module.FlextLdifQuirksRegistry.get_global_instance()
                else:
                    return
                registry.register_acl_quirk(quirk_instance)
            except Exception as e:
                # Registration failures are non-critical during class creation
                # Log at debug level to avoid noise during module import
                logger.debug(
                    f"Failed to register ACL quirk {cls.__name__}: {e}",
                    exc_info=False,
                )

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
        self, acl_data: FlextLdifModels.Acl
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Convert server-specific ACL to RFC-compliant format.

        Args:
        acl_data: Server-specific Acl model

        Returns:
        FlextResult with RFC-compliant Acl model

        """

    @abstractmethod
    def convert_acl_from_rfc(
        self, acl_data: FlextLdifModels.Acl
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Convert RFC-compliant ACL to server-specific format.

        Args:
        acl_data: RFC-compliant Acl model

        Returns:
        FlextResult with server-specific Acl model

        """

    @abstractmethod
    def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
        """Write ACL data to RFC-compliant string format.

        Args:
            acl_data: Acl model

        Returns:
            FlextResult with RFC-compliant ACL string

        """

    def can_handle_attribute(self, _attr_definition: str) -> bool:
        """Check if this quirk can handle the attribute definition.

        ACL quirks typically don't handle attributes, so default False.
        Subclasses can override if they handle both ACL and attributes.

        Args:
            _attr_definition: AttributeType definition string

        Returns:
            True if this quirk can parse this attribute

        """
        return False

    def can_handle_objectclass(self, _oc_definition: str) -> bool:
        """Check if this quirk can handle the objectClass definition.

        ACL quirks typically don't handle objectClasses, so default False.
        Subclasses can override if they handle both ACL and objectClasses.

        Args:
            _oc_definition: ObjectClass definition string

        Returns:
            True if this quirk can parse this objectClass

        """
        return False


class FlextLdifQuirksBaseEntryQuirk(ABC, FlextModels.Value):
    """Base class for entry processing quirks - satisfies FlextLdifProtocols.Quirks.EntryQuirkProtocol.

    Entry quirks handle server-specific entry attributes and transformations
    for LDAP entry processing.

    **Protocol Compliance**: All implementations MUST satisfy
    FlextLdifProtocols.Quirks.EntryQuirkProtocol through structural typing.
    This means all public methods must match protocol signatures exactly.

    **Validation**: Use isinstance(quirk, FlextLdifProtocols.Quirks.EntryQuirkProtocol)
    to check protocol compliance at runtime.

    Example use cases:
    - Oracle operational attributes
    - OpenLDAP configuration entries (cn=config)
    - Active Directory specific attributes
    - Server-specific DN formats
    - RFC baseline entry handling
    """

    server_type: str = Field(
        default="generic", description="Server type this quirk applies to"
    )
    priority: int = Field(default=100, description="Quirk priority")

    def __init_subclass__(cls) -> None:
        """Automatic quirk registration - pure Python 3.13+ pattern.

        Pure Python 3.13+ pattern - no wrappers, no helpers, no boilerplate.
        Entry quirks transparently register in global registry when class is defined.

        Example:
            >>> class MyServerEntryQuirk(FlextLdifQuirksBaseEntryQuirk):
            ...     server_type: str = "myserver"
            ...     # Automatically registered in global FlextLdifQuirksRegistry

        """
        super().__init_subclass__()

        # Only register concrete classes (not base classes or nested abstract classes)
        if not hasattr(cls, "__abstractmethods__") or not cls.__abstractmethods__:
            try:
                # Check if cls has all required fields with defaults
                # Pydantic models can only be instantiated if all required fields have defaults
                try:
                    quirk_instance = cls()
                except TypeError:
                    # Missing required fields (like server_type) - skip registration
                    # This happens for abstract base classes
                    return

                if quirks_registry_module is not None:
                    registry = quirks_registry_module.FlextLdifQuirksRegistry.get_global_instance()
                else:
                    return
                registry.register_entry_quirk(quirk_instance)
            except Exception as e:
                # Registration failures are non-critical during class creation
                # Log at debug level to avoid noise during module import
                logger.debug(
                    f"Failed to register entry quirk {cls.__name__}: {e}",
                    exc_info=False,
                )

    @abstractmethod
    def can_handle_entry(
        self, entry_dn: str, attributes: FlextLdifTypes.Common.EntryAttributesDict
    ) -> bool:
        """Check if this quirk can handle the entry.

        Args:
        entry_dn: Entry distinguished name
        attributes: Entry attributes dict

        Returns:
        True if this quirk should process this entry

        """

    @abstractmethod
    def process_entry(
        self, entry_dn: str, attributes: FlextLdifTypes.Common.EntryAttributesDict
    ) -> FlextResult[FlextLdifTypes.Common.EntryAttributesDict]:
        """Process entry with server-specific logic.

        Args:
        entry_dn: Entry distinguished name
        attributes: Entry attributes dict

        Returns:
        FlextResult with processed entry attributes

        """

    @abstractmethod
    def convert_entry_to_rfc(
        self, entry_data: FlextLdifTypes.Common.EntryAttributesDict
    ) -> FlextResult[FlextLdifTypes.Common.EntryAttributesDict]:
        """Convert server-specific entry to RFC-compliant format.

        Args:
            entry_data: Server-specific entry attributes dict

        Returns:
            FlextResult with RFC-compliant entry attributes

        """

    def can_handle_attribute(self, _attr_definition: str) -> bool:
        """Check if this quirk can handle the attribute definition.

        Entry quirks typically don't handle attributes, so default False.
        Subclasses can override if they handle both entry and attributes.

        Args:
            _attr_definition: AttributeType definition string

        Returns:
            True if this quirk can parse this attribute

        """
        return False

    def can_handle_objectclass(self, _oc_definition: str) -> bool:
        """Check if this quirk can handle the objectClass definition.

        Entry quirks typically don't handle objectClasses, so default False.
        Subclasses can override if they handle both entry and objectClasses.

        Args:
            _oc_definition: ObjectClass definition string

        Returns:
            True if this quirk can parse this objectClass

        """
        return False

    def can_handle_acl(self, _acl_line: str) -> bool:
        """Check if this quirk can handle the ACL definition.

        Entry quirks typically don't handle ACLs, so default False.
        Subclasses can override if they handle both entry and ACLs.

        Args:
            _acl_line: ACL definition line

        Returns:
            True if this quirk can parse this ACL

        """
        return False


class FlextLdifQuirksBase:
    """Main container class for all LDIF quirk functionality.

    Provides unified access to base quirk classes and server-specific implementations.
    Follows FLEXT pattern: one main class per module named FlextLdif[ModuleName].
    """

    # Direct access to base classes using TypeAlias for MyPy compliance
    type SchemaQuirk = FlextLdifQuirksBaseSchemaQuirk
    # Aliases for backward compatibility
    type BaseAclQuirk = FlextLdifQuirksBaseAclQuirk
    type BaseEntryQuirk = FlextLdifQuirksBaseEntryQuirk
    type BaseSchemaQuirk = FlextLdifQuirksBaseSchemaQuirk

    type AclQuirk = FlextLdifQuirksBaseAclQuirk
    type EntryQuirk = FlextLdifQuirksBaseEntryQuirk


__all__ = [
    "FlextLdifQuirksBase",
]
