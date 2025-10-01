"""Base Quirk Classes for LDIF/LDAP Server Extensions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Defines base classes for implementing server-specific quirks that extend
RFC-compliant LDIF/LDAP parsing with vendor-specific features.

Quirks allow extending the RFC base without modifying core parser logic.
"""

from __future__ import annotations

from abc import ABC
from abc import abstractmethod

from flext_core import FlextModels
from flext_core import FlextResult
from pydantic import Field


class BaseSchemaQuirk(ABC, FlextModels.Value):
    """Base class for schema quirks.

    Schema quirks extend RFC 4512 schema parsing with server-specific features.

    Example vendors:
    - Oracle OID: orclOID prefix, Oracle-specific syntaxes
    - Oracle OUD: Enhanced schema features
    - OpenLDAP: olc* configuration attributes
    - Active Directory: AD-specific schema extensions
    """

    server_type: str = Field(
        description="Server type this quirk applies to (e.g., 'oid', 'oud', 'openldap')"
    )
    priority: int = Field(
        default=100, description="Quirk priority (lower = higher priority)"
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
    def parse_attribute(self, attr_definition: str) -> FlextResult[dict[str, object]]:
        """Parse server-specific attribute definition.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            FlextResult with parsed attribute data

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
    def parse_objectclass(self, oc_definition: str) -> FlextResult[dict[str, object]]:
        """Parse server-specific objectClass definition.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            FlextResult with parsed objectClass data

        """

    @abstractmethod
    def convert_attribute_to_rfc(
        self, attr_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert server-specific attribute to RFC-compliant format.

        Args:
            attr_data: Server-specific attribute data

        Returns:
            FlextResult with RFC-compliant attribute data

        """

    @abstractmethod
    def convert_objectclass_to_rfc(
        self, oc_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert server-specific objectClass to RFC-compliant format.

        Args:
            oc_data: Server-specific objectClass data

        Returns:
            FlextResult with RFC-compliant objectClass data

        """


class BaseAclQuirk(ABC, FlextModels.Value):
    """Base class for ACL quirks.

    ACL quirks extend RFC 4516 ACL parsing with server-specific formats.

    Example vendors:
    - Oracle OID: orclaci, orclentrylevelaci
    - Oracle OUD: Enhanced ACI format
    - OpenLDAP: olcAccess directives
    - Active Directory: NT Security Descriptors
    """

    server_type: str = Field(description="Server type this quirk applies to")
    priority: int = Field(default=100, description="Quirk priority")

    @abstractmethod
    def can_handle_acl(self, acl_line: str) -> bool:
        """Check if this quirk can handle the ACL definition.

        Args:
            acl_line: ACL definition line

        Returns:
            True if this quirk can parse this ACL

        """

    @abstractmethod
    def parse_acl(self, acl_line: str) -> FlextResult[dict[str, object]]:
        """Parse server-specific ACL definition.

        Args:
            acl_line: ACL definition line

        Returns:
            FlextResult with parsed ACL data

        """

    @abstractmethod
    def convert_acl_to_rfc(
        self, acl_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert server-specific ACL to RFC-compliant format.

        Args:
            acl_data: Server-specific ACL data

        Returns:
            FlextResult with RFC-compliant ACL data

        """

    @abstractmethod
    def convert_acl_from_rfc(
        self, acl_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert RFC-compliant ACL to server-specific format.

        Args:
            acl_data: RFC-compliant ACL data

        Returns:
            FlextResult with server-specific ACL data

        """


class BaseEntryQuirk(ABC, FlextModels.Value):
    """Base class for entry processing quirks.

    Entry quirks handle server-specific entry attributes and transformations.

    Example use cases:
    - Oracle operational attributes
    - OpenLDAP configuration entries (cn=config)
    - Active Directory specific attributes
    - Server-specific DN formats
    """

    server_type: str = Field(description="Server type this quirk applies to")
    priority: int = Field(default=100, description="Quirk priority")

    @abstractmethod
    def can_handle_entry(self, entry_dn: str, attributes: dict) -> bool:
        """Check if this quirk can handle the entry.

        Args:
            entry_dn: Entry distinguished name
            attributes: Entry attributes

        Returns:
            True if this quirk should process this entry

        """

    @abstractmethod
    def process_entry(
        self, entry_dn: str, attributes: dict
    ) -> FlextResult[dict[str, object]]:
        """Process entry with server-specific logic.

        Args:
            entry_dn: Entry distinguished name
            attributes: Entry attributes

        Returns:
            FlextResult with processed entry data

        """

    @abstractmethod
    def convert_entry_to_rfc(
        self, entry_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert server-specific entry to RFC-compliant format.

        Args:
            entry_data: Server-specific entry data

        Returns:
            FlextResult with RFC-compliant entry data

        """


__all__ = [
    "BaseAclQuirk",
    "BaseEntryQuirk",
    "BaseSchemaQuirk",
]
