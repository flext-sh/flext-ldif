"""LDIF-specific test factories extending flext_tests.

Provides factory methods for creating LDIF test objects:
- Entry factories
- SchemaAttribute factories
- SchemaObjectClass factories
- Acl factories

Extends FlextTestsFactories with LDIF domain-specific factories.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsFactories

from flext_ldif import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifTestFactories(FlextTestsFactories):
    """LDIF-specific test factories extending FlextTestsFactories."""

    @staticmethod
    def create_entry(
        dn: str = "cn=test,dc=example,dc=com",
        attributes: dict[str, str | list[str]] | None = None,
        **overrides: object,
    ) -> FlextLdifModels.Entry:
        """Create a test Entry.

        Args:
            dn: Distinguished name (default: "cn=test,dc=example,dc=com")
            attributes: Optional attributes dictionary
            **overrides: Additional field overrides

        Returns:
            Entry model

        """
        default_attrs: dict[str, str | list[str]] = {
            "objectClass": ["inetOrgPerson", "person"],
            "cn": ["Test User"],
            "sn": ["User"],
        }
        if attributes:
            default_attrs.update(attributes)
        # Filter overrides to ensure type compatibility
        compatible_overrides: dict[str, str | list[str]] = {
            k: v for k, v in overrides.items() if isinstance(v, (str, list))
        }
        default_attrs.update(compatible_overrides)

        result = FlextLdifModels.Entry.create(dn=dn, attributes=default_attrs)
        if result.is_failure:
            msg = f"Failed to create entry: {result.error}"
            raise ValueError(msg)
        entry = result.unwrap()
        if not isinstance(entry, FlextLdifModels.Entry):
            msg = f"Expected Entry but got {type(entry).__name__}"
            raise TypeError(msg)
        return entry

    @staticmethod
    def create_schema_attribute(
        oid: str = "1.3.6.1.4.1.1466.115.121.1.15",
        name: str = "testAttribute",
        syntax: str = "1.3.6.1.4.1.1466.115.121.1.15",
        **overrides: object,
    ) -> FlextLdifModels.SchemaAttribute:
        """Create a test SchemaAttribute.

        Args:
            oid: Attribute OID (default: "1.3.6.1.4.1.1466.115.121.1.15")
            name: Attribute name (default: "testAttribute")
            syntax: Syntax OID (default: "1.3.6.1.4.1.1466.115.121.1.15")
            **overrides: Additional field overrides

        Returns:
            SchemaAttribute model

        """
        attr_def = f"( {oid} NAME '{name}' SYNTAX {syntax} )"
        schema = FlextLdifServersRfc.Schema()
        result = schema.parse(attr_def)
        if result.is_failure:
            msg = f"Failed to parse attribute: {result.error}"
            raise ValueError(msg)
        attr = result.unwrap()
        if not isinstance(attr, FlextLdifModels.SchemaAttribute):
            msg = f"Expected SchemaAttribute but got {type(attr).__name__}"
            raise TypeError(msg)
        return attr

    @staticmethod
    def create_schema_objectclass(
        oid: str = "1.3.6.1.4.1.1466.344",
        name: str = "testObjectClass",
        **overrides: object,
    ) -> FlextLdifModels.SchemaObjectClass:
        """Create a test SchemaObjectClass.

        Args:
            oid: ObjectClass OID (default: "1.3.6.1.4.1.1466.344")
            name: ObjectClass name (default: "testObjectClass")
            **overrides: Additional field overrides

        Returns:
            SchemaObjectClass model

        """
        oc_def = f"( {oid} NAME '{name}' )"
        schema = FlextLdifServersRfc.Schema()
        result = schema.parse(oc_def)
        if result.is_failure:
            msg = f"Failed to parse objectClass: {result.error}"
            raise ValueError(msg)
        oc = result.unwrap()
        if not isinstance(oc, FlextLdifModels.SchemaObjectClass):
            msg = f"Expected SchemaObjectClass but got {type(oc).__name__}"
            raise TypeError(msg)
        return oc

    @staticmethod
    def batch_entries(
        count: int = 5,
        base_dn: str = "dc=example,dc=com",
        **overrides: object,
    ) -> list[FlextLdifModels.Entry]:
        """Create a batch of test entries.

        Args:
            count: Number of entries to create
            base_dn: Base DN for entries
            **overrides: Additional field overrides

        Returns:
            List of Entry models

        """
        return [
            FlextLdifTestFactories.create_entry(
                dn=f"cn=user{i},{base_dn}",
                attributes={"cn": [f"User {i}"], "sn": [f"User{i}"]},
                **overrides,
            )
            for i in range(count)
        ]


__all__ = ["FlextLdifTestFactories"]
