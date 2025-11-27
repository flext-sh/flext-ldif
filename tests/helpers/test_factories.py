"""LDIF-specific test factories and utilities extending flext_tests.

Provides comprehensive factory methods and utilities for creating LDIF test objects:
- Entry factories with validation
- Schema factories (attributes/objectClasses)
- Batch creation utilities
- Advanced Python 3.13 features integration

Extends FlextTestsFactories with LDIF domain-specific factories and utilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator

from flext_tests import FlextTestsFactories

from flext_ldif import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from tests.fixtures.constants import DNs, Names, TestData, Values


@dataclasses.dataclass(frozen=True)
class EntryTemplate:
    """Template for creating test entries with advanced configuration."""

    dn_template: str
    base_attrs: dict[str, str | list[str]]
    variations: dict[str, dict[str, str | list[str]]] = dataclasses.field(
        default_factory=dict,
    )

    def create(
        self,
        variation: str = "default",
        **overrides: str | list[str],
    ) -> dict[str, str | list[str]]:
        """Create entry data with variation and overrides."""
        attrs = self.base_attrs.copy()
        if variation in self.variations:
            attrs.update(self.variations[variation])
        # Filter overrides to only include compatible types
        compatible_overrides = {
            k: v for k, v in overrides.items() if isinstance(v, (str, list))
        }
        attrs.update(compatible_overrides)
        return {"dn": self.dn_template, **attrs}


class FlextLdifTestFactories(FlextTestsFactories):
    """LDIF-specific test factories extending FlextTestsFactories.

    Provides advanced factory patterns using Python 3.13 features:
    - Template-based entry creation
    - Batch generation with iterators
    - Validation integration
    - Builder pattern support
    """

    # Pre-defined entry templates for common test patterns
    USER_TEMPLATE = EntryTemplate(
        dn_template=DNs.TEST_USER,
        base_attrs={
            "objectClass": [
                Names.INET_ORG_PERSON,
                Names.ORGANIZATIONAL_PERSON,
                Names.PERSON,
                Names.TOP,
            ],
            "cn": [Values.TEST],
            "sn": [Values.TEST],
            "mail": [Values.TEST_EMAIL],
            "uid": [Values.TEST],
        },
        variations={
            "minimal": {"objectClass": [Names.PERSON], "cn": [Values.TEST]},
            "multivalue": {"mail": Values.MAIL_VALUES},
            "admin": {
                "cn": [Values.ADMIN],
                "sn": [Values.ADMIN],
                "mail": [f"{Values.ADMIN}@example.com"],
            },
        },
    )

    GROUP_TEMPLATE = EntryTemplate(
        dn_template=DNs.TEST_GROUP,
        base_attrs={
            "objectClass": ["groupOfNames", Names.TOP],
            "cn": [Values.TEST],
            "member": [DNs.TEST_USER],
        },
    )

    @classmethod
    def create_entry(
        cls,
        dn: str = DNs.TEST_USER,
        attributes: dict[str, str | list[str]] | None = None,
        template: EntryTemplate | None = None,
        variation: str = "default",
        **overrides: str | list[str],
    ) -> FlextLdifModels.Entry:
        """Create a test Entry with advanced template support.

        Uses Python 3.13 advanced patterns:
        - Template-based creation with variations
        - Builder pattern integration
        - Type-safe overrides

        Args:
            dn: Distinguished name
            attributes: Optional attributes dictionary
            template: Optional EntryTemplate to use as base
            variation: Template variation to apply
            **overrides: Additional field overrides

        Returns:
            Entry model

        """
        # Use template if provided, otherwise build from parameters
        if template:
            base_attrs = template.create(variation, **overrides)
            final_dn_raw = base_attrs.pop("dn", dn)  # Extract DN from template
            final_dn = str(final_dn_raw) if final_dn_raw else dn
            final_attrs = dict[str, str | list[str]](
                (k, v) for k, v in base_attrs.items() if isinstance(v, (str, list))
            )
        else:
            # Legacy behavior with constants integration
            final_dn = dn
            default_attrs = TestData.user_entry(dn)
            final_attrs = dict[str, str | list[str]](
                (k, v) for k, v in default_attrs.items() if isinstance(v, (str, list))
            )
            if attributes:
                final_attrs.update(attributes)

        # Apply overrides (type-safe)
        compatible_overrides = dict[str, str | list[str]](
            (k, v) for k, v in overrides.items() if isinstance(v, (str, list))
        )
        final_attrs.update(compatible_overrides)

        result = FlextLdifModels.Entry.create(dn=final_dn, attributes=final_attrs)
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

    @classmethod
    def batch_entries(
        cls,
        count: int = 5,
        template: EntryTemplate | None = None,
        base_dn: str = DNs.EXAMPLE,
        variation: str = "default",
        **overrides: str | list[str],
    ) -> list[FlextLdifModels.Entry]:
        """Create a batch of test entries using advanced patterns.

        Uses Python 3.13 iterator patterns for efficient batch creation.

        Args:
            count: Number of entries to create
            template: Optional template to use for all entries
            base_dn: Base DN for entries
            variation: Template variation to apply
            **overrides: Additional field overrides

        Returns:
            List of Entry models

        """
        return [
            cls.create_entry(
                dn=f"cn=user{i},{base_dn}",
                template=template,
                variation=variation,
                attributes={"cn": [f"User {i}"], "sn": [f"User{i}"]},
                **overrides,
            )
            for i in range(count)
        ]

    @classmethod
    def entries_generator(
        cls,
        count: int = 10,
        template: EntryTemplate | None = None,
        base_dn: str = DNs.EXAMPLE,
        variation: str = "default",
        **overrides: str | list[str],
    ) -> Iterator[FlextLdifModels.Entry]:
        """Generate test entries on-demand using Python 3.13 generators.

        Args:
            count: Number of entries to generate
            template: Optional template to use
            base_dn: Base DN for entries
            variation: Template variation to apply
            **overrides: Additional field overrides

        Yields:
            Entry models one at a time

        """
        for i in range(count):
            yield cls.create_entry(
                dn=f"cn=user{i},{base_dn}",
                template=template,
                variation=variation,
                attributes={"cn": [f"User {i}"], "sn": [f"User{i}"]},
                **overrides,
            )

    @classmethod
    def create_user_entry(
        cls,
        username: str = Values.TEST,
        template: EntryTemplate | None = None,
        **overrides: str | list[str],
    ) -> FlextLdifModels.Entry:
        """Create a user entry with convenient parameters.

        Args:
            username: Username for the entry
            template: Optional template (defaults to USER_TEMPLATE)
            **overrides: Additional field overrides

        Returns:
            User Entry model

        """
        template = template or cls.USER_TEMPLATE
        dn = f"cn={username},{DNs.EXAMPLE}"
        # Apply overrides to attributes
        attrs_overrides = dict[str, str | list[str]](
            (k, v) for k, v in overrides.items() if isinstance(v, (str, list))
        )
        return cls.create_entry(
            dn=dn,
            template=template,
            attributes={
                "cn": [username],
                "sn": [username],
                "uid": [username],
                "mail": [f"{username}@example.com"],
                **attrs_overrides,
            },
        )

    @classmethod
    def create_group_entry(
        cls,
        group_name: str = Values.TEST,
        members: list[str] | None = None,
        **overrides: str | list[str],
    ) -> FlextLdifModels.Entry:
        """Create a group entry with members.

        Args:
            group_name: Name of the group
            members: List of member DNs
            **overrides: Additional field overrides

        Returns:
            Group Entry model

        """
        members = members or [DNs.TEST_USER]
        # Apply overrides to attributes
        attrs_overrides = dict[str, str | list[str]](
            (k, v) for k, v in overrides.items() if isinstance(v, (str, list))
        )
        return cls.create_entry(
            dn=f"cn={group_name},{DNs.EXAMPLE}",
            template=cls.GROUP_TEMPLATE,
            attributes={
                "cn": [group_name],
                "member": members,
                **attrs_overrides,
            },
        )

    @classmethod
    def create_multivalue_entry(
        cls,
        dn: str = DNs.TEST_USER,
        multivalue_attr: str = Names.MAIL,
        values: list[str] = Values.MAIL_VALUES,
        **overrides: str | list[str],
    ) -> FlextLdifModels.Entry:
        """Create an entry with multivalue attributes.

        Args:
            dn: Distinguished name
            multivalue_attr: Attribute name for multivalue data
            values: List of values for the attribute
            **overrides: Additional field overrides

        Returns:
            Entry with multivalue attributes

        """
        # Apply overrides to attributes
        attrs_overrides = dict[str, str | list[str]](
            (k, v) for k, v in overrides.items() if isinstance(v, (str, list))
        )
        return cls.create_entry(
            dn=dn,
            attributes={
                multivalue_attr: values,
                **attrs_overrides,
            },
        )


__all__ = ["EntryTemplate", "FlextLdifTestFactories"]
