"""Schema building example with automatic type detection and validation.

Part of Example 5 (Advanced Schema Operations); see
``examples/schema_operations.py`` for the combined facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import MutableSequence, Sequence

from examples import m, p, r, t


class ExamplesFlextLdifSchemaBuilding:
    """Schema-building example namespace: detection, validation, entries."""

    @staticmethod
    def create_entry_or_none(
        dn: str,
        attributes: t.MutableAttributeMapping,
    ) -> m.Ldif.Entry | None:
        """Create an entry, returning None on failure.

        Returns:
            The resulting ``m.Ldif.Entry | None``.

        """
        result = m.Ldif.Entry.create(dn=dn, attributes=attributes)
        return result.unwrap() if result.success else None

    @staticmethod
    def object_class_entries(
        definitions: Sequence[tuple[str, str, str, list[str], list[str]]],
    ) -> list[m.Ldif.Entry]:
        """Build objectClass schema entries from ``(name, desc, sup, must, may)`` rows.

        Returns:
            The resulting ``list[m.Ldif.Entry]``.

        """
        entries: list[m.Ldif.Entry] = []
        for name, desc, sup, must_attrs, may_attrs in definitions:
            attrs: t.MutableAttributeMapping = {
                "objectClass": ["top", "ldapSubentry", "objectClassDescription"],
                "cn": [name],
                "description": [desc],
                "sup": [sup],
            }
            if must_attrs:
                attrs["must"] = must_attrs
            if may_attrs:
                attrs["may"] = may_attrs
            entry = ExamplesFlextLdifSchemaBuilding.create_entry_or_none(
                dn=f"cn={name},cn=schema",
                attributes=attrs,
            )
            if entry is not None:
                entries.append(entry)
        return entries

    @staticmethod
    def intelligent_schema_building() -> p.Result[MutableSequence[m.Ldif.Entry]]:
        """Intelligent schema building with automatic type detection and validation.

        Returns:
            The resulting ``p.Result[MutableSequence[m.Ldif.Entry]]``.

        """
        schema_entries: list[m.Ldif.Entry] = []
        schema_root = ExamplesFlextLdifSchemaBuilding.create_entry_or_none(
            dn="cn=schema",
            attributes={
                "objectClass": ["top", "ldapSubentry", "subschema"],
                "cn": ["schema"],
                "description": ["Schema container for LDAP directory"],
            },
        )
        if schema_root is not None:
            schema_entries.append(schema_root)
        attribute_types: Sequence[tuple[str, str, str, bool]] = [
            ("cn", "Common Name", "1.3.6.1.4.1.1466.115.121.1.15", False),
            ("sn", "Surname", "1.3.6.1.4.1.1466.115.121.1.15", False),
            ("mail", "Email Address", "1.3.6.1.4.1.1466.115.121.1.26", False),
            ("member", "Group member", "1.3.6.1.4.1.1466.115.121.1.12", False),
        ]
        for name, desc, syntax, single_val in attribute_types:
            entry = ExamplesFlextLdifSchemaBuilding.create_entry_or_none(
                dn=f"cn={name},cn=schema",
                attributes={
                    "objectClass": ["top", "ldapSubentry", "attributeTypeDescription"],
                    "cn": [name],
                    "description": [desc],
                    "syntax": [syntax],
                    "singleValue": ["TRUE" if single_val else "FALSE"],
                    "usage": ["userApplications"],
                },
            )
            if entry is not None:
                schema_entries.append(entry)
        object_classes: Sequence[tuple[str, str, str, list[str], list[str]]] = [
            (
                "person",
                "Person object class",
                "top",
                ["cn", "sn"],
                ["mail", "telephoneNumber"],
            ),
            (
                "inetOrgPerson",
                "Internet Organization Person",
                "person",
                ["cn"],
                ["departmentNumber"],
            ),
            (
                "groupOfNames",
                "Group of names",
                "top",
                ["cn", "member"],
                ["description"],
            ),
        ]
        schema_entries.extend(
            ExamplesFlextLdifSchemaBuilding.object_class_entries(object_classes),
        )
        return r[MutableSequence[m.Ldif.Entry]].ok(schema_entries)


# Module-level rebinding of the namespace surface: the lazy package export and
# the schema_operations aggregator import these names as module attributes.
create_entry_or_none = ExamplesFlextLdifSchemaBuilding.create_entry_or_none
object_class_entries = ExamplesFlextLdifSchemaBuilding.object_class_entries
intelligent_schema_building = (
    ExamplesFlextLdifSchemaBuilding.intelligent_schema_building
)

__all__: list[str] = [
    "ExamplesFlextLdifSchemaBuilding",
    "create_entry_or_none",
    "intelligent_schema_building",
    "object_class_entries",
]
