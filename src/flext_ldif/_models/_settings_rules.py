"""LDIF settings mix-in: rules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from types import MappingProxyType
from typing import Annotated, Self

from flext_cli import m, u
from flext_ldif import c, t


class FlextLdifModelsSettingsRules:
    """LDIF settings mix-in: rules."""

    class CategoryRules(m.Value):
        """Rules for entry categorization.

        Contains DN patterns and objectClass lists for each category.
        Replaces dict[str, t.JsonValue] with type-safe Pydantic model.
        """

        user_dn_patterns: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="DN patterns for user entries (e.g., '*,ou=users,*')",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        group_dn_patterns: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(description="DN patterns for group entries"),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        hierarchy_dn_patterns: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="DN patterns for organizational hierarchy",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        schema_dn_patterns: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(description="DN patterns for schema entries"),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        user_objectclasses: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="ObjectClasses identifying user entries",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        group_objectclasses: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="ObjectClasses identifying group entries",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        hierarchy_objectclasses: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="ObjectClasses identifying organizational units",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        acl_attributes: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="Attribute names containing ACL information",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET

        @u.computed_field()
        @property
        def category_markers(self) -> t.FrozensetMapping:
            """Return category markers already normalized for matching."""
            markers: t.MutableFrozensetMapping = {}
            for category, field_name in c.Ldif.CATEGORY_RULE_OBJECTCLASS_FIELDS.items():
                raw_values = getattr(self, field_name)
                if raw_values:
                    markers[category] = frozenset(value.lower() for value in raw_values)
            for category, field_name in c.Ldif.CATEGORY_RULE_ATTRIBUTE_FIELDS.items():
                raw_values = getattr(self, field_name)
                if raw_values:
                    markers[category] = frozenset(
                        f"{c.Ldif.CATEGORY_ATTRIBUTE_MARKER_PREFIX}{value.lower()}"
                        for value in raw_values
                    )
            return MappingProxyType(markers)

    class WhitelistRules(m.Value):
        """Whitelist rules for entry validation.

        Defines blocked objectClasses and validation rules.
        Replaces dict[str, t.JsonValue] with type-safe Pydantic model.
        """

        @u.model_validator(mode="before")
        @classmethod
        def normalize_mapping_input(
            cls: type[Self],
            data: t.MappingKV[
                str,
                t.Ldif.ValueType | frozenset[str] | set[str],
            ]
            | Self,
        ) -> t.MappingKV[
            str,
            t.Ldif.ValueType | frozenset[str] | set[str],
        ]:
            """Accept immutable mapping inputs such as MappingProxyType."""
            if isinstance(data, cls):
                return dict(data.model_dump())
            return dict(data)

        blocked_objectclasses: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="ObjectClasses that should be blocked/rejected",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        allowed_objectclasses: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="ObjectClasses that are explicitly allowed",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        required_attributes: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(description="Attributes that must be present"),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        blocked_attributes: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="Attributes that should be blocked",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        allowed_attribute_oids: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="OID patterns for allowed schema attributes",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        allowed_objectclass_oids: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="OID patterns for allowed objectClasses",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        allowed_matchingrule_oids: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="OID patterns for allowed matchingRules",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        allowed_matchingruleuse_oids: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="OID patterns for allowed matchingRuleUse definitions",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET
        allowed_ldapsyntax_oids: Annotated[
            t.Ldif.NormalizedStrFrozenset,
            u.Field(
                description="OID patterns for allowed ldapSyntaxes definitions",
            ),
        ] = c.Ldif.EMPTY_STR_FROZENSET

        @u.computed_field()
        @property
        def schema_oid_filters(self) -> t.FrozensetMapping:
            """Return whitelist OID filters keyed by canonical schema attribute names."""
            return MappingProxyType({
                attr_name: getattr(self, field_name)
                for field_name, attr_name in c.Ldif.WHITELIST_RULE_SCHEMA_ATTRIBUTE_KEYS
            })

        @u.computed_field()
        @property
        def has_oid_filters(self) -> bool:
            """Check whether any schema OID whitelist is configured."""
            return any(self.schema_oid_filters.values())
