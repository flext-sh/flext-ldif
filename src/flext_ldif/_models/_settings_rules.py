"""LDIF settings mix-in: rules.

from flext_ldif import m
from flext_ldif import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from types import MappingProxyType
from typing import Annotated, Self

from flext_core import m, t, u

from flext_ldif._constants.base import FlextLdifConstantsBase
from flext_ldif._typings.base import FlextLdifTypesBase


class FlextLdifModelsSettingsRules:
    """LDIF settings mix-in: rules."""

    class CategoryRules(m.Value):
        """Rules for entry categorization.

        Contains DN patterns and objectClass lists for each category.
        Replaces t.JsonDict with type-safe Pydantic model.
        """

        user_dn_patterns: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="DN patterns for user entries (e.g., '*,ou=users,*')"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        group_dn_patterns: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="DN patterns for group entries"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        hierarchy_dn_patterns: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="DN patterns for organizational hierarchy"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        schema_dn_patterns: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="DN patterns for schema entries"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        user_objectclasses: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="ObjectClasses identifying user entries"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        group_objectclasses: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="ObjectClasses identifying group entries"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        hierarchy_objectclasses: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="ObjectClasses identifying organizational units"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        acl_attributes: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="Attribute names containing ACL information"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET

        @u.computed_field
        @property
        def category_markers(self) -> t.FrozensetMapping:
            """The category markers already normalized for matching."""
            markers: t.MutableFrozensetMapping = {}
            for (
                category,
                field_name,
            ) in FlextLdifConstantsBase.CATEGORY_RULE_OBJECTCLASS_FIELDS.items():
                raw_values = getattr(self, field_name)
                if raw_values:
                    markers[category] = frozenset(value.lower() for value in raw_values)
            for (
                category,
                field_name,
            ) in FlextLdifConstantsBase.CATEGORY_RULE_ATTRIBUTE_FIELDS.items():
                raw_values = getattr(self, field_name)
                if raw_values:
                    markers[category] = frozenset(
                        f"{FlextLdifConstantsBase.CATEGORY_ATTRIBUTE_MARKER_PREFIX}{value.lower()}"
                        for value in raw_values
                    )
            return MappingProxyType(markers)

    class WhitelistRules(m.Value):
        """Whitelist rules for entry validation.

        Defines blocked objectClasses and validation rules.
        Replaces t.JsonDict with type-safe Pydantic model.
        """

        @u.model_validator(mode="before")
        @classmethod
        def normalize_mapping_input(
            cls: type[Self],
            data: t.MappingKV[
                str, FlextLdifTypesBase.ValueType | frozenset[str] | set[str]
            ]
            | Self,
        ) -> t.MappingKV[str, FlextLdifTypesBase.ValueType | frozenset[str] | set[str]]:
            """Accept immutable mapping inputs such as MappingProxyType.

            Returns:
                The resulting ``t.MappingKV[str, FlextLdifTypesBase.ValueType |
                frozenset[str] | set[str]]``.

            """
            if isinstance(data, cls):
                return dict(data.model_dump())
            return dict(data)

        blocked_objectclasses: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="ObjectClasses that should be blocked/rejected"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        allowed_objectclasses: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="ObjectClasses that are explicitly allowed"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        required_attributes: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="Attributes that must be present"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        blocked_attributes: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="Attributes that should be blocked"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        allowed_attribute_oids: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="OID patterns for allowed schema attributes"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        allowed_objectclass_oids: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="OID patterns for allowed objectClasses"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        allowed_matchingrule_oids: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="OID patterns for allowed matchingRules"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        allowed_matchingruleuse_oids: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="OID patterns for allowed matchingRuleUse definitions"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET
        allowed_ldapsyntax_oids: Annotated[
            FlextLdifTypesBase.NormalizedStrFrozenset,
            m.Field(description="OID patterns for allowed ldapSyntaxes definitions"),
        ] = FlextLdifConstantsBase.EMPTY_STR_FROZENSET

        @u.computed_field
        @property
        def schema_oid_filters(self) -> t.FrozensetMapping:
            """The whitelist OID filters keyed by canonical schema attribute names."""
            return MappingProxyType({
                attr_name: getattr(self, field_name)
                for field_name, attr_name in (
                    FlextLdifConstantsBase.WHITELIST_RULE_SCHEMA_ATTRIBUTE_KEYS
                )
            })

        @u.computed_field
        @property
        def has_oid_filters(self) -> bool:
            """Whether any schema OID whitelist is configured."""
            return any(self.schema_oid_filters.values())


__all__: list[str] = ["FlextLdifModelsSettingsRules"]
