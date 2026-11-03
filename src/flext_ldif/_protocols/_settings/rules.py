# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/_settings/rules
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

from flext_ldif._typings import FlextLdifTypesBase

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifProtocolsSettingsRules:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class CategoryRules(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def user_dn_patterns(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """DN patterns for user entries (e.g., '*,ou=users,*')."""
            ...

        @property
        def group_dn_patterns(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """DN patterns for group entries."""
            ...

        @property
        def hierarchy_dn_patterns(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """DN patterns for organizational hierarchy."""
            ...

        @property
        def schema_dn_patterns(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """DN patterns for schema entries."""
            ...

        @property
        def user_objectclasses(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """ObjectClasses identifying user entries."""
            ...

        @property
        def group_objectclasses(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """ObjectClasses identifying group entries."""
            ...

        @property
        def hierarchy_objectclasses(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """ObjectClasses identifying organizational units."""
            ...

        @property
        def acl_attributes(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """Attribute names containing ACL information."""
            ...

        @property
        def category_markers(self) -> t.FrozensetMapping:
            """The category markers already normalized for matching."""
            ...

    @runtime_checkable
    class WhitelistRules(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def blocked_objectclasses(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """ObjectClasses that should be blocked/rejected."""
            ...

        @property
        def allowed_objectclasses(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """ObjectClasses that are explicitly allowed."""
            ...

        @property
        def required_attributes(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """Attributes that must be present."""
            ...

        @property
        def blocked_attributes(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """Attributes that should be blocked."""
            ...

        @property
        def allowed_attribute_oids(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """OID patterns for allowed schema attributes."""
            ...

        @property
        def allowed_objectclass_oids(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """OID patterns for allowed objectClasses."""
            ...

        @property
        def allowed_matchingrule_oids(
            self,
        ) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """OID patterns for allowed matchingRules."""
            ...

        @property
        def allowed_matchingruleuse_oids(
            self,
        ) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """OID patterns for allowed matchingRuleUse definitions."""
            ...

        @property
        def allowed_ldapsyntax_oids(self) -> FlextLdifTypesBase.NormalizedStrFrozenset:
            """OID patterns for allowed ldapSyntaxes definitions."""
            ...

        @property
        def schema_oid_filters(self) -> t.FrozensetMapping:
            """Structural member projected from the owning model.

            The whitelist OID filters keyed by canonical schema attribute names.
            """
            ...

        @property
        def has_oid_filters(self) -> bool:
            """Whether any schema OID whitelist is configured."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsSettingsRules",
]
