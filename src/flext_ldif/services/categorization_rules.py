"""Categorization rules concern: fields, normalization, merging, matching.

Owns the categorization configuration fields plus the rule/constant
normalization and entry-matching half of the LDIF categorization service;
``FlextLdifCategorization`` composes it via MRO.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import struct
from collections.abc import MutableMapping
from typing import Annotated

from flext_ldif import c, m, p, r, s, t, u


class FlextLdifCategorizationRules(s):
    """Categorization configuration fields and rule matching helpers."""

    @staticmethod
    def _build_rejection_tracker() -> MutableMapping[
        str,
        t.MutableSequenceOf[m.Ldif.Entry],
    ]:
        """Build the canonical rejection tracker structure for one categorization run.

        Returns:
            The resulting ``MutableMapping[str, t.MutableSequenceOf[m.Ldif.Entry]]``.
        """
        return {
            c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514: [],
            c.Ldif.RejectionTrackerKey.BASE_DN_FILTER: [],
            c.Ldif.RejectionTrackerKey.CATEGORIZATION_REJECTED: [],
        }

    categorization_rules: Annotated[
        m.Ldif.CategoryRules
        | MutableMapping[str, str | t.MutableSequenceOf[str] | None]
        | None,
        u.Field(
            default=None,
            exclude=True,
            description="Optional categorization rules applied before server defaults.",
        ),
    ] = None
    schema_whitelist_rules: Annotated[
        m.Ldif.WhitelistRules | None,
        u.Field(
            default=None,
            exclude=True,
            description=(
                "Optional schema whitelist rules used to filter schema entries.",
            ),
        ),
    ] = None
    forbidden_attributes: Annotated[
        t.MutableSequenceOf[str] | None,
        u.Field(
            default=None,
            exclude=True,
            description=(
                (
                    "Attribute names removed from categorized entries after "
                    "classification."
                ),
            ),
        ),
    ] = None
    forbidden_objectclasses: Annotated[
        t.MutableSequenceOf[str] | None,
        u.Field(
            default=None,
            exclude=True,
            description=(
                (
                    "objectClass names removed from categorized entries after "
                    "classification."
                ),
            ),
        ),
    ] = None
    base_dn: Annotated[
        str | None,
        u.Field(
            default=None,
            exclude=True,
            description="Base DN filter applied after categorization when provided.",
        ),
    ] = None
    server_type: Annotated[
        str,
        u.Field(
            default=c.Ldif.ServerTypes.RFC.value,
            exclude=True,
            description=(
                (
                    "Server type used to resolve categorization defaults from the "
                    "registry."
                ),
            ),
        ),
    ] = c.Ldif.ServerTypes.RFC.value
    server_registry: Annotated[
        p.Ldif.ServerRegistry | None,
        u.Field(
            default=None,
            exclude=True,
            description=(
                (
                    "Optional server registry override for categorization "
                    "constants lookup."
                ),
            ),
        ),
    ] = None
    rejection_tracker: Annotated[
        t.MutableMappingKV[str, t.MutableSequenceOf[m.Ldif.Entry]],
        u.Field(
            default_factory=_build_rejection_tracker,
            exclude=True,
            description="Tracks rejected entries by rejection reason.",
        ),
    ] = u.Field(default_factory=_build_rejection_tracker)

    def _normalize_initial_category_rules(self) -> m.Ldif.CategoryRules:
        """Normalize initial categorization rules into the canonical model.

        Returns:
            The resulting ``m.Ldif.CategoryRules``.
        """
        validated_rules: m.Ldif.CategoryRules = m.Ldif.CategoryRules.model_validate(
            self.categorization_rules or {},
        )
        return validated_rules

    def _whitelist_rules_with_oid_filters(self) -> m.Ldif.WhitelistRules | None:
        """Return normalized whitelist rules only when OID filters are configured."""
        whitelist_rules = self.schema_whitelist_rules
        if whitelist_rules is None or not whitelist_rules.has_oid_filters:
            return None
        return whitelist_rules

    @staticmethod
    def _merge_category_from_constants(
        category_map: t.MutableFrozensetMapping,
        server_map: MutableMapping[str, frozenset[str] | str],
        *,
        override_existing: bool,
    ) -> None:
        for key_str, value in server_map.items():
            FlextLdifCategorizationRules._merge_one_category(
                category_map,
                key_str,
                value,
                override_existing=override_existing,
            )

    @staticmethod
    def _merge_one_category(
        category_map: t.MutableFrozensetMapping,
        key_str: str,
        value: frozenset[str] | str,
        *,
        override_existing: bool,
    ) -> None:
        if key_str not in c.Ldif.CATEGORY_VALUES:
            return
        normalized_value = (
            value if isinstance(value, frozenset) else frozenset((value.lower(),))
        )
        if override_existing or key_str not in category_map:
            category_map[key_str] = normalized_value
            return
        existing = category_map.get(key_str, c.Ldif.EMPTY_STR_FROZENSET)
        category_map[key_str] = existing | normalized_value

    @staticmethod
    def matches_schema_entry(entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema definition.

        Returns:
            The resulting ``bool``.
        """
        if entry.attributes is None:
            return False
        attrs_dict: t.MutableStrSequenceMapping = entry.attributes.attributes
        entry_attrs = {attr.lower() for attr in attrs_dict}
        return bool(c.Ldif.SCHEMA_CATEGORY_ATTRIBUTE_KEYS & entry_attrs)

    @staticmethod
    def _check_hierarchy_priority(
        entry: m.Ldif.Entry,
        constants: type[p.Ldif.ServerConstants],
    ) -> bool:
        """Check if entry matches HIERARCHY_PRIORITY_OBJECTCLASSES.

        Returns:
            The resulting ``bool``.
        """
        priority_classes = frozenset(
            oc.lower() for oc in constants.HIERARCHY_PRIORITY_OBJECTCLASSES
        )
        entry_ocs = {oc.lower() for oc in u.Ldif.get_objectclass_names(entry)}
        return bool(priority_classes & entry_ocs)

    @staticmethod
    def _get_priority_order_from_constants(
        constants: type[p.Ldif.ServerConstants] | None,
    ) -> t.MutableSequenceOf[str]:
        """Get priority order from constants or use default.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        if constants is None:
            return list(c.Ldif.DEFAULT_CATEGORIZATION_PRIORITY)
        return [
            item
            for item in constants.CATEGORIZATION_PRIORITY
            if item in c.Ldif.CATEGORY_VALUES
        ]

    def _get_categorization_server_constants(
        self,
        server_type: str,
    ) -> p.Result[type[p.Ldif.ServerConstants]]:
        """Get and validate server constants via FlextLdifServer registry.

        Returns:
            The resulting ``p.Result[type[p.Ldif.ServerConstants]]``.
        """
        registry = self.server_registry or self._server
        if registry is None:
            return r[type[p.Ldif.ServerConstants]].fail(
                c.Ldif.ERR_SERVER_REGISTRY_UNAVAILABLE,
            )

        def default_registry_error(error: str) -> str:
            return error or f"Failed to resolve constants for {server_type}"

        return (
            r[type[p.Ldif.ServerConstants]]
            .from_result(registry.resolve_server_constants(server_type))
            .map_error(default_registry_error)
        )

    @staticmethod
    def _match_entry_to_category(
        entry: m.Ldif.Entry,
        priority_order: t.MutableSequenceOf[str],
        category_map: t.MutableFrozensetMapping,
    ) -> tuple[str, str | None]:
        """Match entry to category using priority order and category map.

        Returns:
            The resulting ``tuple[str, str | None]``.
        """
        attribute_marker_prefix = c.Ldif.CATEGORY_ATTRIBUTE_MARKER_PREFIX
        for category in priority_order:
            category_markers = category_map.get(category)
            if not category_markers:
                continue
            attribute_markers: list[str] = []
            objectclass_markers: list[str] = []
            for marker in category_markers:
                if marker.startswith(attribute_marker_prefix):
                    attribute_markers.append(
                        marker.removeprefix(attribute_marker_prefix),
                    )
                    continue
                objectclass_markers.append(marker)
            if not attribute_markers and not objectclass_markers:
                continue
            criteria = m.Ldif.EntryCriteriaConfig.model_validate({
                "objectclasses": objectclass_markers or None,
                "any_attrs": attribute_markers or None,
            })
            if u.Ldif.matches_criteria(entry, settings=criteria):
                return (category, None)
        return (c.Ldif.Category.REJECTED, c.Ldif.REJECTION_REASON_NO_CATEGORY_MATCH)

    @staticmethod
    def _merge_server_constants_to_map(
        category_map: t.MutableFrozensetMapping,
        constants: type[p.Ldif.ServerConstants],
        *,
        override_existing: bool = False,
    ) -> t.MutableFrozensetMapping:
        """Merge server constants into category map.

        Returns:
            The resulting ``t.MutableFrozensetMapping``.
        """
        server_map: MutableMapping[str, frozenset[str] | str] = {
            map_key: frozenset(map_value)
            for map_key, map_value in constants.CATEGORY_OBJECTCLASSES.items()
        }
        FlextLdifCategorizationRules._merge_category_from_constants(
            category_map,
            server_map,
            override_existing=override_existing,
        )
        acl_attrs_raw = constants.CATEGORIZATION_ACL_ATTRIBUTES
        if acl_attrs_raw:
            acl_category = c.Ldif.Category.ACL
            mapped_acl_attrs = frozenset(
                f"{c.Ldif.CATEGORY_ATTRIBUTE_MARKER_PREFIX}{attr.lower()}"
                for attr in acl_attrs_raw
            )

            if override_existing or acl_category not in category_map:
                category_map[acl_category] = mapped_acl_attrs
                return category_map
            existing_acl = category_map.get(acl_category, c.Ldif.EMPTY_STR_FROZENSET)
            category_map[acl_category] = existing_acl | mapped_acl_attrs
        return category_map

    def _normalize_rules(
        self,
        rules: m.Ldif.CategoryRules | t.MutableJsonMapping | None,
    ) -> p.Result[m.Ldif.CategoryRules]:
        """Normalize rules to CategoryRules model.

        Returns:
            The resulting ``p.Result[m.Ldif.CategoryRules]``.
        """
        if isinstance(rules, m.Ldif.CategoryRules):
            return r[m.Ldif.CategoryRules].ok(rules)
        if rules is None:
            return r[m.Ldif.CategoryRules].ok(self._normalize_initial_category_rules())
        return r[m.Ldif.CategoryRules].from_result(
            u.try_(
                lambda: m.Ldif.CategoryRules.model_validate(rules),
                catch=(
                    ValueError,
                    KeyError,
                    AttributeError,
                    UnicodeDecodeError,
                    struct.error,
                ),
            ).map_error(lambda e: f"Invalid rules mapping: {e}"),
        )


__all__: list[str] = ["FlextLdifCategorizationRules"]
