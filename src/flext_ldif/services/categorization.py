"""Categorization Service - LDIF Entry Categorization Operations."""

from __future__ import annotations

import struct
from collections.abc import (
    MutableMapping,
    MutableSequence,
)
from typing import Annotated, Final, override

from flext_ldif import FlextLdifFilters, FlextLdifServer, c, m, r, s, t, u

_MAX_DN_PREVIEW_LENGTH: Final[int] = 100


class FlextLdifCategorization(s):
    """LDIF Entry Categorization Service."""

    @staticmethod
    def _build_rejection_tracker() -> MutableMapping[
        str, MutableSequence[m.Ldif.Entry]
    ]:
        """Build the canonical rejection tracker structure for one categorization run."""
        return {
            "invalid_dn_rfc4514": [],
            "base_dn_filter": [],
            "categorization_rejected": [],
        }

    categorization_rules: Annotated[
        m.Ldif.CategoryRules
        | MutableMapping[str, str | MutableSequence[str] | None]
        | None,
        u.Field(
            default=None,
            exclude=True,
            description="Optional categorization rules applied before server defaults.",
        ),
    ]
    schema_whitelist_rules: Annotated[
        m.Ldif.WhitelistRules
        | MutableMapping[str, str | MutableSequence[str] | bool | None]
        | None,
        u.Field(
            default=None,
            exclude=True,
            description="Optional schema whitelist rules used to filter schema entries.",
        ),
    ]
    forbidden_attributes: Annotated[
        MutableSequence[str] | None,
        u.Field(
            default=None,
            exclude=True,
            description="Attribute names removed from categorized entries after classification.",
        ),
    ]
    forbidden_objectclasses: Annotated[
        MutableSequence[str] | None,
        u.Field(
            default=None,
            exclude=True,
            description="objectClass names removed from categorized entries after classification.",
        ),
    ]
    base_dn: Annotated[
        str | None,
        u.Field(
            default=None,
            exclude=True,
            description="Base DN filter applied after categorization when provided.",
        ),
    ]
    server_type: Annotated[
        str,
        u.Field(
            default=c.Ldif.ServerTypes.RFC.value,
            exclude=True,
            description="Server type used to resolve categorization defaults from the registry.",
        ),
    ]
    server_registry: Annotated[
        FlextLdifServer | None,
        u.Field(
            default=None,
            exclude=True,
            description="Optional server registry override for categorization constants lookup.",
        ),
    ]

    _categorization_rules: m.Ldif.CategoryRules = u.PrivateAttr(
        default_factory=lambda: m.Ldif.CategoryRules.model_validate({}),
    )
    _schema_whitelist_rules: m.Ldif.WhitelistRules | None = u.PrivateAttr(
        default_factory=lambda: None
    )
    _forbidden_attributes: MutableSequence[str] = u.PrivateAttr(default_factory=list)
    _forbidden_objectclasses: MutableSequence[str] = u.PrivateAttr(
        default_factory=list,
    )
    _base_dn: str | None = u.PrivateAttr(default_factory=lambda: None)
    _server_type: str = u.PrivateAttr(
        default_factory=lambda: c.Ldif.ServerTypes.RFC.value,
    )
    _rejection_tracker: MutableMapping[str, MutableSequence[m.Ldif.Entry]] = (
        u.PrivateAttr(
            default_factory=_build_rejection_tracker,
        )
    )
    _server_registry: FlextLdifServer = u.PrivateAttr(
        default_factory=FlextLdifServer.fetch_global_instance,
    )

    @override
    def model_post_init(self, __context: t.JsonMapping | None, /) -> None:
        """Normalize configured categorization state after Pydantic initialization."""
        super().model_post_init(__context)
        self._server_registry = self.server_registry or self._server
        self._categorization_rules = self._normalize_initial_category_rules()
        self._schema_whitelist_rules = self._normalize_initial_whitelist_rules()
        self._forbidden_attributes = list(self.forbidden_attributes or [])
        self._forbidden_objectclasses = list(self.forbidden_objectclasses or [])
        self._base_dn = self.base_dn
        self._server_type = self.server_type
        self._rejection_tracker = self._build_rejection_tracker()

    def _normalize_initial_category_rules(self) -> m.Ldif.CategoryRules:
        """Normalize initial categorization rules into the canonical model."""
        if isinstance(self.categorization_rules, m.Ldif.CategoryRules):
            return self.categorization_rules
        if isinstance(self.categorization_rules, MutableMapping):
            validated_map: m.Ldif.CategoryRules = m.Ldif.CategoryRules.model_validate(
                dict(self.categorization_rules),
            )
            return validated_map
        validated_empty: m.Ldif.CategoryRules = m.Ldif.CategoryRules.model_validate({})
        return validated_empty

    def _normalize_initial_whitelist_rules(self) -> m.Ldif.WhitelistRules | None:
        """Normalize optional schema whitelist rules into the canonical model."""
        if isinstance(self.schema_whitelist_rules, m.Ldif.WhitelistRules):
            return self.schema_whitelist_rules
        if isinstance(self.schema_whitelist_rules, MutableMapping):
            validated: m.Ldif.WhitelistRules = m.Ldif.WhitelistRules.model_validate(
                dict(self.schema_whitelist_rules),
            )
            return validated
        return None

    @staticmethod
    def _ensure_entry_model(
        value: t.JsonValue | m.Ldif.Entry,
    ) -> m.Ldif.Entry | None:
        if isinstance(value, m.Ldif.Entry):
            return value
        if isinstance(value, m.BaseModel):
            try:
                validated: m.Ldif.Entry = m.Ldif.Entry.model_validate(value)
                return validated
            except c.ValidationError as exc:
                FlextLdifCategorization._get_or_create_logger().warning(
                    "Failed to coerce BaseModel to Entry",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
        return None

    @staticmethod
    def _filter_entries_by_base_dn(
        entries: MutableSequence[m.Ldif.Entry],
        base_dn: str,
    ) -> tuple[MutableSequence[m.Ldif.Entry], MutableSequence[m.Ldif.Entry]]:
        """Filter entries by base DN using u.Ldif."""
        model_entries: MutableSequence[m.Ldif.Entry] = list(entries)
        included: MutableSequence[m.Ldif.Entry] = []
        excluded: MutableSequence[m.Ldif.Entry] = []
        for entry in model_entries:
            dn_str = entry.dn.value if entry.dn else None
            if dn_str and u.Ldif.is_under_base(dn_str, base_dn):
                included.append(entry)
            else:
                excluded.append(entry)
        return (included, excluded)

    @staticmethod
    def _mark_entry_rejected(
        entry: m.Ldif.Entry,
        category: str,
        reason: str,
    ) -> m.Ldif.Entry:
        """Mark entry as rejected in metadata using u."""
        updated: m.Ldif.Entry = u.Ldif.update_entry_statistics(
            entry,
            mark_rejected=(category, reason),
        )
        return updated

    @staticmethod
    def _append_rejected_entries(
        filtered: m.Ldif.FlexibleCategories,
        rejected_entries: MutableSequence[m.Ldif.Entry],
    ) -> None:
        """Append rejected entries into the canonical REJECTED bucket."""
        if not rejected_entries:
            return
        rejected_category = c.Ldif.Category.REJECTED
        existing_rejected_raw: MutableSequence[m.Ldif.Entry] = filtered.get(
            rejected_category,
            [],
        )
        filtered[rejected_category] = [
            entry_model
            for rejected_raw_item in [*existing_rejected_raw, *rejected_entries]
            if (
                entry_model := FlextLdifCategorization._ensure_entry_model(
                    rejected_raw_item
                )
            )
            is not None
        ]

    @staticmethod
    def _merge_category_from_constants(
        category_map: t.MutableFrozensetMapping,
        server_map: MutableMapping[str, frozenset[str] | str],
        *,
        override_existing: bool,
    ) -> None:
        for key_str, value in server_map.items():
            FlextLdifCategorization._merge_one_category(
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
        valid_categories = frozenset(c.Ldif.Category)
        if key_str not in valid_categories:
            return
        if override_existing or key_str not in category_map:
            category_map[key_str] = (
                value if isinstance(value, frozenset) else frozenset([str(value)])
            )

    @staticmethod
    def filter_categories_by_base_dn(
        categories: m.Ldif.FlexibleCategories,
        base_dn: str,
    ) -> m.Ldif.FlexibleCategories:
        """Filter categorized entries by base DN."""
        if not base_dn or not categories:
            return categories
        filtered = m.Ldif.FlexibleCategories()
        excluded_entries: MutableSequence[m.Ldif.Entry] = []
        filterable_categories: t.MutableBoolMapping = {
            c.Ldif.Category.HIERARCHY: True,
            c.Ldif.Category.USERS: True,
            c.Ldif.Category.GROUPS: True,
            c.Ldif.Category.ACL: True,
        }
        for category, entries in categories.items():
            if not entries:
                filtered[category] = []
                continue
            if category in filterable_categories:
                entries_list: MutableSequence[m.Ldif.Entry] = [
                    entry_model
                    for entry_raw in entries
                    if (
                        entry_model := FlextLdifCategorization._ensure_entry_model(
                            entry_raw
                        )
                    )
                    is not None
                ]
                included, excluded = FlextLdifCategorization._filter_entries_by_base_dn(
                    entries_list,
                    base_dn,
                )
                filtered[category] = included
                excluded_updated = [
                    FlextLdifCategorization._mark_entry_rejected(
                        entry,
                        category="BASE_DN_FILTER",
                        reason=f"DN not under base DN: {base_dn}",
                    )
                    for entry in excluded
                ]
                excluded_entries.extend(excluded_updated)
            else:
                filtered[category] = [
                    entry_model
                    for entry_raw in entries
                    if (
                        entry_model := FlextLdifCategorization._ensure_entry_model(
                            entry_raw
                        )
                    )
                    is not None
                ]
        FlextLdifCategorization._append_rejected_entries(filtered, excluded_entries)
        return filtered

    def categorize_entries(
        self,
        entries: MutableSequence[m.Ldif.Entry],
    ) -> r[m.Ldif.FlexibleCategories]:
        """Categorize entries into 6 categories."""
        category_lists: MutableMapping[str, list[m.Ldif.Entry]] = {
            cat_: []
            for cat_ in (
                c.Ldif.Category.SCHEMA,
                c.Ldif.Category.HIERARCHY,
                c.Ldif.Category.USERS,
                c.Ldif.Category.GROUPS,
                c.Ldif.Category.ACL,
                c.Ldif.Category.REJECTED,
            )
        }

        for entry in entries:
            category, match_reason = self.categorize_entry(entry)
            is_rejected = category == c.Ldif.Category.REJECTED
            updated_entry = u.Ldif.update_entry_statistics(
                entry,
                category=category,
                mark_rejected=(
                    c.Ldif.RejectionCategory.NO_CATEGORY_MATCH.value,
                    match_reason if match_reason is not None else "No category match",
                )
                if is_rejected
                else None,
            )
            category_lists[category].append(updated_entry)
            if is_rejected:
                self._rejection_tracker["categorization_rejected"].append(updated_entry)

        self._apply_post_categorization_filters(category_lists)

        categories = m.Ldif.FlexibleCategories()
        for cat, cat_entries in category_lists.items():
            categories[cat] = cat_entries
            if cat_entries:
                self.logger.info(
                    "Category entries",
                    category=cat,
                    entries_count=len(cat_entries),
                )
        return r[m.Ldif.FlexibleCategories].ok(categories)

    def _apply_post_categorization_filters(
        self,
        category_lists: MutableMapping[str, list[m.Ldif.Entry]],
    ) -> None:
        """Apply forbidden attribute/objectClass and schema OID value filters.

        Mutates ``category_lists`` in place. Uses ``_forbidden_attributes``,
        ``_forbidden_objectclasses``, and ``_schema_whitelist_rules`` stored
        during ``__init__``.
        """
        has_forbidden = bool(
            self._forbidden_attributes or self._forbidden_objectclasses
        )
        has_schema_rules = self._schema_whitelist_rules is not None

        if not has_forbidden and not has_schema_rules:
            return

        for cat, entries in category_lists.items():
            if cat == c.Ldif.Category.REJECTED or not entries:
                continue
            if cat == c.Ldif.Category.SCHEMA:
                filtered = list(entries)
                if has_schema_rules:
                    rules = self._schema_whitelist_rules
                    if rules is None:
                        continue
                    allowed_oids: MutableMapping[str, frozenset[str]] = {
                        "attributetypes": frozenset(rules.allowed_attribute_oids),
                        "objectclasses": frozenset(rules.allowed_objectclass_oids),
                        "matchingrules": frozenset(rules.allowed_matchingrule_oids),
                        "matchingruleuse": frozenset(
                            rules.allowed_matchingruleuse_oids
                        ),
                        "ldapsyntaxes": frozenset(rules.allowed_ldapsyntax_oids),
                    }
                    if any(allowed_oids.values()):
                        filtered = [
                            FlextLdifFilters.filter_schema_attribute_values(
                                entry, allowed_oids
                            )
                            for entry in filtered
                        ]
                if has_forbidden:
                    filtered = [
                        FlextLdifFilters.filter_entry_attributes(
                            entry,
                            self._forbidden_attributes,
                            self._forbidden_objectclasses,
                        )
                        for entry in filtered
                    ]
                category_lists[cat] = filtered
            elif has_forbidden:
                category_lists[cat] = [
                    FlextLdifFilters.filter_entry_attributes(
                        entry,
                        self._forbidden_attributes,
                        self._forbidden_objectclasses,
                    )
                    for entry in entries
                ]

    def categorize_entry(
        self,
        entry: m.Ldif.Entry,
        rules: m.Ldif.CategoryRules | MutableMapping[str, t.JsonValue] | None = None,
        server_type: str | None = None,
    ) -> tuple[str, str | None]:
        """Categorize single entry using provided or instance categorization rules."""
        rules_result = self._normalize_rules(rules)
        normalized_rules = rules_result.map_or(None)
        if normalized_rules is None:
            return (
                c.Ldif.Category.REJECTED,
                rules_result.error or "Failed to normalize rules",
            )
        effective_server_type_raw = server_type or self._server_type
        try:
            effective_server_type = u.Ldif.normalize_server_type(
                effective_server_type_raw,
            )
        except (ValueError, TypeError) as e:
            return (
                c.Ldif.Category.REJECTED,
                f"Unknown server type: {effective_server_type_raw} - {e}",
            )
        if self.matches_schema_entry(entry):
            return (c.Ldif.Category.SCHEMA, None)
        merged_category_map = self._build_category_map_from_rules(normalized_rules)
        constants: type | None = None
        constants_result = self._get_categorization_server_constants(
            effective_server_type,
        )
        if constants_result.success:
            constants_raw = constants_result.map_or(None)
            if constants_raw is not None:
                constants = constants_raw
        elif not merged_category_map:
            return (c.Ldif.Category.REJECTED, constants_result.error)
        if constants is not None:
            self._merge_server_constants_to_map(
                merged_category_map,
                constants,
                override_existing=not bool(rules),
            )
        priority_order = self._get_priority_order_from_constants(constants)
        if constants is not None and self._check_hierarchy_priority(entry, constants):
            return (c.Ldif.Category.HIERARCHY, None)
        return self._match_entry_to_category(entry, priority_order, merged_category_map)

    def filter_by_base_dn(
        self,
        categories: m.Ldif.FlexibleCategories,
    ) -> m.Ldif.FlexibleCategories:
        """Filter entries by base DN (if configured)."""
        if not self._base_dn:
            return categories
        filtered = m.Ldif.FlexibleCategories()
        for cat in (
            c.Ldif.Category.SCHEMA,
            c.Ldif.Category.HIERARCHY,
            c.Ldif.Category.USERS,
            c.Ldif.Category.GROUPS,
            c.Ldif.Category.ACL,
            c.Ldif.Category.REJECTED,
        ):
            filtered[cat] = []
        all_excluded_entries: MutableSequence[m.Ldif.Entry] = []
        for category, entries in categories.items():
            if not entries:
                continue
            if category in {
                c.Ldif.Category.HIERARCHY,
                c.Ldif.Category.USERS,
                c.Ldif.Category.GROUPS,
                c.Ldif.Category.ACL,
            }:
                entries_list: MutableSequence[m.Ldif.Entry] = [
                    entry_model
                    for entry_raw in entries
                    if (
                        entry_model := FlextLdifCategorization._ensure_entry_model(
                            entry_raw
                        )
                    )
                    is not None
                ]
                included, excluded = FlextLdifCategorization._filter_entries_by_base_dn(
                    entries_list,
                    self._base_dn,
                )
                included_updated = self._update_metadata_for_filtered_entries(
                    included,
                    passed=True,
                )
                excluded_updated = self._update_metadata_for_filtered_entries(
                    excluded,
                    passed=False,
                    rejection_reason=f"DN not under base DN: {self._base_dn}",
                )
                filtered[category] = included_updated
                all_excluded_entries.extend(excluded_updated)
                self._rejection_tracker["base_dn_filter"].extend(excluded_updated)
                if excluded_updated:
                    self.logger.info(
                        "Applied base DN filter",
                        category=category,
                        total_entries=u.count(entries),
                        kept_entries=u.count(included_updated),
                        rejected_entries=u.count(excluded_updated),
                    )
            else:
                filtered[category] = [
                    entry_model
                    for entry_raw in entries
                    if (
                        entry_model := FlextLdifCategorization._ensure_entry_model(
                            entry_raw
                        )
                    )
                    is not None
                ]
        FlextLdifCategorization._append_rejected_entries(filtered, all_excluded_entries)
        return filtered

    def filter_schema_by_oids(
        self,
        schema_entries: MutableSequence[m.Ldif.Entry],
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Filter schema entries by OID whitelist."""
        if not self._schema_whitelist_rules:
            return r[MutableSequence[m.Ldif.Entry]].ok(schema_entries)
        allowed_oids: t.MutableFrozensetMapping = {
            "allowed_attribute_oids": frozenset(
                self._schema_whitelist_rules.allowed_attribute_oids,
            ),
            "allowed_objectclass_oids": frozenset(
                self._schema_whitelist_rules.allowed_objectclass_oids,
            ),
            "allowed_matchingrule_oids": frozenset(
                self._schema_whitelist_rules.allowed_matchingrule_oids,
            ),
            "allowed_matchingruleuse_oids": frozenset(
                self._schema_whitelist_rules.allowed_matchingruleuse_oids,
            ),
        }
        result = FlextLdifFilters.filter_schema_by_oids(
            entries=schema_entries,
            allowed_oids=allowed_oids,
        )
        if result.success:
            filtered = result.map_or(None)
            if filtered is not None:
                self.logger.info(
                    "Applied schema OID whitelist filter",
                    total_entries=u.count(schema_entries),
                    filtered_entries=u.count(filtered),
                    removed_entries=u.count(schema_entries) - u.count(filtered),
                )
                return r[MutableSequence[m.Ldif.Entry]].ok(filtered)
        error_msg = result.error or "Failed to filter entries"
        return r[MutableSequence[m.Ldif.Entry]].fail(error_msg)

    def matches_schema_entry(self, entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema definition."""
        schema_attrs = {
            "attributetypes",
            "objectclasses",
            "ldapsyntaxes",
            "matchingrules",
        }
        if entry.attributes is None:
            return False
        attrs_dict: t.MutableStrSequenceMapping = (
            entry.attributes.attributes
            if hasattr(entry.attributes, "attributes")
            else {}
        )
        entry_attrs = {attr.lower() for attr in attrs_dict}
        return bool(schema_attrs & entry_attrs)

    def validate_dns(
        self,
        entries: MutableSequence[m.Ldif.Entry] | m.Ldif.ParseResponse,
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Validate and normalize all DNs to RFC 4514."""
        normalized_entries = (
            entries.entries if isinstance(entries, m.Ldif.ParseResponse) else entries
        )

        def validate_entry(entry: m.Ldif.Entry) -> r[m.Ldif.Entry]:
            """Validate and normalize entry DN."""
            dn_str = entry.dn.value if entry.dn else ""
            if not u.Ldif.validate_dn(dn_str):
                rejected_entry = u.Ldif.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        "invalid_dn",
                        f"DN validation failed (RFC 4514): {dn_str[:80]}",
                    ),
                )
                self._rejection_tracker["invalid_dn_rfc4514"].append(rejected_entry)
                self.logger.debug(
                    "Entry DN failed RFC 4514 validation",
                    entry_dn=dn_str,
                )
                return r[m.Ldif.Entry].fail(f"DN validation failed: {dn_str[:80]}")
            norm_result = u.Ldif.norm(dn_str)
            normalized_dn = norm_result.map_or(None)
            if normalized_dn is None:
                rejected_entry = u.Ldif.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        "invalid_dn",
                        f"DN normalization failed: {norm_result.error or 'Unknown error'}",
                    ),
                )
                self._rejection_tracker["invalid_dn_rfc4514"].append(rejected_entry)
                return r[m.Ldif.Entry].fail(
                    f"DN normalization failed: {norm_result.error or 'Unknown error'}",
                )
            dn_obj = m.Ldif.DN(value=normalized_dn)
            return r[m.Ldif.Entry].ok(entry.model_copy(update={"dn": dn_obj}))

        validated: MutableSequence[m.Ldif.Entry] = [
            validation_result.value
            for entry in normalized_entries
            if (validation_result := validate_entry(entry)).success
        ]
        self.logger.info(
            "Validated entries",
            validated_count=len(validated),
            rejected_count=len(self._rejection_tracker["invalid_dn_rfc4514"]),
            rejection_reason="invalid_dn_rfc4514",
        )
        if self._rejection_tracker["invalid_dn_rfc4514"]:
            sample_rejected_dns = [
                entry.dn.value[:_MAX_DN_PREVIEW_LENGTH]
                if entry.dn and len(entry.dn.value) > _MAX_DN_PREVIEW_LENGTH
                else entry.dn.value
                if entry.dn
                else ""
                for entry in self._rejection_tracker["invalid_dn_rfc4514"][:5]
            ]
            self.logger.debug(
                "Sample rejected DNs",
                sample_count=len(sample_rejected_dns),
                rejected_dns_preview=", ".join(sample_rejected_dns),
            )
        return r[MutableSequence[m.Ldif.Entry]].ok(validated)

    def _build_category_map_from_rules(
        self,
        rules: m.Ldif.CategoryRules,
    ) -> t.MutableFrozensetMapping:
        """Build category map from rules."""
        category_map: t.MutableFrozensetMapping = {}
        if rules.hierarchy_objectclasses:
            mapped = u.map(rules.hierarchy_objectclasses, mapper=lambda oc: oc.lower())
            category_map[c.Ldif.Category.HIERARCHY] = frozenset(mapped)
        if rules.user_objectclasses:
            mapped = u.map(rules.user_objectclasses, mapper=lambda oc: oc.lower())
            category_map[c.Ldif.Category.USERS] = frozenset(mapped)
        if rules.group_objectclasses:
            mapped = u.map(rules.group_objectclasses, mapper=lambda oc: oc.lower())
            category_map[c.Ldif.Category.GROUPS] = frozenset(mapped)
        if rules.acl_attributes:
            mapped = u.map(
                rules.acl_attributes,
                mapper=lambda attr: f"attr:{attr.lower()}",
            )
            category_map[c.Ldif.Category.ACL] = frozenset(mapped)
        return category_map

    def _check_hierarchy_priority(
        self,
        entry: m.Ldif.Entry,
        constants: type[c.Ldif],
    ) -> bool:
        """Check if entry matches HIERARCHY_PRIORITY_OBJECTCLASSES."""
        priority_classes_raw: frozenset[str] = getattr(
            constants,
            "HIERARCHY_PRIORITY_OBJECTCLASSES",
            frozenset(),
        )
        priority_classes = frozenset(map(str, priority_classes_raw))
        entry_ocs = {oc.lower() for oc in u.Ldif.get_objectclass_names(entry)}
        return any(oc.lower() in entry_ocs for oc in priority_classes)

    def _get_default_priority_order(self) -> MutableSequence[str]:
        """Get default category priority order."""
        return [
            c.Ldif.Category.USERS,
            c.Ldif.Category.HIERARCHY,
            c.Ldif.Category.GROUPS,
            c.Ldif.Category.ACL,
        ]

    def _get_priority_order_from_constants(
        self,
        constants: type[c.Ldif] | None,
    ) -> MutableSequence[str]:
        """Get priority order from constants or use default."""
        if constants is not None and hasattr(constants, "CATEGORIZATION_PRIORITY"):

            def is_valid_category(value: str) -> bool:
                """Wrapper for TypeIs function to use as filter predicate."""
                return value in {
                    c.Ldif.Category.SCHEMA,
                    c.Ldif.Category.HIERARCHY,
                    c.Ldif.Category.USERS,
                    c.Ldif.Category.GROUPS,
                    c.Ldif.Category.ACL,
                    c.Ldif.Category.REJECTED,
                }

            priority_list: MutableSequence[str] = getattr(
                constants,
                "CATEGORIZATION_PRIORITY",
                [],
            )
            filtered: MutableSequence[str] = [
                item for item in priority_list if is_valid_category(item)
            ]
            valid_categories: frozenset[str] = frozenset(c.Ldif.Category)
            result: MutableSequence[str] = [
                item for item in filtered if item in valid_categories
            ]
            return result
        return self._get_default_priority_order()

    def _get_categorization_server_constants(
        self,
        server_type: str,
    ) -> r[type[c.Ldif]]:
        """Get and validate server constants via FlextLdifServer registry."""
        return (
            r[type[c.Ldif]]
            .from_result(
                self._server_registry.resolve_server_constants(server_type),
            )
            .map_error(
                lambda error: error or f"Failed to resolve constants for {server_type}",
            )
        )

    def _match_entry_to_category(
        self,
        entry: m.Ldif.Entry,
        priority_order: MutableSequence[str],
        category_map: t.MutableFrozensetMapping,
    ) -> tuple[str, str | None]:
        """Match entry to category using priority order and category map."""
        objectclass_names: MutableSequence[str] = u.Ldif.get_objectclass_names(entry)
        entry_ocs: set[str] = {oc.lower() for oc in objectclass_names}
        for category in priority_order:
            if category not in category_map:
                continue
            category_ocs = category_map[category]
            category_ocs_lower = {oc.lower() for oc in category_ocs}
            if category == c.Ldif.Category.ACL:
                for attr_marker in category_ocs:
                    if attr_marker.startswith("attr:"):
                        attr_name = attr_marker[5:]
                        if u.Ldif.has_attribute(entry, attr_name):
                            return (c.Ldif.Category.ACL, None)
            elif any(oc in category_ocs_lower for oc in entry_ocs):
                return (category, None)
        return (c.Ldif.Category.REJECTED, "No category match")

    def _merge_server_constants_to_map(
        self,
        category_map: t.MutableFrozensetMapping,
        constants: type[c.Ldif],
        *,
        override_existing: bool = False,
    ) -> t.MutableFrozensetMapping:
        """Merge server constants into category map."""
        empty_category_map: t.MutableFrozensetMapping = {}
        category_objectclasses: t.MutableFrozensetMapping = getattr(
            constants,
            "CATEGORY_OBJECTCLASSES",
            empty_category_map,
        )
        server_map: MutableMapping[str, frozenset[str] | str] = {}
        for map_key, map_value in category_objectclasses.items():
            server_map[map_key] = frozenset(map_value)
        FlextLdifCategorization._merge_category_from_constants(
            category_map,
            server_map,
            override_existing=override_existing,
        )
        acl_attrs_raw: frozenset[str] = getattr(
            constants,
            "CATEGORIZATION_ACL_ATTRIBUTES",
            frozenset(),
        )
        if acl_attrs_raw:
            acl_attrs = frozenset(map(str, acl_attrs_raw))
            acl_category = c.Ldif.Category.ACL

            if override_existing or acl_category not in category_map:
                mapped = u.map(acl_attrs, mapper=lambda attr: f"attr:{attr.lower()}")
                category_map[acl_category] = frozenset(mapped)
            else:
                existing_acl = category_map.get(acl_category, frozenset())
                mapped = u.map(acl_attrs, mapper=lambda attr: f"attr:{attr.lower()}")
                new_acl_attrs = frozenset(mapped)
                category_map[acl_category] = existing_acl | new_acl_attrs
        return category_map

    def _normalize_rules(
        self,
        rules: m.Ldif.CategoryRules | MutableMapping[str, t.JsonValue] | None,
    ) -> r[m.Ldif.CategoryRules]:
        """Normalize rules to CategoryRules model."""
        if isinstance(rules, m.Ldif.CategoryRules):
            return r[m.Ldif.CategoryRules].ok(rules)
        if rules is None:
            return r[m.Ldif.CategoryRules].ok(self._categorization_rules)
        return r[m.Ldif.CategoryRules].from_result(
            u.try_(
                lambda: m.Ldif.CategoryRules.model_validate(dict(rules)),
                catch=(
                    ValueError,
                    KeyError,
                    AttributeError,
                    UnicodeDecodeError,
                    struct.error,
                ),
            ).map_error(lambda e: f"Invalid rules mapping: {e}"),
        )

    def _update_metadata_for_filtered_entries(
        self,
        entries: MutableSequence[m.Ldif.Entry],
        *,
        passed: bool,
        rejection_reason: str | None = None,
    ) -> MutableSequence[m.Ldif.Entry]:
        """Update metadata for filtered entries using u."""
        return [
            u.Ldif.update_entry_statistics(
                entry,
                mark_filtered=("base_dn_filter", passed),
                mark_rejected=(c.Ldif.Category.REJECTED, rejection_reason)
                if not passed and rejection_reason
                else None,
            )
            for entry in entries
        ]


__all__: list[str] = ["FlextLdifCategorization"]
