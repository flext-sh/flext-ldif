"""Categorization Service - LDIF Entry Categorization Operations."""

from __future__ import annotations

import struct
from collections.abc import MutableMapping
from typing import Annotated

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.services.filters import FlextLdifFilters


class FlextLdifCategorization(s):
    """LDIF Entry Categorization Service."""

    @staticmethod
    def _build_rejection_tracker() -> MutableMapping[
        str, t.MutableSequenceOf[m.Ldif.Entry]
    ]:
        """Build the canonical rejection tracker structure for one categorization run."""
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
            description="Optional schema whitelist rules used to filter schema entries.",
        ),
    ] = None
    forbidden_attributes: Annotated[
        t.MutableSequenceOf[str] | None,
        u.Field(
            default=None,
            exclude=True,
            description="Attribute names removed from categorized entries after classification.",
        ),
    ] = None
    forbidden_objectclasses: Annotated[
        t.MutableSequenceOf[str] | None,
        u.Field(
            default=None,
            exclude=True,
            description="objectClass names removed from categorized entries after classification.",
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
            description="Server type used to resolve categorization defaults from the registry.",
        ),
    ] = c.Ldif.ServerTypes.RFC.value
    server_registry: Annotated[
        p.Ldif.ServerRegistry | None,
        u.Field(
            default=None,
            exclude=True,
            description="Optional server registry override for categorization constants lookup.",
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
        """Normalize initial categorization rules into the canonical model."""
        validated_rules: m.Ldif.CategoryRules = m.Ldif.CategoryRules.model_validate(
            self.categorization_rules or {}
        )
        return validated_rules

    def _whitelist_rules_with_oid_filters(self) -> m.Ldif.WhitelistRules | None:
        """Return normalized whitelist rules only when OID filters are configured."""
        whitelist_rules = self.schema_whitelist_rules
        if whitelist_rules is None or not whitelist_rules.has_oid_filters:
            return None
        return whitelist_rules

    @staticmethod
    def _ensure_entry_model(
        value: t.JsonValue | m.BaseModel | m.Ldif.Entry,
    ) -> m.Ldif.Entry | None:
        if isinstance(value, m.Ldif.Entry):
            return value
        if isinstance(value, m.BaseModel):
            validation_result = u.try_(lambda: u.Ldif.as_entry(value))
            if validation_result.failure:
                FlextLdifCategorization._get_or_create_logger().warning(
                    "Failed to coerce BaseModel to Entry",
                    error=validation_result.error,
                    error_type="ValidationError",
                )
                return None
            validated: m.Ldif.Entry = validation_result.value
            return validated
        return None

    @staticmethod
    def _filter_entries_by_base_dn(
        entries: t.MutableSequenceOf[m.Ldif.Entry], base_dn: str
    ) -> tuple[t.MutableSequenceOf[m.Ldif.Entry], t.MutableSequenceOf[m.Ldif.Entry]]:
        """Filter entries by base DN using u.Ldif."""
        model_entries: t.MutableSequenceOf[m.Ldif.Entry] = list(entries)
        included: t.MutableSequenceOf[m.Ldif.Entry] = []
        excluded: t.MutableSequenceOf[m.Ldif.Entry] = []
        for entry in model_entries:
            dn_str = str(entry.dn) if entry.dn else None
            if dn_str and u.Ldif.is_under_base(dn_str, base_dn):
                included.append(entry)
            else:
                excluded.append(entry)
        return (included, excluded)

    @staticmethod
    def _append_rejected_entries(
        filtered: m.Ldif.FlexibleCategories,
        rejected_entries: t.MutableSequenceOf[m.Ldif.Entry],
    ) -> None:
        """Append rejected entries into the canonical REJECTED bucket."""
        if not rejected_entries:
            return
        rejected_category = c.Ldif.Category.REJECTED
        existing_rejected_raw: t.MutableSequenceOf[m.Ldif.Entry] = filtered.get(
            rejected_category, []
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
                category_map, key_str, value, override_existing=override_existing
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

    def categorize_entries(
        self, entries: t.MutableSequenceOf[m.Ldif.Entry]
    ) -> p.Result[m.Ldif.FlexibleCategories]:
        """Categorize entries into 6 categories."""
        category_lists: MutableMapping[str, list[m.Ldif.Entry]] = {
            category: [] for category in c.Ldif.CATEGORY_BUCKET_ORDER
        }

        for entry in entries:
            category, match_reason = self.categorize_entry(entry)
            is_rejected = category == c.Ldif.Category.REJECTED
            updated_entry = u.Ldif.update_entry_statistics(
                entry,
                category=category,
                mark_rejected=(
                    c.Ldif.RejectionCategory.NO_CATEGORY_MATCH.value,
                    match_reason
                    if match_reason is not None
                    else c.Ldif.REJECTION_REASON_NO_CATEGORY_MATCH,
                )
                if is_rejected
                else None,
            )
            category_lists[category].append(updated_entry)
            if is_rejected:
                self.rejection_tracker[
                    c.Ldif.RejectionTrackerKey.CATEGORIZATION_REJECTED
                ].append(updated_entry)

        self._apply_post_categorization_filters(category_lists)

        categories = m.Ldif.FlexibleCategories()
        for cat, cat_entries in category_lists.items():
            categories[cat] = cat_entries
            if cat_entries:
                self.logger.info(
                    "Category entries", category=cat, entries_count=len(cat_entries)
                )
        return r[m.Ldif.FlexibleCategories].ok(categories)

    def _apply_post_categorization_filters(
        self, category_lists: MutableMapping[str, list[m.Ldif.Entry]]
    ) -> None:
        """Apply forbidden attribute/objectClass and schema OID value filters.

        Mutates ``category_lists`` in place. Uses ``forbidden_attributes``,
        ``forbidden_objectclasses``, and ``schema_whitelist_rules`` stored
        during ``__init__``.
        """
        schema_whitelist_rules = self._whitelist_rules_with_oid_filters()
        forbidden_attributes = self.forbidden_attributes or []
        forbidden_objectclasses = self.forbidden_objectclasses or []
        has_attribute_filters = bool(forbidden_attributes or forbidden_objectclasses)
        if schema_whitelist_rules is None and not has_attribute_filters:
            return

        for category, entries in category_lists.items():
            if category == c.Ldif.Category.REJECTED:
                continue
            if not entries:
                continue
            filtered = entries
            if (
                category == c.Ldif.Category.SCHEMA
                and schema_whitelist_rules is not None
            ):
                filtered = [
                    FlextLdifFilters.filter_schema_attribute_values(
                        entry, schema_whitelist_rules
                    )
                    for entry in filtered
                ]
            if has_attribute_filters:
                filtered = [
                    FlextLdifFilters.filter_entry_attributes(
                        entry, forbidden_attributes, forbidden_objectclasses
                    )
                    for entry in filtered
                ]
            category_lists[category] = filtered

    def categorize_entry(
        self,
        entry: m.Ldif.Entry,
        rules: m.Ldif.CategoryRules | t.MutableJsonMapping | None = None,
        server_type: str | None = None,
    ) -> tuple[str, str | None]:
        """Categorize single entry using provided or instance categorization rules."""
        rules_result = self._normalize_rules(rules)
        normalized_rules = rules_result.map_or(None)
        if normalized_rules is None:
            return (
                c.Ldif.Category.REJECTED,
                rules_result.error or c.Ldif.ERR_FAILED_NORMALIZE_RULES,
            )
        effective_server_type_raw = server_type or self.server_type
        try:
            effective_server_type = u.Ldif.normalize_server_type(
                effective_server_type_raw
            )
        except c.EXC_TYPE_VALIDATION as e:
            return (
                c.Ldif.Category.REJECTED,
                f"Unknown server type: {effective_server_type_raw} - {e}",
            )
        if self.matches_schema_entry(entry):
            return (c.Ldif.Category.SCHEMA, None)
        merged_category_map = dict(normalized_rules.category_markers)
        constants: type | None = None
        constants_result = self._get_categorization_server_constants(
            effective_server_type
        )
        if constants_result.success:
            constants_raw = constants_result.map_or(None)
            if constants_raw is not None:
                constants = constants_raw
        elif not merged_category_map:
            return (c.Ldif.Category.REJECTED, constants_result.error)
        if constants is not None:
            self._merge_server_constants_to_map(
                merged_category_map, constants, override_existing=not bool(rules)
            )
        priority_order = self._get_priority_order_from_constants(constants)
        return (
            (c.Ldif.Category.HIERARCHY, None)
            if constants is not None
            and self._check_hierarchy_priority(entry, constants)
            else self._match_entry_to_category(
                entry, priority_order, merged_category_map
            )
        )

    def filter_by_base_dn(
        self, categories: m.Ldif.FlexibleCategories
    ) -> m.Ldif.FlexibleCategories:
        """Filter entries by base DN (if configured)."""
        if not self.base_dn:
            return categories
        filtered = m.Ldif.FlexibleCategories()
        for category in c.Ldif.CATEGORY_BUCKET_ORDER:
            filtered[category] = []
        all_excluded_entries: t.MutableSequenceOf[m.Ldif.Entry] = []
        for category, entries in categories.items():
            if not entries:
                continue
            if category in c.Ldif.CATEGORY_FILTERABLE_BY_BASE_DN:
                entries_list: t.MutableSequenceOf[m.Ldif.Entry] = [
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
                    entries_list, self.base_dn
                )
                included_updated = self._update_metadata_for_filtered_entries(
                    included, passed=True
                )
                excluded_updated = self._update_metadata_for_filtered_entries(
                    excluded,
                    passed=False,
                    rejection_reason=f"DN not under base DN: {self.base_dn}",
                )
                filtered[category] = included_updated
                all_excluded_entries.extend(excluded_updated)
                self.rejection_tracker[
                    c.Ldif.RejectionTrackerKey.BASE_DN_FILTER
                ].extend(excluded_updated)
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
        self, schema_entries: t.MutableSequenceOf[m.Ldif.Entry]
    ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Filter schema entries by OID whitelist."""
        sw_rules = self._whitelist_rules_with_oid_filters()
        if sw_rules is None:
            return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(schema_entries)
        result = FlextLdifFilters.filter_schema_by_oids(
            entries=schema_entries, allowed_oids=sw_rules
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
                return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(filtered)
        error_msg = result.error or c.Ldif.ERR_FAILED_FILTER_ENTRIES
        return r[t.MutableSequenceOf[m.Ldif.Entry]].fail(error_msg)

    def matches_schema_entry(self, entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema definition."""
        if entry.attributes is None:
            return False
        attrs_dict: t.MutableStrSequenceMapping = entry.attributes.attributes
        entry_attrs = {attr.lower() for attr in attrs_dict}
        return bool(c.Ldif.SCHEMA_CATEGORY_ATTRIBUTE_KEYS & entry_attrs)

    def validate_dns(
        self, entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse
    ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Validate and normalize all DNs to RFC 4514."""
        normalized_entries = u.Ldif.as_entries(entries)

        def validate_entry(entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
            """Validate and normalize entry DN."""
            dn_str = str(entry.dn) if entry.dn else ""
            if not u.Ldif.validate_dn(dn_str):
                rejected_entry = u.Ldif.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        c.Ldif.RejectionCategory.INVALID_DN.value,
                        f"DN validation failed (RFC 4514): {dn_str[:80]}",
                    ),
                )
                self.rejection_tracker[
                    c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514
                ].append(rejected_entry)
                self.logger.debug(
                    "Entry DN failed RFC 4514 validation", entry_dn=dn_str
                )
                return r[m.Ldif.Entry].fail_op("DN validation", dn_str[:80])
            norm_result = u.Ldif.norm(dn_str)
            normalized_dn = norm_result.map_or(None)
            if normalized_dn is None:
                rejected_entry = u.Ldif.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        c.Ldif.RejectionCategory.INVALID_DN.value,
                        f"DN normalization failed: {norm_result.error or c.Ldif.ERR_UNKNOWN}",
                    ),
                )
                self.rejection_tracker[
                    c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514
                ].append(rejected_entry)
                return r[m.Ldif.Entry].fail_op(
                    "DN normalization", norm_result.error or c.Ldif.ERR_UNKNOWN
                )
            dn_obj = m.Ldif.DN(value=normalized_dn)
            return r[m.Ldif.Entry].ok(entry.model_copy(update={"dn": dn_obj}))

        validated: t.MutableSequenceOf[m.Ldif.Entry] = [
            validation_result.value
            for entry in normalized_entries
            if (validation_result := validate_entry(entry)).success
        ]
        self.logger.info(
            "Validated entries",
            validated_count=len(validated),
            rejected_count=len(
                self.rejection_tracker[c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514]
            ),
            rejection_reason=c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514,
        )
        if self.rejection_tracker[c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514]:
            sample_rejected_dns = [
                entry.dn.value[: c.Ldif.DN_PREVIEW_LENGTH]
                if entry.dn and len(entry.dn.value) > c.Ldif.DN_PREVIEW_LENGTH
                else entry.dn.value
                if entry.dn
                else ""
                for entry in self.rejection_tracker[
                    c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514
                ][:5]
            ]
            self.logger.debug(
                "Sample rejected DNs",
                sample_count=len(sample_rejected_dns),
                rejected_dns_preview=", ".join(sample_rejected_dns),
            )
        return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(validated)

    def _check_hierarchy_priority(
        self, entry: m.Ldif.Entry, constants: type[p.Ldif.ServerConstants]
    ) -> bool:
        """Check if entry matches HIERARCHY_PRIORITY_OBJECTCLASSES."""
        priority_classes = frozenset(
            oc.lower() for oc in constants.HIERARCHY_PRIORITY_OBJECTCLASSES
        )
        entry_ocs = {oc.lower() for oc in u.Ldif.get_objectclass_names(entry)}
        return bool(priority_classes & entry_ocs)

    def _get_priority_order_from_constants(
        self, constants: type[p.Ldif.ServerConstants] | None
    ) -> t.MutableSequenceOf[str]:
        """Get priority order from constants or use default."""
        if constants is None:
            return list(c.Ldif.DEFAULT_CATEGORIZATION_PRIORITY)
        return [
            item
            for item in constants.CATEGORIZATION_PRIORITY
            if item in c.Ldif.CATEGORY_VALUES
        ]

    def _get_categorization_server_constants(
        self, server_type: str
    ) -> p.Result[type[p.Ldif.ServerConstants]]:
        """Get and validate server constants via FlextLdifServer registry."""
        registry = self.server_registry or self.server
        if registry is None:
            return r[type[p.Ldif.ServerConstants]].fail(
                c.Ldif.ERR_SERVER_REGISTRY_UNAVAILABLE
            )
        return (
            r[type[p.Ldif.ServerConstants]]
            .from_result(registry.resolve_server_constants(server_type))
            .map_error(
                lambda error: error or f"Failed to resolve constants for {server_type}"
            )
        )

    def _match_entry_to_category(
        self,
        entry: m.Ldif.Entry,
        priority_order: t.MutableSequenceOf[str],
        category_map: t.MutableFrozensetMapping,
    ) -> tuple[str, str | None]:
        """Match entry to category using priority order and category map."""
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
                        marker.removeprefix(attribute_marker_prefix)
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

    def _merge_server_constants_to_map(
        self,
        category_map: t.MutableFrozensetMapping,
        constants: type[p.Ldif.ServerConstants],
        *,
        override_existing: bool = False,
    ) -> t.MutableFrozensetMapping:
        """Merge server constants into category map."""
        server_map: MutableMapping[str, frozenset[str] | str] = {
            map_key: frozenset(map_value)
            for map_key, map_value in constants.CATEGORY_OBJECTCLASSES.items()
        }
        FlextLdifCategorization._merge_category_from_constants(
            category_map, server_map, override_existing=override_existing
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
        self, rules: m.Ldif.CategoryRules | t.MutableJsonMapping | None
    ) -> p.Result[m.Ldif.CategoryRules]:
        """Normalize rules to CategoryRules model."""
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
            ).map_error(lambda e: f"Invalid rules mapping: {e}")
        )

    def _update_metadata_for_filtered_entries(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
        *,
        passed: bool,
        rejection_reason: str | None = None,
    ) -> t.MutableSequenceOf[m.Ldif.Entry]:
        """Update metadata for filtered entries using u."""
        return [
            u.Ldif.update_entry_statistics(
                entry,
                mark_filtered=(c.Ldif.RejectionCategory.BASE_DN_FILTER.value, passed),
                mark_rejected=(
                    c.Ldif.RejectionCategory.BASE_DN_FILTER.value,
                    rejection_reason,
                )
                if not passed and rejection_reason
                else None,
            )
            for entry in entries
        ]


__all__: list[str] = ["FlextLdifCategorization"]
