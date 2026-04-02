"""Categorization Service - LDIF Entry Categorization Operations."""

from __future__ import annotations

import struct
from collections.abc import MutableMapping, MutableSequence
from typing import Final, override

from pydantic import BaseModel, ValidationError

from flext_core import FlextLogger
from flext_ldif import (
    FlextLdifFilters,
    FlextLdifServer,
    FlextLdifServersBaseConstants,
    FlextLdifUtilitiesDN,
    c,
    m,
    r,
    s,
    t,
    u,
)

logger = FlextLogger(__name__)

_MAX_DN_PREVIEW_LENGTH: Final[int] = 100


class _MissingSentinel:
    pass


_MISSING_ATTR: Final[_MissingSentinel] = _MissingSentinel()


class FlextLdifCategorization(s[m.Ldif.FlexibleCategories]):
    """LDIF Entry Categorization Service."""

    def __init__(
        self,
        categorization_rules: m.Ldif.CategoryRules
        | MutableMapping[str, str | MutableSequence[str] | None]
        | None = None,
        schema_whitelist_rules: m.Ldif.WhitelistRules
        | MutableMapping[str, str | MutableSequence[str] | bool | None]
        | None = None,
        forbidden_attributes: MutableSequence[str] | None = None,
        forbidden_objectclasses: MutableSequence[str] | None = None,
        base_dn: str | None = None,
        server_type: str = "rfc",
        server_registry: FlextLdifServer | None = None,
    ) -> None:
        """Initialize categorization service."""
        super().__init__()
        self._categorization_rules: m.Ldif.CategoryRules
        self._schema_whitelist_rules: m.Ldif.WhitelistRules | None
        self._forbidden_attributes: MutableSequence[str]
        self._forbidden_objectclasses: MutableSequence[str]
        self._base_dn: str | None
        self._server_type: str
        self._rejection_tracker: MutableMapping[str, MutableSequence[m.Ldif.Entry]]
        self._server_registry: FlextLdifServer
        if server_registry is not None:
            object.__setattr__(self, "_server_registry", server_registry)
        else:
            object.__setattr__(
                self,
                "_server_registry",
                FlextLdifServer.get_global_instance(),
            )
        if isinstance(categorization_rules, m.Ldif.CategoryRules):
            object.__setattr__(self, "_categorization_rules", categorization_rules)
        elif isinstance(categorization_rules, dict):
            object.__setattr__(
                self,
                "_categorization_rules",
                m.Ldif.CategoryRules.model_validate(categorization_rules),
            )
        else:
            object.__setattr__(
                self, "_categorization_rules", m.Ldif.CategoryRules.model_validate({})
            )
        if isinstance(schema_whitelist_rules, m.Ldif.WhitelistRules):
            object.__setattr__(self, "_schema_whitelist_rules", schema_whitelist_rules)
        elif isinstance(schema_whitelist_rules, dict):
            object.__setattr__(
                self,
                "_schema_whitelist_rules",
                m.Ldif.WhitelistRules.model_validate(schema_whitelist_rules),
            )
        else:
            object.__setattr__(self, "_schema_whitelist_rules", None)
        object.__setattr__(
            self,
            "_forbidden_attributes",
            forbidden_attributes if forbidden_attributes is not None else [],
        )
        object.__setattr__(
            self,
            "_forbidden_objectclasses",
            forbidden_objectclasses if forbidden_objectclasses is not None else [],
        )
        object.__setattr__(self, "_base_dn", base_dn)
        object.__setattr__(self, "_server_type", server_type)
        object.__setattr__(
            self,
            "_rejection_tracker",
            {
                "invalid_dn_rfc4514": [],
                "base_dn_filter": [],
                "categorization_rejected": [],
            },
        )

    @property
    def base_dn(self) -> str | None:
        """Get base DN (read-only)."""
        return self._base_dn

    @property
    def forbidden_attributes(self) -> MutableSequence[str]:
        """Get forbidden attributes list (read-only)."""
        return self._forbidden_attributes

    @property
    def forbidden_objectclasses(self) -> MutableSequence[str]:
        """Get forbidden objectClasses list (read-only)."""
        return self._forbidden_objectclasses

    @property
    def rejection_tracker(self) -> MutableMapping[str, MutableSequence[m.Ldif.Entry]]:
        """Get rejection tracker (read-only access to rejected entries by reason)."""
        return self._rejection_tracker

    @property
    def schema_whitelist_rules(self) -> m.Ldif.WhitelistRules | None:
        """Get schema whitelist rules (read-only)."""
        return self._schema_whitelist_rules

    @staticmethod
    def _cat(category: str) -> str:
        return category

    @staticmethod
    def _ensure_entry_model(
        value: t.NormalizedValue | m.Ldif.Entry,
    ) -> m.Ldif.Entry | None:
        if isinstance(value, m.Ldif.Entry):
            return value
        if isinstance(value, BaseModel):
            try:
                return m.Ldif.Entry.model_validate(value)
            except ValidationError as exc:
                logger.warning(
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
    def _has_attr(obj: t.NormalizedValue | type, attr_name: str) -> bool:
        return getattr(obj, attr_name, _MISSING_ATTR) is not _MISSING_ATTR

    @staticmethod
    def _mark_entry_rejected(
        entry: m.Ldif.Entry,
        category: str,
        reason: str,
    ) -> m.Ldif.Entry:
        """Mark entry as rejected in metadata using u."""
        return u.Ldif.update_entry_statistics(entry, mark_rejected=(category, reason))

    @staticmethod
    def _merge_category_from_constants(
        category_map: MutableMapping[str, frozenset[str]],
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
        category_map: MutableMapping[str, frozenset[str]],
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
        filterable_categories: MutableMapping[str, bool] = {
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
        if excluded_entries:
            rejected_category = c.Ldif.Category.REJECTED
            existing_rejected_raw: MutableSequence[m.Ldif.Entry] = filtered.get(
                rejected_category,
                [],
            )
            filtered[c.Ldif.Category.REJECTED] = [
                entry_model
                for rejected_raw_item in [*existing_rejected_raw, *excluded_entries]
                if (
                    entry_model := FlextLdifCategorization._ensure_entry_model(
                        rejected_raw_item
                    )
                )
                is not None
            ]
        return filtered

    def categorize_entries(
        self,
        entries: MutableSequence[m.Ldif.Entry],
    ) -> r[m.Ldif.FlexibleCategories]:
        """Categorize entries into 6 categories."""
        categories = m.Ldif.FlexibleCategories()
        for cat_ in (
            c.Ldif.Category.SCHEMA,
            c.Ldif.Category.HIERARCHY,
            c.Ldif.Category.USERS,
            c.Ldif.Category.GROUPS,
            c.Ldif.Category.ACL,
            c.Ldif.Category.REJECTED,
        ):
            categories[cat_] = []

        def categorize_single_entry(entry: m.Ldif.Entry) -> tuple[str, m.Ldif.Entry]:
            """Categorize single entry."""
            category, reason = self.categorize_entry(entry)
            rejection_reason = reason if reason is not None else "No category match"
            is_rejected = category == c.Ldif.Category.REJECTED
            category_literal: str | None = None
            if category == c.Ldif.Category.USERS:
                category_literal = c.Ldif.Category.USERS
            elif category == c.Ldif.Category.GROUPS:
                category_literal = c.Ldif.Category.GROUPS
            elif category == c.Ldif.Category.HIERARCHY:
                category_literal = c.Ldif.Category.HIERARCHY
            elif category == c.Ldif.Category.SCHEMA:
                category_literal = c.Ldif.Category.SCHEMA
            elif category == c.Ldif.Category.ACL:
                category_literal = c.Ldif.Category.ACL
            elif category == c.Ldif.Category.REJECTED:
                category_literal = c.Ldif.Category.REJECTED
            entry_to_append = u.Ldif.update_entry_statistics(
                entry,
                category=category_literal,
                mark_rejected=(
                    c.Ldif.RejectionCategory.NO_CATEGORY_MATCH.value,
                    rejection_reason,
                )
                if is_rejected
                else None,
            )
            return (category, entry_to_append)

        for entry in entries:
            category, reason = categorize_single_entry(entry)
            if category == c.Ldif.Category.REJECTED:
                self._rejection_tracker["categorization_rejected"].append(reason)
                logger.debug(
                    "Entry rejected during categorization",
                    entry_dn=str(reason.dn) if reason.dn else "",
                    rejection_reason="",
                )
            updated_entries = [*categories[category], reason]
            categories[category] = updated_entries
        for cat, cat_entries in categories.items():
            if cat_entries:
                entries_count = u.count(cat_entries)
                logger.info(
                    "Category entries",
                    category=cat,
                    entries_count=entries_count,
                )
        return r[m.Ldif.FlexibleCategories].ok(categories)

    def categorize_entry(
        self,
        entry: m.Ldif.Entry,
        rules: m.Ldif.CategoryRules
        | MutableMapping[str, t.MetadataValue]
        | None = None,
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
        if self.is_schema_entry(entry):
            return (c.Ldif.Category.SCHEMA, None)
        merged_category_map = self._build_category_map_from_rules(normalized_rules)
        constants: type | None = None
        constants_result = self._get_server_constants(effective_server_type)
        if constants_result.is_success:
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

    @override
    def execute(self) -> r[m.Ldif.FlexibleCategories]:
        """Execute categorization pass (use individual methods for specific operations)."""
        categories = m.Ldif.FlexibleCategories()
        for cat in (
            c.Ldif.Category.SCHEMA,
            c.Ldif.Category.HIERARCHY,
            c.Ldif.Category.USERS,
            c.Ldif.Category.GROUPS,
            c.Ldif.Category.ACL,
            c.Ldif.Category.REJECTED,
        ):
            categories[cat] = []
        return r[m.Ldif.FlexibleCategories].ok(categories)

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
                    logger.info(
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
        if all_excluded_entries:
            rejected_category = c.Ldif.Category.REJECTED
            existing_rejected_raw: MutableSequence[m.Ldif.Entry] = filtered.get(
                rejected_category,
                [],
            )
            filtered[c.Ldif.Category.REJECTED] = [
                entry_model
                for rejected_raw_item in [*existing_rejected_raw, *all_excluded_entries]
                if (
                    entry_model := FlextLdifCategorization._ensure_entry_model(
                        rejected_raw_item
                    )
                )
                is not None
            ]
        return filtered

    def filter_schema_by_oids(
        self,
        schema_entries: MutableSequence[m.Ldif.Entry],
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Filter schema entries by OID whitelist."""
        if not self._schema_whitelist_rules:
            return r[MutableSequence[m.Ldif.Entry]].ok(schema_entries)
        allowed_oids: MutableMapping[str, frozenset[str]] = {
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
        if result.is_success:
            filtered = result.map_or(None)
            if filtered is not None:
                logger.info(
                    "Applied schema OID whitelist filter",
                    total_entries=u.count(schema_entries),
                    filtered_entries=u.count(filtered),
                    removed_entries=u.count(schema_entries) - u.count(filtered),
                )
                return r[MutableSequence[m.Ldif.Entry]].ok(filtered)
        error_msg = result.error or "Failed to filter entries"
        return r[MutableSequence[m.Ldif.Entry]].fail(error_msg)

    def is_schema_entry(self, entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema definition."""
        schema_attrs = {
            "attributetypes",
            "objectclasses",
            "ldapsyntaxes",
            "matchingrules",
        }
        if entry.attributes is None:
            return False
        attrs_dict: MutableMapping[str, MutableSequence[str]] = (
            entry.attributes.attributes
            if hasattr(entry.attributes, "attributes")
            else {}
        )
        entry_attrs = {attr.lower() for attr in attrs_dict}
        return bool(schema_attrs & entry_attrs)

    def validate_dns(
        self,
        entries: MutableSequence[m.Ldif.Entry],
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Validate and normalize all DNs to RFC 4514."""

        def validate_entry(entry: m.Ldif.Entry) -> r[m.Ldif.Entry]:
            """Validate and normalize entry DN."""
            dn_str = entry.dn.value if entry.dn else ""
            if not FlextLdifUtilitiesDN.validate_dn(dn_str):
                rejected_entry = u.Ldif.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        "invalid_dn",
                        f"DN validation failed (RFC 4514): {dn_str[:80]}",
                    ),
                )
                self._rejection_tracker["invalid_dn_rfc4514"].append(rejected_entry)
                logger.debug("Entry DN failed RFC 4514 validation", entry_dn=dn_str)
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
            for entry in entries
            if (validation_result := validate_entry(entry)).is_success
        ]
        logger.info(
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
            logger.debug(
                "Sample rejected DNs",
                sample_count=len(sample_rejected_dns),
                rejected_dns_preview=", ".join(sample_rejected_dns),
            )
        return r[MutableSequence[m.Ldif.Entry]].ok(validated)

    def _build_category_map_from_rules(
        self,
        rules: m.Ldif.CategoryRules,
    ) -> MutableMapping[str, frozenset[str]]:
        """Build category map from rules."""
        category_map: MutableMapping[str, frozenset[str]] = {}
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
        constants: type[FlextLdifServersBaseConstants],
    ) -> bool:
        """Check if entry matches HIERARCHY_PRIORITY_OBJECTCLASSES."""
        priority_classes_raw: frozenset[str] = getattr(
            constants,
            "HIERARCHY_PRIORITY_OBJECTCLASSES",
            frozenset(),
        )
        priority_classes = frozenset(map(str, priority_classes_raw))
        entry_ocs = {oc.lower() for oc in entry.get_objectclass_names()}
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
        constants: type[FlextLdifServersBaseConstants] | None,
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

    def _get_server_constants(
        self,
        server_type: str,
    ) -> r[type[FlextLdifServersBaseConstants]]:
        """Get and validate server constants via FlextLdifServer registry."""
        return self._server_registry.get_constants(server_type).fold(
            on_failure=lambda e: r[type[FlextLdifServersBaseConstants]].fail(e),
            on_success=lambda v: r[type[FlextLdifServersBaseConstants]].ok(v),
        )

    def _match_entry_to_category(
        self,
        entry: m.Ldif.Entry,
        priority_order: MutableSequence[str],
        category_map: MutableMapping[str, frozenset[str]],
    ) -> tuple[str, str | None]:
        """Match entry to category using priority order and category map."""
        entry_ocs = {oc.lower() for oc in entry.get_objectclass_names()}
        for category in priority_order:
            if category not in category_map:
                continue
            category_ocs = category_map[category]
            category_ocs_lower = {oc.lower() for oc in category_ocs}
            if category == c.Ldif.Category.ACL:
                for attr_marker in category_ocs:
                    if attr_marker.startswith("attr:"):
                        attr_name = attr_marker[5:]
                        if entry.has_attribute(attr_name):
                            return (c.Ldif.Category.ACL, None)
            elif any(oc in category_ocs_lower for oc in entry_ocs):
                return (category, None)
        return (c.Ldif.Category.REJECTED, "No category match")

    def _merge_server_constants_to_map(
        self,
        category_map: MutableMapping[str, frozenset[str]],
        constants: type[FlextLdifServersBaseConstants],
        *,
        override_existing: bool = False,
    ) -> MutableMapping[str, frozenset[str]]:
        """Merge server constants into category map."""
        empty_category_map: MutableMapping[str, frozenset[str]] = {}
        category_objectclasses: MutableMapping[str, frozenset[str]] = getattr(
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

            def _to_attr_key(attr: str) -> str:
                return f"attr:{attr.lower()}"

            if override_existing or acl_category not in category_map:
                mapped = u.map(acl_attrs, mapper=_to_attr_key)
                category_map[acl_category] = frozenset(mapped)
            else:
                existing_acl = category_map.get(acl_category, frozenset())
                mapped = u.map(acl_attrs, mapper=_to_attr_key)
                new_acl_attrs = frozenset(mapped)
                category_map[acl_category] = existing_acl | new_acl_attrs
        return category_map

    def _normalize_rules(
        self,
        rules: m.Ldif.CategoryRules | MutableMapping[str, t.MetadataValue] | None,
    ) -> r[m.Ldif.CategoryRules]:
        """Normalize rules to CategoryRules model."""
        if isinstance(rules, m.Ldif.CategoryRules):
            return r[m.Ldif.CategoryRules].ok(rules)
        if rules is None:
            return r[m.Ldif.CategoryRules].ok(self._categorization_rules)
        return u.try_(
            lambda: m.Ldif.CategoryRules.model_validate(dict(rules)),
            catch=(
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ),
        ).map_error(lambda e: f"Invalid rules mapping: {e}")

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


__all__ = ["FlextLdifCategorization"]
