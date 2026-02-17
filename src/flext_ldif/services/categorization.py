"""Categorization Service - LDIF Entry Categorization Operations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, override

from flext_core import FlextLogger, r

from flext_ldif.base import s
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import t
from flext_ldif.utilities import u

_MAX_DN_PREVIEW_LENGTH: Final[int] = 100
_TUPLE_PAIR_LENGTH: Final[int] = 2

logger: Final = FlextLogger(__name__)


def _cat(
    category: str,
) -> str:
    """Convert Categories enum to CategoryLiteral type (local shorthand)."""
    return category


def _merge_one_category(
    category_map: dict[str, frozenset[str]],
    key_str: str,
    value: frozenset[str] | str,
    *,
    override_existing: bool,
) -> None:
    """Merge one category key from server constants (helper to isolate TypeIs check)."""
    valid_categories = {"schema", "hierarchy", "users", "groups", "acl", "rejected"}
    if key_str not in valid_categories:
        return

    if override_existing or key_str not in category_map:
        category_map[key_str] = (
            value if isinstance(value, frozenset) else frozenset([str(value)])
        )


def _merge_category_from_constants(
    category_map: dict[str, frozenset[str]],
    server_map: dict[str, frozenset[str] | str],
    *,
    override_existing: bool,
) -> None:
    """Merge server constants into category map (helper to avoid type flow issues)."""
    for key_str, value in server_map.items():
        _merge_one_category(
            category_map,
            key_str,
            value,
            override_existing=override_existing,
        )


class FlextLdifCategorization(
    s[m.Ldif.LdifResults.FlexibleCategories],
):
    """LDIF Entry Categorization Service."""

    def __init__(
        self,
        categorization_rules: (
            m.Ldif.LdifResults.CategoryRules | dict[str, str | list[str] | None] | None
        ) = None,
        schema_whitelist_rules: (
            m.Ldif.LdifResults.WhitelistRules
            | dict[str, str | list[str] | bool | None]
            | None
        ) = None,
        forbidden_attributes: list[str] | None = None,
        forbidden_objectclasses: list[str] | None = None,
        base_dn: str | None = None,
        server_type: str = "rfc",
        server_registry: FlextLdifServer | None = None,
    ) -> None:
        """Initialize categorization service."""
        super().__init__()

        self._categorization_rules: m.Ldif.LdifResults.CategoryRules
        self._schema_whitelist_rules: m.Ldif.LdifResults.WhitelistRules | None
        self._forbidden_attributes: list[str]
        self._forbidden_objectclasses: list[str]
        self._base_dn: str | None
        self._server_type: str
        self._rejection_tracker: dict[str, list[m.Ldif.Entry]]
        self._server_registry: FlextLdifServer

        if server_registry is not None:
            object.__setattr__(self, "_server_registry", server_registry)
        else:
            object.__setattr__(
                self,
                "_server_registry",
                FlextLdifServer.get_global_instance(),
            )

        if isinstance(categorization_rules, m.Ldif.LdifResults.CategoryRules):
            object.__setattr__(self, "_categorization_rules", categorization_rules)
        elif isinstance(categorization_rules, dict):
            object.__setattr__(
                self,
                "_categorization_rules",
                m.Ldif.LdifResults.CategoryRules.model_validate(categorization_rules),
            )
        else:
            object.__setattr__(
                self,
                "_categorization_rules",
                m.Ldif.LdifResults.CategoryRules(),
            )

        if isinstance(schema_whitelist_rules, m.Ldif.LdifResults.WhitelistRules):
            object.__setattr__(self, "_schema_whitelist_rules", schema_whitelist_rules)
        elif isinstance(schema_whitelist_rules, dict):
            object.__setattr__(
                self,
                "_schema_whitelist_rules",
                m.Ldif.LdifResults.WhitelistRules.model_validate(
                    schema_whitelist_rules,
                ),
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

    @override
    def execute(
        self,
    ) -> r[m.Ldif.LdifResults.FlexibleCategories]:
        """Execute empty categorization (placeholder - use individual methods)."""
        categories = m.Ldif.LdifResults.FlexibleCategories()
        categories[_cat("schema")] = []
        categories[_cat("hierarchy")] = []
        categories[_cat("users")] = []
        categories[_cat("groups")] = []
        categories[_cat("acl")] = []
        categories[_cat("rejected")] = []

        return r[m.Ldif.LdifResults.FlexibleCategories].ok(categories)

    @property
    def rejection_tracker(self) -> dict[str, list[m.Ldif.Entry]]:
        """Get rejection tracker (read-only access to rejected entries by reason)."""
        return self._rejection_tracker

    @property
    def forbidden_attributes(self) -> list[str]:
        """Get forbidden attributes list (read-only)."""
        return self._forbidden_attributes

    @property
    def forbidden_objectclasses(self) -> list[str]:
        """Get forbidden objectClasses list (read-only)."""
        return self._forbidden_objectclasses

    @property
    def base_dn(self) -> str | None:
        """Get base DN (read-only)."""
        return self._base_dn

    @property
    def schema_whitelist_rules(
        self,
    ) -> m.Ldif.LdifResults.WhitelistRules | None:
        """Get schema whitelist rules (read-only)."""
        return self._schema_whitelist_rules

    def validate_dns(
        self,
        entries: list[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Validate and normalize all DNs to RFC 4514."""

        def validate_entry(
            entry: m.Ldif.Entry,
        ) -> m.Ldif.Entry | r[m.Ldif.Entry]:
            """Validate and normalize entry DN."""
            dn_str = u.Ldif.DN.get_dn_value(entry.dn)

            if not u.Ldif.DN.validate(dn_str):
                rejected_entry = u.Ldif.Metadata.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        "invalid_dn",
                        f"DN validation failed (RFC 4514): {dn_str[:80]}",
                    ),
                )
                self._rejection_tracker["invalid_dn_rfc4514"].append(rejected_entry)
                logger.debug(
                    "Entry DN failed RFC 4514 validation",
                    entry_dn=dn_str,
                )
                return r[m.Ldif.Entry].fail(f"DN validation failed: {dn_str[:80]}")

            norm_result = u.Ldif.DN.norm(dn_str)
            normalized_dn = norm_result.map_or(None)
            if normalized_dn is None:
                rejected_entry = u.Ldif.Metadata.update_entry_statistics(
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
            return entry.model_copy(
                update={"dn": dn_obj},
            )

        batch_result = u.Collection.batch(
            entries,
            validate_entry,
            on_error="skip",
        )
        batch_data = batch_result.map_or(None)

        validated: list[m.Ldif.Entry] = (
            [entry for entry in batch_data.results if isinstance(entry, m.Ldif.Entry)]
            if batch_data is not None
            else []
        )

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
                else (entry.dn.value if entry.dn else "")
                for entry in self._rejection_tracker["invalid_dn_rfc4514"][:5]
            ]
            logger.debug(
                "Sample rejected DNs",
                sample_count=len(sample_rejected_dns),
                rejected_dns_preview=sample_rejected_dns,
            )

        return r[list[m.Ldif.Entry]].ok(validated)

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

        attrs_dict = (
            entry.attributes.attributes
            if hasattr(entry.attributes, "attributes")
            else {}
        )
        entry_attrs = {attr.lower() for attr in attrs_dict}
        return bool(schema_attrs & entry_attrs)

    def _get_server_constants(
        self,
        server_type: str,
    ) -> r[type]:
        """Get and validate server constants via FlextLdifServer registry."""
        return self._server_registry.get_constants(server_type)

    def _check_hierarchy_priority(
        self,
        entry: m.Ldif.Entry,
        constants: type,
    ) -> bool:
        """Check if entry matches HIERARCHY_PRIORITY_OBJECTCLASSES."""
        if not hasattr(constants, "HIERARCHY_PRIORITY_OBJECTCLASSES"):
            return False

        priority_classes = constants.HIERARCHY_PRIORITY_OBJECTCLASSES
        entry_ocs = {oc.lower() for oc in entry.get_objectclass_names()}
        return any(oc.lower() in entry_ocs for oc in priority_classes)

    def _get_default_priority_order(
        self,
    ) -> list[str]:
        """Get default category priority order."""
        return [
            _cat("users"),
            _cat("hierarchy"),
            _cat("groups"),
            _cat("acl"),
        ]

    def _get_priority_order_from_constants(
        self,
        constants: type | None,
    ) -> list[str]:
        """Get priority order from constants or use default."""
        if constants is not None and hasattr(constants, "CATEGORIZATION_PRIORITY"):

            def is_valid_category(value: str) -> bool:
                """Wrapper for TypeIs function to use as filter predicate."""
                return value in {
                    "schema",
                    "hierarchy",
                    "users",
                    "groups",
                    "acl",
                    "rejected",
                }

            priority_list = getattr(constants, "CATEGORIZATION_PRIORITY", [])

            if isinstance(priority_list, (list, tuple)):
                filtered = [
                    item
                    for item in priority_list
                    if isinstance(item, str) and is_valid_category(item)
                ]
            else:
                filtered = []

            result: list[str] = [
                item
                for item in filtered
                if isinstance(item, str)
                and item
                in {"schema", "hierarchy", "users", "groups", "acl", "rejected"}
            ]
            return result
        return self._get_default_priority_order()

    def _build_category_map_from_rules(
        self,
        rules: m.Ldif.LdifResults.CategoryRules,
    ) -> dict[str, frozenset[str]]:
        """Build category map from rules."""
        category_map: dict[
            str,
            frozenset[str],
        ] = {}

        if rules.hierarchy_objectclasses:
            mapped = u.Collection.map(
                rules.hierarchy_objectclasses,
                mapper=lambda oc: oc.lower(),
            )
            category_map[_cat("hierarchy")] = frozenset(
                mapped if isinstance(mapped, list) else [],
            )
        if rules.user_objectclasses:
            mapped = u.Collection.map(
                rules.user_objectclasses,
                mapper=lambda oc: oc.lower(),
            )
            category_map[_cat("users")] = frozenset(
                mapped if isinstance(mapped, list) else [],
            )
        if rules.group_objectclasses:
            mapped = u.Collection.map(
                rules.group_objectclasses,
                mapper=lambda oc: oc.lower(),
            )
            category_map[_cat("groups")] = frozenset(
                mapped if isinstance(mapped, list) else [],
            )
        if rules.acl_attributes:
            mapped = u.Collection.map(
                rules.acl_attributes,
                mapper=lambda attr: f"attr:{attr.lower()}",
            )
            category_map[_cat("acl")] = frozenset(
                mapped if isinstance(mapped, list) else [],
            )

        return category_map

    def _merge_server_constants_to_map(
        self,
        category_map: dict[
            str,
            frozenset[str],
        ],
        constants: type,
        *,
        override_existing: bool = False,
    ) -> dict[str, frozenset[str]]:
        """Merge server constants into category map."""
        if hasattr(constants, "CATEGORY_OBJECTCLASSES"):
            _merge_category_from_constants(
                category_map,
                constants.CATEGORY_OBJECTCLASSES,
                override_existing=override_existing,
            )

        if hasattr(constants, "CATEGORIZATION_ACL_ATTRIBUTES"):
            acl_attrs = constants.CATEGORIZATION_ACL_ATTRIBUTES
            if acl_attrs:
                acl_category = _cat("acl")

                if override_existing or acl_category not in category_map:
                    mapped = u.Collection.map(
                        acl_attrs,
                        mapper=lambda attr: f"attr:{attr.lower()}",
                    )

                    if isinstance(mapped, frozenset):
                        category_map[acl_category] = mapped
                    elif isinstance(mapped, list):
                        category_map[acl_category] = frozenset(mapped)
                    else:
                        category_map[acl_category] = frozenset()
                else:
                    existing_acl = category_map.get(acl_category, frozenset())

                    mapped = u.Collection.map(
                        acl_attrs,
                        mapper=lambda attr: f"attr:{attr.lower()}",
                    )

                    if isinstance(mapped, frozenset):
                        new_acl_attrs = mapped
                    elif isinstance(mapped, list):
                        new_acl_attrs = frozenset(mapped)
                    else:
                        new_acl_attrs = frozenset()

                    category_map[acl_category] = existing_acl | new_acl_attrs

        return category_map

    def _normalize_rules(
        self,
        rules: m.Ldif.LdifResults.CategoryRules | None,
    ) -> r[m.Ldif.LdifResults.CategoryRules]:
        """Normalize rules to CategoryRules model."""
        if isinstance(rules, m.Ldif.LdifResults.CategoryRules):
            return r[m.Ldif.LdifResults.CategoryRules].ok(rules)
        if rules is None:
            return r[m.Ldif.LdifResults.CategoryRules].ok(self._categorization_rules)
        
        return r[m.Ldif.LdifResults.CategoryRules].fail(
            f"Invalid rules type: {type(rules)}. Expected CategoryRules model."
        )

    def _match_entry_to_category(
        self,
        entry: m.Ldif.Entry,
        priority_order: list[str],
        category_map: dict[
            str,
            frozenset[str],
        ],
    ) -> tuple[str, str | None]:
        """Match entry to category using priority order and category map."""
        entry_ocs = {oc.lower() for oc in entry.get_objectclass_names()}

        for category in priority_order:
            if category not in category_map:
                continue

            category_ocs = category_map[category]

            category_ocs_lower = {oc.lower() for oc in category_ocs}

            if category == _cat("acl"):
                for attr_marker in category_ocs:
                    if attr_marker.startswith("attr:"):
                        attr_name = attr_marker[5:]
                        if entry.has_attribute(attr_name):
                            return (_cat("acl"), None)

            elif any(oc in category_ocs_lower for oc in entry_ocs):
                return (category, None)

        return (_cat("rejected"), "No category match")

    def _update_metadata_for_filtered_entries(
        self,
        entries: list[m.Ldif.Entry],
        *,
        passed: bool,
        rejection_reason: str | None = None,
    ) -> list[m.Ldif.Entry]:
        """Update metadata for filtered entries using u."""
        updated_entries: list[m.Ldif.Entry] = []
        for entry in entries:
            updated_entry = u.Ldif.Metadata.update_entry_statistics(
                entry,
                mark_filtered=(
                    "base_dn_filter",
                    passed,
                ),
                mark_rejected=(
                    ("rejected", rejection_reason)
                    if not passed and rejection_reason
                    else None
                ),
            )
            updated_entries.append(updated_entry)
        return updated_entries

    def categorize_entry(
        self,
        entry: m.Ldif.Entry,
        rules: (
            m.Ldif.LdifResults.CategoryRules
            | Mapping[str, t.MetadataAttributeValue]
            | None
        ) = None,
        server_type: str | None = None,
    ) -> tuple[str, str | None]:
        """Categorize single entry using provided or instance categorization rules."""
        rules_result = self._normalize_rules(rules)
        normalized_rules = rules_result.map_or(None)
        if normalized_rules is None:
            return (_cat("rejected"), rules_result.error or "Failed to normalize rules")

        effective_server_type_raw = server_type or self._server_type
        try:
            effective_server_type = u.Ldif.Server.normalize_server_type(
                effective_server_type_raw,
            )
        except (ValueError, TypeError) as e:
            return (
                _cat("rejected"),
                f"Unknown server type: {effective_server_type_raw} - {e}",
            )

        if self.is_schema_entry(entry):
            return (_cat("schema"), None)

        merged_category_map = self._build_category_map_from_rules(normalized_rules)

        constants: type | None = None
        constants_result = self._get_server_constants(effective_server_type)
        if constants_result.is_success:
            constants_raw = constants_result.map_or(None)
            if constants_raw is not None and isinstance(constants_raw, type):
                constants = constants_raw
        elif not merged_category_map:
            return (
                _cat("rejected"),
                constants_result.error,
            )

        if constants is not None:
            self._merge_server_constants_to_map(
                merged_category_map,
                constants,
                override_existing=not bool(rules),
            )

        priority_order = self._get_priority_order_from_constants(constants)

        if constants is not None and self._check_hierarchy_priority(entry, constants):
            return (_cat("hierarchy"), None)

        return self._match_entry_to_category(entry, priority_order, merged_category_map)

    def categorize_entries(
        self,
        entries: list[m.Ldif.Entry],
    ) -> r[m.Ldif.LdifResults.FlexibleCategories]:
        """Categorize entries into 6 categories."""
        categories = m.Ldif.LdifResults.FlexibleCategories()
        categories[_cat("schema")] = []
        categories[_cat("hierarchy")] = []
        categories[_cat("users")] = []
        categories[_cat("groups")] = []
        categories[_cat("acl")] = []
        categories[_cat("rejected")] = []

        def categorize_single_entry(
            entry: m.Ldif.Entry,
        ) -> tuple[str, m.Ldif.Entry]:
            """Categorize single entry."""
            category, reason = self.categorize_entry(entry)

            rejection_reason = reason if reason is not None else "No category match"
            is_rejected = category == _cat("rejected")

            category_literal: c.Ldif.LiteralTypes.CategoryLiteral | None = None
            if category == "users":
                category_literal = "users"
            elif category == "groups":
                category_literal = "groups"
            elif category == "hierarchy":
                category_literal = "hierarchy"
            elif category == "schema":
                category_literal = "schema"
            elif category == "acl":
                category_literal = "acl"
            elif category == "rejected":
                category_literal = "rejected"

            entry_to_append = u.Ldif.Metadata.update_entry_statistics(
                entry,
                category=category_literal,
                mark_rejected=(
                    (c.Ldif.RejectionCategory.NO_CATEGORY_MATCH.value, rejection_reason)
                    if is_rejected
                    else None
                ),
            )
            return category, entry_to_append

        batch_result = u.Collection.batch(
            entries,
            categorize_single_entry,
            on_error="skip",
        )
        batch_data = batch_result.map_or(None)
        if batch_data is not None:
            # Use dict access for BatchResultDict
            results_list = batch_data.get("results") if isinstance(batch_data, dict) else getattr(batch_data, "results", [])
            for result_item in results_list:
                if (
                    result_item is not None
                    and isinstance(result_item, tuple)
                    and len(result_item) == _TUPLE_PAIR_LENGTH
                ):
                    category_raw, entry_raw = result_item
                    if isinstance(category_raw, str) and isinstance(
                        entry_raw, m.Ldif.Entry
                    ):
                        category = category_raw
                        entry_to_append = entry_raw
                        if category == _cat("rejected"):
                            self._rejection_tracker["categorization_rejected"].append(
                                entry_to_append,
                            )
                            logger.debug(
                                "Entry rejected during categorization",
                                entry_dn=str(entry_to_append.dn)
                                if entry_to_append.dn
                                else None,
                                rejection_reason=None,
                            )
                        categories[category].append(entry_to_append)
        else:
            for entry in entries:
                category, reason = self.categorize_entry(entry)

                rejection_reason = reason if reason is not None else "No category match"

                is_rejected = category == _cat("rejected")
                entry_to_append = u.Ldif.Metadata.update_entry_statistics(
                    entry,
                    category="rejected" if is_rejected else None,
                    mark_rejected=(
                        (
                            c.Ldif.RejectionCategory.NO_CATEGORY_MATCH.value,
                            rejection_reason,
                        )
                        if is_rejected
                        else None
                    ),
                )

                if is_rejected:
                    self._rejection_tracker["categorization_rejected"].append(
                        entry_to_append,
                    )
                    logger.debug(
                        "Entry rejected during categorization",
                        entry_dn=str(entry_to_append.dn)
                        if entry_to_append.dn
                        else None,
                        rejection_reason=reason,
                    )

                categories[category].append(entry_to_append)

        for cat, cat_entries in categories.items():
            if cat_entries:
                entries_count: int = (
                    u.count(cat_entries) if isinstance(cat_entries, list) else 0
                )
                logger.info(
                    "Category entries",
                    category=cat,
                    entries_count=entries_count,
                )

        return r[m.Ldif.LdifResults.FlexibleCategories].ok(categories)

    def filter_by_base_dn(
        self,
        categories: m.Ldif.LdifResults.FlexibleCategories,
    ) -> m.Ldif.LdifResults.FlexibleCategories:
        """Filter entries by base DN (if configured)."""
        if not self._base_dn:
            return categories

        filtered = m.Ldif.LdifResults.FlexibleCategories()

        filtered[_cat("schema")] = []
        filtered[_cat("hierarchy")] = []
        filtered[_cat("users")] = []
        filtered[_cat("groups")] = []
        filtered[_cat("acl")] = []
        filtered[_cat("rejected")] = []

        all_excluded_entries: list[m.Ldif.Entry] = []

        for category, entries in categories.items():
            if not entries:
                continue

            if category in {
                _cat("hierarchy"),
                _cat("users"),
                _cat("groups"),
                _cat("acl"),
            }:
                entries_list: list[m.Ldif.Entry] = [
                    e for e in entries if isinstance(e, m.Ldif.Entry)
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

                filtered[category] = list(included_updated)

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
                filtered[category] = list(entries)

        if all_excluded_entries:
            existing_rejected = filtered.get(_cat("rejected"), [])

            filtered[_cat("rejected")] = list(existing_rejected) + list(
                all_excluded_entries,
            )

        return filtered

    def filter_schema_by_oids(
        self,
        schema_entries: list[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Filter schema entries by OID whitelist."""
        if not self._schema_whitelist_rules:
            return r[list[m.Ldif.Entry]].ok(schema_entries)

        allowed_oids: Mapping[str, frozenset[str]] = {
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
                return r[list[m.Ldif.Entry]].ok(filtered)

        error_msg = result.error or "Failed to filter entries"
        return r[list[m.Ldif.Entry]].fail(error_msg)

    @staticmethod
    def filter_categories_by_base_dn(
        categories: m.Ldif.LdifResults.FlexibleCategories,
        base_dn: str,
    ) -> m.Ldif.LdifResults.FlexibleCategories:
        """Filter categorized entries by base DN."""
        if not base_dn or not categories:
            return categories

        filtered = m.Ldif.LdifResults.FlexibleCategories()

        excluded_entries: list[m.Ldif.Entry] = []

        filterable_categories: dict[str, bool] = {
            _cat("hierarchy"): True,
            _cat("users"): True,
            _cat("groups"): True,
            _cat("acl"): True,
        }

        for category, entries in categories.items():
            if not entries:
                filtered[category] = []
                continue

            if category in filterable_categories:
                entries_list: list[m.Ldif.Entry] = [
                    e for e in entries if isinstance(e, m.Ldif.Entry)
                ]
                included, excluded = FlextLdifCategorization._filter_entries_by_base_dn(
                    entries_list,
                    base_dn,
                )

                filtered[category] = list(included)

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
                filtered[category] = list(entries) if isinstance(entries, list) else []

        if excluded_entries:
            existing_rejected = filtered.get(_cat("rejected"), [])

            filtered[_cat("rejected")] = list(existing_rejected) + list(
                excluded_entries,
            )

        return filtered

    @staticmethod
    def _filter_entries_by_base_dn(
        entries: list[m.Ldif.Entry],
        base_dn: str,
    ) -> tuple[list[m.Ldif.Entry], list[m.Ldif.Entry]]:
        """Filter entries by base DN using u.Ldif.DN."""
        model_entries: list[m.Ldif.Entry] = list(entries)
        included: list[m.Ldif.Entry] = []
        excluded: list[m.Ldif.Entry] = []

        for entry in model_entries:
            dn_str = entry.dn.value if entry.dn else None
            if dn_str and u.Ldif.DN.is_under_base(dn_str, base_dn):
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
        return u.Ldif.Metadata.update_entry_statistics(
            entry,
            mark_rejected=(category, reason),
        )


__all__ = ["FlextLdifCategorization"]
