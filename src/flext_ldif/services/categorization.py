"""Categorization Service - LDIF Entry Categorization Operations.

Unified service for categorizing LDIF entries into 6 categories (schema, hierarchy,
users, groups, acl, rejected) with validation, filtering, and rejection tracking.

Scope: Entry categorization, DN validation, base DN filtering, schema OID
whitelisting, rejection tracking with statistics. All server-specific logic
delegated to FlextLdifServer via dependency injection.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, cast, override

from flext_core import FlextLogger, r

from flext_ldif._models.results import _FlexibleCategories
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import t
from flext_ldif.utilities import u

logger: Final = FlextLogger(__name__)


def _cat(
    category: c.Categories,
) -> c.LiteralTypes.CategoryLiteral:
    """Convert Categories enum to CategoryLiteral type (local shorthand)."""
    return c.to_category_literal(category)


def _merge_one_category(
    category_map: dict[c.LiteralTypes.CategoryLiteral, frozenset[str]],
    key_str: str,
    value: frozenset[str] | str,
    *,
    override_existing: bool,
) -> None:
    """Merge one category key from server constants (helper to isolate TypeIs check).

    This helper avoids pyrefly's cycle-breaking limitation with TypeIs + loops
    by processing one key at a time without a loop context.
    """
    if not c.is_valid_category_literal(key_str):
        return
    # After TypeIs check, key_str is narrowed to CategoryLiteral
    if override_existing or key_str not in category_map:
        category_map[key_str] = (
            value if isinstance(value, frozenset) else frozenset([str(value)])
        )


def _merge_category_from_constants(
    category_map: dict[c.LiteralTypes.CategoryLiteral, frozenset[str]],
    server_map: dict[str, frozenset[str] | str],
    *,
    override_existing: bool,
) -> None:
    """Merge server constants into category map (helper to avoid type flow issues).

    Args:
        category_map: Target category map to update
        server_map: Server CATEGORY_OBJECTCLASSES dict
        override_existing: Whether to override existing entries

    """
    for key_str, value in server_map.items():
        _merge_one_category(
            category_map,
            key_str,
            value,
            override_existing=override_existing,
        )


class FlextLdifCategorization(
    FlextLdifServiceBase[m.FlexibleCategories],
):
    """LDIF Entry Categorization Service.

    Unified service combining high-level orchestration and low-level categorization.
    All server-specific logic delegated to FlextLdifServer via dependency injection.

    Public API for categorizing LDIF entries into 6 categories:
    - schema: Structural schema definitions
    - hierarchy: Organizational hierarchy (OUs, etc.)
    - users: User account entries
    - groups: Group/role entries
    - acl: Access control list entries
    - rejected: Entries that don't match any category

    All methods return FlextResult for composable error handling.
    Uses FlextLdifUtilities extensively for metadata operations.

    Example:
        service = FlextLdifCategorization(
            categorization_rules={
                "hierarchy_objectclasses": ["organization", "organizationalUnit"],
                "user_objectclasses": ["inetOrgPerson", "person"],
                "group_objectclasses": ["groupOfNames"],
                "acl_attributes": ["aci"],
            },
            schema_whitelist_rules={
                "allowed_attribute_oids": ["1.3.6.1.*"],
            },
            server_type=c.ServerTypes.OID,
        )

        # Parse and categorize entries
        result = (
            parser.parse_ldif_file(file_path, c.ServerTypes.OID)
            .flat_map(service.validate_dns)
            .flat_map(service.categorize_entries)
            .flat_map(service.filter_by_base_dn(base_dn="dc=example,dc=com"))
        )

    """

    def __init__(
        self,
        categorization_rules: (
            m.CategoryRules | t.Migration.CategoryRulesDict | None
        ) = None,
        schema_whitelist_rules: (
            m.WhitelistRules | t.Migration.WhitelistRulesDict | None
        ) = None,
        forbidden_attributes: list[str] | None = None,
        forbidden_objectclasses: list[str] | None = None,
        base_dn: str | None = None,
        server_type: c.LiteralTypes.ServerTypeLiteral = "rfc",
        server_registry: FlextLdifServer | None = None,
    ) -> None:
        """Initialize categorization service.

        Args:
            categorization_rules: Rules for categorizing entries (CategoryRules model or dict)
            schema_whitelist_rules: Whitelist rules (WhitelistRules model or dict)
            forbidden_attributes: Attributes to remove from all entries
            forbidden_objectclasses: ObjectClasses to remove
            base_dn: Base DN for filtering (optional, used by filter_by_base_dn)
            server_type: LDAP server type (oid, oud, rfc, etc.) for server-specific categorization
            server_registry: FlextLdifServer instance for DI (defaults to global instance)

        """
        super().__init__()
        # Declare private attributes with proper types
        self._categorization_rules: m.CategoryRules
        self._schema_whitelist_rules: m.WhitelistRules | None
        self._forbidden_attributes: list[str]
        self._forbidden_objectclasses: list[str]
        self._base_dn: str | None
        self._server_type: c.LiteralTypes.ServerTypeLiteral
        self._rejection_tracker: dict[str, list[m.Entry]]
        self._server_registry: FlextLdifServer

        # Initialize server registry via DI (use object.__setattr__ for frozen model)
        if server_registry is not None:
            object.__setattr__(self, "_server_registry", server_registry)
        else:
            object.__setattr__(
                self,
                "_server_registry",
                FlextLdifServer.get_global_instance(),
            )

        # Normalize categorization rules
        if isinstance(categorization_rules, m.CategoryRules):
            object.__setattr__(self, "_categorization_rules", categorization_rules)
        elif isinstance(categorization_rules, dict):
            object.__setattr__(
                self,
                "_categorization_rules",
                m.CategoryRules.model_validate(categorization_rules),
            )
        else:
            object.__setattr__(self, "_categorization_rules", m.CategoryRules())

        # Normalize schema whitelist rules
        if isinstance(schema_whitelist_rules, m.WhitelistRules):
            object.__setattr__(self, "_schema_whitelist_rules", schema_whitelist_rules)
        elif isinstance(schema_whitelist_rules, dict):
            object.__setattr__(
                self,
                "_schema_whitelist_rules",
                m.WhitelistRules.model_validate(schema_whitelist_rules),
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
    ) -> r[m.FlexibleCategories]:
        """Execute empty categorization (placeholder - use individual methods).

        This service provides multiple public methods for categorization steps.
        Use validate_dns(), categorize_entries(), etc. instead of execute().

        Returns:
            FlextResult with empty FlexibleCategories

        """
        # Create FlexibleCategories (_FlexibleCategories extends Categories[Entry])
        # Use _FlexibleCategories directly for type compatibility
        categories = _FlexibleCategories()
        categories[c.Categories.SCHEMA] = []
        categories[c.Categories.HIERARCHY] = []
        categories[c.Categories.USERS] = []
        categories[c.Categories.GROUPS] = []
        categories[c.Categories.ACL] = []
        categories[c.Categories.REJECTED] = []
        # Cast to m.FlexibleCategories for return type compatibility
        return r[m.FlexibleCategories].ok(cast("m.FlexibleCategories", categories))

    @property
    def rejection_tracker(self) -> dict[str, list[m.Entry]]:
        """Get rejection tracker (read-only access to rejected entries by reason).

        Returns:
            Dictionary mapping rejection reasons to lists of rejected entries

        """
        return self._rejection_tracker

    @property
    def forbidden_attributes(self) -> list[str]:
        """Get forbidden attributes list (read-only).

        Returns:
            List of forbidden attribute names

        """
        return self._forbidden_attributes

    @property
    def forbidden_objectclasses(self) -> list[str]:
        """Get forbidden objectClasses list (read-only).

        Returns:
            List of forbidden objectClass names

        """
        return self._forbidden_objectclasses

    @property
    def base_dn(self) -> str | None:
        """Get base DN (read-only).

        Returns:
            Base DN string or None if not set

        """
        return self._base_dn

    @property
    def schema_whitelist_rules(self) -> m.WhitelistRules | None:
        """Get schema whitelist rules (read-only).

        Returns:
            WhitelistRules model or None if not set

        """
        return self._schema_whitelist_rules

    def validate_dns(
        self,
        entries: list[m.Entry],
    ) -> r[list[m.Entry]]:
        """Validate and normalize all DNs to RFC 4514.

        Business Rule: DN validation follows RFC 4514 specification. Invalid DNs are
        rejected and tracked in rejection tracker with metadata updates. Normalized DNs
        replace original DNs in entry models. Validation failures don't stop processing -
        entries are filtered out but processing continues.

        Implication: DN validation ensures RFC compliance before categorization and processing.
        Rejected entries maintain metadata for audit trail and potential recovery.

        Public method for DN validation using u.DN.
        Updates entry metadata with validation results.

        Args:
            entries: Raw entries from parser

        Returns:
            FlextResult with validated entries (invalid DNs filtered out)

        """

        def validate_entry(
            entry: m.Entry,
        ) -> m.Entry | r[m.Entry]:
            """Validate and normalize entry DN."""
            dn_str = u.DN.get_dn_value(entry.dn)

            if not u.DN.validate(dn_str):
                # Track rejection in metadata using FlextLdifUtilities
                rejected_entry = u.Metadata.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        c.RejectionCategory.INVALID_DN,
                        f"DN validation failed (RFC 4514): {dn_str[:80]}",
                    ),
                )
                self._rejection_tracker["invalid_dn_rfc4514"].append(rejected_entry)
                logger.debug(
                    "Entry DN failed RFC 4514 validation",
                    entry_dn=dn_str,
                )
                return r[m.Entry].fail(f"DN validation failed: {dn_str[:80]}")

            norm_result = u.DN.norm(dn_str)
            # Use u.unwrap_or(, default=None) for unified result value extraction (DSL pattern)
            normalized_dn = u.unwrap_or(norm_result, default=None)
            if normalized_dn is None:
                # Track rejection in metadata using FlextLdifUtilities
                rejected_entry = u.Metadata.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        c.RejectionCategory.INVALID_DN,
                        f"DN normalization failed: {u.err(norm_result)}",
                    ),
                )
                self._rejection_tracker["invalid_dn_rfc4514"].append(rejected_entry)
                return r[m.Entry].fail(f"DN normalization failed: {u.err(norm_result)}")
            # Create new Entry with normalized DN
            # Use model_copy with DN string value, not DistinguishedName object
            dn_obj = m.DistinguishedName(value=normalized_dn)
            return entry.model_copy(
                update={"dn": dn_obj},
            )

        batch_result = u.Collection.batch(
            entries,
            validate_entry,
            on_error="skip",
        )
        # Use u.unwrap_or(, default=None) with ternary operator for unified result handling
        batch_data = u.unwrap_or(batch_result, default=None)
        validated = (
            [
                cast("m.Entry", entry)
                for entry in batch_data["results"]
                if entry is not None
            ]
            if batch_data is not None
            else []
        )

        logger.info(
            "Validated entries",
            validated_count=len(validated),
            rejected_count=len(self._rejection_tracker["invalid_dn_rfc4514"]),
            rejection_reason="invalid_dn_rfc4514",
        )

        # Log sample rejected DNs for diagnostic purposes
        if self._rejection_tracker["invalid_dn_rfc4514"]:
            sample_rejected_dns = [
                entry.dn.value[: c.DN_LOG_PREVIEW_LENGTH]
                if entry.dn and len(entry.dn.value) > c.DN_LOG_PREVIEW_LENGTH
                else (entry.dn.value if entry.dn else "")
                for entry in self._rejection_tracker["invalid_dn_rfc4514"][:5]
            ]
            logger.debug(
                "Sample rejected DNs",
                sample_count=len(sample_rejected_dns),
                rejected_dns_preview=sample_rejected_dns,
            )

        return r[list[m.Entry]].ok(validated)

    def is_schema_entry(self, entry: m.Entry) -> bool:
        """Check if entry is a schema definition.

        Schema entries are detected by presence of attributeTypes or objectClasses
        attributes, which are universal across all LDAP servers.

        Args:
            entry: Entry to check

        Returns:
            True if entry is a schema definition

        """
        schema_attrs = {
            "attributetypes",
            "objectclasses",
            "ldapsyntaxes",
            "matchingrules",
        }

        # Business Rule: Schema detection requires non-None attributes.
        # None attributes indicate invalid entry state - cannot be schema entry.
        if entry.attributes is None:
            return False
        # Type narrowing: entry.attributes is not None
        attrs_dict = (
            entry.attributes.attributes
            if hasattr(entry.attributes, "attributes")
            else {}
        )
        if not isinstance(attrs_dict, dict):
            return False
        entry_attrs = {attr.lower() for attr in attrs_dict}
        return bool(schema_attrs & entry_attrs)

    def _get_server_constants(
        self,
        server_type: c.LiteralTypes.ServerTypeLiteral,
    ) -> r[type]:
        """Get and validate server constants via FlextLdifServer registry.

        DELEGATED TO: FlextLdifServer.get_constants() for SRP compliance.
        No direct knowledge of OID, OUD, etc. - all via server registry.

        Args:
            server_type: Server type identifier (oid, oud, rfc, etc.)

        Returns:
            FlextResult with constants class or error message

        """
        return self._server_registry.get_constants(server_type)

    def _check_hierarchy_priority(
        self,
        entry: m.Entry,
        constants: type,
    ) -> bool:
        """Check if entry matches HIERARCHY_PRIORITY_OBJECTCLASSES.

        This solves ambiguous entries like cn=PERFIS with both
        orclContainer + orclprivilegegroup where hierarchy takes priority.

        Args:
            entry: Entry to check
            constants: Server Constants class (from FlextLdifServer)

        Returns:
            True if entry has priority hierarchy objectClass

        """
        if not hasattr(constants, "HIERARCHY_PRIORITY_OBJECTCLASSES"):
            return False

        priority_classes = constants.HIERARCHY_PRIORITY_OBJECTCLASSES
        entry_ocs = {oc.lower() for oc in entry.get_objectclass_names()}
        return any(oc.lower() in entry_ocs for oc in priority_classes)

    def _get_default_priority_order(
        self,
    ) -> list[c.LiteralTypes.CategoryLiteral]:
        """Get default category priority order.

        Returns:
            List of CategoryLiteral in default priority order

        """
        # Using _cat helper for type-safe conversion from enum to literal
        return [
            _cat(c.Categories.USERS),
            _cat(c.Categories.HIERARCHY),
            _cat(c.Categories.GROUPS),
            _cat(c.Categories.ACL),
        ]

    def _get_priority_order_from_constants(
        self,
        constants: type | None,
    ) -> list[c.LiteralTypes.CategoryLiteral]:
        """Get priority order from constants or use default.

        Args:
            constants: Server Constants class (from FlextLdifServer)

        Returns:
            List of CategoryLiteral in priority order

        """
        if constants is not None and hasattr(constants, "CATEGORIZATION_PRIORITY"):
            # Use manual filtering to avoid type issues with u.filter overloads
            # Wrap TypeIs function to return bool for filter predicate
            def is_valid_category(value: str) -> bool:
                """Wrapper for TypeIs function to use as filter predicate."""
                return bool(c.is_valid_category_literal(value))

            priority_list = getattr(constants, "CATEGORIZATION_PRIORITY", [])
            # Type narrowing: priority_list should be list[str] or similar
            if isinstance(priority_list, (list, tuple)):
                filtered = [
                    item
                    for item in priority_list
                    if isinstance(item, str) and is_valid_category(item)
                ]
            else:
                filtered = []

            # Explicit cast for type checker - is_valid_category_literal is TypeIs
            result: list[c.LiteralTypes.CategoryLiteral] = [
                item
                for item in filtered
                if isinstance(item, str) and c.is_valid_category_literal(item)
            ]
            return result
        return self._get_default_priority_order()

    def _build_category_map_from_rules(
        self,
        rules: m.CategoryRules,
    ) -> dict[c.LiteralTypes.CategoryLiteral, frozenset[str]]:
        """Build category map from rules.

        Args:
            rules: Category rules

        Returns:
            Category to objectClasses/attributes mapping

        """
        category_map: dict[
            c.LiteralTypes.CategoryLiteral,
            frozenset[str],
        ] = {}

        # Use u.map to transform objectclasses/attributes to lowercase
        # Using _cat helper for type-safe conversion from enum to literal
        if rules.hierarchy_objectclasses:
            mapped = u.Collection.map(
                rules.hierarchy_objectclasses,
                mapper=lambda oc: oc.lower(),
            )
            category_map[_cat(c.Categories.HIERARCHY)] = frozenset(
                mapped if isinstance(mapped, list) else [],
            )
        if rules.user_objectclasses:
            mapped = u.Collection.map(
                rules.user_objectclasses,
                mapper=lambda oc: oc.lower(),
            )
            category_map[_cat(c.Categories.USERS)] = frozenset(
                mapped if isinstance(mapped, list) else [],
            )
        if rules.group_objectclasses:
            mapped = u.Collection.map(
                rules.group_objectclasses,
                mapper=lambda oc: oc.lower(),
            )
            category_map[_cat(c.Categories.GROUPS)] = frozenset(
                mapped if isinstance(mapped, list) else [],
            )
        if rules.acl_attributes:
            mapped = u.Collection.map(
                rules.acl_attributes,
                mapper=lambda attr: f"attr:{attr.lower()}",
            )
            category_map[_cat(c.Categories.ACL)] = frozenset(
                mapped if isinstance(mapped, list) else [],
            )

        return category_map

    def _merge_server_constants_to_map(
        self,
        category_map: dict[
            c.LiteralTypes.CategoryLiteral,
            frozenset[str],
        ],
        constants: type,
        *,
        override_existing: bool = False,
    ) -> dict[c.LiteralTypes.CategoryLiteral, frozenset[str]]:
        """Merge server constants into category map.

        Args:
            category_map: Existing category map (may be modified in place)
            constants: Server Constants class (from FlextLdifServer)
            override_existing: Whether to override existing entries

        Returns:
            Updated category map

        """
        if hasattr(constants, "CATEGORY_OBJECTCLASSES"):
            # Use helper function to avoid pyrefly type flow cycle issues
            _merge_category_from_constants(
                category_map,
                constants.CATEGORY_OBJECTCLASSES,
                override_existing=override_existing,
            )

        if hasattr(constants, "CATEGORIZATION_ACL_ATTRIBUTES"):
            acl_attrs = constants.CATEGORIZATION_ACL_ATTRIBUTES
            if acl_attrs:
                acl_category = _cat(c.Categories.ACL)
                # Respect override_existing flag for ACL attributes
                if override_existing or acl_category not in category_map:
                    # Use u.map to transform attributes to lowercase with prefix
                    mapped = u.Collection.map(
                        acl_attrs,
                        mapper=lambda attr: f"attr:{attr.lower()}",
                    )
                    # u.map returns same type (frozenset -> frozenset, list -> list)
                    if isinstance(mapped, frozenset):
                        category_map[acl_category] = mapped
                    elif isinstance(mapped, list):
                        category_map[acl_category] = frozenset(mapped)
                    else:
                        category_map[acl_category] = frozenset()
                else:
                    # Merge ACL attributes instead of replacing
                    existing_acl = category_map.get(acl_category, frozenset())
                    # Use u.map to transform attributes to lowercase with prefix
                    mapped = u.Collection.map(
                        acl_attrs,
                        mapper=lambda attr: f"attr:{attr.lower()}",
                    )
                    # u.map returns same type (frozenset -> frozenset, list -> list)
                    if isinstance(mapped, frozenset):
                        new_acl_attrs = mapped
                    elif isinstance(mapped, list):
                        new_acl_attrs = frozenset(mapped)
                    else:
                        new_acl_attrs = frozenset()
                    # Merge existing and new ACL attributes
                    category_map[acl_category] = existing_acl | new_acl_attrs

        return category_map

    def _normalize_rules(
        self,
        rules: (m.CategoryRules | Mapping[str, t.MetadataAttributeValue] | None),
    ) -> r[m.CategoryRules]:
        """Normalize rules to CategoryRules model.

        Args:
            rules: Category rules (CategoryRules model or dict or None)

        Returns:
            FlextResult with normalized CategoryRules

        """
        if isinstance(rules, m.CategoryRules):
            return r.ok(rules)
        if isinstance(rules, dict):
            try:
                return r.ok(m.CategoryRules.model_validate(rules))
            except Exception as e:
                return r.fail(f"Invalid category rules: {e}")
        return r.ok(self._categorization_rules)

    def _match_entry_to_category(
        self,
        entry: m.Entry,
        priority_order: list[c.LiteralTypes.CategoryLiteral],
        category_map: dict[
            c.LiteralTypes.CategoryLiteral,
            frozenset[str],
        ],
    ) -> tuple[c.LiteralTypes.CategoryLiteral, str | None]:
        """Match entry to category using priority order and category map.

        Args:
            entry: Entry to categorize
            priority_order: Category priority order
            category_map: Category to objectClasses/attributes mapping

        Returns:
            Tuple of (category, rejection_reason)

        """
        entry_ocs = {oc.lower() for oc in entry.get_objectclass_names()}

        for category in priority_order:
            if category not in category_map:
                continue

            category_ocs = category_map[category]
            # Lowercase category_ocs for case-insensitive comparison
            category_ocs_lower = {oc.lower() for oc in category_ocs}

            # Check for attribute-based categories (ACL)
            if category == _cat(c.Categories.ACL):
                for attr_marker in category_ocs:
                    if attr_marker.startswith("attr:"):
                        attr_name = attr_marker[5:]
                        if entry.has_attribute(attr_name):
                            return (_cat(c.Categories.ACL), None)
            # Check for objectClass-based categories
            elif any(oc in category_ocs_lower for oc in entry_ocs):
                return (category, None)

        return (_cat(c.Categories.REJECTED), "No category match")

    def _categorize_by_priority(
        self,
        entry: m.Entry,
        constants: type,
        priority_order: list[c.LiteralTypes.CategoryLiteral],
        category_map: dict[
            c.LiteralTypes.CategoryLiteral,
            frozenset[str],
        ],
    ) -> tuple[c.LiteralTypes.CategoryLiteral, str | None]:
        """Categorize entry by iterating through priority order.

        Args:
            entry: Entry to categorize
            constants: Server Constants class (from FlextLdifServer)
            priority_order: Category priority order
            category_map: Category to objectClasses mapping

        Returns:
            Tuple of (category, rejection_reason)

        """
        acl_literal = _cat(c.Categories.ACL)
        for category in priority_order:
            if category == acl_literal:
                if hasattr(constants, "CATEGORIZATION_ACL_ATTRIBUTES"):
                    acl_attributes = list(constants.CATEGORIZATION_ACL_ATTRIBUTES)
                    if u.Entry.has_any_attributes(
                        entry,
                        acl_attributes,
                    ):
                        return (acl_literal, None)
                continue

            category_objectclasses = category_map.get(category)
            if not category_objectclasses:
                continue

            if u.Entry.has_objectclass(
                entry,
                tuple(category_objectclasses),
            ):
                # Category from priority_order is validated to be a CategoryLiteral
                # priority_order is list[CategoryLiteral] - no cast needed
                return (category, None)

        return (_cat(c.Categories.REJECTED), "No category match")

    def _update_metadata_for_filtered_entries(
        self,
        entries: list[m.Entry],
        *,
        passed: bool,
        rejection_reason: str | None = None,
    ) -> list[m.Entry]:
        """Update metadata for filtered entries using u.

        Args:
            entries: Entries to update
            passed: Whether entries passed the filter
            rejection_reason: Rejection reason if not passed

        Returns:
            Updated entries with metadata

        """
        updated_entries: list[m.Entry] = []
        for entry in entries:
            updated_entry = u.Metadata.update_entry_statistics(
                entry,
                mark_filtered=(
                    c.FilterType.BASE_DN_FILTER,
                    passed,
                ),
                mark_rejected=(
                    (
                        c.RejectionCategory.BASE_DN_FILTER,
                        rejection_reason,
                    )
                    if not passed and rejection_reason
                    else None
                ),
            )
            updated_entries.append(updated_entry)
        return updated_entries

    def categorize_entry(
        self,
        entry: m.Entry,
        rules: (m.CategoryRules | Mapping[str, t.MetadataAttributeValue] | None) = None,
        server_type: c.LiteralTypes.ServerTypeLiteral | None = None,
    ) -> tuple[c.LiteralTypes.CategoryLiteral, str | None]:
        """Categorize single entry using provided or instance categorization rules.

        Business Rule: Entry categorization follows priority order: schema → hierarchy →
        users/groups → acl → rejected. Server-specific rules override defaults via dependency
        injection. Invalid rules or server types result in rejected category with error reason.

        Args:
            entry: LDIF entry to categorize
            rules: Category rules (override instance/server rules if provided)
            server_type: Server type (defaults to instance server_type)

        Returns:
            Tuple of (category, rejection_reason)

        """
        # Normalize rules using helper
        rules_result = self._normalize_rules(rules)
        # Use u.unwrap_or(, default=None) for unified result value extraction (DSL pattern)
        normalized_rules = u.unwrap_or(rules_result, default=None)
        if normalized_rules is None:
            return (_cat(c.Categories.REJECTED), u.err(rules_result))

        # Normalize server_type
        effective_server_type_raw = server_type or self._server_type
        try:
            effective_server_type = c.normalize_server_type(effective_server_type_raw)
        except (ValueError, TypeError) as e:
            return (
                _cat(c.Categories.REJECTED),
                f"Unknown server type: {effective_server_type_raw} - {e}",
            )

        # Schema detection first (universal across servers)
        if self.is_schema_entry(entry):
            return (_cat(c.Categories.SCHEMA), None)

        # Build category map from rules
        merged_category_map = self._build_category_map_from_rules(normalized_rules)

        # Get server constants
        constants: type | None = None
        constants_result = self._get_server_constants(effective_server_type)
        if constants_result.is_success:
            constants_raw = u.unwrap_or(constants_result, default=None)
            if constants_raw is not None and isinstance(constants_raw, type):
                constants = constants_raw
        elif not merged_category_map:
            # No rules and no constants = fail
            return (
                _cat(c.Categories.REJECTED),
                constants_result.error,
            )

        # Merge server constants into category map
        if constants is not None:
            self._merge_server_constants_to_map(
                merged_category_map,
                constants,
                override_existing=not bool(rules),
            )

        # Get priority order
        priority_order = self._get_priority_order_from_constants(constants)

        # Check hierarchy priority first
        if constants is not None and self._check_hierarchy_priority(entry, constants):
            return (_cat(c.Categories.HIERARCHY), None)

        # Match entry to category
        return self._match_entry_to_category(entry, priority_order, merged_category_map)

    def categorize_entries(
        self,
        entries: list[m.Entry],
    ) -> r[m.FlexibleCategories]:
        """Categorize entries into 6 categories.

        Business Rule: Batch categorization processes all entries and organizes them into
        categories (schema, hierarchy, users, groups, acl, rejected). Each entry's metadata
        is updated with category assignment and rejection tracking. Rejected entries are
        tracked separately for analysis.

        Implication: Categorization enables entry organization for migration, filtering, and
        analysis. Category assignments are stored in entry metadata for downstream processing.

        Uses internal categorize_entry() method for each entry.
        Updates entry metadata with category assignment and rejection tracking.

        Args:
            entries: Validated entries with normalized DNs

        Returns:
            FlextResult with FlexibleCategories containing categorized entries

        """
        # Create FlexibleCategories (_FlexibleCategories extends Categories[Entry])
        # Use _FlexibleCategories directly for type compatibility
        categories = _FlexibleCategories()
        categories[c.Categories.SCHEMA] = []
        categories[c.Categories.HIERARCHY] = []
        categories[c.Categories.USERS] = []
        categories[c.Categories.GROUPS] = []
        categories[c.Categories.ACL] = []
        categories[c.Categories.REJECTED] = []

        def categorize_single_entry(
            entry: m.Entry,
        ) -> tuple[str, m.Entry]:
            """Categorize single entry."""
            category, reason = self.categorize_entry(entry)

            # Track category assignment and rejection in metadata using FlextLdifUtilities
            rejection_reason = reason if reason is not None else "No category match"
            entry_to_append = u.Metadata.update_entry_statistics(
                entry,
                category=category,
                mark_rejected=(
                    (
                        c.RejectionCategory.NO_CATEGORY_MATCH,
                        rejection_reason,
                    )
                    if category == c.Categories.REJECTED.value
                    else None
                ),
            )
            return category, entry_to_append

        batch_result = u.Collection.batch(
            entries,
            categorize_single_entry,
            on_error="skip",
        )
        # Use u.unwrap_or(, default=None) for unified result value extraction (DSL pattern)
        batch_data = u.unwrap_or(batch_result, default=None)
        if batch_data is not None:
            for result_item in batch_data["results"]:
                if result_item is not None:
                    category, entry_to_append = cast("tuple[str, m.Entry]", result_item)
                    if category == c.Categories.REJECTED.value:
                        self._rejection_tracker["categorization_rejected"].append(
                            entry_to_append,
                        )
                        logger.debug(
                            "Entry rejected during categorization",
                            entry_dn=str(entry_to_append.dn)
                            if entry_to_append.dn
                            else None,
                            rejection_reason=None,  # Reason not available in batch context
                        )
                    categories[category].append(entry_to_append)
        else:
            # Fallback to original loop if batch fails
            for entry in entries:
                category, reason = self.categorize_entry(entry)

                # Track category assignment and rejection in metadata using FlextLdifUtilities
                rejection_reason = reason if reason is not None else "No category match"
                entry_to_append = u.Metadata.update_entry_statistics(
                    entry,
                    category=category,
                    mark_rejected=(
                        (
                            c.RejectionCategory.NO_CATEGORY_MATCH,
                            rejection_reason,
                        )
                        if category == c.Categories.REJECTED.value
                        else None
                    ),
                )

                if category == c.Categories.REJECTED.value:
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

                # Append entry directly (categories is Categories[m.Entry])
                categories[category].append(entry_to_append)

        # Log category statistics
        # Categories is Categories[Entry], use .items() directly (not u.pairs which requires dict/Mapping)
        for cat, cat_entries in categories.items():
            if cat_entries:
                # Type narrowing: cat_entries is list[Entry], u.count accepts list
                entries_count: int = (
                    u.Collection.count(cat_entries)
                    if isinstance(cat_entries, list)
                    else 0
                )
                logger.info(
                    "Category entries",
                    category=cat,
                    entries_count=entries_count,
                )

        # Cast to m.FlexibleCategories for return type compatibility
        return r[m.FlexibleCategories].ok(cast("m.FlexibleCategories", categories))

    def filter_by_base_dn(
        self,
        categories: m.FlexibleCategories,
    ) -> m.FlexibleCategories:
        """Filter entries by base DN (if configured).

        Applies to data categories only (not schema/rejected).
        Uses u.DN.is_under_base() directly for DN hierarchy check.
        Updates entry metadata with filter results.

        Args:
            categories: FlexibleCategories with entries grouped by category

        Returns:
            FlexibleCategories with filtered entries (rejected entries tracked separately)

        """
        if not self._base_dn:
            return categories

        # Create FlexibleCategories (_FlexibleCategories extends Categories[Entry])
        # Use _FlexibleCategories directly for type compatibility
        filtered = _FlexibleCategories()
        # Initialize all categories to ensure they exist even if empty
        filtered[c.Categories.SCHEMA] = []
        filtered[c.Categories.HIERARCHY] = []
        filtered[c.Categories.USERS] = []
        filtered[c.Categories.GROUPS] = []
        filtered[c.Categories.ACL] = []
        filtered[c.Categories.REJECTED] = []

        # Collect all excluded entries from all categories
        all_excluded_entries: list[m.Entry] = []

        # Categories is Categories[Entry], use .items() directly (not u.pairs which requires dict/Mapping)
        for category, entries in categories.items():
            if not entries:
                continue

            # Apply base DN filter to data categories only
            if category in {
                c.Categories.HIERARCHY,
                c.Categories.USERS,
                c.Categories.GROUPS,
                c.Categories.ACL,
            }:
                # entries is list[m.Entry] from categories.items()
                # Convert to list[m.Entry] for type compatibility
                entries_typed: list[m.Entry] = [
                    cast("m.Entry", entry) for entry in entries
                ]
                included, excluded = FlextLdifCategorization._filter_entries_by_base_dn(
                    entries_typed,
                    self._base_dn,
                )
                # Track filter results in metadata
                included_updated = self._update_metadata_for_filtered_entries(
                    included,
                    passed=True,
                )
                excluded_updated = self._update_metadata_for_filtered_entries(
                    excluded,
                    passed=False,
                    rejection_reason=f"DN not under base DN: {self._base_dn}",
                )
                # Convert back to m.Entry for filtered assignment
                # included_updated is list[m.Entry], convert to m.Entry for filtered
                filtered[category] = [
                    cast("m.Entry", entry) for entry in included_updated
                ]
                # excluded_updated is list[m.Entry] - add directly to all_excluded_entries (which is list[m.Entry])
                all_excluded_entries.extend(excluded_updated)
                # Rejection tracker uses m.Entry - no conversion needed
                self._rejection_tracker["base_dn_filter"].extend(excluded_updated)

                if excluded_updated:
                    logger.info(
                        "Applied base DN filter",
                        category=category,
                        total_entries=u.Collection.count(entries),
                        kept_entries=u.Collection.count(included_updated),
                        rejected_entries=u.Collection.count(excluded_updated),
                    )
            else:
                filtered[category] = entries

        # Add all excluded entries to the rejected category
        # Business Rule: Entries filtered out by base DN must be added to REJECTED category
        # Implication: Preserves audit trail and allows downstream processing to see rejected entries
        if all_excluded_entries:
            # filtered.get returns list[m.Entry], convert to list[m.Entry] for concatenation
            existing_rejected_raw = filtered.get(c.Categories.REJECTED, [])
            existing_rejected: list[m.Entry] = [
                cast("m.Entry", entry) for entry in existing_rejected_raw
            ]
            # Convert result back to m.Entry for filtered assignment
            filtered[c.Categories.REJECTED] = [
                cast("m.Entry", entry)
                for entry in existing_rejected + all_excluded_entries
            ]

        # Cast to m.FlexibleCategories for return type compatibility
        return cast("m.FlexibleCategories", filtered)

    def filter_schema_by_oids(
        self,
        schema_entries: list[m.Entry],
    ) -> r[list[m.Entry]]:
        """Filter schema entries by OID whitelist.

        Public method using FlextLdifFilters.filter_schema_by_oids service.

        Args:
            schema_entries: Schema category entries

        Returns:
            FlextResult with filtered schema entries

        """
        if not self._schema_whitelist_rules:
            return r[list[m.Entry]].ok(schema_entries)

        # Build Mapping[str, frozenset[str]] from WhitelistRules model fields
        # Convert list[str] to frozenset[str] for type compatibility
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

        # Call FlextLdifFilters.filter_schema_by_oids classmethod directly
        result = FlextLdifFilters.filter_schema_by_oids(
            entries=schema_entries,
            allowed_oids=allowed_oids,
        )

        if result.is_success:
            filtered = u.unwrap_or(result, default=None)
            if filtered is not None:
                # filtered is already list[m.Entry] after None check
                logger.info(
                    "Applied schema OID whitelist filter",
                    total_entries=u.Collection.count(schema_entries),
                    filtered_entries=u.Collection.count(filtered),
                    removed_entries=u.Collection.count(schema_entries)
                    - u.Collection.count(filtered),
                )
                return r[list[m.Entry]].ok(filtered)

        # Error handling: result.error might be None
        # Use u.err() for unified error extraction (DSL pattern)
        error_msg = u.err(result)
        return r[list[m.Entry]].fail(error_msg)

    @staticmethod
    def filter_categories_by_base_dn(
        categories: m.FlexibleCategories,
        base_dn: str,
    ) -> m.FlexibleCategories:
        """Filter categorized entries by base DN.

        Applies base DN filtering to HIERARCHY, USERS, GROUPS, and ACL categories.
        Excluded entries are moved to REJECTED category with processing stats.

        Args:
            categories: FlexibleCategories to filter
            base_dn: Base DN for filtering

        Returns:
            FlexibleCategories with filtered entries by base DN

        """
        if not base_dn or not categories:
            return categories

        # Create FlexibleCategories (_FlexibleCategories extends Categories[Entry])
        # Use _FlexibleCategories directly for type compatibility
        filtered = _FlexibleCategories()
        # excluded_entries must be list[m.Entry] to match filtered type
        excluded_entries: list[m.Entry] = []

        filterable_categories = {
            c.Categories.HIERARCHY,
            c.Categories.USERS,
            c.Categories.GROUPS,
            c.Categories.ACL,
        }

        # Categories is Categories[Entry], use .items() directly (not u.pairs which requires dict/Mapping)
        for category, entries in categories.items():
            if not entries:
                filtered[category] = []
                continue

            if category in filterable_categories:
                # Type narrowing: entries is list[m.Entry] from categories.items()
                # Convert to list[m.Entry] for _filter_entries_by_base_dn
                entries_list: list[m.Entry] = [
                    cast("m.Entry", entry)
                    for entry in (entries if isinstance(entries, list) else [])
                ]
                included, excluded = FlextLdifCategorization._filter_entries_by_base_dn(
                    entries_list,
                    base_dn,
                )
                # Convert back to m.Entry for filtered assignment
                filtered[category] = [cast("m.Entry", entry) for entry in included]

                # Update metadata for excluded entries
                excluded_updated = [
                    FlextLdifCategorization._mark_entry_rejected(
                        entry,
                        c.RejectionCategory.BASE_DN_FILTER,
                        f"DN not under base DN: {base_dn}",
                    )
                    for entry in excluded
                ]
                # excluded_updated is list[m.Entry], excluded_entries is list[m.Entry]
                # Convert to m.Entry before extending
                excluded_entries_converted: list[m.Entry] = [
                    cast("m.Entry", entry) for entry in excluded_updated
                ]
                excluded_entries.extend(excluded_entries_converted)
            else:
                # Type narrowing: entries is list[m.Entry] from categories.items()
                # No conversion needed - direct assignment to filtered
                filtered[category] = entries if isinstance(entries, list) else []

        if excluded_entries:
            # filtered.get returns list[m.Entry], excluded_entries is also list[m.Entry]
            # No conversion needed - direct concatenation
            existing_rejected = filtered.get(c.Categories.REJECTED, [])
            filtered[c.Categories.REJECTED] = existing_rejected + excluded_entries

        # Cast to m.FlexibleCategories for return type compatibility
        return cast("m.FlexibleCategories", filtered)

    @staticmethod
    def _filter_entries_by_base_dn(
        entries: list[m.Entry],
        base_dn: str,
    ) -> tuple[list[m.Entry], list[m.Entry]]:
        """Filter entries by base DN using u.DN.

        Args:
            entries: Entries to filter
            base_dn: Base DN for filtering

        Returns:
            Tuple of (included_entries, excluded_entries)

        """
        model_entries: list[m.Entry] = list(entries)
        included: list[m.Entry] = []
        excluded: list[m.Entry] = []

        for entry in model_entries:
            dn_str = entry.dn.value if entry.dn else None
            if dn_str and u.DN.is_under_base(dn_str, base_dn):
                included.append(entry)
            else:
                excluded.append(entry)

        return (included, excluded)

    @staticmethod
    def _mark_entry_rejected(
        entry: m.Entry,
        category: str,
        reason: str,
    ) -> m.Entry:
        """Mark entry as rejected in metadata using u.

        Args:
            entry: Entry to mark
            category: Rejection category
            reason: Rejection reason

        Returns:
            Entry with updated metadata

        """
        return u.Metadata.update_entry_statistics(
            entry,
            mark_rejected=(category, reason),
        )


__all__ = ["FlextLdifCategorization"]
