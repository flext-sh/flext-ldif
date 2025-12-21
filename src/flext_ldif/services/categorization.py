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
from typing import Final, override

from flext_core import FlextLogger, FlextTypes, r

from flext_ldif._models.results import _FlexibleCategories
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.utilities import u

# Module-level constants
_MAX_DN_PREVIEW_LENGTH: Final[int] = 100

logger: Final = FlextLogger(__name__)


def _cat(
    category: str,
) -> str:
    """Convert Categories enum to CategoryLiteral type (local shorthand)."""
    # category is already a string (CategoryLiteral), just return it
    # The function name suggests enum conversion, but category is already str
    return category


def _merge_one_category(
    category_map: dict[str, frozenset[str]],
    key_str: str,
    value: frozenset[str] | str,
    *,
    override_existing: bool,
) -> None:
    """Merge one category key from server constants (helper to isolate TypeIs check).

    This helper avoids pyrefly's cycle-breaking limitation with TypeIs + loops
    by processing one key at a time without a loop context.
    """
    # Type narrowing: check if key_str is a valid category
    valid_categories = {"schema", "hierarchy", "users", "groups", "acl", "rejected"}
    if key_str not in valid_categories:
        return
    # After TypeIs check, key_str is narrowed to CategoryLiteral
    # Type narrowing: key_str is validated to be in valid_categories
    if override_existing or key_str not in category_map:
        # Type narrowing: key_str is a valid category key
        category_map[key_str] = (
            value if isinstance(value, frozenset) else frozenset([str(value)])
        )


def _merge_category_from_constants(
    category_map: dict[str, frozenset[str]],
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
    FlextLdifServiceBase[_FlexibleCategories],
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
            server_type="oid",
        )

        # Parse and categorize entries
        result = (
            parser.parse_ldif_file(file_path, "oid")
            .flat_map(service.validate_dns)
            .flat_map(service.categorize_entries)
            .flat_map(service.filter_by_base_dn(base_dn="dc=example,dc=com"))
        )

    """

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
        self._categorization_rules: m.Ldif.LdifResults.CategoryRules
        self._schema_whitelist_rules: m.Ldif.LdifResults.WhitelistRules | None
        self._forbidden_attributes: list[str]
        self._forbidden_objectclasses: list[str]
        self._base_dn: str | None
        self._server_type: str
        self._rejection_tracker: dict[str, list[m.Ldif.Entry]]
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

        # Normalize schema whitelist rules
        if isinstance(schema_whitelist_rules, m.Ldif.LdifResults.WhitelistRules):
            object.__setattr__(self, "_schema_whitelist_rules", schema_whitelist_rules)
        elif isinstance(schema_whitelist_rules, dict):
            object.__setattr__(
                self,
                "_schema_whitelist_rules",
                m.Ldif.LdifResults.WhitelistRules.model_validate(
                    schema_whitelist_rules
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
        """Execute empty categorization (placeholder - use individual methods).

        This service provides multiple public methods for categorization steps.
        Use validate_dns(), categorize_entries(), etc. instead of execute().

        Returns:
            FlextResult with empty FlexibleCategories

        """
        # Create FlexibleCategories (_FlexibleCategories extends Categories[Entry])
        # Use _FlexibleCategories directly for type compatibility
        categories = _FlexibleCategories()
        categories[_cat("schema")] = []
        categories[_cat("hierarchy")] = []
        categories[_cat("users")] = []
        categories[_cat("groups")] = []
        categories[_cat("acl")] = []
        categories[_cat("rejected")] = []
        # Type narrowing: categories is already m.Ldif.LdifResults.FlexibleCategories compatible
        return r[m.Ldif.LdifResults.FlexibleCategories].ok(categories)

    @property
    def rejection_tracker(self) -> dict[str, list[m.Ldif.Entry]]:
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
    def schema_whitelist_rules(
        self,
    ) -> m.Ldif.LdifResults.WhitelistRules | None:
        """Get schema whitelist rules (read-only).

        Returns:
            WhitelistRules model or None if not set

        """
        return self._schema_whitelist_rules

    def validate_dns(
        self,
        entries: list[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Validate and normalize all DNs to RFC 4514.

        Business Rule: DN validation follows RFC 4514 specification. Invalid DNs are
        rejected and tracked in rejection tracker with metadata updates. Normalized DNs
        replace original DNs in entry models. Validation failures don't stop processing -
        entries are filtered out but processing continues.

        Implication: DN validation ensures RFC compliance before categorization and processing.
        Rejected entries maintain metadata for audit trail and potential recovery.

        Public method for DN validation using FlextLdifUtilitiesDN.
        Updates entry metadata with validation results.

        Args:
            entries: Raw entries from parser

        Returns:
            FlextResult with validated entries (invalid DNs filtered out)

        """

        def validate_entry(
            entry: m.Ldif.Entry,
        ) -> m.Ldif.Entry | r[m.Ldif.Entry]:
            """Validate and normalize entry DN."""
            dn_str = FlextLdifUtilitiesDN.get_dn_value(entry.dn)

            if not FlextLdifUtilitiesDN.validate(dn_str):
                # Track rejection in metadata using FlextLdifUtilities
                rejected_entry = FlextLdifUtilitiesMetadata.update_entry_statistics(
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

            norm_result = FlextLdifUtilitiesDN.norm(dn_str)
            # Extract value from result with default fallback
            normalized_dn = norm_result.value if norm_result.is_success else None
            if normalized_dn is None:
                # Track rejection in metadata using FlextLdifUtilities
                rejected_entry = FlextLdifUtilitiesMetadata.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        "invalid_dn",
                        f"DN normalization failed: {norm_result.error or 'Unknown error'}",
                    ),
                )
                self._rejection_tracker["invalid_dn_rfc4514"].append(rejected_entry)
                return r[m.Ldif.Entry].fail(
                    f"DN normalization failed: {norm_result.error or 'Unknown error'}"
                )
            # Create new Entry with normalized DN
            # Use model_copy with DN string value, not DN object
            dn_obj = m.Ldif.DN(value=normalized_dn)
            return entry.model_copy(
                update={"dn": dn_obj},
            )

        batch_result = u.Collection.batch(
            entries,
            validate_entry,
            _on_error="skip",
        )
        # Extract value from result with default fallback
        batch_data = batch_result.value if batch_result.is_success else None
        # Type narrowing: batch_data["results"] contains m.Ldif.Entry after validation
        validated = (
            [entry for entry in batch_data["results"] if entry is not None]
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

        return r[list[m.Ldif.Entry]].ok(
            cast(list[m.Ldif.Entry], validated)
        )

    def is_schema_entry(self, entry: m.Ldif.Entry) -> bool:
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
        server_type: str,
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
        entry: m.Ldif.Entry,
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
    ) -> list[str]:
        """Get default category priority order.

        Returns:
            List of CategoryLiteral in default priority order

        """
        # Using _cat helper for type-safe conversion from enum to literal
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
                # Validate category literal - must be one of valid categories
                return value in {
                    "schema",
                    "hierarchy",
                    "users",
                    "groups",
                    "acl",
                    "rejected",
                }

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
        """Build category map from rules.

        Args:
            rules: Category rules

        Returns:
            Category to objectClasses/attributes mapping

        """
        category_map: dict[
            str,
            frozenset[str],
        ] = {}

        # Use u.map to transform objectclasses/attributes to lowercase
        # Using _cat helper for type-safe conversion from enum to literal
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
                acl_category = _cat("acl")
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
        rules: (
            m.Ldif.LdifResults.CategoryRules
            | Mapping[str, FlextTypes.MetadataAttributeValue]
            | None
        ),
    ) -> r[m.Ldif.LdifResults.CategoryRules]:
        """Normalize rules to CategoryRules model.

        Args:
            rules: Category rules (CategoryRules model or dict or None)

        Returns:
            FlextResult with normalized CategoryRules

        """
        # Type narrowing: check if rules is already CategoryRules
        if isinstance(rules, m.Ldif.LdifResults.CategoryRules):
            return r.ok(rules)
        if isinstance(rules, dict):
            try:
                # model_validate is a Pydantic method, type checker should recognize it
                validated_rules = m.Ldif.LdifResults.CategoryRules.model_validate(rules)
                return r.ok(validated_rules)
            except Exception as e:
                return r.fail(f"Invalid category rules: {e}")
        return r.ok(self._categorization_rules)

    def _match_entry_to_category(
        self,
        entry: m.Ldif.Entry,
        priority_order: list[str],
        category_map: dict[
            str,
            frozenset[str],
        ],
    ) -> tuple[str, str | None]:
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
            if category == _cat("acl"):
                for attr_marker in category_ocs:
                    if attr_marker.startswith("attr:"):
                        attr_name = attr_marker[5:]
                        if entry.has_attribute(attr_name):
                            return (_cat("acl"), None)
            # Check for objectClass-based categories
            elif any(oc in category_ocs_lower for oc in entry_ocs):
                return (category, None)

        return (_cat("rejected"), "No category match")

    def _categorize_by_priority(
        self,
        entry: m.Ldif.Entry,
        constants: type,
        priority_order: list[str],
        category_map: dict[
            str,
            frozenset[str],
        ],
    ) -> tuple[str, str | None]:
        """Categorize entry by iterating through priority order.

        Args:
            entry: Entry to categorize
            constants: Server Constants class (from FlextLdifServer)
            priority_order: Category priority order
            category_map: Category to objectClasses mapping

        Returns:
            Tuple of (category, rejection_reason)

        """
        acl_literal = _cat("acl")
        for category in priority_order:
            if category == acl_literal:
                if hasattr(constants, "CATEGORIZATION_ACL_ATTRIBUTES"):
                    acl_attributes = list(constants.CATEGORIZATION_ACL_ATTRIBUTES)
                    if FlextLdifUtilitiesEntry.has_any_attributes(
                        entry,
                        acl_attributes,
                    ):
                        return (acl_literal, None)
                continue

            category_objectclasses = category_map.get(category)
            if not category_objectclasses:
                continue

            if FlextLdifUtilitiesEntry.has_objectclass(
                entry,
                tuple(category_objectclasses),
            ):
                # Category from priority_order is validated to be a CategoryLiteral
                # priority_order is list[CategoryLiteral] - no cast needed
                return (category, None)

        return (_cat("rejected"), "No category match")

    def _update_metadata_for_filtered_entries(
        self,
        entries: list[m.Ldif.Entry],
        *,
        passed: bool,
        rejection_reason: str | None = None,
    ) -> list[m.Ldif.Entry]:
        """Update metadata for filtered entries using u.

        Args:
            entries: Entries to update
            passed: Whether entries passed the filter
            rejection_reason: Rejection reason if not passed

        Returns:
            Updated entries with metadata

        """
        updated_entries: list[m.Ldif.Entry] = []
        for entry in entries:
            updated_entry = FlextLdifUtilitiesMetadata.update_entry_statistics(
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
            | Mapping[str, FlextTypes.MetadataAttributeValue]
            | None
        ) = None,
        server_type: str | None = None,
    ) -> tuple[str, str | None]:
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
        # Extract value from result with default fallback
        normalized_rules = rules_result.value if rules_result.is_success else None
        if normalized_rules is None:
            return (_cat("rejected"), rules_result.error or "Failed to normalize rules")

        # Normalize server_type
        effective_server_type_raw = server_type or self._server_type
        try:
            effective_server_type = FlextLdifUtilitiesServer.normalize_server_type(
                effective_server_type_raw
            )
        except (ValueError, TypeError) as e:
            return (
                _cat("rejected"),
                f"Unknown server type: {effective_server_type_raw} - {e}",
            )

        # Schema detection first (universal across servers)
        if self.is_schema_entry(entry):
            return (_cat("schema"), None)

        # Build category map from rules
        merged_category_map = self._build_category_map_from_rules(normalized_rules)

        # Get server constants
        constants: type | None = None
        constants_result = self._get_server_constants(effective_server_type)
        if constants_result.is_success:
            constants_raw = (
                constants_result.value if constants_result.is_success else None
            )
            if constants_raw is not None and isinstance(constants_raw, type):
                constants = constants_raw
        elif not merged_category_map:
            # No rules and no constants = fail
            return (
                _cat("rejected"),
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
            return (_cat("hierarchy"), None)

        # Match entry to category
        return self._match_entry_to_category(entry, priority_order, merged_category_map)

    def categorize_entries(
        self,
        entries: list[m.Ldif.Entry],
    ) -> r[m.Ldif.LdifResults.FlexibleCategories]:
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

            # Track category assignment and rejection in metadata using FlextLdifUtilities
            rejection_reason = reason if reason is not None else "No category match"
            # Only pass category if it's "rejected" to ensure type safety
            is_rejected = category == _cat("rejected")
            entry_to_append = FlextLdifUtilitiesMetadata.update_entry_statistics(
                entry,
                category="rejected" if is_rejected else None,
                mark_rejected=(("rejected", rejection_reason) if is_rejected else None),
            )
            return category, entry_to_append

        batch_result = u.Collection.batch(
            entries,
            categorize_single_entry,
            _on_error="skip",
        )
        # Extract value from result with default fallback
        batch_data = batch_result.value if batch_result.is_success else None
        if batch_data is not None:
            for result_item in batch_data["results"]:
                if result_item is not None and isinstance(result_item, tuple):
                    # Type narrowing: result_item is tuple[str, m.Ldif.Entry] after processing
                    result_tuple = cast(tuple[str, m.Ldif.Entry], result_item)
                    category, entry_to_append = result_tuple
                    if category == _cat("rejected"):
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
                # Only pass category if it's "rejected" to ensure type safety
                is_rejected = category == _cat("rejected")
                entry_to_append = FlextLdifUtilitiesMetadata.update_entry_statistics(
                    entry,
                    category="rejected" if is_rejected else None,
                    mark_rejected=(
                        ("rejected", rejection_reason) if is_rejected else None
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

                # Append entry directly (categories is Categories[m.Ldif.Entry])
                categories[category].append(entry_to_append)

        # Log category statistics
        # Categories is Categories[Entry], use .items() directly (not u.pairs which requires dict/Mapping)
        for cat, cat_entries in categories.items():
            if cat_entries:
                # Type narrowing: cat_entries is list[Entry], u.count accepts list
                entries_count: int = (
                    u.count(cat_entries)
                    if isinstance(cat_entries, list)
                    else 0
                )
                logger.info(
                    "Category entries",
                    category=cat,
                    entries_count=entries_count,
                )

        # Type narrowing: categories is already m.Ldif.LdifResults.FlexibleCategories compatible
        return r[m.Ldif.LdifResults.FlexibleCategories].ok(categories)

    def filter_by_base_dn(
        self,
        categories: m.Ldif.LdifResults.FlexibleCategories,
    ) -> m.Ldif.LdifResults.FlexibleCategories:
        """Filter entries by base DN (if configured).

        Applies to data categories only (not schema/rejected).
        Uses FlextLdifUtilitiesDN.is_under_base() directly for DN hierarchy check.
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
        filtered[_cat("schema")] = []
        filtered[_cat("hierarchy")] = []
        filtered[_cat("users")] = []
        filtered[_cat("groups")] = []
        filtered[_cat("acl")] = []
        filtered[_cat("rejected")] = []

        # Collect all excluded entries from all categories
        all_excluded_entries: list[m.Ldif.Entry] = []

        # Categories is Categories[Entry], use .items() directly (not u.pairs which requires dict/Mapping)
        for category, entries in categories.items():
            if not entries:
                continue

            # Apply base DN filter to data categories only
            if category in {
                _cat("hierarchy"),
                _cat("users"),
                _cat("groups"),
                _cat("acl"),
            }:
                # entries from categories.items() needs cast to m.Ldif.Entry
                # _filter_entries_by_base_dn expects list[m.Ldif.Entry]
                included, excluded = FlextLdifCategorization._filter_entries_by_base_dn(
                    cast(list[m.Ldif.Entry], list(entries)),
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
                # Convert to list[m.Ldif.Entry] for _FlexibleCategories
                # _FlexibleCategories uses m.Ldif.Entry internally
                filtered[category] = list(included_updated)
                # excluded_updated is list[m.Ldif.Entry] - add directly to all_excluded_entries
                all_excluded_entries.extend(excluded_updated)
                # Rejection tracker uses m.Ldif.Entry - no conversion needed
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
                # Convert to list[m.Ldif.Entry] for _FlexibleCategories
                filtered[category] = list(entries)

        # Add all excluded entries to the rejected category
        # Business Rule: Entries filtered out by base DN must be added to REJECTED category
        # Implication: Preserves audit trail and allows downstream processing to see rejected entries
        if all_excluded_entries:
            # filtered.get returns list[m.Ldif.Entry] from _FlexibleCategories
            existing_rejected = filtered.get(_cat("rejected"), [])
            # Convert both lists to same type for concatenation
            filtered[_cat("rejected")] = list(existing_rejected) + list(
                all_excluded_entries
            )

        # Type narrowing: filtered is already m.Ldif.LdifResults.FlexibleCategories compatible
        return filtered

    def filter_schema_by_oids(
        self,
        schema_entries: list[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Filter schema entries by OID whitelist.

        Public method using FlextLdifFilters.filter_schema_by_oids service.

        Args:
            schema_entries: Schema category entries

        Returns:
            FlextResult with filtered schema entries

        """
        if not self._schema_whitelist_rules:
            return r[list[m.Ldif.Entry]].ok(schema_entries)

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
            filtered = result.value if result.is_success else None
            if filtered is not None:
                # filtered is already list[m.Ldif.Entry] after None check
                logger.info(
                    "Applied schema OID whitelist filter",
                    total_entries=u.count(schema_entries),
                    filtered_entries=u.count(filtered),
                    removed_entries=u.count(schema_entries)
                    - u.count(filtered),
                )
                return r[list[m.Ldif.Entry]].ok(filtered)

        # Error handling: result.error might be None
        # Extract error message directly from FlextResult
        error_msg = result.error or "Failed to filter entries"
        return r[list[m.Ldif.Entry]].fail(error_msg)

    @staticmethod
    def filter_categories_by_base_dn(
        categories: m.Ldif.LdifResults.FlexibleCategories,
        base_dn: str,
    ) -> m.Ldif.LdifResults.FlexibleCategories:
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
        # excluded_entries must be list[m.Ldif.Entry] to match filtered type
        excluded_entries: list[m.Ldif.Entry] = []

        filterable_categories: dict[str, bool] = {
            # Categories enum values to filter
            _cat("hierarchy"): True,
            _cat("users"): True,
            _cat("groups"): True,
            _cat("acl"): True,
        }

        # Categories is Categories[Entry], use .items() directly (not u.pairs which requires dict/Mapping)
        for category, entries in categories.items():
            if not entries:
                filtered[category] = []
                continue

            if category in filterable_categories:
                # entries from categories.items() needs cast to list[m.Ldif.Entry]
                # _filter_entries_by_base_dn expects list[m.Ldif.Entry]
                entries_list = cast(list[m.Ldif.Entry], list(entries))
                included, excluded = FlextLdifCategorization._filter_entries_by_base_dn(
                    entries_list,
                    base_dn,
                )
                # Convert to list[m.Ldif.Entry] for _FlexibleCategories
                filtered[category] = list(included)

                # Update metadata for excluded entries
                excluded_updated = [
                    FlextLdifCategorization._mark_entry_rejected(
                        entry,
                        # RejectionCategory enum values - use direct stringsBASE_DN_FILTER,
                        f"DN not under base DN: {base_dn}",
                    )
                    for entry in excluded
                ]
                # excluded_updated is list[m.Ldif.Entry], excluded_entries is list[m.Ldif.Entry]
                excluded_entries.extend(excluded_updated)
            else:
                # Convert to list[m.Ldif.Entry] for _FlexibleCategories
                filtered[category] = list(entries) if isinstance(entries, list) else []

        if excluded_entries:
            # filtered.get returns list[m.Ldif.Entry] from _FlexibleCategories
            existing_rejected = filtered.get(_cat("rejected"), [])
            # Convert both lists to same type for concatenation
            filtered[_cat("rejected")] = list(existing_rejected) + list(
                excluded_entries
            )

        # Type narrowing: filtered is already m.Ldif.LdifResults.FlexibleCategories compatible
        return filtered

    @staticmethod
    def _filter_entries_by_base_dn(
        entries: list[m.Ldif.Entry],
        base_dn: str,
    ) -> tuple[list[m.Ldif.Entry], list[m.Ldif.Entry]]:
        """Filter entries by base DN using FlextLdifUtilitiesDN.

        Args:
            entries: Entries to filter
            base_dn: Base DN for filtering

        Returns:
            Tuple of (included_entries, excluded_entries)

        """
        model_entries: list[m.Ldif.Entry] = list(entries)
        included: list[m.Ldif.Entry] = []
        excluded: list[m.Ldif.Entry] = []

        for entry in model_entries:
            dn_str = entry.dn.value if entry.dn else None
            if dn_str and FlextLdifUtilitiesDN.is_under_base(dn_str, base_dn):
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
        """Mark entry as rejected in metadata using u.

        Args:
            entry: Entry to mark
            category: Rejection category
            reason: Rejection reason

        Returns:
            Entry with updated metadata

        """
        return FlextLdifUtilitiesMetadata.update_entry_statistics(
            entry,
            mark_rejected=(category, reason),
        )


__all__ = ["FlextLdifCategorization"]
