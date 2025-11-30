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

from flext_core import FlextLogger, FlextResult, FlextRuntime

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger: Final = FlextLogger(__name__)


class FlextLdifCategorization(
    FlextLdifServiceBase[FlextLdifModels.FlexibleCategories],
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
            server_type=FlextLdifConstants.ServerTypes.OID,
        )

        # Parse and categorize entries
        result = (
            parser.parse_ldif_file(file_path, FlextLdifConstants.ServerTypes.OID)
            .flat_map(service.validate_dns)
            .flat_map(service.categorize_entries)
            .flat_map(service.filter_by_base_dn(base_dn="dc=example,dc=com"))
        )

    """

    def __init__(
        self,
        categorization_rules: (
            FlextLdifModels.CategoryRules
            | FlextLdifTypes.Migration.CategoryRulesDict
            | None
        ) = None,
        schema_whitelist_rules: (
            FlextLdifModels.WhitelistRules
            | FlextLdifTypes.Migration.WhitelistRulesDict
            | None
        ) = None,
        forbidden_attributes: list[str] | None = None,
        forbidden_objectclasses: list[str] | None = None,
        base_dn: str | None = None,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = "rfc",
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
        self._categorization_rules: FlextLdifModels.CategoryRules
        self._schema_whitelist_rules: FlextLdifModels.WhitelistRules | None
        self._forbidden_attributes: list[str]
        self._forbidden_objectclasses: list[str]
        self._base_dn: str | None
        self._server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
        self._rejection_tracker: dict[str, list[FlextLdifModels.Entry]]
        self._server_registry: FlextLdifServer

        # Initialize server registry via DI
        if server_registry is not None:
            self._server_registry = server_registry
        else:
            self._server_registry = FlextLdifServer.get_global_instance()

        # Normalize categorization rules
        if isinstance(categorization_rules, FlextLdifModels.CategoryRules):
            self._categorization_rules = categorization_rules
        elif FlextRuntime.is_dict_like(categorization_rules):
            self._categorization_rules = FlextLdifModels.CategoryRules.model_validate(
                categorization_rules,
            )
        else:
            self._categorization_rules = FlextLdifModels.CategoryRules()

        # Normalize schema whitelist rules
        if isinstance(schema_whitelist_rules, FlextLdifModels.WhitelistRules):
            self._schema_whitelist_rules = schema_whitelist_rules
        elif FlextRuntime.is_dict_like(schema_whitelist_rules):
            self._schema_whitelist_rules = (
                FlextLdifModels.WhitelistRules.model_validate(schema_whitelist_rules)
            )
        else:
            self._schema_whitelist_rules = None

        self._forbidden_attributes = (
            forbidden_attributes if forbidden_attributes is not None else []
        )
        self._forbidden_objectclasses = (
            forbidden_objectclasses if forbidden_objectclasses is not None else []
        )
        self._base_dn = base_dn
        self._server_type = server_type
        self._rejection_tracker = {
            "invalid_dn_rfc4514": [],
            "base_dn_filter": [],
            "categorization_rejected": [],
        }

    @override
    def execute(
        self,
    ) -> FlextResult[FlextLdifModels.FlexibleCategories]:
        """Execute empty categorization (placeholder - use individual methods).

        This service provides multiple public methods for categorization steps.
        Use validate_dns(), categorize_entries(), etc. instead of execute().

        Returns:
            FlextResult with empty FlexibleCategories

        """
        categories = FlextLdifModels.FlexibleCategories()
        categories[FlextLdifConstants.Categories.SCHEMA] = []
        categories[FlextLdifConstants.Categories.HIERARCHY] = []
        categories[FlextLdifConstants.Categories.USERS] = []
        categories[FlextLdifConstants.Categories.GROUPS] = []
        categories[FlextLdifConstants.Categories.ACL] = []
        categories[FlextLdifConstants.Categories.REJECTED] = []
        return FlextResult[FlextLdifModels.FlexibleCategories].ok(categories)

    @property
    def rejection_tracker(self) -> dict[str, list[FlextLdifModels.Entry]]:
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
    def schema_whitelist_rules(self) -> FlextLdifModels.WhitelistRules | None:
        """Get schema whitelist rules (read-only).

        Returns:
            WhitelistRules model or None if not set

        """
        return self._schema_whitelist_rules

    def validate_dns(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Validate and normalize all DNs to RFC 4514.

        Public method for DN validation using FlextLdifUtilities.DN.
        Updates entry metadata with validation results.

        Args:
            entries: Raw entries from parser

        Returns:
            FlextResult with validated entries or failure

        """
        validated: list[FlextLdifModels.Entry] = []

        for entry in entries:
            dn_str = FlextLdifUtilities.DN.get_dn_value(entry.dn)

            if not FlextLdifUtilities.DN.validate(dn_str):
                # Track rejection in metadata using FlextLdifUtilities
                rejected_entry = FlextLdifUtilities.Metadata.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        FlextLdifConstants.RejectionCategory.INVALID_DN,
                        f"DN validation failed (RFC 4514): {dn_str[:80]}",
                    ),
                )
                self._rejection_tracker["invalid_dn_rfc4514"].append(rejected_entry)
                logger.debug(
                    "Entry DN failed RFC 4514 validation",
                    entry_dn=dn_str,
                )
                continue

            norm_result = FlextLdifUtilities.DN.norm(dn_str)
            if not norm_result.is_success:
                # Track rejection in metadata using FlextLdifUtilities
                rejected_entry = FlextLdifUtilities.Metadata.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        FlextLdifConstants.RejectionCategory.INVALID_DN,
                        f"DN normalization failed: {norm_result.error or 'Unknown error'}",
                    ),
                )
                self._rejection_tracker["invalid_dn_rfc4514"].append(rejected_entry)
                continue

            normalized_dn = norm_result.unwrap()
            validated_entry = entry.model_copy(
                update={"dn": FlextLdifModels.DistinguishedName(value=normalized_dn)},
            )
            validated.append(validated_entry)

        logger.info(
            "Validated entries",
            validated_count=len(validated),
            rejected_count=len(self._rejection_tracker["invalid_dn_rfc4514"]),
            rejection_reason="invalid_dn_rfc4514",
        )

        # Log sample rejected DNs for diagnostic purposes
        if self._rejection_tracker["invalid_dn_rfc4514"]:
            sample_rejected_dns = [
                entry.dn.value[: FlextLdifConstants.DN_LOG_PREVIEW_LENGTH]
                if entry.dn
                and len(entry.dn.value) > FlextLdifConstants.DN_LOG_PREVIEW_LENGTH
                else (entry.dn.value if entry.dn else "")
                for entry in self._rejection_tracker["invalid_dn_rfc4514"][:5]
            ]
            logger.debug(
                "Sample rejected DNs",
                sample_count=len(sample_rejected_dns),
                rejected_dns_preview=sample_rejected_dns,
            )

        return FlextResult[list[FlextLdifModels.Entry]].ok(validated)

    def is_schema_entry(self, entry: FlextLdifModels.Entry) -> bool:
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

        entry_attrs = {attr.lower() for attr in entry.attributes.attributes}
        return bool(schema_attrs & entry_attrs)

    def _get_server_constants(
        self,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
    ) -> FlextResult[type]:
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
        entry: FlextLdifModels.Entry,
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

    def _categorize_by_priority(
        self,
        entry: FlextLdifModels.Entry,
        constants: type,
        priority_order: list[FlextLdifConstants.LiteralTypes.CategoryLiteral],
        category_map: dict[
            FlextLdifConstants.LiteralTypes.CategoryLiteral,
            frozenset[str],
        ],
    ) -> tuple[FlextLdifConstants.LiteralTypes.CategoryLiteral, str | None]:
        """Categorize entry by iterating through priority order.

        Args:
            entry: Entry to categorize
            constants: Server Constants class (from FlextLdifServer)
            priority_order: Category priority order
            category_map: Category to objectClasses mapping

        Returns:
            Tuple of (category, rejection_reason)

        """
        for category in priority_order:
            if category == FlextLdifConstants.Categories.ACL.value:
                if hasattr(constants, "CATEGORIZATION_ACL_ATTRIBUTES"):
                    acl_attributes = list(constants.CATEGORIZATION_ACL_ATTRIBUTES)
                    if FlextLdifUtilities.Entry.has_any_attributes(
                        entry,
                        acl_attributes,
                    ):
                        acl_value = FlextLdifConstants.Categories.ACL.value
                        if FlextLdifConstants.is_valid_category_literal(acl_value):
                            return (acl_value, None)
                        # Fallback if validation fails (should never happen)
                        return (
                            FlextLdifConstants.Categories.ACL.value,
                            None,
                        )
                continue

            category_objectclasses = category_map.get(category)
            if not category_objectclasses:
                continue

            if FlextLdifUtilities.Entry.has_objectclass(
                entry,
                tuple(category_objectclasses),
            ):
                # Category from priority_order is validated to be a CategoryLiteral
                return (
                    category,
                    None,
                )

        rejected_value = FlextLdifConstants.Categories.REJECTED.value
        if FlextLdifConstants.is_valid_category_literal(rejected_value):
            return (rejected_value, "No category match")
        # Fallback if validation fails (should never happen)
        return (
            FlextLdifConstants.Categories.REJECTED.value,
            "No category match",
        )

    def _update_metadata_for_filtered_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        *,
        passed: bool,
        rejection_reason: str | None = None,
    ) -> list[FlextLdifModels.Entry]:
        """Update metadata for filtered entries using FlextLdifUtilities.

        Args:
            entries: Entries to update
            passed: Whether entries passed the filter
            rejection_reason: Rejection reason if not passed

        Returns:
            Updated entries with metadata

        """
        updated_entries: list[FlextLdifModels.Entry] = []
        for entry in entries:
            updated_entry = FlextLdifUtilities.Metadata.update_entry_statistics(
                entry,
                mark_filtered=(
                    FlextLdifConstants.FilterType.BASE_DN_FILTER,
                    passed,
                ),
                mark_rejected=(
                    (
                        FlextLdifConstants.RejectionCategory.BASE_DN_FILTER,
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
        entry: FlextLdifModels.Entry,
        _rules: (
            FlextLdifModels.CategoryRules
            | Mapping[str, FlextLdifTypes.MetadataValue]
            | None
        ) = None,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
    ) -> tuple[FlextLdifConstants.LiteralTypes.CategoryLiteral, str | None]:
        """Categorize single entry using server-specific rules.

        Uses server-specific constants from FlextLdifServer registry.
        No direct knowledge of OID, OUD, etc. - all via server registry.

        Args:
            entry: LDIF entry to categorize
            _rules: Category rules (unused, server constants take precedence)
            server_type: Server type (defaults to instance server_type)

        Returns:
            Tuple of (category, rejection_reason)
            - category: One of schema, users, hierarchy, groups, acl, rejected
            - rejection_reason: None if categorized, error message if rejected

        """
        effective_server_type = (
            server_type if server_type is not None else self._server_type
        )

        # Check schema first (universal across all servers)
        if self.is_schema_entry(entry):
            schema_value = FlextLdifConstants.Categories.SCHEMA.value
            if FlextLdifConstants.is_valid_category_literal(schema_value):
                return (schema_value, None)
            # Fallback if validation fails (should never happen)
            return (
                FlextLdifConstants.Categories.SCHEMA.value,
                None,
            )

        # Get and validate server constants via FlextLdifServer
        constants_result = self._get_server_constants(effective_server_type)
        if constants_result.is_failure:
            rejected_value = FlextLdifConstants.Categories.REJECTED.value
            if FlextLdifConstants.is_valid_category_literal(rejected_value):
                return (rejected_value, constants_result.error)
            # Fallback if validation fails (should never happen)
            return (
                FlextLdifConstants.Categories.REJECTED.value,
                constants_result.error,
            )

        constants = constants_result.unwrap()

        # Type narrowing: verify constants has required attributes
        if not hasattr(constants, "CATEGORIZATION_PRIORITY") or not hasattr(
            constants,
            "CATEGORY_OBJECTCLASSES",
        ):
            rejected_value = FlextLdifConstants.Categories.REJECTED.value
            if FlextLdifConstants.is_valid_category_literal(rejected_value):
                return (rejected_value, "Server constants missing required attributes")
            # Fallback if validation fails (should never happen)
            return (
                FlextLdifConstants.Categories.REJECTED.value,
                "Server constants missing required attributes",
            )

        # Check for HIERARCHY PRIORITY objectClasses first
        if self._check_hierarchy_priority(entry, constants):
            hierarchy_value = FlextLdifConstants.Categories.HIERARCHY.value
            if FlextLdifConstants.is_valid_category_literal(hierarchy_value):
                return (hierarchy_value, None)
            # Fallback if validation fails (should never happen)
            return (
                FlextLdifConstants.Categories.HIERARCHY.value,
                None,
            )

        # Get server-specific categorization priority and mappings
        priority_order = constants.CATEGORIZATION_PRIORITY
        category_map = constants.CATEGORY_OBJECTCLASSES

        # Type validation: ensure they are the correct types
        if not FlextRuntime.is_list_like(
            priority_order,
        ) or not FlextRuntime.is_dict_like(category_map):
            rejected_value = FlextLdifConstants.Categories.REJECTED.value
            if FlextLdifConstants.is_valid_category_literal(rejected_value):
                return (rejected_value, "Invalid constants type")
            # Fallback if validation fails (should never happen)
            return (
                FlextLdifConstants.Categories.REJECTED.value,
                "Invalid constants type",
            )

        # Categorize by priority order with proper type construction
        # priority_order comes from server constants and should contain valid category strings
        # Filter and validate using TypeGuard for type narrowing
        validated_items: list[str] = [str(item) for item in priority_order]
        priority_order_list: list[FlextLdifConstants.LiteralTypes.CategoryLiteral] = [
            item
            for item in validated_items
            if FlextLdifConstants.is_valid_category_literal(item)
        ]

        validated_category_map: dict[str, frozenset[str]] = {
            str(k): (v if isinstance(v, frozenset) else frozenset([str(v)]))
            for k, v in category_map.items()
        }
        category_map_dict: dict[
            FlextLdifConstants.LiteralTypes.CategoryLiteral,
            frozenset[str],
        ] = {
            k: v
            for k, v in validated_category_map.items()
            if FlextLdifConstants.is_valid_category_literal(k)
        }

        return self._categorize_by_priority(
            entry,
            constants,
            priority_order_list,
            category_map_dict,
        )

    def categorize_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.FlexibleCategories]:
        """Categorize entries into 6 categories.

        Uses internal categorize_entry() method for each entry.
        Updates entry metadata with category assignment and rejection tracking.

        Args:
            entries: Validated entries with normalized DNs

        Returns:
            FlextResult with FlexibleCategories

        """
        categories = FlextLdifModels.FlexibleCategories()
        categories[FlextLdifConstants.Categories.SCHEMA] = []
        categories[FlextLdifConstants.Categories.HIERARCHY] = []
        categories[FlextLdifConstants.Categories.USERS] = []
        categories[FlextLdifConstants.Categories.GROUPS] = []
        categories[FlextLdifConstants.Categories.ACL] = []
        categories[FlextLdifConstants.Categories.REJECTED] = []

        for entry in entries:
            category, reason = self.categorize_entry(entry)

            # Track category assignment and rejection in metadata using FlextLdifUtilities
            rejection_reason = reason if reason is not None else "No category match"
            entry_to_append = FlextLdifUtilities.Metadata.update_entry_statistics(
                entry,
                category=category,
                mark_rejected=(
                    (
                        FlextLdifConstants.RejectionCategory.NO_CATEGORY_MATCH,
                        rejection_reason,
                    )
                    if category == FlextLdifConstants.Categories.REJECTED.value
                    else None
                ),
            )

            if category == FlextLdifConstants.Categories.REJECTED.value:
                self._rejection_tracker["categorization_rejected"].append(
                    entry_to_append,
                )
                logger.debug(
                    "Entry rejected during categorization",
                    entry_dn=str(entry_to_append.dn) if entry_to_append.dn else None,
                    rejection_reason=reason,
                )

            categories[category].append(entry_to_append)

        # Log category statistics
        for cat, cat_entries in categories.items():
            if cat_entries:
                logger.info(
                    "Category entries",
                    category=cat,
                    entries_count=len(cat_entries),
                )

        return FlextResult[FlextLdifModels.FlexibleCategories].ok(categories)

    def filter_by_base_dn(
        self,
        categories: FlextLdifModels.FlexibleCategories,
    ) -> FlextLdifModels.FlexibleCategories:
        """Filter entries by base DN (if configured).

        Applies to data categories only (not schema/rejected).
        Uses FlextLdifUtilities.DN.is_under_base() directly for DN hierarchy check.
        Updates entry metadata with filter results.

        Args:
            categories: FlexibleCategories with entries grouped by category

        Returns:
            FlexibleCategories with filtered entries (rejected entries tracked separately)

        """
        if not self._base_dn:
            return categories

        filtered = FlextLdifModels.FlexibleCategories()
        # Initialize all categories to ensure they exist even if empty
        filtered[FlextLdifConstants.Categories.SCHEMA] = []
        filtered[FlextLdifConstants.Categories.HIERARCHY] = []
        filtered[FlextLdifConstants.Categories.USERS] = []
        filtered[FlextLdifConstants.Categories.GROUPS] = []
        filtered[FlextLdifConstants.Categories.ACL] = []
        filtered[FlextLdifConstants.Categories.REJECTED] = []

        for category, entries in categories.items():
            if not entries:
                continue

            # Apply base DN filter to data categories only
            if category in {
                FlextLdifConstants.Categories.HIERARCHY,
                FlextLdifConstants.Categories.USERS,
                FlextLdifConstants.Categories.GROUPS,
                FlextLdifConstants.Categories.ACL,
            }:
                model_entries: list[FlextLdifModels.Entry] = list(entries)
                # Use FlextLdifUtilities.DN directly to avoid circular dependency
                included: list[FlextLdifModels.Entry] = []
                excluded: list[FlextLdifModels.Entry] = []

                for entry in model_entries:
                    dn_str = entry.dn.value if entry.dn else None
                    if dn_str and FlextLdifUtilities.DN.is_under_base(
                        dn_str,
                        self._base_dn,
                    ):
                        included.append(entry)
                    else:
                        excluded.append(entry)
                # Track filter results in metadata
                included = self._update_metadata_for_filtered_entries(
                    included,
                    passed=True,
                )
                excluded = self._update_metadata_for_filtered_entries(
                    excluded,
                    passed=False,
                    rejection_reason=f"DN not under base DN: {self._base_dn}",
                )
                filtered[category] = included
                self._rejection_tracker["base_dn_filter"].extend(excluded)

                if excluded:
                    logger.info(
                        "Applied base DN filter",
                        category=category,
                        total_entries=len(entries),
                        kept_entries=len(included),
                        rejected_entries=len(excluded),
                    )
            else:
                filtered[category] = entries

        return filtered

    def filter_schema_by_oids(
        self,
        schema_entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter schema entries by OID whitelist.

        Public method using FlextLdifFilters.filter_schema_by_oids service.

        Args:
            schema_entries: Schema category entries

        Returns:
            FlextResult with filtered schema entries

        """
        if not self._schema_whitelist_rules:
            return FlextResult[list[FlextLdifModels.Entry]].ok(schema_entries)

        # Build dict from WhitelistRules model fields for filter_schema_by_oids
        allowed_oids = {
            "allowed_attribute_oids": self._schema_whitelist_rules.allowed_attribute_oids,
            "allowed_objectclass_oids": self._schema_whitelist_rules.allowed_objectclass_oids,
            "allowed_matchingrule_oids": self._schema_whitelist_rules.allowed_matchingrule_oids,
            "allowed_matchingruleuse_oids": self._schema_whitelist_rules.allowed_matchingruleuse_oids,
        }

        # Call FlextLdifFilters.filter_schema_by_oids classmethod directly
        result = FlextLdifFilters.filter_schema_by_oids(
            entries=schema_entries,
            allowed_oids=allowed_oids,
        )

        if result.is_success:
            filtered = result.unwrap()
            logger.info(
                "Applied schema OID whitelist filter",
                total_entries=len(schema_entries),
                filtered_entries=len(filtered),
                removed_entries=len(schema_entries) - len(filtered),
            )
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

        # Error handling: result.error might be None
        error_msg = result.error or "Unknown filtering error"
        return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)

    @staticmethod
    def filter_categories_by_base_dn(
        categories: FlextLdifModels.FlexibleCategories,
        base_dn: str,
    ) -> FlextLdifModels.FlexibleCategories:
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

        filtered = FlextLdifModels.FlexibleCategories()
        excluded_entries: list[FlextLdifModels.Entry] = []

        filterable_categories = {
            FlextLdifConstants.Categories.HIERARCHY,
            FlextLdifConstants.Categories.USERS,
            FlextLdifConstants.Categories.GROUPS,
            FlextLdifConstants.Categories.ACL,
        }

        for category, entries in categories.items():
            if not entries:
                filtered[category] = []
                continue

            if category in filterable_categories:
                included, excluded = FlextLdifCategorization._filter_entries_by_base_dn(
                    entries,
                    base_dn,
                )
                filtered[category] = included

                # Update metadata for excluded entries
                excluded = [
                    FlextLdifCategorization._mark_entry_rejected(
                        entry,
                        FlextLdifConstants.RejectionCategory.BASE_DN_FILTER,
                        f"DN not under base DN: {base_dn}",
                    )
                    for entry in excluded
                ]
                excluded_entries.extend(excluded)
            else:
                filtered[category] = entries

        if excluded_entries:
            existing_rejected = (
                filtered.get(FlextLdifConstants.Categories.REJECTED, []) or []
            )
            filtered[FlextLdifConstants.Categories.REJECTED] = (
                existing_rejected + excluded_entries
            )

        return filtered

    @staticmethod
    def _filter_entries_by_base_dn(
        entries: list[FlextLdifModels.Entry],
        base_dn: str,
    ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]:
        """Filter entries by base DN using FlextLdifUtilities.DN.

        Args:
            entries: Entries to filter
            base_dn: Base DN for filtering

        Returns:
            Tuple of (included_entries, excluded_entries)

        """
        model_entries: list[FlextLdifModels.Entry] = list(entries)
        included: list[FlextLdifModels.Entry] = []
        excluded: list[FlextLdifModels.Entry] = []

        for entry in model_entries:
            dn_str = entry.dn.value if entry.dn else None
            if dn_str and FlextLdifUtilities.DN.is_under_base(dn_str, base_dn):
                included.append(entry)
            else:
                excluded.append(entry)

        return (included, excluded)

    @staticmethod
    def _mark_entry_rejected(
        entry: FlextLdifModels.Entry,
        category: str,
        reason: str,
    ) -> FlextLdifModels.Entry:
        """Mark entry as rejected in metadata using FlextLdifUtilities.

        Args:
            entry: Entry to mark
            category: Rejection category
            reason: Rejection reason

        Returns:
            Entry with updated metadata

        """
        return FlextLdifUtilities.Metadata.update_entry_statistics(
            entry,
            mark_rejected=(category, reason),
        )


__all__ = ["FlextLdifCategorization"]
