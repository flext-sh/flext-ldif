"""LDIF Entry Categorization Service.

Provides direct, composable categorization operations without wrappers.
All methods are public and return FlextResult for railway-oriented error handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

from flext_core import FlextLogger, FlextResult, FlextRuntime

from flext_ldif.base import LdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.utilities import FlextLdifUtilities

logger: Final = FlextLogger(__name__)


class FlextLdifCategorization(LdifServiceBase):
    """LDIF Entry Categorization Service.

    Public API for categorizing LDIF entries into 6 categories:
    - schema: Structural schema definitions
    - hierarchy: Organizational hierarchy (OUs, etc.)
    - users: User account entries
    - groups: Group/role entries
    - acl: Access control list entries
    - rejected: Entries that don't match any category

    All methods return FlextResult for composable error handling.
    No private methods - everything is public and reusable.

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
        )

        # Parse and categorize entries
        result = (
            parser.parse_ldif_file(file_path, "oid")
            .flat_map(service.validate_dns)
            .flat_map(service.categorize_entries)
            .flat_map(service.filter_by_base_dn(base_dn="dc=example,dc=com"))
            .map(service.remove_forbidden_attributes(forbidden=["creatorsName"]))
        )

    """

    def execute(
        self,
        **_kwargs: object,
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

    def __init__(
        self,
        categorization_rules: FlextLdifModels.CategoryRules
        | dict[str, object]
        | None = None,
        schema_whitelist_rules: FlextLdifModels.WhitelistRules
        | dict[str, list[str]]
        | None = None,
        forbidden_attributes: list[str] | None = None,
        forbidden_objectclasses: list[str] | None = None,
        base_dn: str | None = None,
        server_type: str = "rfc",
    ) -> None:
        """Initialize categorization service.

        Args:
            categorization_rules: Rules for categorizing entries (CategoryRules model or dict)
            schema_whitelist_rules: Whitelist rules (WhitelistRules model or dict)
            forbidden_attributes: Attributes to remove from all entries
            forbidden_objectclasses: ObjectClasses to remove
            base_dn: Base DN for filtering (optional, used by filter_by_base_dn)
            server_type: LDAP server type (oid, oud, rfc, etc.) for server-specific categorization

        """
        super().__init__()
        # Declare private attributes with proper types
        self._categorization_rules: FlextLdifModels.CategoryRules
        self._schema_whitelist_rules: FlextLdifModels.WhitelistRules | None
        self._forbidden_attributes: list[str]
        self._forbidden_objectclasses: list[str]
        self._base_dn: str | None
        self._server_type: str
        self._rejection_tracker: dict[str, list[FlextLdifModels.Entry]]

        # Convert dict to model if needed
        if FlextRuntime.is_dict_like(categorization_rules):
            # Type narrowing: is_dict_like ensures dict[str, object]
            rules_dict: dict[str, object] = dict(categorization_rules)
            # Extract list fields with type guards - CategoryRules uses different field names
            user_dn_patterns = rules_dict.get("user_dn_patterns") or rules_dict.get(
                "users",
            )
            group_dn_patterns = rules_dict.get("group_dn_patterns") or rules_dict.get(
                "groups",
            )
            hierarchy_dn_patterns = rules_dict.get(
                "hierarchy_dn_patterns",
            ) or rules_dict.get("hierarchy")
            schema_dn_patterns = rules_dict.get("schema_dn_patterns") or rules_dict.get(
                "schema",
            )
            user_objectclasses = rules_dict.get("user_objectclasses", [])
            group_objectclasses = rules_dict.get("group_objectclasses", [])
            hierarchy_objectclasses = rules_dict.get("hierarchy_objectclasses", [])
            acl_attributes = rules_dict.get("acl_attributes") or rules_dict.get("acl")
            self._categorization_rules = FlextLdifModels.CategoryRules(
                user_dn_patterns=list(user_dn_patterns)
                if isinstance(user_dn_patterns, list)
                else [],
                group_dn_patterns=list(group_dn_patterns)
                if isinstance(group_dn_patterns, list)
                else [],
                hierarchy_dn_patterns=list(hierarchy_dn_patterns)
                if isinstance(hierarchy_dn_patterns, list)
                else [],
                schema_dn_patterns=list(schema_dn_patterns)
                if isinstance(schema_dn_patterns, list)
                else [],
                user_objectclasses=list(user_objectclasses)
                if isinstance(user_objectclasses, list)
                else [],
                group_objectclasses=list(group_objectclasses)
                if isinstance(group_objectclasses, list)
                else [],
                hierarchy_objectclasses=list(hierarchy_objectclasses)
                if isinstance(hierarchy_objectclasses, list)
                else [],
                acl_attributes=list(acl_attributes)
                if isinstance(acl_attributes, list)
                else [],
            )
        elif categorization_rules is None:
            self._categorization_rules = FlextLdifModels.CategoryRules()
        elif isinstance(categorization_rules, FlextLdifModels.CategoryRules):
            # Type narrowing: isinstance ensures CategoryRules
            self._categorization_rules = categorization_rules
        else:
            self._categorization_rules = FlextLdifModels.CategoryRules()

        if FlextRuntime.is_dict_like(schema_whitelist_rules):
            # Type narrowing: is_dict_like ensures dict[str, object]
            whitelist_dict: dict[str, object] = dict(schema_whitelist_rules)
            # Extract list fields with type guards
            blocked_objectclasses = whitelist_dict.get("blocked_objectclasses")
            self._schema_whitelist_rules = FlextLdifModels.WhitelistRules(
                blocked_objectclasses=list(blocked_objectclasses)
                if isinstance(blocked_objectclasses, list)
                else [],
            )
        elif schema_whitelist_rules is None:
            # Keep None - don't create empty WhitelistRules
            # Empty WhitelistRules with [] for all fields means "allow nothing"
            self._schema_whitelist_rules = None
        elif isinstance(schema_whitelist_rules, FlextLdifModels.WhitelistRules):
            # Type narrowing: isinstance ensures WhitelistRules
            self._schema_whitelist_rules = schema_whitelist_rules
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

        Public method for DN validation using service utilities.

        Args:
            entries: Raw entries from parser

        Returns:
            FlextResult with validated entries or failure

        """
        validated: list[FlextLdifModels.Entry] = []

        for entry in entries:
            dn_str = FlextLdifUtilities.DN.get_dn_value(entry.dn)

            if not FlextLdifUtilities.DN.validate(dn_str):
                self._rejection_tracker["invalid_dn_rfc4514"].append(entry)
                # Track rejection in statistics
                if entry.metadata.processing_stats:
                    _ = entry.metadata.processing_stats.mark_rejected(
                        FlextLdifConstants.RejectionCategory.INVALID_DN,
                        f"DN validation failed (RFC 4514): {dn_str[:80]}",
                    )
                # Use structured logging to avoid base64 encoding
                logger.debug(
                    "Entry DN failed RFC 4514 validation",
                    entry_dn=dn_str,
                )
                continue

            norm_result = FlextLdifUtilities.DN.norm(dn_str)
            if not norm_result.is_success:
                self._rejection_tracker["invalid_dn_rfc4514"].append(entry)
                # Track rejection in statistics
                if entry.metadata.processing_stats:
                    _ = entry.metadata.processing_stats.mark_rejected(
                        FlextLdifConstants.RejectionCategory.INVALID_DN,
                        f"DN normalization failed: {norm_result.error or 'Unknown error'}",
                    )
                continue
            normalized_dn = norm_result.unwrap()
            entry.dn = FlextLdifModels.DistinguishedName(value=normalized_dn)
            validated.append(entry)

        logger.info(
            "Validated entries",
            validated_count=len(validated),
            rejected_count=len(self._rejection_tracker["invalid_dn_rfc4514"]),
            rejection_reason="invalid_dn_rfc4514",
        )

        # Log sample rejected DNs for diagnostic purposes (track 289 missing entries)
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

    def categorize_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.FlexibleCategories]:
        """Categorize entries into 6 categories using FlextLdifFilters.

        Public method delegating directly to filters service.

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
            category, reason = FlextLdifFilters.categorize_entry(
                entry,
                rules=self._categorization_rules,
                whitelist_rules=self._schema_whitelist_rules,
                server_type=self._server_type,
            )

            # Track category assignment in statistics before appending
            entry_to_append = entry
            if entry.metadata.processing_stats:
                # EntryStatistics is frozen, use model_copy to update
                updated_stats = entry.metadata.processing_stats.model_copy(
                    update={"category_assigned": category},
                )
                # Update metadata with new stats instance
                updated_metadata = entry.metadata.model_copy(
                    update={"processing_stats": updated_stats},
                )
                # Create updated entry with new metadata
                entry_to_append = entry.model_copy(
                    update={"metadata": updated_metadata},
                )

            categories[category].append(entry_to_append)

            if category == FlextLdifConstants.Categories.REJECTED:
                self._rejection_tracker["categorization_rejected"].append(
                    entry_to_append,
                )
                # Track rejection in statistics
                if entry_to_append.metadata.processing_stats:
                    rejection_reason = (
                        reason if reason is not None else "No category match"
                    )
                    _ = entry_to_append.metadata.processing_stats.mark_rejected(
                        FlextLdifConstants.RejectionCategory.NO_CATEGORY_MATCH,
                        rejection_reason,
                    )
                logger.debug(
                    "Entry rejected during categorization",
                    entry_dn=str(entry_to_append.dn) if entry_to_append.dn else None,
                    rejection_reason=reason,
                )

        # category_names is a computed_field property that returns list[str]
        # Iterate using items() method for proper type safety
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
        Public method using FlextLdifFilters.by_base_dn service.

        Args:
            categories: FlexibleCategories with entries grouped by category

        Returns:
            FlexibleCategories with filtered entries (rejected entries tracked separately)

        """
        if not self._base_dn:
            return categories

        filtered = FlextLdifModels.FlexibleCategories()

        for category, entries in categories.items():
            if not entries:
                filtered[category] = []
                continue

            # Apply base DN filter to data categories only
            if category in {
                FlextLdifConstants.Categories.HIERARCHY,
                FlextLdifConstants.Categories.USERS,
                FlextLdifConstants.Categories.GROUPS,
                FlextLdifConstants.Categories.ACL,
            }:
                # Convert domain entries to models entries for by_base_dn
                # Use model_copy() instead of model_dump()+model_validate()
                model_entries: list[FlextLdifModels.Entry] = [
                    entry
                    if isinstance(entry, FlextLdifModels.Entry)
                    else entry.model_copy(deep=True)
                    for entry in entries
                ]
                included, excluded = FlextLdifFilters.by_base_dn(
                    model_entries,
                    self._base_dn,
                )
                # FlexibleCategories uses FlextLdifModels.Entry directly
                filtered[category] = included
                self._rejection_tracker["base_dn_filter"].extend(excluded)

                # Track filter results in statistics
                for entry in included:
                    if entry.metadata.processing_stats:
                        _ = entry.metadata.processing_stats.mark_filtered(
                            FlextLdifConstants.FilterType.BASE_DN_FILTER,
                            passed=True,
                        )
                for entry in excluded:
                    if entry.metadata.processing_stats:
                        _ = entry.metadata.processing_stats.mark_filtered(
                            FlextLdifConstants.FilterType.BASE_DN_FILTER,
                            passed=False,
                        )
                        _ = entry.metadata.processing_stats.mark_rejected(
                            FlextLdifConstants.RejectionCategory.BASE_DN_FILTER,
                            f"DN not under base DN: {self._base_dn}",
                        )

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

        return result

    @staticmethod
    def filter_categories_by_base_dn(
        categories: FlextLdifModels.FlexibleCategories,
        base_dn: str,
    ) -> FlextLdifModels.FlexibleCategories:
        """Filter categorized entries by base DN.

        Applies base DN filtering to HIERARCHY, USERS, GROUPS, and ACL categories.
        Excluded entries are moved to REJECTED category with processing stats.

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
                model_entries: list[FlextLdifModels.Entry] = [
                    entry
                    if isinstance(entry, FlextLdifModels.Entry)
                    else entry.model_copy(deep=True)
                    for entry in entries
                ]
                included, excluded = FlextLdifFilters.by_base_dn(
                    model_entries,
                    base_dn,
                    mark_excluded=True,
                )
                filtered[category] = included

                for entry in excluded:
                    if entry.metadata.processing_stats:
                        _ = entry.metadata.processing_stats.mark_rejected(
                            FlextLdifConstants.RejectionCategory.BASE_DN_FILTER,
                            f"DN not under base DN: {base_dn}",
                        )
                excluded_entries.extend(excluded)
            else:
                filtered[category] = entries

        if excluded_entries:
            existing_rejected = filtered.get(FlextLdifConstants.Categories.REJECTED, [])
            if existing_rejected is None:
                existing_rejected = []
            filtered[FlextLdifConstants.Categories.REJECTED] = (
                existing_rejected + excluded_entries
            )

        return filtered
