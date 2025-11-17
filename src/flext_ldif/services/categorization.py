"""LDIF Entry Categorization Service.

Provides direct, composable categorization operations without wrappers.
All methods are public and return FlextResult for railway-oriented error handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.utilities import FlextLdifUtilities

logger: Final = FlextLogger(__name__)


class FlextLdifCategorization(FlextService[dict[str, list[FlextLdifModels.Entry]]]):
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
    ) -> FlextResult[dict[str, list[FlextLdifModels.Entry]]]:
        """Execute empty categorization (placeholder - use individual methods).

        This service provides multiple public methods for categorization steps.
        Use validate_dns(), categorize_entries(), etc. instead of execute().

        Returns:
            FlextResult with empty categories dict

        """
        return FlextResult[dict[str, list[FlextLdifModels.Entry]]].ok({
            FlextLdifConstants.Categories.SCHEMA: [],
            FlextLdifConstants.Categories.HIERARCHY: [],
            FlextLdifConstants.Categories.USERS: [],
            FlextLdifConstants.Categories.GROUPS: [],
            FlextLdifConstants.Categories.ACL: [],
            FlextLdifConstants.Categories.REJECTED: [],
        })

    def __init__(
        self,
        categorization_rules: FlextLdifModels.CategoryRules
        | dict[str, list[str]]
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
        # Convert dict to model if needed (backward compatibility)
        if isinstance(categorization_rules, dict):
            self._categorization_rules = FlextLdifModels.CategoryRules(
                **categorization_rules,
            )
        elif categorization_rules is None:
            self._categorization_rules = FlextLdifModels.CategoryRules()
        else:
            self._categorization_rules = categorization_rules

        if isinstance(schema_whitelist_rules, dict):
            self._schema_whitelist_rules = FlextLdifModels.WhitelistRules(
                **schema_whitelist_rules,
            )
        elif schema_whitelist_rules is None:
            self._schema_whitelist_rules = FlextLdifModels.WhitelistRules()
        else:
            self._schema_whitelist_rules = schema_whitelist_rules
        self._forbidden_attributes = (
            forbidden_attributes if forbidden_attributes is not None else []
        )
        self._forbidden_objectclasses = (
            forbidden_objectclasses if forbidden_objectclasses is not None else []
        )
        self._base_dn = base_dn
        self._server_type = server_type
        self._rejection_tracker: dict[str, list[FlextLdifModels.Entry]] = {
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
                if entry.statistics:
                    entry.statistics.mark_rejected(
                        FlextLdifConstants.RejectionCategory.INVALID_DN,
                        f"DN validation failed (RFC 4514): {dn_str[:80]}",
                    )
                # Use structured logging to avoid base64 encoding
                logger.debug("Invalid DN (RFC 4514)", dn=dn_str)
                continue

            norm_result = FlextLdifUtilities.DN.norm(dn_str)
            if not norm_result.is_success:
                self._rejection_tracker["invalid_dn_rfc4514"].append(entry)
                # Track rejection in statistics
                if entry.statistics:
                    entry.statistics.mark_rejected(
                        FlextLdifConstants.RejectionCategory.INVALID_DN,
                        f"DN normalization failed: {norm_result.error or 'Unknown error'}",
                    )
                continue
            normalized_dn = norm_result.unwrap()
            entry.dn = FlextLdifModels.DistinguishedName(value=normalized_dn)
            validated.append(entry)

        logger.info(
            f"Validated {len(validated)} entries, "
            f"rejected {len(self._rejection_tracker['invalid_dn_rfc4514'])} invalid DNs",
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
            logger.debug("Sample rejected DNs (first 5): %s", sample_rejected_dns)

        return FlextResult[list[FlextLdifModels.Entry]].ok(validated)

    def categorize_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[dict[str, list[FlextLdifModels.Entry]]]:
        """Categorize entries into 6 categories using FlextLdifFilters.

        Public method delegating directly to filters service.

        Args:
            entries: Validated entries with normalized DNs

        Returns:
            FlextResult with dict[category -> entries]

        """
        categories: dict[str, list[FlextLdifModels.Entry]] = {
            FlextLdifConstants.Categories.SCHEMA: [],
            FlextLdifConstants.Categories.HIERARCHY: [],
            FlextLdifConstants.Categories.USERS: [],
            FlextLdifConstants.Categories.GROUPS: [],
            FlextLdifConstants.Categories.ACL: [],
            FlextLdifConstants.Categories.REJECTED: [],
        }

        for entry in entries:
            category, reason = FlextLdifFilters.categorize_entry(
                entry,
                rules=self._categorization_rules,
                whitelist_rules=self._schema_whitelist_rules,
                server_type=self._server_type,
            )

            categories[category].append(entry)

            # Track category assignment in statistics
            if entry.statistics:
                entry.statistics.category_assigned = category

            if category == FlextLdifConstants.Categories.REJECTED:
                self._rejection_tracker["categorization_rejected"].append(entry)
                # Track rejection in statistics
                if entry.statistics:
                    rejection_reason = (
                        reason if reason is not None else "No category match"
                    )
                    entry.statistics.mark_rejected(
                        FlextLdifConstants.RejectionCategory.NO_CATEGORY_MATCH,
                        rejection_reason,
                    )
                logger.debug(f"Entry rejected: {entry.dn}, reason: {reason}")

        for cat, cat_entries in categories.items():
            if cat_entries:
                logger.info(f"Category '{cat}': {len(cat_entries)} entries")

        return FlextResult[dict[str, list[FlextLdifModels.Entry]]].ok(categories)

    def filter_by_base_dn(
        self,
        categories: dict[str, list[FlextLdifModels.Entry]],
    ) -> dict[str, list[FlextLdifModels.Entry]]:
        """Filter entries by base DN (if configured).

        Applies to data categories only (not schema/rejected).
        Public method using FlextLdifFilters.by_base_dn service.

        Args:
            categories: Entries grouped by category

        Returns:
            dict with filtered entries (rejected entries tracked separately)

        """
        if not self._base_dn:
            return categories

        filtered: dict[str, list[FlextLdifModels.Entry]] = {}

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
                included, excluded = FlextLdifFilters.by_base_dn(entries, self._base_dn)
                filtered[category] = included
                self._rejection_tracker["base_dn_filter"].extend(excluded)

                # Track filter results in statistics
                for entry in included:
                    if entry.statistics:
                        entry.statistics.mark_filtered(
                            FlextLdifConstants.FilterType.BASE_DN_FILTER,
                            passed=True,
                        )
                for entry in excluded:
                    if entry.statistics:
                        entry.statistics.mark_filtered(
                            FlextLdifConstants.FilterType.BASE_DN_FILTER,
                            passed=False,
                        )
                        entry.statistics.mark_rejected(
                            FlextLdifConstants.RejectionCategory.BASE_DN_FILTER,
                            f"DN not under base DN: {self._base_dn}",
                        )

                if excluded:
                    logger.info(
                        f"Base DN filter ({category}): {len(entries)} → "
                        f"{len(included)} kept, {len(excluded)} rejected",
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
                f"Schema OID filter: {len(schema_entries)} → {len(filtered)} entries",
            )

        return result
