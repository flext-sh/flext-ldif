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

from flext_core import FlextLogger, FlextResult, FlextTypes
from flext_core._models.collections import FlextModelsCollections

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

        # Initialize server registry via DI (use object.__setattr__ for frozen model)
        if server_registry is not None:
            object.__setattr__(self, "_server_registry", server_registry)
        else:
            object.__setattr__(
                self, "_server_registry", FlextLdifServer.get_global_instance()
            )

        # Normalize categorization rules
        if isinstance(categorization_rules, FlextLdifModels.CategoryRules):
            object.__setattr__(self, "_categorization_rules", categorization_rules)
        elif isinstance(categorization_rules, dict):
            object.__setattr__(
                self,
                "_categorization_rules",
                FlextLdifModels.CategoryRules.model_validate(categorization_rules),
            )
        else:
            object.__setattr__(
                self, "_categorization_rules", FlextLdifModels.CategoryRules()
            )

        # Normalize schema whitelist rules
        if isinstance(schema_whitelist_rules, FlextLdifModels.WhitelistRules):
            object.__setattr__(self, "_schema_whitelist_rules", schema_whitelist_rules)
        elif isinstance(schema_whitelist_rules, dict):
            object.__setattr__(
                self,
                "_schema_whitelist_rules",
                FlextLdifModels.WhitelistRules.model_validate(schema_whitelist_rules),
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
    ) -> FlextResult[FlextLdifModels.FlexibleCategories]:
        """Execute empty categorization (placeholder - use individual methods).

        This service provides multiple public methods for categorization steps.
        Use validate_dns(), categorize_entries(), etc. instead of execute().

        Returns:
            FlextResult with empty FlexibleCategories

        """
        # Create FlexibleCategories (Categories[FlextLdifModels.Entry])
        categories = FlextModelsCollections.Categories[FlextLdifModels.Entry]()
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

        Business Rule: DN validation follows RFC 4514 specification. Invalid DNs are
        rejected and tracked in rejection tracker with metadata updates. Normalized DNs
        replace original DNs in entry models. Validation failures don't stop processing -
        entries are filtered out but processing continues.

        Implication: DN validation ensures RFC compliance before categorization and processing.
        Rejected entries maintain metadata for audit trail and potential recovery.

        Public method for DN validation using FlextLdifUtilities.DN.
        Updates entry metadata with validation results.

        Args:
            entries: Raw entries from parser

        Returns:
            FlextResult with validated entries (invalid DNs filtered out)

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
                            # Business Rule: Return type must be CategoryLiteral, not str
                            # Implication: Explicit cast required for pyrefly type checking
                            return (acl_value, None)
                        # Fallback if validation fails (should never happen)
                        return (FlextLdifConstants.Categories.ACL.value, None)
                continue

            category_objectclasses = category_map.get(category)
            if not category_objectclasses:
                continue

            if FlextLdifUtilities.Entry.has_objectclass(
                entry,
                tuple(category_objectclasses),
            ):
                # Category from priority_order is validated to be a CategoryLiteral
                # priority_order is list[CategoryLiteral] - no cast needed
                return (category, None)

        rejected_value = FlextLdifConstants.Categories.REJECTED.value
        if FlextLdifConstants.is_valid_category_literal(rejected_value):
            # Business Rule: Return type must be CategoryLiteral, not str
            # StrEnum.value already satisfies CategoryLiteral - no cast needed
            return (rejected_value, "No category match")
        # Fallback if validation fails (should never happen)
        return (FlextLdifConstants.Categories.REJECTED.value, "No category match")

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
        rules: (
            FlextLdifModels.CategoryRules
            | Mapping[str, FlextTypes.MetadataAttributeValue]
            | None
        ) = None,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
    ) -> tuple[FlextLdifConstants.LiteralTypes.CategoryLiteral, str | None]:
        """Categorize single entry using provided or instance categorization rules.

        Business Rule: Entry categorization follows priority order: schema → hierarchy →
        users/groups → acl → rejected. Server-specific rules override defaults via dependency
        injection. Invalid rules or server types result in rejected category with error reason.

        Implication: Categorization enables entry organization for migration, filtering, and
        analysis. Server-specific rules ensure accurate categorization per LDAP server type.
        Schema entries are always detected first (universal across servers).

        Uses provided rules to override server constants if available.
        Merges rules with server constants where rules define custom categorization.

        Args:
            entry: LDIF entry to categorize
            rules: Category rules (override instance/server rules if provided)
            server_type: Server type (defaults to instance server_type)

        Returns:
            Tuple of (category, rejection_reason)
            - category: One of schema, users, hierarchy, groups, acl, rejected
            - rejection_reason: None if categorized, error message if rejected

        """
        # Use provided rules, fall back to instance rules
        effective_rules = rules if rules is not None else self._categorization_rules

        # Normalize rules if needed
        if isinstance(effective_rules, FlextLdifModels.CategoryRules):
            normalized_rules = effective_rules
        elif isinstance(effective_rules, dict):
            try:
                normalized_rules = FlextLdifModels.CategoryRules.model_validate(
                    effective_rules,
                )
            except Exception as e:
                # Business Rule: Invalid rules result in rejected category with error reason
                # StrEnum.value already satisfies CategoryLiteral - no cast needed
                return (
                    FlextLdifConstants.Categories.REJECTED.value,
                    f"Invalid category rules: {e}",
                )
        else:
            normalized_rules = self._categorization_rules

        effective_server_type_raw = (
            server_type if server_type is not None else self._server_type
        )

        # Normalize server_type to canonical form and validate
        try:
            effective_server_type = FlextLdifConstants.normalize_server_type(
                effective_server_type_raw,
            )
        except (ValueError, TypeError) as e:
            # Business Rule: Invalid server types result in rejected category
            # StrEnum.value already satisfies CategoryLiteral - no cast needed
            return (
                FlextLdifConstants.Categories.REJECTED.value,
                f"Unknown server type: {effective_server_type_raw} - {e}",
            )

        # Check schema first (universal across all servers)
        # Business Rule: Schema entries are detected first (highest priority) as they
        # are universal across all LDAP servers. Schema detection uses attributeTypes,
        # objectClasses, ldapsyntaxes, matchingrules attributes.
        if self.is_schema_entry(entry):
            # Business Rule: Return type must be CategoryLiteral, not str
            # StrEnum.value already satisfies CategoryLiteral - no cast needed
            return (FlextLdifConstants.Categories.SCHEMA.value, None)

        # Build merged category map from rules
        # Priority: explicit rules > server constants (server constants as fallback)
        merged_category_map: dict[
            FlextLdifConstants.LiteralTypes.CategoryLiteral,
            frozenset[str],
        ] = {}

        # Add rules-based categories if provided
        # Business Rule: merged_category_map keys must be CategoryLiteral
        # StrEnum.value already satisfies CategoryLiteral - no cast needed
        if normalized_rules.hierarchy_objectclasses:
            merged_category_map[FlextLdifConstants.Categories.HIERARCHY.value] = (
                frozenset([
                    oc.lower() for oc in normalized_rules.hierarchy_objectclasses
                ])
            )
        if normalized_rules.user_objectclasses:
            merged_category_map[FlextLdifConstants.Categories.USERS.value] = frozenset([
                oc.lower() for oc in normalized_rules.user_objectclasses
            ])
        if normalized_rules.group_objectclasses:
            merged_category_map[FlextLdifConstants.Categories.GROUPS.value] = (
                frozenset([oc.lower() for oc in normalized_rules.group_objectclasses])
            )
        if normalized_rules.acl_attributes:
            # ACL is attribute-based, store as special marker
            merged_category_map[FlextLdifConstants.Categories.ACL.value] = frozenset([
                f"attr:{attr.lower()}" for attr in normalized_rules.acl_attributes
            ])

        # Get server constants as fallback if no rules provided
        priority_order: list[FlextLdifConstants.LiteralTypes.CategoryLiteral] = []
        constants: type | None = None
        if not merged_category_map:
            # Fallback to server constants
            constants_result = self._get_server_constants(effective_server_type)
            if constants_result.is_failure:
                # Business Rule: Server constants retrieval failure results in rejected category
                # StrEnum.value already satisfies CategoryLiteral - no cast needed
                return (
                    FlextLdifConstants.Categories.REJECTED.value,
                    constants_result.error,
                )

            constants = constants_result.unwrap()
            if hasattr(constants, "CATEGORIZATION_PRIORITY"):
                # Business Rule: priority_order must be list[CategoryLiteral]
                # is_valid_category_literal validates items are CategoryLiteral
                priority_order = [
                    item
                    for item in constants.CATEGORIZATION_PRIORITY
                    if FlextLdifConstants.is_valid_category_literal(item)
                ]
            # Business Rule: If server doesn't provide CATEGORIZATION_PRIORITY, use default
            # Implication: Ensure priority_order is always populated for correct categorization
            if not priority_order:
                priority_order = [
                    cat
                    for cat in [
                        FlextLdifConstants.Categories.USERS.value,
                        FlextLdifConstants.Categories.HIERARCHY.value,
                        FlextLdifConstants.Categories.GROUPS.value,
                        FlextLdifConstants.Categories.ACL.value,
                    ]
                    if FlextLdifConstants.is_valid_category_literal(cat)
                ]
            if hasattr(constants, "CATEGORY_OBJECTCLASSES"):
                server_map = constants.CATEGORY_OBJECTCLASSES
                for k, v in server_map.items():
                    if FlextLdifConstants.is_valid_category_literal(k):
                        # Business Rule: k is validated as CategoryLiteral via TypeIs
                        # TypeIs narrows type - no cast needed
                        merged_category_map[k] = (
                            v if isinstance(v, frozenset) else frozenset([str(v)])
                        )
            if hasattr(constants, "CATEGORIZATION_ACL_ATTRIBUTES"):
                acl_attrs = constants.CATEGORIZATION_ACL_ATTRIBUTES
                if acl_attrs:
                    # Business Rule: merged_category_map keys must be CategoryLiteral
                    # StrEnum.value already satisfies CategoryLiteral - no cast needed
                    merged_category_map[FlextLdifConstants.Categories.ACL.value] = (
                        frozenset([f"attr:{attr.lower()}" for attr in acl_attrs])
                    )
        else:
            # Use rules, but still get constants for priority_order, hierarchy priority check,
            # and to complement rules with server constants for categories not specified in rules
            # Business Rule: Rules can be partial - complement with server constants for missing categories
            # Implication: Server constants fill gaps in rules, ensuring all categories are covered
            constants_result = self._get_server_constants(effective_server_type)
            if constants_result.is_success:
                constants = constants_result.unwrap()
                # Business Rule: Use server CATEGORIZATION_PRIORITY for correct order
                # Implication: Server knows best priority order (schema first, then acl, etc.)
                if hasattr(constants, "CATEGORIZATION_PRIORITY"):
                    priority_order = [
                        item
                        for item in constants.CATEGORIZATION_PRIORITY
                        if FlextLdifConstants.is_valid_category_literal(item)
                    ]
                else:
                    # Fallback: Use default priority order if server doesn't provide it
                    priority_order = [
                        cat
                        for cat in [
                            FlextLdifConstants.Categories.USERS.value,
                            FlextLdifConstants.Categories.HIERARCHY.value,
                            FlextLdifConstants.Categories.GROUPS.value,
                            FlextLdifConstants.Categories.ACL.value,
                        ]
                        if FlextLdifConstants.is_valid_category_literal(cat)
                    ]

                # Complement rules with server constants for categories not specified in rules
                # Business Rule: Rules override server constants, but server constants fill gaps
                # Implication: If rules don't specify a category, use server constants for it
                if hasattr(constants, "CATEGORY_OBJECTCLASSES"):
                    server_map = constants.CATEGORY_OBJECTCLASSES
                    for k, v in server_map.items():
                        if FlextLdifConstants.is_valid_category_literal(k):
                            # TypeIs narrows k to CategoryLiteral - no cast needed
                            # Only add if not already in merged_category_map (rules take precedence)
                            if k not in merged_category_map:
                                merged_category_map[k] = (
                                    v
                                    if isinstance(v, frozenset)
                                    else frozenset([str(v)])
                                )

                # Always use ACL attributes from constants when available, overriding rules
                # Business Rule: ACL attributes from server constants override rules
                # Implication: Server knows best ACL attributes for its type
                if hasattr(constants, "CATEGORIZATION_ACL_ATTRIBUTES"):
                    acl_attrs = constants.CATEGORIZATION_ACL_ATTRIBUTES
                    if acl_attrs:
                        # Business Rule: merged_category_map keys must be CategoryLiteral
                        # StrEnum.value already satisfies CategoryLiteral - no cast needed
                        merged_category_map[FlextLdifConstants.Categories.ACL.value] = (
                            frozenset([f"attr:{attr.lower()}" for attr in acl_attrs])
                        )
            else:
                # Fallback: Use default priority order if server constants unavailable
                # Business Rule: priority_order must be list[CategoryLiteral]
                # StrEnum values satisfy Literal type - no cast needed
                priority_order = [
                    cat
                    for cat in [
                        FlextLdifConstants.Categories.USERS.value,
                        FlextLdifConstants.Categories.HIERARCHY.value,
                        FlextLdifConstants.Categories.GROUPS.value,
                        FlextLdifConstants.Categories.ACL.value,
                    ]
                    if FlextLdifConstants.is_valid_category_literal(cat)
                ]
                constants = None

        # Check hierarchy priority first (if constants available)
        # Business Rule: Hierarchy entries have priority over users/groups when detected
        # via server-specific priority rules. This ensures containers are categorized
        # correctly before user/group entries.
        if constants is not None and self._check_hierarchy_priority(entry, constants):
            # Business Rule: Return type must be CategoryLiteral, not str
            # StrEnum.value already satisfies CategoryLiteral - no cast needed
            return (FlextLdifConstants.Categories.HIERARCHY.value, None)

        # Business Rule: If priority_order is empty, all entries will be rejected
        # Implication: Ensure priority_order is populated from server constants or default
        if not priority_order:
            # Fallback: Use default priority order if server didn't provide one
            # Business Rule: Default order ensures basic categorization works
            # Implication: Even without server constants, categorization should work
            priority_order = [
                cat
                for cat in [
                    FlextLdifConstants.Categories.USERS.value,
                    FlextLdifConstants.Categories.HIERARCHY.value,
                    FlextLdifConstants.Categories.GROUPS.value,
                    FlextLdifConstants.Categories.ACL.value,
                ]
                if FlextLdifConstants.is_valid_category_literal(cat)
            ]

        # Check entry objectClasses against merged category map
        entry_ocs = {oc.lower() for oc in entry.get_objectclass_names()}

        for category in priority_order:
            if category in merged_category_map:
                category_ocs = merged_category_map[category]
                # Check for attribute-based categories (ACL)
                if category == FlextLdifConstants.Categories.ACL.value:
                    for attr_marker in category_ocs:
                        if attr_marker.startswith("attr:"):
                            attr_name = attr_marker[5:]
                            if entry.has_attribute(attr_name):
                                # Business Rule: Return type must be CategoryLiteral, not str
                                # StrEnum.value already satisfies CategoryLiteral - no cast needed
                                return (
                                    FlextLdifConstants.Categories.ACL.value,
                                    None,
                                )
                # Check for objectClass-based categories
                elif any(oc in category_ocs for oc in entry_ocs):
                    # Business Rule: category is CategoryLiteral from priority_order
                    # category comes from priority_order which is list[CategoryLiteral]
                    return (category, None)

        # Business Rule: Entries that don't match any category are rejected.
        # Rejection reason provides diagnostic information for troubleshooting.
        # StrEnum.value already satisfies CategoryLiteral - no cast needed
        return (FlextLdifConstants.Categories.REJECTED.value, "No category match")

    def categorize_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.FlexibleCategories]:
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
        # Create FlexibleCategories (Categories[FlextLdifModels.Entry])
        categories = FlextModelsCollections.Categories[FlextLdifModels.Entry]()
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

            # Append entry directly (categories is Categories[FlextLdifModels.Entry])
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

        # Create FlexibleCategories (Categories[FlextLdifModels.Entry])
        filtered = FlextModelsCollections.Categories[FlextLdifModels.Entry]()
        # Initialize all categories to ensure they exist even if empty
        filtered[FlextLdifConstants.Categories.SCHEMA] = []
        filtered[FlextLdifConstants.Categories.HIERARCHY] = []
        filtered[FlextLdifConstants.Categories.USERS] = []
        filtered[FlextLdifConstants.Categories.GROUPS] = []
        filtered[FlextLdifConstants.Categories.ACL] = []
        filtered[FlextLdifConstants.Categories.REJECTED] = []

        # Collect all excluded entries from all categories
        all_excluded_entries: list[FlextLdifModels.Entry] = []

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
                # entries is already list[FlextLdifModels.Entry] from categories.items()
                included, excluded = FlextLdifCategorization._filter_entries_by_base_dn(
                    entries,
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
                filtered[category] = included_updated
                # Collect excluded entries to add to REJECTED category
                all_excluded_entries.extend(excluded_updated)
                # Rejection tracker uses FlextLdifModels.Entry
                self._rejection_tracker["base_dn_filter"].extend(excluded_updated)

                if excluded_updated:
                    logger.info(
                        "Applied base DN filter",
                        category=category,
                        total_entries=len(entries),
                        kept_entries=len(included_updated),
                        rejected_entries=len(excluded_updated),
                    )
            else:
                filtered[category] = entries

        # Add all excluded entries to the rejected category
        # Business Rule: Entries filtered out by base DN must be added to REJECTED category
        # Implication: Preserves audit trail and allows downstream processing to see rejected entries
        if all_excluded_entries:
            existing_rejected = (
                filtered.get(FlextLdifConstants.Categories.REJECTED, []) or []
            )
            filtered[FlextLdifConstants.Categories.REJECTED] = (
                existing_rejected + all_excluded_entries
            )

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

        # Create FlexibleCategories (Categories[FlextLdifModels.Entry])
        filtered = FlextModelsCollections.Categories[FlextLdifModels.Entry]()
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
                # entries is already list[FlextLdifModels.Entry] from categories
                included, excluded = FlextLdifCategorization._filter_entries_by_base_dn(
                    entries,
                    base_dn,
                )
                filtered[category] = included

                # Update metadata for excluded entries
                excluded_updated = [
                    FlextLdifCategorization._mark_entry_rejected(
                        entry,
                        FlextLdifConstants.RejectionCategory.BASE_DN_FILTER,
                        f"DN not under base DN: {base_dn}",
                    )
                    for entry in excluded
                ]
                excluded_entries.extend(excluded_updated)
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
