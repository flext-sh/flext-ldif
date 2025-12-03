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

from flext_core import FlextLogger, r, t, u
from flext_core.models import FlextModelsCollections

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

    def __init__(  # noqa: PLR0913, PLR0917
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
    ) -> r[FlextLdifModels.FlexibleCategories]:
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
        return r[FlextLdifModels.FlexibleCategories].ok(categories)

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
    ) -> r[list[FlextLdifModels.Entry]]:
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

        def validate_entry(
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry | None:
            """Validate and normalize entry DN."""
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
                return None

            norm_result = FlextLdifUtilities.DN.norm(dn_str)
            # Use u.val() for unified result value extraction (DSL pattern)
            normalized_dn = u.val(norm_result)
            if normalized_dn is None:
                # Track rejection in metadata using FlextLdifUtilities
                rejected_entry = FlextLdifUtilities.Metadata.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        FlextLdifConstants.RejectionCategory.INVALID_DN,
                        f"DN normalization failed: {u.err(norm_result)}",
                    ),
                )
                self._rejection_tracker["invalid_dn_rfc4514"].append(rejected_entry)
                return None
            return entry.model_copy(
                update={"dn": FlextLdifModels.DistinguishedName(value=normalized_dn)},
            )

        batch_result = u.batch(
            entries,
            validate_entry,
            on_error="skip",
        )
        # Use u.val() with u.when() for unified result handling (DSL pattern)
        batch_data = u.val(batch_result)
        validated = u.when(
            condition=batch_data is not None,
            then_value=[
                cast("FlextLdifModels.Entry", entry)
                for entry in batch_data["results"]  # type: ignore[index]
                if entry is not None
            ],
            else_value=[],
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

        return r[list[FlextLdifModels.Entry]].ok(validated)

    def is_schema_entry(self, entry: FlextLdifModels.Entry) -> bool:  # noqa: PLR6301
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

    def _check_hierarchy_priority(  # noqa: PLR6301
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

    def _get_default_priority_order(  # noqa: PLR6301
        self,
    ) -> list[FlextLdifConstants.LiteralTypes.CategoryLiteral]:
        """Get default category priority order.

        Returns:
            List of CategoryLiteral in default priority order

        """
        # Use u.filter to filter valid categories
        categories = [
            FlextLdifConstants.Categories.USERS.value,
            FlextLdifConstants.Categories.HIERARCHY.value,
            FlextLdifConstants.Categories.GROUPS.value,
            FlextLdifConstants.Categories.ACL.value,
        ]
        filtered = u.filter(
            categories,
            predicate=FlextLdifConstants.is_valid_category_literal,
        )
        return filtered if isinstance(filtered, list) else []

    def _get_priority_order_from_constants(
        self,
        constants: type | None,
    ) -> list[FlextLdifConstants.LiteralTypes.CategoryLiteral]:
        """Get priority order from constants or use default.

        Args:
            constants: Server Constants class (from FlextLdifServer)

        Returns:
            List of CategoryLiteral in priority order

        """
        if constants is not None and hasattr(constants, "CATEGORIZATION_PRIORITY"):
            # Use u.filter to filter valid categories
            filtered = u.filter(
                constants.CATEGORIZATION_PRIORITY,
                predicate=FlextLdifConstants.is_valid_category_literal,
            )
            return filtered if isinstance(filtered, list) else []
        return self._get_default_priority_order()

    def _build_category_map_from_rules(  # noqa: PLR6301
        self,
        rules: FlextLdifModels.CategoryRules,
    ) -> dict[FlextLdifConstants.LiteralTypes.CategoryLiteral, frozenset[str]]:
        """Build category map from rules.

        Args:
            rules: Category rules

        Returns:
            Category to objectClasses/attributes mapping

        """
        category_map: dict[
            FlextLdifConstants.LiteralTypes.CategoryLiteral,
            frozenset[str],
        ] = {}

        # Use u.map to transform objectclasses/attributes to lowercase
        if rules.hierarchy_objectclasses:
            mapped = u.map(
                rules.hierarchy_objectclasses,
                mapper=lambda oc: oc.lower(),
            )
            category_map[FlextLdifConstants.Categories.HIERARCHY.value] = frozenset(
                mapped if isinstance(mapped, list) else []
            )
        if rules.user_objectclasses:
            mapped = u.map(
                rules.user_objectclasses,
                mapper=lambda oc: oc.lower(),
            )
            category_map[FlextLdifConstants.Categories.USERS.value] = frozenset(
                mapped if isinstance(mapped, list) else []
            )
        if rules.group_objectclasses:
            mapped = u.map(
                rules.group_objectclasses,
                mapper=lambda oc: oc.lower(),
            )
            category_map[FlextLdifConstants.Categories.GROUPS.value] = frozenset(
                mapped if isinstance(mapped, list) else []
            )
        if rules.acl_attributes:
            mapped = u.map(
                rules.acl_attributes,
                mapper=lambda attr: f"attr:{attr.lower()}",
            )
            category_map[FlextLdifConstants.Categories.ACL.value] = frozenset(
                mapped if isinstance(mapped, list) else []
            )

        return category_map

    def _merge_server_constants_to_map(  # noqa: PLR6301
        self,
        category_map: dict[
            FlextLdifConstants.LiteralTypes.CategoryLiteral,
            frozenset[str],
        ],
        constants: type,
        *,
        override_existing: bool = False,
    ) -> dict[FlextLdifConstants.LiteralTypes.CategoryLiteral, frozenset[str]]:
        """Merge server constants into category map.

        Args:
            category_map: Existing category map (may be modified in place)
            constants: Server Constants class (from FlextLdifServer)
            override_existing: Whether to override existing entries

        Returns:
            Updated category map

        """
        if hasattr(constants, "CATEGORY_OBJECTCLASSES"):
            server_map = constants.CATEGORY_OBJECTCLASSES
            for k, v in server_map.items():
                if FlextLdifConstants.is_valid_category_literal(k) and (
                    override_existing or k not in category_map
                ):
                    category_map[k] = (
                        v if isinstance(v, frozenset) else frozenset([str(v)])
                    )

        if hasattr(constants, "CATEGORIZATION_ACL_ATTRIBUTES"):
            acl_attrs = constants.CATEGORIZATION_ACL_ATTRIBUTES
            if acl_attrs:
                # Use u.map to transform attributes to lowercase with prefix
                mapped = u.map(
                    acl_attrs,
                    mapper=lambda attr: f"attr:{attr.lower()}",
                )
                category_map[FlextLdifConstants.Categories.ACL.value] = frozenset(
                    mapped if isinstance(mapped, list) else []
                )

        return category_map

    def _normalize_rules(
        self,
        rules: (
            FlextLdifModels.CategoryRules
            | Mapping[str, t.MetadataAttributeValue]
            | None
        ),
    ) -> r[FlextLdifModels.CategoryRules]:
        """Normalize rules to CategoryRules model.

        Args:
            rules: Category rules (CategoryRules model or dict or None)

        Returns:
            FlextResult with normalized CategoryRules

        """
        if isinstance(rules, FlextLdifModels.CategoryRules):
            return r.ok(rules)
        if isinstance(rules, dict):
            try:
                return r.ok(
                    FlextLdifModels.CategoryRules.model_validate(rules)
                )
            except Exception as e:
                return r.fail(f"Invalid category rules: {e}")
        return r.ok(self._categorization_rules)

    def _match_entry_to_category(  # noqa: PLR6301
        self,
        entry: FlextLdifModels.Entry,
        priority_order: list[FlextLdifConstants.LiteralTypes.CategoryLiteral],
        category_map: dict[
            FlextLdifConstants.LiteralTypes.CategoryLiteral,
            frozenset[str],
        ],
    ) -> tuple[FlextLdifConstants.LiteralTypes.CategoryLiteral, str | None]:
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

            # Check for attribute-based categories (ACL)
            if category == FlextLdifConstants.Categories.ACL.value:
                for attr_marker in category_ocs:
                    if attr_marker.startswith("attr:"):
                        attr_name = attr_marker[5:]
                        if entry.has_attribute(attr_name):
                            return (FlextLdifConstants.Categories.ACL.value, None)
            # Check for objectClass-based categories
            elif any(oc in category_ocs for oc in entry_ocs):
                return (category, None)

        return (FlextLdifConstants.Categories.REJECTED.value, "No category match")

    def _categorize_by_priority(  # noqa: PLR6301
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

    def _update_metadata_for_filtered_entries(  # noqa: PLR6301
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
            | Mapping[str, t.MetadataAttributeValue]
            | None
        ) = None,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = None,
    ) -> tuple[FlextLdifConstants.LiteralTypes.CategoryLiteral, str | None]:
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
        # Use u.val() for unified result value extraction (DSL pattern)
        normalized_rules = u.val(rules_result)
        if normalized_rules is None:
            return (FlextLdifConstants.Categories.REJECTED.value, u.err(rules_result))

        # Normalize server_type
        effective_server_type_raw = server_type or self._server_type
        try:
            effective_server_type = FlextLdifConstants.normalize_server_type(
                effective_server_type_raw
            )
        except (ValueError, TypeError) as e:
            return (
                FlextLdifConstants.Categories.REJECTED.value,
                f"Unknown server type: {effective_server_type_raw} - {e}",
            )

        # Schema detection first (universal across servers)
        if self.is_schema_entry(entry):
            return (FlextLdifConstants.Categories.SCHEMA.value, None)

        # Build category map from rules
        merged_category_map = self._build_category_map_from_rules(normalized_rules)

        # Get server constants
        constants: type | None = None
        constants_result = self._get_server_constants(effective_server_type)
        if constants_result.is_success:
            constants_raw = u.val(constants_result)
            if constants_raw is not None:
                constants = cast("type", constants_raw)
        elif not merged_category_map:
            # No rules and no constants = fail
            return (
                FlextLdifConstants.Categories.REJECTED.value,
                constants_result.error,
            )

        # Merge server constants into category map
        if constants is not None:
            self._merge_server_constants_to_map(
                merged_category_map, constants, override_existing=not bool(rules)
            )

        # Get priority order
        priority_order = self._get_priority_order_from_constants(constants)

        # Check hierarchy priority first
        if constants is not None and self._check_hierarchy_priority(entry, constants):
            return (FlextLdifConstants.Categories.HIERARCHY.value, None)

        # Match entry to category
        return self._match_entry_to_category(entry, priority_order, merged_category_map)

    def categorize_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> r[FlextLdifModels.FlexibleCategories]:
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

        def categorize_single_entry(
            entry: FlextLdifModels.Entry,
        ) -> tuple[str, FlextLdifModels.Entry]:
            """Categorize single entry."""
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
            return category, entry_to_append

        batch_result = u.batch(
            entries,
            categorize_single_entry,
            on_error="skip",
        )
        # Use u.val() for unified result value extraction (DSL pattern)
        batch_data = u.val(batch_result)
        if batch_data is not None:
            for result_item in batch_data["results"]:  # type: ignore[index]
                if result_item is not None:
                    category, entry_to_append = cast(
                        "tuple[str, FlextLdifModels.Entry]", result_item
                    )
                    if category == FlextLdifConstants.Categories.REJECTED.value:
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
                        entry_dn=str(entry_to_append.dn)
                        if entry_to_append.dn
                        else None,
                        rejection_reason=reason,
                    )

                # Append entry directly (categories is Categories[FlextLdifModels.Entry])
                categories[category].append(entry_to_append)

        # Log category statistics
        for cat, cat_entries in u.pairs(categories):
            if cat_entries:
                logger.info(
                    "Category entries",
                    category=cat,
                    entries_count=u.count(cat_entries),
                )

        return r[FlextLdifModels.FlexibleCategories].ok(categories)

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

        for category, entries in u.pairs(categories):
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
                        total_entries=u.count(entries),
                        kept_entries=u.count(included_updated),
                        rejected_entries=u.count(excluded_updated),
                    )
            else:
                filtered[category] = entries

        # Add all excluded entries to the rejected category
        # Business Rule: Entries filtered out by base DN must be added to REJECTED category
        # Implication: Preserves audit trail and allows downstream processing to see rejected entries
        if all_excluded_entries:
            existing_rejected: list[FlextLdifModels.Entry] = filtered.get(
                FlextLdifConstants.Categories.REJECTED, []
            )
            filtered[FlextLdifConstants.Categories.REJECTED] = (
                existing_rejected + all_excluded_entries
            )

        return filtered

    def filter_schema_by_oids(
        self,
        schema_entries: list[FlextLdifModels.Entry],
    ) -> r[list[FlextLdifModels.Entry]]:
        """Filter schema entries by OID whitelist.

        Public method using FlextLdifFilters.filter_schema_by_oids service.

        Args:
            schema_entries: Schema category entries

        Returns:
            FlextResult with filtered schema entries

        """
        if not self._schema_whitelist_rules:
            return r[list[FlextLdifModels.Entry]].ok(schema_entries)

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
            filtered_raw = u.val(result)
            if filtered_raw is not None:
                filtered = cast("list[FlextLdifModels.Entry]", filtered_raw)
                logger.info(
                    "Applied schema OID whitelist filter",
                    total_entries=u.count(schema_entries),
                    filtered_entries=u.count(filtered),
                    removed_entries=u.count(schema_entries) - u.count(filtered),
                )
                return r[list[FlextLdifModels.Entry]].ok(filtered)

        # Error handling: result.error might be None
        # Use u.err() for unified error extraction (DSL pattern)
        error_msg = u.err(result)
        return r[list[FlextLdifModels.Entry]].fail(error_msg)

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

        for category, entries in u.pairs(categories):
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
            existing_rejected: list[FlextLdifModels.Entry] = filtered.get(
                FlextLdifConstants.Categories.REJECTED, []
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
