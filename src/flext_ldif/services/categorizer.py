"""FLEXT-LDIF Categorizer Service - Entry categorization by objectClass and ACL attributes.

This service handles categorization of LDIF entries into predefined categories
using server-specific constants and rules.

Extracted from FlextLdifFilters to follow Single Responsibility Principle.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from flext_core import FlextResult, FlextRuntime

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


def _get_server_registry() -> FlextLdifServer:
    """Get server registry instance."""
    return FlextLdifServer.get_global_instance()


class FlextLdifCategorizer(
    FlextLdifServiceBase[FlextLdifTypes.Models.ServiceResponseTypes]
):
    """Service for entry categorization.

    Provides methods for:
    - Categorizing entries by objectClass and attributes
    - Server-specific category rules (OID, OUD, RFC)
    - Hierarchy priority detection
    - Schema entry detection
    - ACL entry detection

    Categories (server-specific priority):
    - schema: Has attributeTypes/objectClasses
    - users: User accounts (person, inetOrgPerson, orcluser for OID)
    - hierarchy: Containers (organizationalUnit, orclContainer for OID)
    - groups: Group entries (groupOfNames, orclGroup for OID)
    - acl: Entries with ACL attributes (orclaci for OID, aci for OUD)
    - rejected: No match

    Example:
        categorizer_service = FlextLdifCategorizer()

        # Categorize single entry
        category, reason = categorizer_service.categorize_entry(
            entry,
            rules=category_rules,
            server_type="oid"
        )

        if category == "schema":
            print("Entry is a schema definition")
        elif category == "users":
            print("Entry is a user account")
        elif category == "rejected":
            print(f"Entry rejected: {reason}")

    """

    def execute(
        self,
        **_kwargs: object,
    ) -> FlextResult[FlextLdifTypes.Models.ServiceResponseTypes]:
        """Execute method required by FlextService abstract base class.

        This service provides specific methods (categorize_entry, is_schema_entry, etc.)
        rather than a generic execute operation.

        Args:
            **_kwargs: Ignored parameters for FlextService protocol compatibility

        Returns:
            FlextResult with not implemented error

        """
        return FlextResult.fail(
            "FlextLdifCategorizer does not support generic execute(). Use specific methods instead.",
        )

    def is_schema_entry(self, entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is a schema definition.

        Schema entries are detected by presence of attributeTypes or objectClasses
        attributes, which are universal across all LDAP servers.

        Args:
            entry: Entry to check

        Returns:
            True if entry is a schema definition

        """
        # Schema detection is universal - not server-specific
        schema_attrs = {
            "attributetypes",
            "objectclasses",
            "ldapsyntaxes",
            "matchingrules",
        }

        entry_attrs = {attr.lower() for attr in entry.attributes.attributes}
        return bool(schema_attrs & entry_attrs)

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
            constants: Server Constants class

        Returns:
            True if entry has priority hierarchy objectClass

        """
        if not hasattr(constants, "HIERARCHY_PRIORITY_OBJECTCLASSES"):
            return False

        priority_classes = constants.HIERARCHY_PRIORITY_OBJECTCLASSES
        entry_ocs = {oc.lower() for oc in entry.get_objectclass_names()}
        return any(oc.lower() in entry_ocs for oc in priority_classes)

    def _get_server_constants(self, server_type: str) -> FlextResult[type]:
        """Get and validate server constants via FlextLdifServer registry.

        Args:
            server_type: Server type identifier (oid, oud, rfc, etc.)

        Returns:
            FlextResult with constants class or error message

        """
        try:
            registry = _get_server_registry()
            server_quirk = registry.quirk(server_type)

            if not server_quirk:
                return FlextResult[type].fail(f"Unknown server type: {server_type}")

            quirk_class = type(server_quirk)
            if not hasattr(quirk_class, "Constants"):
                error_msg = f"Server type {server_type} missing Constants class"
                return FlextResult[type].fail(error_msg)

            constants = quirk_class.Constants

            if not hasattr(constants, "CATEGORIZATION_PRIORITY"):
                error_msg = f"Server {server_type} missing CATEGORIZATION_PRIORITY"
                return FlextResult[type].fail(error_msg)
            if not hasattr(constants, "CATEGORY_OBJECTCLASSES"):
                error_msg = f"Server {server_type} missing CATEGORY_OBJECTCLASSES"
                return FlextResult[type].fail(error_msg)

            return FlextResult[type].ok(constants)
        except ValueError as e:
            error_msg = f"Failed to get server constants: {e}"
            return FlextResult[type].fail(error_msg)

    def _categorize_by_priority(
        self,
        entry: FlextLdifModels.Entry,
        constants: type,
        priority_order: list[str],
        category_map: dict[str, frozenset[str]],
    ) -> tuple[str, str | None]:
        """Categorize entry by iterating through priority order.

        Args:
            entry: Entry to categorize
            constants: Server Constants class
            priority_order: Category priority order
            category_map: Category to objectClasses mapping

        Returns:
            Tuple of (category, rejection_reason)

        """
        for category in priority_order:
            if category == "acl":
                if hasattr(constants, "CATEGORIZATION_ACL_ATTRIBUTES"):
                    acl_attributes = list(constants.CATEGORIZATION_ACL_ATTRIBUTES)
                    # Use direct utility method - no helper wrapper
                    if FlextLdifUtilities.Entry.has_any_attributes(
                        entry,
                        acl_attributes,
                    ):
                        return ("acl", None)
                continue

            category_objectclasses = category_map.get(category)
            if not category_objectclasses:
                continue

            # Use direct utility method - no helper wrapper
            if FlextLdifUtilities.Entry.has_objectclass(
                entry,
                tuple(category_objectclasses),
            ):
                return (category, None)

        return ("rejected", "No category match")

    def categorize_entry(
        self,
        entry: FlextLdifModels.Entry,
        _rules: FlextLdifModels.CategoryRules | Mapping[str, object] | None = None,
        server_type: str = "rfc",
    ) -> tuple[str, str | None]:
        """Categorize entry using SERVER-SPECIFIC rules.

        Uses server-specific constants from servers/oid.py, servers/oud.py, etc.
        for objectClass prioritization and ACL detection.

        Args:
            entry: LDIF entry to categorize
            _rules: Category rules (unused, server constants take precedence)
            server_type: Server type ("oid", "oud", "rfc") determines constants

        Returns:
            Tuple of (category, rejection_reason)
            - category: One of schema, users, hierarchy, groups, acl, rejected
            - rejection_reason: None if categorized, error message if rejected

        """
        # Check schema first (universal across all servers)
        if self.is_schema_entry(entry):
            return ("schema", None)

        # Get and validate server constants
        constants_result = self._get_server_constants(server_type)
        if constants_result.is_failure:
            return ("rejected", constants_result.error)

        constants = constants_result.unwrap()

        # Type narrowing: verify constants has required attributes
        if not hasattr(constants, "CATEGORIZATION_PRIORITY") or not hasattr(
            constants,
            "CATEGORY_OBJECTCLASSES",
        ):
            return ("rejected", "Server constants missing required attributes")

        # Check for HIERARCHY PRIORITY objectClasses first
        # This solves entries like cn=PERFIS with both orclContainer + orclprivilegegroup
        if self._check_hierarchy_priority(entry, constants):
            return ("hierarchy", None)

        # Get server-specific categorization priority and mappings
        # Type narrowing: we've verified these attributes exist above
        priority_order = constants.CATEGORIZATION_PRIORITY
        category_map = constants.CATEGORY_OBJECTCLASSES

        # Type validation: ensure they are the correct types
        if not FlextRuntime.is_list_like(
            priority_order
        ) or not FlextRuntime.is_dict_like(category_map):
            return ("rejected", "Invalid constants type")

        # Categorize by priority order
        return self._categorize_by_priority(
            entry,
            constants,
            cast("list[str]", priority_order),
            cast("dict[str, frozenset[str]]", category_map),
        )


__all__ = ["FlextLdifCategorizer"]
