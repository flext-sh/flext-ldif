"""LDIF Entry Categorization Service.

Provides comprehensive entry categorization for LDIF pipeline operations:
- Category classification (schema, hierarchy, users, groups, acl, rejected)
- Whitelist-based schema filtering
- Attribute/ObjectClass filtering and blocking
- Entry exclusion and rejection tracking

Used by writer services and migration pipelines to organize entries
into logical groups for structured file output.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.filters import FlextLdifFilters


class FlextLdifCategorizationService:
    """Service for categorizing LDIF entries into logical groups.

    Provides methods for:
    - Entry categorization by type (schema, hierarchy, users, groups, acl)
    - Whitelist-based schema filtering
    - Attribute and ObjectClass filtering
    - Rejection tracking and reasoning

    Categories:
    - schema: Schema definitions (attributeTypes, objectClasses)
    - hierarchy: Organizational structure (ou, o, dc, domain)
    - users: User entries (person, inetOrgPerson, organizationalPerson)
    - groups: Group entries (groupOfNames, groupOfUniqueNames)
    - acl: ACL entries (entries with aci attributes)
    - rejected: Entries that failed validation/filtering

    """

    def __init__(
        self,
        categorization_rules: dict[str, object] | None = None,
        schema_whitelist_rules: dict[str, list[str]] | None = None,
        forbidden_attributes: list[str] | None = None,
        forbidden_objectclasses: list[str] | None = None,
    ) -> None:
        """Initialize categorization service.

        Args:
            schema_whitelist_rules: Optional whitelist rules for schema filtering
            forbidden_attributes: List of attributes to filter/block
            forbidden_objectclasses: List of objectClasses to filter/block

        """
        self._categorization_rules = categorization_rules or {}
        self._schema_whitelist_rules = schema_whitelist_rules or {}
        self._forbidden_attributes = {
            attr.lower() for attr in (forbidden_attributes or [])
        }
        self._forbidden_objectclasses = {
            oc.lower() for oc in (forbidden_objectclasses or [])
        }

    def categorize_entries(
        self,
        entries: list[dict[str, object]] | list[FlextLdifModels.Entry],
    ) -> FlextResult[dict[str, list[dict[str, object]]]]:
        """Categorize entries into logical groups.

        Categorizes entries into 6 categories:
        - schema: Schema definitions
        - hierarchy: Organizational structure
        - users: User accounts
        - groups: Group definitions
        - acl: Access control lists
        - rejected: Entries that failed categorization

        Args:
            entries: List of entries to categorize

        Returns:
            FlextResult with dict mapping category names to entry lists

        """
        try:
            categorized: dict[str, list[dict[str, object]]] = {
                "schema": [],
                "hierarchy": [],
                "users": [],
                "groups": [],
                "acl": [],
                "rejected": [],
            }

            for entry in entries:
                # Ensure we have an Entry object
                if not isinstance(entry, FlextLdifModels.Entry):
                    # If it's a dict, we can't categorize it properly
                    categorized["rejected"].append({})
                    continue

                # Use FlextLdifFilters to categorize with Entry object
                category, _reason = FlextLdifFilters.categorize_entry(
                    entry,
                    self._categorization_rules,
                    self._schema_whitelist_rules,  # type: ignore[assignment]
                )

                # Convert to dict for storage
                entry_dict = self._entry_to_dict(entry) or {}

                if category in categorized:
                    categorized[category].append(entry_dict)
                else:
                    categorized["rejected"].append(entry_dict)

            return FlextResult[dict[str, list[dict[str, object]]]].ok(categorized)

        except Exception as e:
            return FlextResult[dict[str, list[dict[str, object]]]].fail(
                f"Entry categorization failed: {e}",
            )

    def filter_entries_by_whitelist(
        self,
        entries: list[dict[str, object]],
        whitelist_rules: dict[str, list[str]] | None = None,
    ) -> FlextResult[dict[str, list[dict[str, object]]]]:
        """Filter entries based on whitelist rules.

        Whitelist rules format:
        {
            "attributeTypes": ["oid1", "oid2", "oid3"],
            "objectClasses": ["oid4", "oid5"],
        }

        Only entries matching whitelist patterns are included.

        Args:
            entries: List of entries to filter
            whitelist_rules: Optional whitelist rules (uses service defaults if not provided)

        Returns:
            FlextResult with filtered entries dict: {included: [...], excluded: [...]}

        """
        try:
            rules = whitelist_rules or self._schema_whitelist_rules

            if not rules:
                # No whitelist rules, include all
                return FlextResult[dict[str, list[dict[str, object]]]].ok({
                    "included": entries,
                    "excluded": [],
                })

            included: list[dict[str, object]] = []
            excluded: list[dict[str, object]] = []

            for entry in entries:
                if self._matches_whitelist(entry, rules):
                    included.append(entry)
                else:
                    excluded.append(entry)

            return FlextResult[dict[str, list[dict[str, object]]]].ok({
                "included": included,
                "excluded": excluded,
            })

        except Exception as e:
            return FlextResult[dict[str, list[dict[str, object]]]].fail(
                f"Whitelist filtering failed: {e}",
            )

    def filter_forbidden_attributes(
        self,
        entries: list[dict[str, object]],
    ) -> FlextResult[list[dict[str, object]]]:
        """Filter out forbidden attributes from entries.

        Removes specified attributes from all entries.

        Args:
            entries: List of entries to filter

        Returns:
            FlextResult with entries having forbidden attributes removed

        """
        try:
            filtered_entries: list[dict[str, object]] = []

            for entry in entries:
                # Convert dict to Entry if needed
                if isinstance(entry, dict):
                    # Try to create Entry from dict
                    dn = entry.get("dn")
                    attributes = entry.get("attributes", {})
                    if isinstance(dn, str) and isinstance(attributes, dict):
                        entry_obj_result = FlextLdifModels.Entry.create(
                            dn=dn, attributes=attributes
                        )
                        if entry_obj_result.is_success:
                            entry_obj = entry_obj_result.value
                        else:
                            filtered_entries.append(
                                entry
                            )  # Keep original if conversion fails
                            continue
                    else:
                        filtered_entries.append(
                            entry
                        )  # Keep original if invalid format
                        continue
                elif isinstance(entry, FlextLdifModels.Entry):
                    entry_obj = entry
                else:
                    filtered_entries.append(entry)  # Keep original if unknown type
                    continue

                filtered_entry = FlextLdifFilters.filter_entry_attributes(
                    entry_obj,
                    list(self._forbidden_attributes),
                )

                if filtered_entry.is_success:
                    # Convert back to dict
                    filtered_entries.append(
                        self._entry_to_dict(filtered_entry.unwrap()) or entry
                    )
                else:
                    filtered_entries.append(entry)  # Keep original if filter fails

            return FlextResult[list[dict[str, object]]].ok(filtered_entries)

        except Exception as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"Attribute filtering failed: {e}",
            )

    def filter_forbidden_objectclasses(
        self,
        entries: list[dict[str, object]],
    ) -> FlextResult[list[dict[str, object]]]:
        """Filter out forbidden objectClasses from entries.

        Removes specified objectClasses from all entries.

        Args:
            entries: List of entries to filter

        Returns:
            FlextResult with entries having forbidden objectClasses removed

        """
        try:
            filtered_entries: list[dict[str, object]] = []

            for entry in entries:
                # Convert dict to Entry if needed
                if isinstance(entry, dict):
                    # Try to create Entry from dict
                    dn = entry.get("dn")
                    attributes = entry.get("attributes", {})
                    if isinstance(dn, str) and isinstance(attributes, dict):
                        entry_obj_result = FlextLdifModels.Entry.create(
                            dn=dn, attributes=attributes
                        )
                        if entry_obj_result.is_success:
                            entry_obj = entry_obj_result.value
                        else:
                            filtered_entries.append(
                                entry
                            )  # Keep original if conversion fails
                            continue
                    else:
                        filtered_entries.append(
                            entry
                        )  # Keep original if invalid format
                        continue
                elif isinstance(entry, FlextLdifModels.Entry):
                    entry_obj = entry
                else:
                    filtered_entries.append(entry)  # Keep original if unknown type
                    continue

                filtered_entry = FlextLdifFilters.filter_entry_objectclasses(
                    entry_obj,
                    list(self._forbidden_objectclasses),
                )

                if filtered_entry.is_success:
                    # Convert back to dict
                    filtered_entries.append(
                        self._entry_to_dict(filtered_entry.unwrap()) or entry
                    )
                else:
                    filtered_entries.append(entry)  # Keep original if filter fails

            return FlextResult[list[dict[str, object]]].ok(filtered_entries)

        except Exception as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"ObjectClass filtering failed: {e}",
            )

    def separate_by_category(
        self,
        entries: list[dict[str, object]],
    ) -> FlextResult[dict[str, list[dict[str, object]]]]:
        """Separate entries by category for output organization.

        Organizes entries into 6 output categories:
        1. schema - Schema definitions first (must load first)
        2. hierarchy - Organizational structure second
        3. users - User accounts third
        4. groups - Groups fourth
        5. acl - ACLs fifth
        6. rejected - Failed entries last

        Args:
            entries: List of entries to separate

        Returns:
            FlextResult with categorized entries

        """
        return self.categorize_entries(entries)

    def _matches_whitelist(
        self,
        entry: dict[str, object],
        rules: dict[str, list[str]],
    ) -> bool:
        """Check if entry matches whitelist rules.

        Args:
            entry: Entry dictionary to check
            rules: Whitelist rules

        Returns:
            True if entry matches any whitelist rule

        """
        # Schema entries match schema whitelist
        oid_value = entry.get("oid", "")
        if isinstance(oid_value, str):
            attribute_patterns = rules.get("attributeTypes", [])
            if isinstance(
                attribute_patterns,
                list,
            ) and FlextLdifFilters.matches_oid_pattern(oid_value, attribute_patterns):
                return True

            objectclass_patterns = rules.get("objectClasses", [])
            if isinstance(
                objectclass_patterns,
                list,
            ) and FlextLdifFilters.matches_oid_pattern(oid_value, objectclass_patterns):
                return True

        # No whitelist rules match, exclude entry
        return False

    @staticmethod
    def _entry_to_dict(
        entry: dict[str, object] | FlextLdifModels.Entry,
    ) -> dict[str, object] | None:
        """Convert Entry object to dictionary if needed.

        Args:
            entry: Entry object or dictionary

        Returns:
            Dictionary representation or None if conversion fails

        """
        if isinstance(entry, dict):
            return entry

        if isinstance(entry, FlextLdifModels.Entry):
            return {
                FlextLdifConstants.DictKeys.DN: entry.dn.value,
                FlextLdifConstants.DictKeys.ATTRIBUTES: dict(
                    entry.attributes.attributes.items(),
                ),
            }

        return None

    def set_whitelist_rules(
        self,
        rules: dict[str, list[str]],
    ) -> None:
        """Update whitelist rules.

        Args:
            rules: New whitelist rules

        """
        self._schema_whitelist_rules = rules

    def set_forbidden_attributes(
        self,
        attributes: list[str],
    ) -> None:
        """Update forbidden attributes list.

        Args:
            attributes: List of attribute names to forbid

        """
        self._forbidden_attributes = {attr.lower() for attr in attributes}

    def set_forbidden_objectclasses(
        self,
        objectclasses: list[str],
    ) -> None:
        """Update forbidden objectClasses list.

        Args:
            objectclasses: List of objectClass names to forbid

        """
        self._forbidden_objectclasses = {oc.lower() for oc in objectclasses}


__all__ = ["FlextLdifCategorizationService"]
