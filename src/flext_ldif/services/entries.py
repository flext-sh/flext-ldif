"""Entries Service - Comprehensive Entry Operations.

Provides comprehensive entry management operations including creation, extraction,
transformation, and manipulation of LDIF entries with proper SRP separation.

Scope:
- Entry CRUD operations (create, read attributes, DN extraction)
- Entry transformation (remove attributes, remove operational attributes, remove objectClasses)
- Entry manipulation (get attributes, normalize values, extract objectClasses)
- Metadata preservation using FlextLdifUtilities.Metadata
- Server-agnostic operations using FlextLdifServer via DI when needed

All operations use:
- FlextLdifUtilities.Entry for entry operations
- FlextLdifUtilities.Metadata for metadata operations
- FlextLdifUtilities.DN for DN operations
- FlextLdifServer via DI for server-specific logic (never direct OID/OUD knowledge)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Self, override

from flext_core import FlextResult, FlextRuntime
from pydantic import Field

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifEntries(
    FlextLdifServiceBase[list[FlextLdifModels.Entry]]
):
    """Comprehensive entry service with SRP-separated responsibilities.

    Provides methods for:
    - Entry CRUD: create_entry, get_entry_dn, get_entry_attributes, get_entry_objectclasses
    - Entry transformation: remove_attributes, remove_operational_attributes, remove_objectclasses
    - Entry manipulation: get_attribute, normalize_attribute_value, get_normalized_attribute
    - Metadata operations: apply_marked_removals (uses FlextLdifUtilities.Metadata)

    All operations use FlextLdifUtilities for core logic and FlextLdifServer via DI
    for server-specific operations. No direct knowledge of OID, OUD, or other servers.

    Example:
        entries_service = FlextLdifEntries()

        # Create entry
        result = entries_service.create_entry(
            dn="cn=John Doe,ou=Users,dc=example,dc=com",
            attributes={"cn": "John Doe", "sn": "Doe"},
            objectclasses=["inetOrgPerson", "person", "top"]
        )

        # Extract DN
        dn_result = entries_service.get_entry_dn(entry)

        # Remove operational attributes
        clean_result = entries_service.remove_operational_attributes(entry)

        # Remove specific attributes
        filtered_result = entries_service.remove_attributes(entry, ["tempAttr"])

    """

    # Pydantic fields for batch operations
    entries: list[FlextLdifModels.Entry] = Field(default_factory=list)
    operation: str = "remove_operational_attributes"
    attributes_to_remove: list[str] = Field(default_factory=list)

    # Server registry for DI (lazy initialization)
    _server_registry: FlextLdifServer | None = None

    def _get_server_registry(self) -> FlextLdifServer:
        """Get server registry instance (lazy initialization for DI)."""
        if self._server_registry is None:
            self._server_registry = FlextLdifServer()
        return self._server_registry

    # ════════════════════════════════════════════════════════════════════════
    # EXECUTE PATTERN (FlextService compatibility)
    # ════════════════════════════════════════════════════════════════════════

    @override
    def execute(
        self,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute method for FlextService protocol compatibility.

        This service provides specific methods rather than a generic execute operation.
        Batch operations use execute() pattern for consistency.

        Returns:
            FlextResult with not implemented error for direct execute() calls

        """
        if self.operation == "remove_operational_attributes":
            return self._remove_operational_attributes_batch()
        if self.operation == "remove_attributes":
            return self._remove_attributes_batch()
        return FlextResult[list[FlextLdifModels.Entry]].fail(
            "FlextLdifEntries does not support generic execute(). Use specific methods instead.",
        )

    # ════════════════════════════════════════════════════════════════════════
    # ENTRY CRUD OPERATIONS
    # ════════════════════════════════════════════════════════════════════════

    def get_entry_dn(
        self,
        entry: FlextLdifModels.Entry
        | FlextLdifProtocols.Entry.EntryWithDnProtocol
        | dict[str, str | list[str]],
    ) -> FlextResult[str]:
        """Extract DN (Distinguished Name) from any entry type.

        Uses FlextLdifUtilities.DN for DN operations.
        Handles Entry models, LDAP entries, and dicts.

        Args:
            entry: Entry model, LDAP entry, or dict to extract DN from

        Returns:
            FlextResult containing DN as string

        Example:
            result = entries_service.get_entry_dn(entry_model)
            if result.is_success:
                dn = result.unwrap()

        """
        try:
            # Handle dict
            if FlextRuntime.is_dict_like(entry):
                dn_val = entry.get("dn")
                if not dn_val:
                    return FlextResult[str].fail("Dict entry missing 'dn' key")
                return FlextResult[str].ok(str(dn_val))

            # Handle models/protocols - check Entry first to avoid protocol overlap
            if isinstance(entry, FlextLdifModels.Entry):
                if not entry.dn:
                    return FlextResult[str].fail("Entry missing DN attribute")
                dn_value: object = entry.dn
            elif isinstance(entry, FlextLdifProtocols.Entry.EntryWithDnProtocol):
                dn_value = entry.dn
            else:
                return FlextResult[str].fail(
                    "Entry does not implement EntryWithDnProtocol or is not Entry model"
                )

            # Extract DN value using FlextLdifUtilities.DN
            dn_str = FlextLdifUtilities.DN.get_dn_value(dn_value)
            return FlextResult[str].ok(dn_str)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str].fail(f"Failed to extract DN: {e}")

    def get_entry_attributes(
        self,
        entry: FlextLdifModels.Entry
        | FlextLdifProtocols.Entry.EntryWithDnProtocol,
    ) -> FlextResult[FlextLdifTypes.CommonDict.AttributeDict]:
        """Extract attributes from any entry type.

        Handles FlextLdifModels.Entry (from LDIF files) and
        any object with 'dn' and 'attributes' attributes (EntryWithDnProtocol).

        Returns attributes as dict[str, str | list[str]] per
        FlextLdifTypes.CommonDict.AttributeDict.

        Args:
            entry: LDIF or LDAP entry to extract attributes from

        Returns:
            FlextResult containing AttributeDict with attribute names mapped to
            str | list[str] values matching FlextLdifTypes definition.

        Example:
            result = entries_service.get_entry_attributes(entry)
            if result.is_success:
                attrs = result.unwrap()

        """
        try:
            if not entry or not hasattr(entry, "attributes"):
                return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].fail(
                    "Entry missing attributes",
                )

            attrs_container = entry.attributes

            # Handle both LdifAttributes and dict-like access
            if isinstance(attrs_container, FlextLdifModels.LdifAttributes):
                attrs_source: Mapping[str, object] = attrs_container.attributes
            elif FlextRuntime.is_dict_like(attrs_container):
                attrs_source = attrs_container
            else:
                return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].fail(
                    f"Unknown attributes container type: {type(attrs_container)}",
                )

            result_dict = self._extract_attributes_to_dict(attrs_source)
            return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].ok(result_dict)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].fail(
                f"Failed to extract attributes: {e}",
            )

    def get_entry_objectclasses(
        self,
        entry: FlextLdifModels.Entry
        | FlextLdifProtocols.Entry.EntryWithDnProtocol,
    ) -> FlextResult[list[str]]:
        """Extract objectClass values from any entry type.

        Uses FlextLdifConstants.DictKeys.OBJECTCLASS for consistency.
        Handles FlextLdifModels.Entry (from LDIF files) and
        any object with 'dn' and 'attributes' attributes (EntryWithDnProtocol).

        Args:
            entry: LDIF or LDAP entry to extract objectClasses from

        Returns:
            FlextResult containing list of objectClass values

        Example:
            result = entries_service.get_entry_objectclasses(entry)
            if result.is_success:
                object_classes = result.unwrap()

        """
        try:
            # Get objectClass from attributes
            attrs_result = self.get_entry_attributes(entry)
            if attrs_result.is_failure:
                return FlextResult[list[str]].fail(
                    f"Failed to get entry attributes: {attrs_result.error}",
                )

            attrs = attrs_result.unwrap()
            # objectClass might be stored as "objectClass" or "objectclass"
            oc_values = attrs.get(
                FlextLdifConstants.DictKeys.OBJECTCLASS,
            ) or attrs.get(FlextLdifConstants.DictKeys.OBJECTCLASS.lower())
            if oc_values:
                # Normalize to list (get_entry_attributes returns str | list[str])
                return FlextResult[list[str]].ok(self._normalize_to_list(oc_values))

            return FlextResult[list[str]].fail("Entry missing objectClass attribute")

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[str]].fail(f"Failed to extract objectClasses: {e}")

    def create_entry(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create a new LDIF entry with validation.

        Uses FlextLdifModels.Entry.create() factory method.
        Validates DN using FlextLdifUtilities.DN.

        Args:
            dn: Distinguished Name for the entry
            attributes: Dict mapping attribute names to values (string or list)
            objectclasses: Optional list of objectClass values (added to attributes if provided)

        Returns:
            FlextResult containing new FlextLdifModels.Entry

        Example:
            result = entries_service.create_entry(
                dn="cn=John Doe,ou=Users,dc=example,dc=com",
                attributes={"cn": "John Doe", "sn": "Doe", "mail": "john@example.com"},
                objectclasses=["inetOrgPerson", "person", "top"]
            )
            if result.is_success:
                entry = result.unwrap()

        """
        try:
            # Validate DN using FlextLdifUtilities.DN
            if not FlextLdifUtilities.DN.validate(dn):
                return FlextResult[FlextLdifModels.Entry].fail(f"Invalid DN: {dn}")

            # Normalize attributes - Entry.create accepts dict[str, str | list[str]] | LdifAttributes
            normalized_attrs: dict[str, str | list[str]] = {
                k: ([str(v) for v in v] if FlextRuntime.is_list_like(v) else str(v))
                for k, v in attributes.items()
            }

            # Add objectClass if provided
            if objectclasses:
                normalized_attrs[FlextLdifConstants.DictKeys.OBJECTCLASS] = [
                    str(v) for v in objectclasses
                ]

            # Use FlextLdifModels.Entry.create() factory method
            create_result = FlextLdifModels.Entry.create(
                dn=dn,
                attributes=dict(normalized_attrs),
            )

            if create_result.is_success:
                # Type narrowing: convert internal Entry to public Entry
                entry_unwrapped = create_result.unwrap()
                if not isinstance(entry_unwrapped, FlextLdifModels.Entry):
                    entry_public = FlextLdifModels.Entry.model_validate(
                        entry_unwrapped.model_dump(),
                    )
                else:
                    entry_public = entry_unwrapped
                return FlextResult[FlextLdifModels.Entry].ok(entry_public)
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create entry: {create_result.error}",
            )

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create entry: {e}",
            )

    def get_attribute_values(
        self,
        attribute: FlextLdifProtocols.AttributeValueProtocol | list[str] | str,
    ) -> FlextResult[list[str]]:
        """Extract values from an attribute value object using monadic pattern.

        Handles various attribute value formats from both LDIF and LDAP entries.
        Uses FlextResult for composable error handling.

        Args:
            attribute: Attribute value object with .values property, list, or string.

        Returns:
            FlextResult containing list of attribute values as strings.

        Example:
            result = entries_service.get_attribute_values(attr_value_obj)
            if result.is_success:
                values = result.unwrap()

        """
        # Handle objects with .values property (protocol-based)
        if isinstance(attribute, FlextLdifProtocols.AttributeValueProtocol):
            return FlextResult[list[str]].ok(self._to_string_list(attribute.values))

        # Handle lists and strings
        if FlextRuntime.is_list_like(attribute) or isinstance(attribute, str):
            return FlextResult[list[str]].ok(self._to_string_list(attribute))

        # Fast fail for unknown types
        return FlextResult[list[str]].fail(
            f"Unsupported attribute type: {type(attribute).__name__}. "
            "Expected AttributeValueProtocol, list[str], or str.",
        )

    # ════════════════════════════════════════════════════════════════════════
    # ENTRY TRANSFORMATION OPERATIONS
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def remove_operational_attributes(
        cls,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove operational attributes from a single entry.

        Removes COMMON operational attributes (createTimestamp, modifyTimestamp, etc.)
        making the entry portable across different LDAP servers.
        Uses FlextLdifConstants.OperationalAttributes.COMMON.

        Args:
            entry: Entry to adapt

        Returns:
            FlextResult with adapted entry (operational attrs removed)

        Example:
            result = FlextLdifEntries.remove_operational_attributes(entry)
            if result.is_success:
                portable_entry = result.unwrap()

        """
        return cls().remove_operational_attributes_single(entry)

    @classmethod
    def remove_operational_attributes_batch(
        cls,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Remove operational attributes from multiple entries.

        Args:
            entries: Entries to adapt

        Returns:
            FlextResult with adapted entries

        Example:
            result = FlextLdifEntries.remove_operational_attributes_batch(entries)
            if result.is_success:
                portable_entries = result.unwrap()

        """
        return cls(entries=entries, operation="remove_operational_attributes").execute()

    def remove_operational_attributes_single(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove operational attributes from single entry.

        Uses FlextLdifConstants.OperationalAttributes.COMMON and
        FlextLdifUtilities.DN for DN operations.

        Args:
            entry: Entry to adapt

        Returns:
            FlextResult with adapted entry

        """
        if not entry.attributes:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Entry {FlextLdifUtilities.DN.get_dn_value(entry.dn)} has no attributes",
            )

        operational_attrs = set(FlextLdifConstants.OperationalAttributes.COMMON)
        operational_attrs_lower = {attr.lower() for attr in operational_attrs}

        adapted_attrs: dict[str, list[str]] = {}

        for attr_name, attr_values in entry.attributes.attributes.items():
            # Skip operational attributes (case-insensitive check)
            if attr_name.lower() in operational_attrs_lower:
                # Track transformation in metadata using FlextLdifUtilities.Metadata
                if entry.metadata:
                    FlextLdifUtilities.Metadata.track_transformation(
                        metadata=entry.metadata,
                        original_name=attr_name,
                        target_name=None,
                        original_values=attr_values.copy(),
                        target_values=None,
                        transformation_type="removed",
                        reason="Operational attribute removed for portability",
                    )
                self.logger.debug(
                    "Removed operational attribute",
                    attribute_name=attr_name,
                    entry_dn=FlextLdifUtilities.DN.get_dn_value(entry.dn),
                )
                continue

            # Keep attribute as-is
            adapted_attrs[attr_name] = attr_values.copy()

        # Create adapted entry
        ldif_attributes = FlextLdifModels.LdifAttributes(attributes=adapted_attrs)

        # Check DN is not None before creating entry
        if not entry.dn:
            return FlextResult[FlextLdifModels.Entry].fail("Entry has no DN")

        create_result = FlextLdifModels.Entry.create(
            dn=entry.dn,
            attributes=ldif_attributes,
            metadata=entry.metadata,
        )
        if create_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                create_result.error or "Unknown error",
            )
        adapted_entry = create_result.unwrap()
        return FlextResult[FlextLdifModels.Entry].ok(adapted_entry)

    @classmethod
    def remove_attributes(
        cls,
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove specific attributes from a single entry.

        Uses FlextLdifUtilities.Entry.remove_attributes() for core logic.

        Args:
            entry: Entry to clean
            attributes: List of attribute names to remove (case-insensitive)

        Returns:
            FlextResult with cleaned entry

        Example:
            result = FlextLdifEntries.remove_attributes(
                entry,
                attributes=["tempAttribute", "debugInfo"]
            )
            if result.is_success:
                cleaned_entry = result.unwrap()

        """
        return cls().remove_attributes_single(entry, attributes)

    @classmethod
    def remove_attributes_batch(
        cls,
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Remove specific attributes from multiple entries.

        Args:
            entries: Entries to clean
            attributes: List of attribute names to remove

        Returns:
            FlextResult with cleaned entries

        Example:
            result = FlextLdifEntries.remove_attributes_batch(
                entries,
                attributes=["tempAttribute", "debugInfo"]
            )
            if result.is_success:
                cleaned_entries = result.unwrap()

        """
        return cls(
            entries=entries,
            operation="remove_attributes",
            attributes_to_remove=attributes,
        ).execute()

    def remove_attributes_single(
        self,
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove specific attributes from single entry.

        Uses FlextLdifUtilities.Entry.remove_attributes() for core logic.

        Args:
            entry: Entry to clean
            attributes: List of attribute names to remove

        Returns:
            FlextResult with cleaned entry

        """
        # Check if entry has attributes
        if not entry.attributes:
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        # Track transformations in metadata using FlextLdifUtilities.Metadata
        attrs_to_remove_lower = {attr.lower() for attr in attributes}
        if entry.metadata:
            for attr_name, attr_values in entry.attributes.attributes.items():
                if attr_name.lower() in attrs_to_remove_lower:
                    FlextLdifUtilities.Metadata.track_transformation(
                        metadata=entry.metadata,
                        original_name=attr_name,
                        target_name=None,
                        original_values=attr_values.copy(),
                        target_values=None,
                        transformation_type="removed",
                        reason="Attribute removed by request",
                    )
                    self.logger.debug(
                        "Removed attribute",
                        attribute_name=attr_name,
                        entry_dn=FlextLdifUtilities.DN.get_dn_value(entry.dn),
                    )

        cleaned_entry = FlextLdifUtilities.Entry.remove_attributes(
            entry,
            attributes,
        )
        return FlextResult[FlextLdifModels.Entry].ok(cleaned_entry)

    def remove_objectclasses(
        self,
        entry: FlextLdifModels.Entry,
        objectclasses: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove objectClasses from entry with validation.

        Uses FlextLdifConstants.DictKeys.OBJECTCLASS and validates that
        not all objectClasses are removed (Entry Model requirement: entries must have at least one objectClass).

        Args:
            entry: Entry to transform
            objectclasses: List of objectClass names to remove

        Returns:
            FlextResult with transformed entry

        Example:
            result = entries_service.remove_objectclasses(entry, ["oldClass"])
            if result.is_success:
                transformed_entry = result.unwrap()

        """
        validation_result = self._validate_entry_dn_and_attributes(entry)
        if validation_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                validation_result.error or "Entry validation failed",
            )

        blocked_lower = {oc.lower() for oc in objectclasses}
        oc_values = entry.get_attribute_values(FlextLdifConstants.DictKeys.OBJECTCLASS)
        if not oc_values:
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        filtered_ocs = [oc for oc in oc_values if oc.lower() not in blocked_lower]
        if not filtered_ocs:
            return FlextResult[FlextLdifModels.Entry].fail(
                "All objectClasses would be removed",
            )

        new_attrs_dict = dict(entry.attributes.attributes)
        new_attrs_dict[FlextLdifConstants.DictKeys.OBJECTCLASS] = filtered_ocs

        new_attributes = FlextLdifModels.LdifAttributes(
            attributes=new_attrs_dict,
            metadata=entry.attributes.metadata,
        )

        entry_result = FlextLdifModels.Entry.create(
            dn=entry.dn,
            attributes=new_attributes,
            metadata=entry.metadata,
        )
        if entry_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                entry_result.error or "Entry creation failed",
            )

        return entry_result

    # ════════════════════════════════════════════════════════════════════════
    # ENTRY MANIPULATION OPERATIONS
    # ════════════════════════════════════════════════════════════════════════

    def get_entry_attribute(
        self,
        entry: FlextLdifModels.Entry,
        attr_name: str,
    ) -> FlextResult[object]:
        """Safely get attribute value from LDAP entry.

        Args:
            entry: LDAP entry to extract attribute from
            attr_name: Name of the attribute to retrieve

        Returns:
            FlextResult with attribute value or failure if not found

        Example:
            result = entries_service.get_entry_attribute(entry, "cn")
            if result.is_success:
                value = result.unwrap()

        """
        if not entry.attributes or not hasattr(entry.attributes, "attributes"):
            return FlextResult[object].fail(
                f"Entry has no attributes dictionary for attribute '{attr_name}'",
            )
        attr_dict = entry.attributes.attributes
        if not FlextRuntime.is_dict_like(attr_dict):
            return FlextResult[object].fail(
                f"Entry attributes is not a dictionary for attribute '{attr_name}'",
            )
        if attr_name not in attr_dict:
            return FlextResult[object].fail(
                f"Attribute '{attr_name}' not found in entry",
            )
        return FlextResult[object].ok(attr_dict[attr_name])

    def normalize_attribute_value(self, attr_value: object) -> FlextResult[str]:
        """Normalize LDAP attribute value to string.

        Args:
            attr_value: Raw LDAP attribute value (list or single value)

        Returns:
            FlextResult with normalized string value or failure if invalid/empty

        Example:
            result = entries_service.normalize_attribute_value(["value1", "value2"])
            if result.is_success:
                normalized = result.unwrap()  # "value1"

        """
        # Defensive check for None values
        if attr_value is None:
            return FlextResult[str].fail(
                "Attribute value is None - cannot normalize",
            )

        if FlextRuntime.is_list_like(attr_value) and len(attr_value) > 0:
            return FlextResult[str].ok(str(attr_value[0]))

        try:
            str_value = str(attr_value).strip()
            if not str_value:
                return FlextResult[str].fail(
                    "Attribute value is empty after normalization",
                )
            return FlextResult[str].ok(str_value)
        except (TypeError, AttributeError) as e:
            return FlextResult[str].fail(f"Failed to normalize attribute value: {e}")

    def get_normalized_attribute(
        self,
        entry: FlextLdifModels.Entry,
        attr_name: str,
    ) -> FlextResult[str]:
        """Get and normalize LDAP attribute value.

        Args:
            entry: LDAP entry to extract attribute from
            attr_name: Name of the attribute to retrieve and normalize

        Returns:
            FlextResult with normalized string value or failure if not found/invalid

        Example:
            result = entries_service.get_normalized_attribute(entry, "cn")
            if result.is_success:
                normalized = result.unwrap()

        """
        raw_value_result = self.get_entry_attribute(entry, attr_name)
        if not raw_value_result.is_success:
            return FlextResult[str].fail(
                f"Failed to get attribute '{attr_name}': {raw_value_result.error}",
            )
        return self.normalize_attribute_value(raw_value_result.unwrap())

    # ════════════════════════════════════════════════════════════════════════
    # METADATA OPERATIONS
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def apply_marked_removals(
        cls,
        entry: FlextLdifModels.Entry,
    ) -> FlextLdifModels.Entry:
        """Remove attributes that were marked for removal by filters.

        SRP: Entry service performs actual removal based on metadata markers.
        Uses FlextLdifUtilities.Metadata patterns and FlextLdifConstants for status.

        Reads: entry.metadata.removed_attributes (set by filters)
        Removes: All attributes in removed_attributes dict
        Preserves: Removal info in metadata for writer to show as comments

        Args:
            entry: Entry to process

        Returns:
            Entry with marked attributes removed

        Example:
            # Filter marks attributes
            marked_entry = filter_service.mark_attributes(entry, attrs_to_remove)

            # Entry service removes marked attributes
            cleaned_entry = FlextLdifEntries.apply_marked_removals(marked_entry)

        """
        # Check if entry has metadata and removed attributes
        if not entry.metadata or not entry.metadata.removed_attributes:
            return entry

        # Get attributes to remove from metadata.removed_attributes
        # This is set by filters when marking attributes for removal
        attrs_to_remove = list(entry.metadata.removed_attributes.keys())
        if not attrs_to_remove or not entry.attributes:
            return entry

        # Remove marked attributes and update metadata
        return cls._create_cleaned_entry(entry, attrs_to_remove)

    # ════════════════════════════════════════════════════════════════════════
    # FLUENT BUILDER PATTERN
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def builder(cls) -> Self:
        """Create fluent builder for complex entry transformations.

        Returns:
            Service instance for method chaining

        Example:
            result = (FlextLdifEntries.builder()
                .with_entries(entries)
                .with_operation("remove_operational_attributes")
                .build())

        """
        return cls(entries=[])

    def with_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> Self:
        """Set entries to transform (fluent builder)."""
        self.entries = entries
        return self

    def with_operation(self, operation: str) -> Self:
        """Set transformation operation (fluent builder)."""
        self.operation = operation
        return self

    def with_attributes_to_remove(self, attributes: list[str]) -> Self:
        """Set attributes to remove (fluent builder)."""
        self.attributes_to_remove = attributes
        return self

    def build(self) -> list[FlextLdifModels.Entry]:
        """Execute and return unwrapped result (fluent terminal)."""
        result: FlextResult[list[FlextLdifModels.Entry]] = self.execute()
        if result.is_failure:
            raise ValueError(result.error or "Build failed")
        return result.unwrap()

    # ════════════════════════════════════════════════════════════════════════
    # PRIVATE IMPLEMENTATION HELPERS
    # ════════════════════════════════════════════════════════════════════════

    def _remove_operational_attributes_batch(
        self,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Remove operational attributes from all entries."""
        adapted_entries: list[FlextLdifModels.Entry] = []

        for entry in self.entries:
            result = self.remove_operational_attributes_single(entry)
            if result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    result.error or "Unknown error",
                )
            adapted_entries.append(result.unwrap())

        return FlextResult[list[FlextLdifModels.Entry]].ok(adapted_entries)

    def _remove_attributes_batch(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Remove specific attributes from all entries."""
        adapted_entries: list[FlextLdifModels.Entry] = []

        for entry in self.entries:
            result = self.remove_attributes_single(entry, self.attributes_to_remove)
            if result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    result.error or "Unknown error",
                )
            adapted_entries.append(result.unwrap())

        return FlextResult[list[FlextLdifModels.Entry]].ok(adapted_entries)

    @staticmethod
    def _normalize_to_list(value: str | list[str]) -> list[str]:
        """Normalize value to list[str]."""
        return [value] if isinstance(value, str) else value

    @staticmethod
    def _to_string_list(value: object) -> list[str]:
        """Convert any value to list[str]."""
        if FlextRuntime.is_list_like(value):
            return [str(v) for v in value]
        return [str(value)]

    @staticmethod
    def _extract_attributes_to_dict(
        attrs: Mapping[str, object],
    ) -> dict[str, list[str]]:
        """Extract attributes from any container to dict.

        Args:
            attrs: Attributes container (dict, LdifAttributes.attributes, etc.)

        Returns:
            Dict with normalized values as list[str]

        """
        return {
            attr_name: FlextLdifEntries._to_string_list(attr_val)
            for attr_name, attr_val in attrs.items()
        }

    @staticmethod
    def _validate_entry_dn_and_attributes(
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[str]:
        """Validate entry has DN and attributes, return DN value."""
        if not entry.dn:
            return FlextResult[str].fail("Entry has no DN")
        dn_value = FlextLdifUtilities.DN.get_dn_value(entry.dn)
        if entry.attributes is None:
            return FlextResult[str].fail(f"Entry {dn_value} has no attributes")
        return FlextResult[str].ok(dn_value)

    @staticmethod
    def _create_cleaned_entry(
        entry: FlextLdifModels.Entry,
        attrs_to_remove: list[str],
    ) -> FlextLdifModels.Entry:
        """Create entry with removed attributes (extracted to reduce complexity).

        Uses FlextLdifUtilities.Entry.remove_attributes() for core logic and
        updates metadata using FlextLdifUtilities.Metadata patterns.

        """
        # Remove marked attributes using FlextLdifUtilities.Entry
        cleaned_entry = FlextLdifUtilities.Entry.remove_attributes(
            entry,
            attrs_to_remove,
        )

        # Track transformations in metadata using FlextLdifUtilities.Metadata
        if cleaned_entry.metadata:
            for attr_name in attrs_to_remove:
                if attr_name in entry.attributes.attributes:
                    attr_values = entry.attributes.attributes[attr_name]
                    FlextLdifUtilities.Metadata.track_transformation(
                        metadata=cleaned_entry.metadata,
                        original_name=attr_name,
                        target_name=None,
                        original_values=attr_values.copy(),
                        target_values=None,
                        transformation_type="removed",
                        reason="Attribute marked for removal by filters",
                    )

        # Store removed attributes in metadata extensions for writer to show as comments
        # Use FlextLdifConstants.MetadataKeys for consistency
        if not cleaned_entry.metadata:
            return cleaned_entry

        # Get original values from entry.metadata.removed_attributes before removal
        removed_attributes_with_values: dict[str, list[str]] = {}
        if entry.metadata and entry.metadata.removed_attributes:
            for attr_name in attrs_to_remove:
                if attr_name in entry.metadata.removed_attributes:
                    removed_attributes_with_values[attr_name] = (
                        entry.metadata.removed_attributes[attr_name]
                    )

        # Update metadata extensions with removed_attributes_with_values for writer
        new_extensions = cleaned_entry.metadata.extensions.copy()
        new_extensions[
            FlextLdifConstants.MetadataKeys.REMOVED_ATTRIBUTES_WITH_VALUES
        ] = removed_attributes_with_values

        new_metadata = cleaned_entry.metadata.model_copy(
            update={"extensions": new_extensions}
        )

        result = FlextLdifModels.Entry.create(
            dn=cleaned_entry.dn,
            attributes=cleaned_entry.attributes,
            metadata=new_metadata,
        )
        if result.is_success:
            return result.unwrap()
        return cleaned_entry

    @staticmethod
    def convert_ldif_attributes_to_ldap3_format(
        attributes: dict[str, list[str]],
    ) -> dict[str, list[str]]:
        """Convert LDIF attributes format to ldap3 format.

        Args:
            attributes: Dict with attribute names as keys and list of string values

        Returns:
            Dict compatible with ldap3 library format

        """
        # LDIF attributes are already in the format expected by ldap3
        # ldap3 expects dict[str, list[str]] where each attribute has a list of values
        return dict(attributes)


# Rebuild model to resolve forward references
# Forward references resolved automatically by Pydantic


__all__ = ["FlextLdifEntries"]
