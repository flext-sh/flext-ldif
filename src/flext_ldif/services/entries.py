"""FLEXT-LDIF Entries Service - Entry CRUD operations.

This service handles all entry-related operations including creation,
attribute extraction, DN handling, and objectClass management.

Extracted from FlextLdif facade to follow Single Responsibility Principle.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextResult, FlextRuntime

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.typings import FlextLdifTypes


class FlextLdifEntries(
    FlextLdifServiceBase[FlextLdifTypes.Models.ServiceResponseTypes],
):
    """Service for entry CRUD operations.

    Provides methods for:
    - Creating new entries with validation
    - Extracting DNs from various entry formats
    - Getting entry attributes
    - Extracting objectClass values
    - Getting attribute values

    Example:
        entries_service = FlextLdifEntries()

        # Create new entry
        result = entries_service.create_entry(
            dn="cn=John Doe,ou=Users,dc=example,dc=com",
            attributes={"cn": "John Doe", "sn": "Doe"},
            objectclasses=["inetOrgPerson", "person", "top"]
        )

        # Extract DN
        dn_result = entries_service.get_entry_dn(entry)

        # Get attributes
        attrs_result = entries_service.get_entry_attributes(entry)

    """

    def execute(
        self,
        **_kwargs: object,
    ) -> FlextResult[FlextLdifTypes.Models.ServiceResponseTypes]:
        """Execute method required by FlextService abstract base class.

        This service provides specific methods (create_entry, get_entry_dn, etc.)
        rather than a generic execute operation.

        Args:
            **_kwargs: Ignored parameters for FlextService protocol compatibility

        Returns:
            FlextResult with not implemented error

        """
        return FlextResult.fail(
            "FlextLdifEntries does not support generic execute(). Use specific methods instead.",
        )

    def get_entry_dn(
        self,
        entry: FlextLdifModels.Entry
        | FlextLdifProtocols.Entry.EntryWithDnProtocol
        | dict[str, str | list[str]],
    ) -> FlextResult[str]:
        """Extract DN (Distinguished Name) from any entry type.

        Handles Entry models, LDAP entries, and dicts.

        Args:
            entry: Entry model, LDAP entry, or dict to extract DN from

        Returns:
            FlextResult containing DN as string

        Example:
            # Works with Entry models
            result = entries_service.get_entry_dn(entry_model)

            # Works with dicts
            result = entries_service.get_entry_dn({"dn": "cn=test,dc=example", "cn": ["test"]})

            # Works with LDAP entries
            result = entries_service.get_entry_dn(ldap_entry)

        """
        try:
            # Handle dict
            if FlextRuntime.is_dict_like(entry):
                dn_val = entry.get("dn")
                if not dn_val:
                    return FlextResult[str].fail("Dict entry missing 'dn' key")
                return FlextResult[str].ok(str(dn_val))

            # Handle models/protocols
            if not entry or not hasattr(entry, "dn"):
                return FlextResult[str].fail("Entry missing DN attribute")

            dn_value = entry.dn
            # Handle both DistinguishedName objects (with .value) and plain strings
            value_attr = getattr(dn_value, "value", None)
            if value_attr is not None:
                return FlextResult[str].ok(str(value_attr))
            return FlextResult[str].ok(str(dn_value))

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str].fail(f"Failed to extract DN: {e}")

    @staticmethod
    def _normalize_attribute_value(attr_values: list[str]) -> str | list[str]:
        """Normalize attribute values to str or list[str].

        Args:
            attr_values: List of attribute values

        Returns:
            Single string if length==1, otherwise list

        """
        if len(attr_values) == 1:
            return attr_values[0]
        return attr_values

    @staticmethod
    def _extract_from_ldif_attributes(
        attrs_container: FlextLdifModels.LdifAttributes,
    ) -> FlextLdifTypes.CommonDict.AttributeDict:
        """Extract attributes from LdifAttributes container.

        Args:
            attrs_container: LdifAttributes object

        Returns:
            AttributeDict with normalized values

        """
        result_dict: FlextLdifTypes.CommonDict.AttributeDict = {}

        for attr_name, attr_values in attrs_container.attributes.items():
            # attr_values is always a list[str] in LdifAttributes
            result_dict[attr_name] = FlextLdifEntries._normalize_attribute_value(
                attr_values,
            )

        return result_dict

    @staticmethod
    def _extract_from_dict_attributes(
        attrs_container: dict[str, str | list[str]],
    ) -> FlextLdifTypes.CommonDict.AttributeDict:
        """Extract attributes from dict representation.

        Args:
            attrs_container: Dict of attributes

        Returns:
            AttributeDict with normalized values

        """
        result_dict: FlextLdifTypes.CommonDict.AttributeDict = {}

        for attr_name, attr_val in attrs_container.items():
            if FlextRuntime.is_list_like(attr_val):
                # Return list as-is or single item if length==1
                result_dict[attr_name] = FlextLdifEntries._normalize_attribute_value(
                    [str(v) for v in attr_val],
                )
            else:
                # Single value - return as string
                result_dict[attr_name] = str(attr_val)

        return result_dict

    def get_entry_attributes(
        self,
        entry: FlextLdifModels.Entry | FlextLdifProtocols.Entry.EntryWithDnProtocol,
    ) -> FlextResult[FlextLdifTypes.CommonDict.AttributeDict]:
        """Extract attributes from any entry type.

        Handles FlextLdifModels.Entry (from LDIF files) and
        any object with 'dn' and 'attributes' attributes (EntryWithDnProtocol).

        Returns attributes as dict[str, str | list[str]] per
        FlextLdifTypes.CommonDict.AttributeDict.
        Attribute values are returned as provided (str or list).

        Args:
            entry: LDIF or LDAP entry to extract attributes from

        Returns:
            FlextResult containing AttributeDict with attribute names mapped to
            str | list[str] values matching FlextLdifTypes definition.

        Example:
            # Works with both LDIF and LDAP entries
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
                result_dict = FlextLdifEntries._extract_from_ldif_attributes(
                    attrs_container,
                )
            elif FlextRuntime.is_dict_like(attrs_container):
                # Normalize dict to expected type - convert values to str | list[str]
                normalized_dict: dict[str, str | list[str]] = {}
                for key, value in attrs_container.items():
                    if FlextRuntime.is_list_like(value):
                        # Type narrowing: value is list[object], convert to list[str]
                        normalized_dict[key] = [str(v) for v in value]
                    elif isinstance(value, str):
                        # Type narrowing: value is str
                        normalized_dict[key] = value
                    else:
                        # Convert to str
                        normalized_dict[key] = str(value)
                result_dict = FlextLdifEntries._extract_from_dict_attributes(
                    normalized_dict,
                )
            else:
                return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].fail(
                    f"Unknown attributes container type: {type(attrs_container)}",
                )

            return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].ok(result_dict)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].fail(
                f"Failed to extract attributes: {e}",
            )

    def create_entry(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create a new LDIF entry with validation.

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
            # Normalize attributes to ensure all values are lists
            normalized_attrs: FlextLdifTypes.CommonDict.AttributeDict = {}
            for key, value in attributes.items():
                if FlextRuntime.is_list_like(value):
                    # Type narrowing: value is list[object], convert to list[str]
                    normalized_attrs[key] = [str(v) for v in value]
                else:
                    normalized_attrs[key] = [str(value)]

            # Add objectClass if provided
            if objectclasses:
                normalized_attrs["objectClass"] = [str(v) for v in objectclasses]

            # Use FlextLdifModels.Entry.create() factory method
            create_result = FlextLdifModels.Entry.create(
                dn=dn,
                attributes=normalized_attrs,
            )

            if create_result.is_success:
                # Cast to ensure type compatibility between FlextLdifModelsDomains.Entry and FlextLdifModels.Entry
                return cast("FlextResult[FlextLdifModels.Entry]", create_result)
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create entry: {create_result.error}",
            )

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create entry: {e}",
            )

    def get_entry_objectclasses(
        self,
        entry: FlextLdifModels.Entry | FlextLdifProtocols.Entry.EntryWithDnProtocol,
    ) -> FlextResult[list[str]]:
        """Extract objectClass values from any entry type.

        Handles FlextLdifModels.Entry (from LDIF files) and
        any object with 'dn' and 'attributes' attributes (EntryWithDnProtocol).

        Args:
            entry: LDIF or LDAP entry to extract objectClasses from

        Returns:
            FlextResult containing list of objectClass values

        Example:
            # Works with both LDIF and LDAP entries
            result = entries_service.get_entry_objectclasses(entry)
            if result.is_success:
                object_classes = result.unwrap()
                if "inetOrgPerson" in object_classes:
                    print("Entry is a person")

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
            oc_values = attrs.get("objectClass") or attrs.get("objectclass")
            if oc_values:
                # Normalize to list (get_entry_attributes returns str | list[str])
                if isinstance(oc_values, str):
                    return FlextResult[list[str]].ok([oc_values])
                return FlextResult[list[str]].ok(oc_values)

            return FlextResult[list[str]].fail("Entry missing objectClass attribute")

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[str]].fail(f"Failed to extract objectClasses: {e}")

    def get_attribute_values(
        self,
        attribute: (FlextLdifProtocols.AttributeValueProtocol | list[str] | str),
    ) -> FlextResult[list[str]]:
        """Extract values from an attribute value object using monadic pattern.

        Handles various attribute value formats from both LDIF and LDAP entries.
        Uses FlextResult and_then/map for composable error handling.

        Args:
            attribute: Attribute value object with .values property, list, or string.
                      Type annotation guarantees non-None.

        Returns:
            FlextResult containing list of attribute values as strings.

        Example:
            # Extract values using monadic composition
            result = entries_service.get_attribute_values(attr_value_obj)
            if result.is_success:
                values = result.unwrap()
                for value in values:
                    print(f"Value: {value}")

        """
        # Type annotation guarantees attribute is not None - no defensive check needed

        # Handle objects with .values property (protocol-based)
        if isinstance(attribute, FlextLdifProtocols.AttributeValueProtocol):
            values = attribute.values
            if FlextRuntime.is_list_like(values):
                return FlextResult[list[str]].ok([str(v) for v in values])
            return FlextResult[list[str]].ok([str(values)])

        # Handle lists directly
        if FlextRuntime.is_list_like(attribute):
            # Type narrowing: attribute is list[object], convert to list[str]
            return FlextResult[list[str]].ok([str(v) for v in attribute])

        # Handle single string values
        if isinstance(attribute, str):
            return FlextResult[list[str]].ok([attribute])

        # Fast fail for unknown types
        return FlextResult[list[str]].fail(
            f"Unsupported attribute type: {type(attribute).__name__}. "
            "Expected AttributeValueProtocol, list[str], or str.",
        )


__all__ = ["FlextLdifEntries"]
