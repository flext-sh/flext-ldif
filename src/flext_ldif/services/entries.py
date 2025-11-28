"""Entries Service - Direct Entry Operations with flext-core APIs.

This service provides direct entry operations using flext-core and flext-ldif APIs:
- Direct use of FlextLdifModels.Entry for entry operations
- Direct use of FlextLdifUtilities for DN and attribute operations
- No unnecessary validation wrappers or conversions
- Railway-oriented error handling with FlextResult

Single Responsibility: Provide entry operations using direct APIs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifEntries(FlextLdifServiceBase[list[FlextLdifModels.Entry]]):
    """Direct entry operations service using flext-core APIs.

    This service provides minimal, direct entry operations by delegating
    to FlextLdifModels.Entry and FlextLdifUtilities for all logic.
    No unnecessary abstraction layers or validation wrappers.
    """

    def get_entry_dn(
        self,
        entry: FlextLdifModels.Entry | dict[str, str | list[str]],
    ) -> FlextResult[str]:
        """Extract DN from entry.

        Args:
            entry: Entry model or dict to extract DN from

        Returns:
            FlextResult containing DN as string

        """
        if isinstance(entry, dict):
            dn_val = entry.get("dn")
            if not dn_val:
                return FlextResult.fail("Dict entry missing 'dn' key")
            return FlextResult.ok(str(dn_val))

        if not entry.dn:
            return FlextResult.fail("Entry missing DN attribute")

        # Use FlextLdifUtilities.DN directly
        dn_str = FlextLdifUtilities.DN.get_dn_value(entry.dn)
        return FlextResult.ok(dn_str)

    def get_entry_attributes(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[dict[str, list[str]]]:
        """Extract attributes from entry.

        Args:
            entry: Entry to extract attributes from

        Returns:
            FlextResult containing attribute dictionary

        """
        if not entry.attributes or not entry.attributes.attributes:
            return FlextResult.ok({})

        # Return attributes directly from entry
        return FlextResult.ok(dict(entry.attributes.attributes))

    def get_entry_objectclasses(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[list[str]]:
        """Extract objectClass values from entry.

        Args:
            entry: Entry to extract objectClasses from

        Returns:
            FlextResult containing list of objectClass values

        """
        if not entry.attributes or not entry.attributes.attributes:
            return FlextResult.ok([])

        objectclasses = entry.attributes.attributes.get("objectClass", [])
        if isinstance(objectclasses, str):
            return FlextResult.ok([objectclasses])
        return FlextResult.ok(list(objectclasses))

    def create_entry(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create a new entry.

        Args:
            dn: Distinguished Name for the entry
            attributes: Attribute dictionary
            objectclasses: Optional objectClass values

        Returns:
            FlextResult containing new Entry

        """
        # Validate DN using FlextLdifUtilities.DN
        if not FlextLdifUtilities.DN.validate(dn):
            return FlextResult.fail(f"Invalid DN: {dn}")

        # Prepare attributes
        final_attrs = dict(attributes)
        if objectclasses:
            final_attrs["objectClass"] = objectclasses

        # Use FlextLdifModels.Entry.create directly
        return FlextLdifModels.Entry.create(dn=dn, attributes=final_attrs)

    def remove_attributes(
        self,
        entry: FlextLdifModels.Entry,
        attributes_to_remove: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove attributes from entry.

        Args:
            entry: Entry to modify
            attributes_to_remove: List of attribute names to remove

        Returns:
            FlextResult containing modified entry

        """
        if not entry.attributes or not entry.attributes.attributes:
            return FlextResult.ok(entry)

        # Create new attributes dict without the specified attributes
        new_attrs = {
            k: v for k, v in entry.attributes.attributes.items()
            if k not in attributes_to_remove
        }

        # Create new entry with modified attributes
        modified_entry = FlextLdifModels.Entry(
            dn=entry.dn,
            attributes=FlextLdifModels.LdifAttributes(attributes=new_attrs),
            metadata=entry.metadata,
        )

        return FlextResult.ok(modified_entry)

    def get_attribute_values(
        self,
        attribute: list[str] | str,
    ) -> FlextResult[list[str]]:
        """Extract values from attribute.

        Args:
            attribute: Attribute value(s) to extract

        Returns:
            FlextResult containing list of string values

        """
        if isinstance(attribute, str):
            return FlextResult.ok([attribute])
        return FlextResult.ok(list(attribute))


__all__ = ["FlextLdifEntries"]
