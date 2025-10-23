"""FLEXT LDIF Entry Builder.

This module provides generic entry templates and builders for creating
LDIF entries with validation and format conversion capabilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import json
from typing import override

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.schema import FlextLdifObjectClassManager
from flext_ldif.typings import FlextLdifTypes


class FlextLdifEntryBuilder(FlextService[FlextLdifModels.Entry]):
    """Entry builder service for creating LDIF entries."""

    @override
    def __init__(self) -> None:
        """Initialize entry builder."""
        super().__init__()
        self._objectclass_manager = FlextLdifObjectClassManager()

    def _normalize_attributes(
        self, attributes: dict[str, str | list[str]]
    ) -> dict[str, list[str]]:
        """Normalize attributes dict to ensure all values are lists.

        Args:
            attributes: Attributes dict with potentially str or list[str] values

        Returns:
            Normalized dict[str, list[str]] where all values are lists

        """
        normalized: dict[str, list[str]] = {}
        for key, value in attributes.items():
            if isinstance(value, str):
                normalized[key] = [value]
            else:
                normalized[key] = value
        return normalized

    @override
    def execute(self) -> FlextResult[FlextLdifModels.Entry]:
        """Execute entry builder service."""
        return FlextResult[FlextLdifModels.Entry].fail(
            "Use specific build methods (build_person_entry, etc.)"
        )

    def build_person_entry(
        self,
        cn: str,
        sn: str,
        base_dn: str,
        uid: str | None = None,
        mail: str | None = None,
        given_name: str | None = None,
        additional_attrs: dict[str, str | list[str]] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Build a person entry with standard attributes."""
        dn = f"cn={cn},{base_dn}"

        # Build basic attributes using FlextLdifConstants
        attributes: dict[str, str | list[str]] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: [
                "inetOrgPerson",
                FlextLdifConstants.DictKeys.PERSON,
            ],
            FlextLdifConstants.DictKeys.CN: [cn],
            FlextLdifConstants.DictKeys.SN: [sn],
        }

        # Add optional attributes
        if uid:
            attributes[FlextLdifConstants.DictKeys.UID] = [uid]
        if mail:
            attributes[FlextLdifConstants.DictKeys.MAIL] = [mail]
        if given_name:
            attributes["givenName"] = [given_name]
        if additional_attrs:
            attributes.update(additional_attrs)

        # Create entry
        return FlextLdifModels.Entry.create(
            dn=dn,
            attributes=attributes,
        )

    def build_group_entry(
        self,
        cn: str,
        base_dn: str,
        members: list[str] | None = None,
        description: str | None = None,
        additional_attrs: dict[str, str | list[str]] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Build a group entry with standard attributes."""
        dn = f"cn={cn},{base_dn}"
        attributes: dict[str, str | list[str]] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: [
                FlextLdifConstants.DictKeys.TOP,
                FlextLdifConstants.DictKeys.GROUP_OF_NAMES,
            ],
            FlextLdifConstants.DictKeys.CN: [cn],
        }

        if members:
            attributes[FlextLdifConstants.DictKeys.MEMBER] = members
        else:
            attributes[FlextLdifConstants.DictKeys.MEMBER] = [dn]

        if description:
            attributes[FlextLdifConstants.DictKeys.DESCRIPTION] = [description]

        if additional_attrs:
            for key, values in additional_attrs.items():
                if key not in attributes:
                    attributes[key] = values

        # Create entry directly with typed variables (no cast needed)
        result: FlextResult[FlextLdifModels.Entry] = FlextLdifModels.Entry.create(
            dn=dn,
            attributes=attributes,
        )

        if result.is_success and self.logger:
            self.logger.info(f"Created group entry: {dn}")

        return result

    def build_organizational_unit_entry(
        self,
        ou: str,
        base_dn: str,
        description: str | None = None,
        additional_attrs: dict[str, str | list[str]] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Build an organizational unit entry with standard attributes."""
        dn = f"ou={ou},{base_dn}"
        attributes: dict[str, str | list[str]] = {
            FlextLdifConstants.DictKeys.OBJECTCLASS: [
                FlextLdifConstants.DictKeys.TOP,
                FlextLdifConstants.DictKeys.ORGANIZATIONAL_UNIT,
            ],
            FlextLdifConstants.DictKeys.OU: [ou],
        }

        if description:
            attributes[FlextLdifConstants.DictKeys.DESCRIPTION] = [description]

        if additional_attrs:
            for key, values in additional_attrs.items():
                if key not in attributes:
                    attributes[key] = values

        # Create entry directly with typed variables (no cast needed)
        result: FlextResult[FlextLdifModels.Entry] = FlextLdifModels.Entry.create(
            dn=dn,
            attributes=attributes,
        )

        if result.is_success and self.logger:
            self.logger.info(f"Created organizational unit entry: {dn}")

        return result

    def build_custom_entry(
        self,
        dn: str,
        objectclasses: list[str],
        attributes: dict[str, str | list[str]],
        *,
        validate: bool = True,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Build a custom entry with specified object classes and attributes."""
        entry_attrs = attributes.copy()
        entry_attrs[FlextLdifConstants.DictKeys.OBJECTCLASS] = objectclasses

        if validate and self.logger:
            self.logger.debug(
                f"Validation requested for objectClasses: {objectclasses}"
            )

        # Create entry directly with typed variables (no cast needed)
        result: FlextResult[FlextLdifModels.Entry] = FlextLdifModels.Entry.create(
            dn=dn,
            attributes=entry_attrs,
        )

        if result.is_success and self.logger:
            self.logger.info(f"Created custom entry: {dn}")

        return result

    def build_entries_from_json(
        self, json_data: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Build entries from JSON data."""
        try:
            data: object = json.loads(json_data)

            if not isinstance(data, list):
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    "JSON data must be a list of entry objects"
                )

            entries: list[FlextLdifModels.Entry] = []

            for item in data:
                if not isinstance(item, dict):
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        "Each item must be a dictionary"
                    )

                dn = item.get(FlextLdifConstants.DictKeys.DN)
                attributes: dict[str, object] = item.get(
                    FlextLdifConstants.DictKeys.ATTRIBUTES, {}
                )

                if not dn:
                    dn_field = FlextLdifConstants.DictKeys.DN
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Each entry must have a '{dn_field}' field"
                    )

                normalized_attrs: FlextLdifTypes.CommonDict.AttributeDict = {}
                for key, value in attributes.items():
                    # Normalize attribute names to lowercase (LDAP standard)
                    normalized_key = key.lower()
                    if isinstance(value, str):
                        normalized_attrs[normalized_key] = [value]
                    elif isinstance(value, list):
                        normalized_attrs[normalized_key] = [str(v) for v in value]
                    else:
                        normalized_attrs[normalized_key] = [str(value)]

                # Type narrow DN from dict.get()
                if not isinstance(dn, str):
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"DN must be a string, got {type(dn).__name__}"
                    )

                # Create entry directly with typed variables
                entry_result: FlextResult[FlextLdifModels.Entry] = (
                    FlextLdifModels.Entry.create(
                        dn=dn,
                        attributes=normalized_attrs,
                    )
                )

                if entry_result.is_failure:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Failed to create entry for DN '{dn}': {entry_result.error}"
                    )

                entries.append(entry_result.value)

            if self.logger:
                self.logger.info(f"Created {len(entries)} entries from JSON")
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        except json.JSONDecodeError as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Invalid JSON: {e}")
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Failed to build entries from JSON: {e}"
            )

    def build_entries_from_dict(
        self, data: list[dict[str, object]]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Build entries from dictionary data."""
        entries: list[FlextLdifModels.Entry] = []

        for item in data:
            dn = item.get(FlextLdifConstants.DictKeys.DN)
            attributes_raw = item.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
            attributes: dict[str, object] = (
                attributes_raw if isinstance(attributes_raw, dict) else {}
            )

            if not dn:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Each entry must have a '{FlextLdifConstants.DictKeys.DN}' field"
                )

            normalized_attrs: FlextLdifTypes.CommonDict.AttributeDict = {}
            if isinstance(attributes, dict):
                for key, value in attributes.items():
                    # Normalize attribute names to lowercase (LDAP standard)
                    normalized_key = key.lower()
                    if isinstance(value, str):
                        normalized_attrs[normalized_key] = [value]
                    elif isinstance(value, list):
                        normalized_attrs[normalized_key] = [str(v) for v in value]
                    else:
                        normalized_attrs[normalized_key] = [str(value)]

            # Type narrow DN from dict.get()
            if not isinstance(dn, str):
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"DN must be a string, got {type(dn).__name__}"
                )

            # Validate that entry has objectClass (required in LDAP RFC 4512)
            has_objectclass = any(
                key.lower() == "objectclass" for key in normalized_attrs
            )
            if not has_objectclass:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Entry '{dn}' must have objectClass attribute"
                )

            # Create entry with AttributeDict type
            entry_result: FlextResult[FlextLdifModels.Entry] = (
                FlextLdifModels.Entry.create(
                    dn=dn,
                    attributes=normalized_attrs,
                )
            )

            if entry_result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Failed to create entry for DN '{dn}': {entry_result.error}"
                )

            entries.append(entry_result.value)

        if self.logger:
            self.logger.info(f"Created {len(entries)} entries from dictionary")
        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def convert_entry_to_dict(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[dict[str, object]]:
        """Convert an entry to dictionary format."""
        attributes_dict: dict[str, list[str]] = {
            name: attr.values for name, attr in entry.attributes.attributes.items()
        }

        entry_dict: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: entry.dn.value,
            FlextLdifConstants.DictKeys.ATTRIBUTES: attributes_dict,
        }

        return FlextResult[dict[str, object]].ok(entry_dict)

    def convert_entries_to_json(
        self, entries: list[FlextLdifModels.Entry], indent: int = 2
    ) -> FlextResult[str]:
        """Convert entries to JSON format."""
        try:
            entries_data: list[dict[str, object]] = []

            for entry in entries:
                entry_dict_result: FlextResult[dict[str, object]] = (
                    self.convert_entry_to_dict(entry)
                )
                if entry_dict_result.is_failure:
                    return FlextResult[str].fail(
                        f"Failed to convert entry: {entry_dict_result.error}"
                    )
                entries_data.append(entry_dict_result.value)

            json_str = json.dumps(entries_data, indent=indent)
            if self.logger:
                self.logger.info(f"Converted {len(entries)} entries to JSON")
            return FlextResult[str].ok(json_str)

        except Exception as e:
            return FlextResult[str].fail(f"Failed to convert entries to JSON: {e}")


__all__ = ["FlextLdifEntryBuilder"]
