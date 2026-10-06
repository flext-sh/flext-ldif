"""Oracle Internet Directory (OID) entry server — boolean value conversion helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidEntryBooleanMixin(FlextLdifServersRfc.Entry):
    """OID entry boolean value conversion helpers."""

    @staticmethod
    def _convert_boolean_attributes_to_rfc(
        entry_attributes: t.MutableStrSequenceMapping,
    ) -> tuple[
        t.MutableStrSequenceMapping,
        set[str],
        MutableMapping[str, t.MutableAttributeMapping],
    ]:
        """Convert OID boolean attribute values to RFC format.

        Returns:
            The resulting ``tuple[t.MutableStrSequenceMapping, set[str],
                MutableMapping[str, t.MutableAttributeMapping]]``.
        """
        oid_constants = FlextLdifServersOidConstants
        boolean_attributes = oid_constants.BOOLEAN_ATTRIBUTES
        boolean_attr_names = {attr.lower() for attr in boolean_attributes}
        converted_attrs_for_util: t.MutableStrSequenceMapping = dict(
            entry_attributes.items(),
        )
        source_format = f"{oid_constants.ZERO_OID}/{oid_constants.ONE_OID}"
        target_format = "TRUE/FALSE"
        converted_attributes = u.Ldif.convert_boolean_attributes(
            converted_attrs_for_util,
            boolean_attr_names,
            source_format=source_format,
            target_format=target_format,
        )
        converted_attrs: set[str] = set()
        boolean_conversions: MutableMapping[str, t.MutableAttributeMapping] = {}
        for attr_name, attr_values in entry_attributes.items():
            if attr_name.lower() in boolean_attr_names:
                original_values: t.MutableSequenceOf[str] = list(attr_values)
                converted_values: t.MutableSequenceOf[str] = converted_attributes.get(
                    attr_name,
                    original_values,
                )
                if converted_values != original_values:
                    converted_attrs.add(attr_name)
                    original_format_str = (
                        f"{oid_constants.ONE_OID}/{oid_constants.ZERO_OID}"
                    )
                    converted_format_str = f"{c.Ldif.TRUE_RFC}/{c.Ldif.FALSE_RFC}"
                    conversion_dict: MutableMapping[
                        str,
                        str | t.MutableSequenceOf[str],
                    ] = {}
                    original_key: str = c.Ldif.CONVERSION_ORIGINAL_VALUE
                    converted_key: str = c.Ldif.CONVERSION_CONVERTED_VALUE
                    format_key: str = c.Ldif.ORIGINAL_FORMAT
                    conversion_dict[original_key] = original_values
                    conversion_dict[converted_key] = converted_values
                    conversion_dict["conversion_type"] = "boolean_oid_to_rfc"
                    conversion_dict[format_key] = original_format_str
                    conversion_dict["converted_format"] = converted_format_str
                    boolean_conversions[attr_name] = conversion_dict
                    FlextLdifServersOidEntry._module_logger.debug(
                        "Converted boolean attribute OID→RFC",
                        attribute_name=attr_name,
                    )
        return (converted_attributes, converted_attrs, boolean_conversions)
    def _convert_boolean_values_to_oid(
        self,
        attr_name: str,
        current_values: t.MutableSequenceOf[str],
        restored_attrs: t.MutableStrSequenceMapping,
    ) -> None:
        """Convert RFC boolean values to OID format for an attribute."""
        new_values: t.MutableSequenceOf[str] = []
        changed = False
        for val in current_values:
            converted, was_converted = self._convert_rfc_boolean_to_oid(val)
            new_values.append(converted)
            if was_converted:
                changed = True
        if changed:
            restored_attrs[attr_name] = new_values
    def _convert_rfc_boolean_to_oid(self, value: str) -> tuple[str, bool]:
        """Convert single RFC boolean value to OID format.

        Returns:
            The resulting ``tuple[str, bool]``.
        """
        if value == "TRUE":
            return (FlextLdifServersOidConstants.ONE_OID, True)
        if value == "FALSE":
            return (FlextLdifServersOidConstants.ZERO_OID, True)
        return (value, False)
    @staticmethod
    def _restore_boolean_attribute_from_metadata(
        attr_name: str,
        conv_data: t.MutableAttributeMapping,
        restored_attrs: t.MutableStrSequenceMapping,
    ) -> bool:
        """Restore single boolean attribute from conversion metadata.

        Returns:
            The resulting ``bool``.
        """
        mk = c.Ldif
        converted_val = conv_data.get(mk.CONVERSION_CONVERTED_VALUE)
        match converted_val:
            case str() as s:
                converted_val_list: t.StrSequence = [s]
            case list() as items:
                converted_val_list = list(items)
            case _:
                return False
        rfc_value = converted_val_list[0]
        oid_value = FlextLdifServersOidConstants.RFC_TO_OID.get(rfc_value, rfc_value)
        restored_attrs[attr_name] = [oid_value]
        FlextLdifServersOidEntry._module_logger.debug(
            "Restored OID boolean format from metadata",
            attribute_name=attr_name,
            rfc_value=rfc_value,
            oid_value=oid_value,
            operation="_restore_boolean_values_to_oid",
        )
        return True
    def _restore_boolean_values_to_oid(self, entry_data: m.Ldif.Entry) -> m.Ldif.Entry:
        """Restore OID boolean format from RFC format (RFC → OID: TRUE/FALSE → 0/1).

        Returns:
            The resulting ``m.Ldif.Entry``.
        """
        if not entry_data.attributes:
            return entry_data
        boolean_conversions = self._parse_metadata_boolean_flags(entry_data)
        boolean_attr_names = {
            attr.lower() for attr in FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES
        }
        restored_attrs = dict(entry_data.attributes.attributes)
        for attr_name in list(restored_attrs.keys()):
            if attr_name.lower() not in boolean_attr_names:
                continue
            conv_data = boolean_conversions.get(attr_name, {})
            if conv_data:
                self._restore_boolean_attribute_from_metadata(
                    attr_name,
                    conv_data,
                    restored_attrs,
                )
                continue
            self._convert_boolean_values_to_oid(
                attr_name,
                restored_attrs[attr_name],
                restored_attrs,
            )
        if restored_attrs == entry_data.attributes.attributes:
            return entry_data
        entry_metadata: t.MutableJsonMapping | None = None
        if entry_data.attributes and entry_data.attributes.metadata:
            entry_metadata = entry_data.attributes.metadata
        copied: m.Ldif.Entry = entry_data.model_copy(
            update={
                "attributes": m.Ldif.Attributes.model_validate({
                    "attributes": restored_attrs,
                    "attribute_metadata": entry_data.attributes.attribute_metadata
                    if entry_data.attributes
                    else {},
                    "metadata": entry_metadata,
                }),
            },
        )
        return copied


__all__: list[str] = ["FlextLdifServersOidEntryBooleanMixin"]
