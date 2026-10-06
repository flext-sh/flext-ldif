"""LDIF entry OID/RFC transformation utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, p, t


class FlextLdifEntryOidRfcTransforming:
    """Transform entry attributes and schema DNs between OID and RFC forms."""

    @staticmethod
    def remap_oid_rfc_attributes(
        attributes: t.MutableStrSequenceMapping,
        *,
        attribute_mapping: t.StrMapping,
        boolean_value_mapping: t.StrMapping,
    ) -> t.MutableStrSequenceMapping:
        """Remap attribute names and boolean values for OID/RFC compatibility.

        Returns:
            The resulting ``t.MutableStrSequenceMapping``.
        """
        remapped: t.MutableStrSequenceMapping = {}
        for attr_name, values in attributes.items():
            normalized_name = attr_name.lower()
            normalized_values: t.MutableSequenceOf[str] = list(values)
            converted_values = (
                [boolean_value_mapping.get(value, value) for value in normalized_values]
                if normalized_name in c.Ldif.OID_BOOLEAN_ATTRIBUTES
                else normalized_values
            )
            mapped_name = attribute_mapping.get(normalized_name, normalized_name)
            remapped[mapped_name] = converted_values
        return remapped

    @staticmethod
    def transform_entry_attributes_between_oid_rfc(
        entry: p.Ldif.Entry,
        source_type_norm: str,
        target_type_norm: str,
    ) -> t.MutableStrSequenceMapping | None:
        """Compute transformed attribute map between OID and RFC formats.

        Returns:
            The resulting ``t.MutableStrSequenceMapping | None``.
        """
        attributes_model = entry.attributes
        if attributes_model is None or not attributes_model.attributes:
            return None
        current_attrs = dict(attributes_model.attributes)
        transformed_attrs: t.MutableStrSequenceMapping | None = None
        if source_type_norm == "oid" and target_type_norm == "rfc":
            transformed_attrs = FlextLdifEntryOidRfcTransforming.remap_oid_rfc_attributes(
                current_attrs,
                attribute_mapping=c.Ldif.ATTRIBUTE_TRANSFORMATION_OID_TO_RFC,
                boolean_value_mapping=c.Ldif.OID_TO_RFC_BOOL,
            )
        elif source_type_norm == "rfc" and target_type_norm == "oid":
            transformed_attrs = FlextLdifEntryOidRfcTransforming.remap_oid_rfc_attributes(
                current_attrs,
                attribute_mapping=c.Ldif.ATTRIBUTE_TRANSFORMATION_RFC_TO_OID,
                boolean_value_mapping=c.Ldif.RFC_TO_OID_BOOL,
            )
        return transformed_attrs

    @staticmethod
    def transform_schema_dn_between_oid_rfc(
        entry: p.Ldif.Entry,
        source_type_norm: str,
        target_type_norm: str,
    ) -> str | None:
        """Compute transformed schema DN between OID and RFC conventions.

        Returns:
            The resulting ``str | None``.
        """
        dn_model = entry.dn
        if dn_model is None:
            return None
        dn_value: str = dn_model.value
        is_oid_to_rfc = (
            source_type_norm == c.Ldif.ServerTypes.OID
            and target_type_norm == c.Ldif.ServerTypes.RFC
        )
        is_rfc_to_oid = (
            source_type_norm == c.Ldif.ServerTypes.RFC
            and target_type_norm == c.Ldif.ServerTypes.OID
        )
        if is_oid_to_rfc:
            source_dn, target_dn = c.Ldif.OID_SCHEMA_DN, c.Ldif.RFC_SCHEMA_DN
        elif is_rfc_to_oid:
            source_dn, target_dn = c.Ldif.RFC_SCHEMA_DN, c.Ldif.OID_SCHEMA_DN
        else:
            return None
        if source_dn not in dn_value.lower():
            return None
        return dn_value.replace(source_dn, target_dn)


__all__: list[str] = ["FlextLdifEntryOidRfcTransforming"]
