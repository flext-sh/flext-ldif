"""Oracle Internet Directory (OID) Quirks."""

from __future__ import annotations

import struct
from collections.abc import Mapping, MutableMapping, MutableSequence
from functools import reduce
from typing import override

from flext_core import FlextLogger, r, u as core_u
from pydantic import RootModel

from flext_ldif import (
    FlextLdifModelsMetadata,
    FlextLdifModelsSettings,
    FlextLdifServersOidConstants,
    FlextLdifServersRfc,
    FlextLdifUtilitiesACL,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesEntry,
    FlextLdifUtilitiesMetadata,
    c,
    m,
    p,
    t,
    u,
)

logger = FlextLogger(__name__)


class _OidStringListJson(RootModel[MutableSequence[str]]):
    pass


class _OidObjectListJson(RootModel[t.MutableContainerList]):
    pass


class FlextLdifServersOidEntry(FlextLdifServersRfc.Entry):
    """Oracle Internet Directory (OID) Entry implementation."""

    def normalize_schema_strings_inline(self, entry: m.Ldif.Entry) -> m.Ldif.Entry:
        """Normalize schema attribute strings (attributetypes, objectclasses)."""
        if not entry.attributes:
            return entry
        schema_attrs = FlextLdifServersOidConstants.SCHEMA_FILTERABLE_FIELDS
        if not any(
            attr_name.lower() in schema_attrs
            for attr_name in entry.attributes.attributes
        ):
            return entry
        replacements = FlextLdifServersOidConstants.MATCHING_RULE_TO_RFC
        new_attributes: MutableMapping[str, MutableSequence[str]] = {
            attr_name: [
                reduce(
                    lambda val, pair: val.replace(pair[0], pair[1]),
                    replacements.items(),
                    value,
                )
                for value in attr_values
            ]
            if attr_name.lower() in schema_attrs
            else attr_values
            for attr_name, attr_values in entry.attributes.attributes.items()
        }
        if new_attributes == entry.attributes.attributes:
            return entry
        return entry.model_copy(
            update={
                "attributes": m.Ldif.Attributes.model_validate({
                    "attributes": new_attributes,
                }),
            },
        )

    def _convert_boolean_attributes_to_rfc(
        self,
        entry_attributes: MutableMapping[str, MutableSequence[str]],
    ) -> tuple[
        MutableMapping[str, MutableSequence[str]],
        set[str],
        MutableMapping[str, MutableMapping[str, str | MutableSequence[str]]],
    ]:
        """Convert OID boolean attribute values to RFC format."""
        boolean_attributes = FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES
        boolean_attr_names = {attr.lower() for attr in boolean_attributes}
        converted_attrs_for_util: MutableMapping[str, MutableSequence[str]] = dict(
            entry_attributes.items(),
        )
        source_format = f"{FlextLdifServersOidConstants.ZERO_OID}/{FlextLdifServersOidConstants.ONE_OID}"
        target_format = "TRUE/FALSE"
        converted_attributes = FlextLdifUtilitiesEntry.convert_boolean_attributes(
            converted_attrs_for_util,
            boolean_attr_names,
            source_format=source_format,
            target_format=target_format,
        )
        converted_attrs: set[str] = set()
        boolean_conversions: MutableMapping[
            str,
            MutableMapping[str, str | MutableSequence[str]],
        ] = {}
        for attr_name, attr_values in entry_attributes.items():
            if attr_name.lower() in boolean_attr_names:
                original_values: MutableSequence[str] = list(attr_values)
                converted_values: MutableSequence[str] = converted_attributes.get(
                    attr_name,
                    original_values,
                )
                if converted_values != original_values:
                    converted_attrs.add(attr_name)
                    original_format_str = f"{FlextLdifServersOidConstants.ONE_OID}/{FlextLdifServersOidConstants.ZERO_OID}"
                    converted_format_str = f"{c.Ldif.TRUE_RFC}/{c.Ldif.FALSE_RFC}"
                    conversion_dict: MutableMapping[
                        str,
                        str | MutableSequence[str],
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
                    logger.debug(
                        "Converted boolean attribute OID→RFC",
                        attribute_name=attr_name,
                    )
        return (converted_attributes, converted_attrs, boolean_conversions)

    def _convert_boolean_values_to_oid(
        self,
        attr_name: str,
        current_values: MutableSequence[str],
        restored_attrs: MutableMapping[str, MutableSequence[str]],
    ) -> None:
        """Convert RFC boolean values to OID format for an attribute."""
        new_values: MutableSequence[str] = []
        changed = False
        for val in current_values:
            converted, was_converted = self._convert_rfc_boolean_to_oid(str(val))
            new_values.append(converted)
            if was_converted:
                changed = True
        if changed:
            restored_attrs[attr_name] = new_values

    def _convert_line_acl_to_oid(self, original_line: str) -> str:
        """Convert RFC ACL attribute name (aci) to OID format (orclaci)."""
        if ":" not in original_line:
            return original_line
        parts = original_line.split(":", 1)
        attr_lower = parts[0].strip().lower()
        if attr_lower == "aci":
            logger.debug("Converting aci to orclaci", line=original_line)
            value_part = parts[1]
            return f"orclaci:{value_part}"
        return original_line

    def _convert_line_boolean_to_oid(self, original_line: str) -> str:
        """Convert RFC boolean values in line to OID format."""
        if ":" not in original_line:
            return original_line
        parts = original_line.split(":", 1)
        attr_lower = parts[0].strip().lower()
        if attr_lower not in FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES:
            return original_line
        value_part = parts[1].strip() if len(parts) > 1 else ""
        if value_part == "TRUE":
            return f"{parts[0]}: {FlextLdifServersOidConstants.ONE_OID}"
        if value_part == "FALSE":
            return f"{parts[0]}: {FlextLdifServersOidConstants.ZERO_OID}"
        return original_line

    def _convert_rfc_boolean_to_oid(self, value: str) -> tuple[str, bool]:
        """Convert single RFC boolean value to OID format."""
        if value == "TRUE":
            return (FlextLdifServersOidConstants.ONE_OID, True)
        if value == "FALSE":
            return (FlextLdifServersOidConstants.ZERO_OID, True)
        return (value, False)

    def _create_entry_result_with_metadata(
        self,
        _entry: m.Ldif.Entry,
        cleaned_dn: str,
        original_dn: str,
        _dn_stats: m.Ldif.DNStatistics,
        converted_attrs: set[str],
        boolean_conversions: MutableMapping[
            str,
            MutableMapping[str, str | MutableSequence[str]],
        ],
        acl_transformations: MutableMapping[str, m.Ldif.AttributeTransformation],
        rfc_violations: MutableSequence[str],
        attribute_conflicts: MutableSequence[
            MutableMapping[str, str | MutableSequence[str]]
        ],
        converted_attributes: MutableMapping[str, MutableSequence[str]],
        original_entry: m.Ldif.Entry,
    ) -> r[m.Ldif.Entry]:
        """Create entry result with complete metadata."""
        original_attrs: MutableMapping[str, MutableSequence[str]] = (
            original_entry.attributes.attributes if original_entry.attributes else {}
        )
        mk = c.Ldif
        conversion_metadata: t.MutableContainerMapping = (
            {mk.CONVERSION_CONVERTED_ATTRIBUTE_NAMES: list(converted_attrs)}
            if converted_attrs
            else {}
        )
        mk = c.Ldif
        dn_metadata: t.MutableContainerMapping = (
            {
                mk.ORIGINAL_DN_COMPLETE: original_dn,
                mk.ORIGINAL_DN_LINE_COMPLETE: cleaned_dn,
                mk.HAS_DIFFERENCES: True,
            }
            if original_dn != cleaned_dn
            else {}
        )
        rfc_violations_str: str = (
            _OidStringListJson(root=rfc_violations).model_dump_json()
            if rfc_violations
            else ""
        )
        attribute_conflicts_str: str = (
            _OidObjectListJson(
                root=[dict(conflict) for conflict in attribute_conflicts],
            ).model_dump_json()
            if attribute_conflicts
            else ""
        )
        boolean_conversions_str: str = (
            m.Ldif.DynamicMetadata.from_dict(
                dict(boolean_conversions),
            ).model_dump_json()
            if boolean_conversions
            else ""
        )
        converted_attributes_str: str = (
            m.Ldif.DynamicMetadata.from_dict(
                dict(converted_attributes),
            ).model_dump_json()
            if converted_attributes
            else ""
        )
        original_entry_str: str = (
            original_entry.model_dump_json() if original_entry else ""
        )
        rfc_compliance_metadata = (
            FlextLdifUtilitiesMetadata.build_rfc_compliance_metadata(
                "oid",
                rfc_violations=rfc_violations_str,
                attribute_conflicts=attribute_conflicts_str,
                boolean_conversions=boolean_conversions_str,
                converted_attributes=converted_attributes_str,
                original_entry=original_entry_str,
                entry_dn=cleaned_dn,
            )
        )
        original_attributes_str: str | None = (
            m.Ldif.DynamicMetadata.from_dict(original_attrs).model_dump_json()
            if original_attrs
            else None
        )
        processed_attributes_str: str | None = (
            m.Ldif.DynamicMetadata.from_dict(
                dict(converted_attributes),
            ).model_dump_json()
            if converted_attributes
            else None
        )
        metadata_keys_dict = {
            k: v
            for k, v in c.Ldif.__dict__.items()
            if not k.startswith("_") and core_u.is_type(v, str)
        }
        metadata_keys_str: str | None = (
            m.Ldif.DynamicMetadata.from_dict(metadata_keys_dict).model_dump_json()
            if metadata_keys_dict
            else None
        )
        operational_attributes_str: str | None = (
            _OidStringListJson(
                root=list(FlextLdifServersOidConstants.OPERATIONAL_ATTRIBUTES),
            ).model_dump_json()
            if FlextLdifServersOidConstants.OPERATIONAL_ATTRIBUTES
            else None
        )
        generic_metadata: t.MutableContainerMapping = dict(
            FlextLdifUtilitiesMetadata.build_entry_metadata_extensions("oid"),
        )
        generic_metadata["entry_dn"] = original_dn
        if original_attributes_str:
            generic_metadata["original_attributes"] = original_attributes_str
        if processed_attributes_str:
            generic_metadata["processed_attributes"] = processed_attributes_str
        generic_metadata["server_type"] = "oid"
        if metadata_keys_str:
            generic_metadata["metadata_keys"] = metadata_keys_str
        if operational_attributes_str:
            generic_metadata["operational_attributes"] = operational_attributes_str
        mk = c.Ldif
        attr_name_conversions: MutableMapping[str, str] = (
            {
                FlextLdifServersOidConstants.ORCLACI: FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME,
            }
            if FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME in converted_attributes
            and FlextLdifServersOidConstants.ORCLACI in original_attrs
            else {}
        )
        boolean_conversions_dict: MutableMapping[
            str,
            MutableMapping[str, str | MutableSequence[str]],
        ] = {
            attr_name: dict(conversion_data)
            for attr_name, conversion_data in boolean_conversions.items()
        }
        converted_attrs_data: MutableMapping[
            str,
            MutableMapping[str, MutableMapping[str, str | MutableSequence[str]]]
            | MutableMapping[str, str],
        ] = {
            c.Ldif.CONVERSION_BOOLEAN_CONVERSIONS: boolean_conversions_dict,
            c.Ldif.CONVERSION_ATTRIBUTE_NAME_CONVERSIONS: attr_name_conversions,
        }
        converted_attrs_data_str: str = m.Ldif.DynamicMetadata.from_dict(
            converted_attrs_data,
        ).model_dump_json()
        generic_metadata[mk.CONVERTED_ATTRIBUTES] = converted_attrs_data_str
        generic_metadata[c.Ldif.ENTRY_TARGET_DN_CASE] = cleaned_dn
        generic_metadata[c.Ldif.ENTRY_ORIGINAL_FORMAT] = (
            f"OID Entry with {len(converted_attrs)} boolean conversions"
        )
        original_extensions = self._extract_original_extensions(original_entry)
        extensions_data: t.MutableContainerMapping = {
            **conversion_metadata,
            **dn_metadata,
            **generic_metadata,
        }
        for key, val in rfc_compliance_metadata.items():
            if isinstance(val, list):
                extensions_data[key] = [str(item) for item in val]
            elif isinstance(val, Mapping):
                nested_dict: MutableMapping[
                    str,
                    t.Scalar | MutableSequence[t.Scalar],
                ] = {}
                for nk, nv in val.items():
                    if isinstance(nv, list):
                        nested_dict[nk] = [str(item) for item in nv]
                    else:
                        nested_dict[nk] = str(nv)
                widened_dict: t.NormalizedValue = nested_dict
                extensions_data[key] = widened_dict
            else:
                extensions_data[key] = val
        for ext_key, ext_val in original_extensions.items():
            if isinstance(ext_val, list):
                extensions_data[ext_key] = [str(item) for item in ext_val]
            else:
                extensions_data[ext_key] = ext_val
        extensions_data[c.Ldif.ORIGINAL_DN_COMPLETE] = str(
            original_entry.dn,
        )
        metadata = m.Ldif.QuirkMetadata.create_for(
            self._get_server_type(),
            extensions=m.Ldif.DynamicMetadata.from_dict(extensions_data),
        )
        original_strings_data: MutableMapping[str, str] = {}
        if original_entry.metadata:
            original_strings_data.update({
                key: value
                for key, value in original_entry.metadata.original_strings.items()
                if isinstance(value, str)
            })
        for attr_name, conv_data in boolean_conversions.items():
            original_vals_raw = conv_data.get(mk.CONVERSION_ORIGINAL_VALUE)
            converted_vals_raw = conv_data.get(mk.CONVERSION_CONVERTED_VALUE)
            original_vals: MutableSequence[str] = (
                [original_vals_raw]
                if isinstance(original_vals_raw, str)
                else [str(item) for item in original_vals_raw]
                if isinstance(original_vals_raw, list)
                else []
            )
            converted_vals: MutableSequence[str] = (
                [converted_vals_raw]
                if isinstance(converted_vals_raw, str)
                else [str(item) for item in converted_vals_raw]
                if isinstance(converted_vals_raw, list)
                else []
            )
            if original_vals and converted_vals:
                FlextLdifUtilitiesMetadata.track_boolean_conversion(
                    metadata=metadata,
                    attr_name=attr_name,
                    original_value=original_vals[0]
                    if len(original_vals) == 1
                    else str(original_vals),
                    converted_value=converted_vals[0]
                    if len(converted_vals) == 1
                    else str(converted_vals),
                    format_direction="OID->RFC",
                )
        orig_dn_line: str | None = None
        orig_attr_lines: MutableSequence[str] = []
        if original_entry.metadata and original_entry.metadata.original_format_details:
            format_details = original_entry.metadata.original_format_details
            raw_dn_line = getattr(format_details, "original_dn_line", None)
            orig_dn_line = str(raw_dn_line) if raw_dn_line is not None else None
            raw_lines = getattr(format_details, "original_attr_lines", [])
            orig_attr_lines = [str(line) for line in raw_lines]
        if "entry_original_ldif" not in original_strings_data:
            if orig_dn_line or orig_attr_lines:
                original_parts: MutableSequence[str] = []
                if orig_dn_line:
                    original_parts.append(orig_dn_line)
                if orig_attr_lines:
                    original_parts.extend(orig_attr_lines)
                original_strings_data["entry_original_ldif"] = "\n".join(original_parts)
            else:
                fallback_parts: MutableSequence[str] = [f"dn: {original_dn}"]
                for attr_name, attr_values in original_attrs.items():
                    fallback_parts.extend(
                        f"{attr_name}: {attr_value}" for attr_value in attr_values
                    )
                original_strings_data["entry_original_ldif"] = "\n".join(fallback_parts)
        if "dn_original" not in original_strings_data:
            original_strings_data["dn_original"] = original_dn
        if original_strings_data:
            metadata.original_strings = m.Ldif.DynamicMetadata.from_dict(
                original_strings_data,
            )
        converted_attrs_format_str: str = (
            _OidStringListJson(root=list(converted_attrs)).model_dump_json()
            if converted_attrs
            else ""
        )
        boolean_conversions_format_str: str = (
            m.Ldif.DynamicMetadata.from_dict(
                dict(boolean_conversions),
            ).model_dump_json()
            if boolean_conversions
            else ""
        )
        converted_attributes_format_str: str = (
            m.Ldif.DynamicMetadata.from_dict(
                dict(converted_attributes),
            ).model_dump_json()
            if converted_attributes
            else ""
        )
        original_attributes_format_str: str = (
            m.Ldif.DynamicMetadata.from_dict(original_attrs).model_dump_json()
            if original_attrs
            else ""
        )
        original_attr_lines_str: str = (
            _OidStringListJson(root=orig_attr_lines).model_dump_json()
            if orig_attr_lines
            else ""
        )
        metadata.original_format_details = (
            FlextLdifUtilitiesMetadata.build_original_format_details(
                "oid",
                original_dn=original_dn,
                cleaned_dn=cleaned_dn,
                converted_attrs=converted_attrs_format_str,
                boolean_conversions=boolean_conversions_format_str,
                converted_attributes=converted_attributes_format_str,
                original_attributes=original_attributes_format_str,
                server_type="oid",
                original_dn_line=orig_dn_line or "",
                original_attr_lines=original_attr_lines_str,
            )
        )
        if (
            original_dn != cleaned_dn
            and original_dn.lower()
            == FlextLdifServersOidConstants.SCHEMA_DN_QUIRK.lower()
        ):
            schema_transformations_raw = metadata.extensions.get(
                "schema_transformations",
            )
            schema_transformations = (
                [str(item) for item in schema_transformations_raw]
                if isinstance(schema_transformations_raw, list)
                else []
            )
            schema_transformations.append("schema_dn_normalization")
            schema_transformations_typed: MutableSequence[t.Ldif.MetadataValue] = [
                str(item) for item in schema_transformations
            ]
            metadata.extensions.schema_transformations = schema_transformations_typed
        if acl_transformations:
            metadata.attribute_transformations = {
                **metadata.attribute_transformations,
                **acl_transformations,
            }
        ldif_attrs = m.Ldif.Attributes.model_validate({
            "attributes": {**converted_attributes},
        })
        return r[m.Ldif.Entry].ok(
            m.Ldif.Entry(
                dn=m.Ldif.DN(value=cleaned_dn),
                attributes=ldif_attrs,
                metadata=metadata,
            ),
        )

    def _denormalize_oid_attributes_for_output(
        self,
        attrs: MutableMapping[str, MutableSequence[str]],
        metadata: m.Ldif.QuirkMetadata | None,
    ) -> MutableMapping[str, MutableSequence[str]]:
        """Denormalize RFC attributes to OID format."""
        mk = c.Ldif
        original_attrs_raw = (
            metadata.extensions.get(mk.ORIGINAL_ATTRIBUTES_COMPLETE)
            if metadata and metadata.extensions
            else None
        )
        original_attrs: MutableMapping[str, MutableSequence[str]] | None = None
        if isinstance(original_attrs_raw, Mapping):
            result_attrs: MutableMapping[str, MutableSequence[str]] = {}
            for k, v in original_attrs_raw.items():
                if isinstance(v, list):
                    result_attrs[k] = [str(item) for item in v]
                else:
                    result_attrs[k] = [str(v)]
            original_attrs = result_attrs
        denormalized: MutableMapping[str, MutableSequence[str]] = {}
        for attr_name, attr_values in attrs.items():
            restored_name, restored_values = self._restore_single_attribute(
                attr_name,
                attr_values,
                original_attrs,
            )
            denormalized[restored_name] = restored_values
        return denormalized

    def _detect_entry_acl_transformations(
        self,
        entry_attrs: MutableMapping[str, MutableSequence[str]],
        converted_attributes: MutableMapping[str, MutableSequence[str]],
    ) -> MutableMapping[str, m.Ldif.AttributeTransformation]:
        """Detect ACL attribute transformations (orclaci→aci)."""
        original_attr_names: MutableMapping[str, str] = {
            normalized.lower(): str(raw_attr_name)
            for raw_attr_name in entry_attrs
            if (
                normalized := self._normalize_attribute_name(str(raw_attr_name))
            ).lower()
            != str(raw_attr_name).lower()
        }
        acl_transformations: MutableMapping[str, m.Ldif.AttributeTransformation] = {
            original_name: m.Ldif.AttributeTransformation(
                original_name=original_name,
                target_name=attr_name,
                original_values=attr_values,
                target_values=attr_values,
                transformation_type="renamed",
                reason=f"OID ACL ({original_name}) → RFC 2256 (aci)",
            )
            for attr_name, attr_values in converted_attributes.items()
            if attr_name.lower() in original_attr_names
            and (original_name := original_attr_names[attr_name.lower()]).lower()
            in {"orclaci", "orclentrylevelaci"}
        }
        return acl_transformations

    def _detect_rfc_violations(
        self,
        converted_attributes: MutableMapping[str, MutableSequence[str]],
    ) -> tuple[
        MutableSequence[str],
        MutableSequence[MutableMapping[str, str | MutableSequence[str]]],
    ]:
        """Detect RFC compliance violations in entry."""
        object_classes_raw = converted_attributes.get("objectClass", [])
        object_classes: MutableSequence[str] = [str(oc) for oc in object_classes_raw]
        object_classes_lower = {oc.lower() for oc in object_classes}
        structural_classes = {
            "domain",
            "organization",
            "organizationalunit",
            "person",
            "groupofuniquenames",
            "groupofnames",
            "orclsubscriber",
            "orclgroup",
            "customsistemas",
            "customuser",
        }
        found_structural = object_classes_lower & structural_classes
        structural_str = ", ".join(sorted(found_structural))
        rfc_violations: MutableSequence[str] = (
            [f"Multiple structural objectClasses: {structural_str}"]
            if len(found_structural) > 1
            else []
        )
        domain_invalid_attrs = {
            "cn",
            "uniquemember",
            "member",
            "orclsubscriberfullname",
            "orclversion",
            "orclgroupcreatedate",
        }
        attribute_conflicts: MutableSequence[
            MutableMapping[str, str | MutableSequence[str]]
        ] = [
            {
                "attribute": attr_name,
                "values": converted_attributes[attr_name],
                "reason": f"'{attr_name}' not allowed by RFC 4519 domain",
                "conflicting_objectclass": "domain",
            }
            for attr_name in converted_attributes
            if "domain" in object_classes_lower
            and attr_name.lower() in domain_invalid_attrs
        ]
        return (rfc_violations, attribute_conflicts)

    def _extract_acl_metadata_from_string(
        self,
        acl_value: str,
        current_extensions: t.MutableContainerMapping,
    ) -> None:
        """Extract OID-specific ACL metadata from ACL string."""
        bindmode = FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_BINDMODE_PATTERN,
            group=1,
        )
        if bindmode:
            current_extensions[c.Ldif.ACL_BINDMODE] = bindmode
        if FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_DENY_GROUP_OVERRIDE_PATTERN,
        ):
            current_extensions[c.Ldif.ACL_DENY_GROUP_OVERRIDE] = True
        if FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_APPEND_TO_ALL_PATTERN,
        ):
            current_extensions[c.Ldif.ACL_APPEND_TO_ALL] = True
        bind_ip_filter = FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_BIND_IP_FILTER_PATTERN,
            group=1,
        )
        if bind_ip_filter:
            current_extensions[c.Ldif.ACL_BIND_IP_FILTER] = bind_ip_filter
        constrain_to_added = FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_CONSTRAIN_TO_ADDED_PATTERN,
            group=1,
        )
        if constrain_to_added:
            current_extensions[c.Ldif.ACL_CONSTRAIN_TO_ADDED_OBJECT] = (
                constrain_to_added
            )

    def _extract_boolean_conversions_from_metadata(
        self,
        entry_data: m.Ldif.Entry,
    ) -> MutableMapping[str, MutableMapping[str, str | MutableSequence[str]]]:
        """Extract boolean conversions from entry metadata."""
        mk = c.Ldif
        boolean_conversions: MutableMapping[
            str,
            MutableMapping[str, str | MutableSequence[str]],
        ] = {}
        if not (entry_data.metadata and entry_data.metadata.extensions):
            return boolean_conversions
        converted_attrs_data = (
            entry_data.metadata.extensions.get(mk.CONVERTED_ATTRIBUTES)
            if entry_data.metadata and entry_data.metadata.extensions
            else None
        )
        if isinstance(converted_attrs_data, Mapping):
            boolean_conversions_obj: t.NormalizedValue = converted_attrs_data.get(
                mk.CONVERSION_BOOLEAN_CONVERSIONS,
                {},
            )
            if isinstance(boolean_conversions_obj, Mapping):
                for key, value in boolean_conversions_obj.items():
                    if isinstance(value, Mapping):
                        value_metadata = m.Ldif.DynamicMetadata.model_validate(value)
                        typed_dict: MutableMapping[str, str | MutableSequence[str]] = {}
                        for key_str, raw_value in value_metadata.items():
                            if isinstance(raw_value, str):
                                typed_dict[key_str] = raw_value
                            elif isinstance(raw_value, list):
                                typed_items: MutableSequence[str] = [
                                    str(item)
                                    for item in raw_value
                                    if u.is_primitive(item)
                                ]
                                typed_dict[key_str] = typed_items
                        boolean_conversions[key] = typed_dict
        return boolean_conversions

    def _extract_original_extensions(
        self,
        original_entry: m.Ldif.Entry,
    ) -> MutableMapping[str, t.Scalar | MutableSequence[str]]:
        """Extract compatible extensions from original entry metadata."""
        original_extensions: MutableMapping[str, t.Scalar | MutableSequence[str]] = {}
        if not (original_entry.metadata and original_entry.metadata.extensions):
            return original_extensions
        ext = original_entry.metadata.extensions
        for k, v in ext.items():
            if isinstance(v, (str, int, bool)):
                original_extensions[k] = v
            elif isinstance(v, list) and (
                all(isinstance(item, str) for item in v)
                or all(u.is_primitive(item) for item in v)
            ):
                original_extensions[k] = [str(item) for item in v]
        return original_extensions

    def _get_current_attrs_with_acl_equivalence(
        self,
        entry_data: m.Ldif.Entry,
    ) -> set[str]:
        """Get current attribute names with OID ACL equivalence."""
        current_attrs: set[str] = set()
        if entry_data.attributes and entry_data.attributes.attributes:
            current_attrs = {
                attr_name.lower() for attr_name in entry_data.attributes.attributes
            }
            if "aci" in current_attrs:
                current_attrs.add("orclaci")
            if "orclaci" in current_attrs:
                current_attrs.add("aci")
        return current_attrs

    def _hook_finalize_entry_parse(
        self,
        entry: m.Ldif.Entry,
        original_dn: str,
        original_attrs: MutableMapping[str, MutableSequence[str]],
    ) -> r[m.Ldif.Entry]:
        """Finalize OID entry with ACL and RFC violation metadata."""
        _ = original_dn
        if not entry.attributes:
            return r[m.Ldif.Entry].ok(entry)
        normalized_attrs = entry.attributes.attributes
        if not entry.metadata:
            entry.metadata = m.Ldif.QuirkMetadata.create_for(
                "oid",
                extensions=FlextLdifModelsMetadata.DynamicMetadata(),
            )
        elif entry.metadata.quirk_type != "oid":
            entry.metadata = entry.metadata.model_copy(update={"quirk_type": "oid"})
        current_extensions: t.MutableContainerMapping = (
            dict(entry.metadata.extensions) if entry.metadata.extensions else {}
        )
        mk = c.Ldif
        current_extensions[mk.ORIGINAL_DN_COMPLETE] = str(original_dn)
        orclaci_raw = original_attrs.get("orclaci") if original_attrs else None
        if not orclaci_raw:
            orclaci_raw = normalized_attrs.get("orclaci") if normalized_attrs else None
        orclaci_values: MutableSequence[str] | str | None = None
        if isinstance(orclaci_raw, str):
            orclaci_values = orclaci_raw
        elif isinstance(orclaci_raw, list):
            orclaci_values = [str(v) for v in orclaci_raw]
        self._process_orclaci_values(orclaci_values, current_extensions)
        acl_transformations = self._detect_entry_acl_transformations(
            original_attrs,
            normalized_attrs,
        )
        rfc_violations, attribute_conflicts = self._detect_rfc_violations(
            normalized_attrs,
        )
        if acl_transformations:
            acl_transformations_dict = {
                name: trans.model_dump() for name, trans in acl_transformations.items()
            }
            current_extensions["acl_transformations"] = (
                m.Ldif.DynamicMetadata.from_dict(
                    acl_transformations_dict,
                ).model_dump_json()
            )
        if rfc_violations:
            current_extensions["rfc_violations"] = _OidStringListJson(
                root=rfc_violations,
            ).model_dump_json()
        if attribute_conflicts:
            current_extensions["attribute_conflicts"] = _OidObjectListJson(
                root=[dict(conflict) for conflict in attribute_conflicts],
            ).model_dump_json()
        if current_extensions != (entry.metadata.extensions if entry.metadata else {}):
            updated_extensions = (
                FlextLdifModelsMetadata.DynamicMetadata.from_dict(current_extensions)
                if current_extensions
                else FlextLdifModelsMetadata.DynamicMetadata()
            )
            entry.metadata = entry.metadata.model_copy(
                update={"extensions": updated_extensions},
            )
            logger.debug(
                "OID finalize: Added server-specific metadata",
                acl_count=len(acl_transformations),
                violations_count=len(rfc_violations),
                conflicts_count=len(attribute_conflicts),
            )
        return r[m.Ldif.Entry].ok(entry)

    @override
    def _hook_post_parse_entry(self, entry: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Hook: Transform parsed entry using OID-specific enhancements."""
        try:
            if not entry.attributes or not entry.dn:
                return r[m.Ldif.Entry].ok(entry)
            logger.debug(
                "_hook_post_parse_entry attributes",
                attributes=",".join(entry.attributes.attributes.keys()),
            )
            converted_attributes, converted_attrs, boolean_conversions = (
                self._convert_boolean_attributes_to_rfc(entry.attributes.attributes)
            )
            logger.debug("converted_attrs", attrs=",".join(converted_attrs))
            logger.debug("boolean_conversions", count=len(boolean_conversions))
            normalized_attributes: MutableMapping[str, MutableSequence[str]] = {}
            for attr_name, attr_values in converted_attributes.items():
                normalized_name = self._normalize_attribute_name(attr_name)
                normalized_attributes[normalized_name] = attr_values
            entry.attributes.attributes = normalized_attributes
            mk = c.Ldif
            if entry.metadata:
                if not entry.metadata.extensions:
                    entry.metadata.extensions = (
                        FlextLdifModelsMetadata.DynamicMetadata()
                    )
                converted_attrs_list: MutableSequence[t.Ldif.MetadataValue] = [
                    str(item) for item in converted_attrs
                ]
                if boolean_conversions:
                    boolean_conversions_dict: MutableMapping[
                        str,
                        MutableMapping[str, str | MutableSequence[str]],
                    ] = {
                        attr_name: dict(conversion_data)
                        for attr_name, conversion_data in boolean_conversions.items()
                    }
                    conv_data: MutableMapping[
                        str,
                        MutableMapping[
                            str,
                            MutableMapping[str, str | MutableSequence[str]],
                        ]
                        | MutableSequence[t.Ldif.MetadataValue],
                    ] = {
                        mk.CONVERSION_CONVERTED_ATTRIBUTE_NAMES: converted_attrs_list,
                        mk.CONVERSION_BOOLEAN_CONVERSIONS: boolean_conversions_dict,
                    }
                    conv_data_str: str = m.Ldif.DynamicMetadata.from_dict(
                        conv_data,
                    ).model_dump_json()
                    setattr(
                        entry.metadata.extensions,
                        mk.CONVERTED_ATTRIBUTES,
                        conv_data_str,
                    )
                else:
                    setattr(
                        entry.metadata.extensions,
                        mk.CONVERTED_ATTRIBUTES,
                        converted_attrs_list,
                    )
            return r[m.Ldif.Entry].ok(entry)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception("OID post-parse entry hook failed")
            return r[m.Ldif.Entry].fail(f"OID post-parse entry hook failed: {e}")

    def _hook_transform_entry_raw(
        self,
        dn: str,
        attrs: MutableMapping[str, MutableSequence[str | bytes]],
    ) -> r[tuple[str, MutableMapping[str, MutableSequence[str | bytes]]]]:
        """Transform OID-specific DN and attributes before RFC parsing."""
        cleaned_dn, _ = FlextLdifUtilitiesDN.clean_dn_with_statistics(dn)
        normalized_dn = cleaned_dn
        if cleaned_dn.lower() == FlextLdifServersOidConstants.SCHEMA_DN_QUIRK.lower():
            normalized_dn = FlextLdifServersRfc.Constants.SCHEMA_DN
            logger.debug(
                "OID→RFC transform: Normalizing schema DN",
                original_dn=cleaned_dn,
                normalized_dn=normalized_dn,
            )
        return r[tuple[str, MutableMapping[str, MutableSequence[str | bytes]]]].ok((
            normalized_dn,
            attrs,
        ))

    def _merge_parsed_acl_extensions(
        self,
        acl_quirk: p.Ldif.AclQuirk,
        acl_value: str,
        current_extensions: t.MutableContainerMapping,
    ) -> None:
        """Parse ACL and merge additional extensions from parsed model."""
        try:
            acl_result = acl_quirk.parse_quirk(acl_value)
            if not acl_result.is_success:
                return
            acl_model = m.Ldif.Acl.model_validate(acl_result.value)
            if not (acl_model.metadata and acl_model.metadata.extensions):
                return
            acl_extensions = (
                acl_model.metadata.extensions.model_dump()
                if hasattr(acl_model.metadata.extensions, "model_dump")
                else dict(acl_model.metadata.extensions)
            )
            key_mapping = {
                "bindmode": c.Ldif.ACL_BINDMODE,
                "deny_group_override": c.Ldif.ACL_DENY_GROUP_OVERRIDE,
            }
            for key, value in acl_extensions.items():
                mapped_key = key_mapping.get(key)
                if mapped_key and (not current_extensions.get(mapped_key)):
                    current_extensions[mapped_key] = value
        except (ValueError, KeyError, AttributeError, UnicodeDecodeError, struct.error):
            logger.debug("Failed to parse ACL extension metadata", exc_info=True)

    @override
    def _normalize_attribute_name(self, attr_name: str) -> str:
        """Normalize OID attribute names to RFC-canonical format."""
        match attr_name.lower():
            case attr_lower if attr_lower in {
                FlextLdifServersOidConstants.ORCLACI.lower(),
                FlextLdifServersOidConstants.ORCLENTRYLEVELACI.lower(),
            }:
                return FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME
            case _:
                return super()._normalize_attribute_name(attr_name)

    @override
    def _parse_entry_from_lines(self, lines: MutableSequence[str]) -> r[m.Ldif.Entry]:
        """Parse entry from LDIF lines and finalize with OID metadata (original_dn_complete)."""
        result = super()._parse_entry_from_lines(lines)
        if result.is_failure:
            return result
        entry = result.value
        original_dn = entry.dn.value if entry.dn else ""
        original_attrs = dict(entry.attributes.attributes) if entry.attributes else {}
        return self._hook_finalize_entry_parse(entry, original_dn, original_attrs)

    def _process_orclaci_values(
        self,
        orclaci_values: MutableSequence[str] | str | None,
        current_extensions: t.MutableContainerMapping,
    ) -> None:
        """Process orclaci values and extract ACL metadata."""
        if not orclaci_values:
            return
        parent = self._get_parent_quirk_safe()
        acl_quirk = getattr(parent, "_acl_quirk", None) if parent is not None else None
        acl_list = (
            list(orclaci_values)
            if core_u.is_type(orclaci_values, (list, tuple))
            else [str(orclaci_values)]
        )
        for acl_value in acl_list:
            if not core_u.is_type(acl_value, str):
                continue
            self._extract_acl_metadata_from_string(acl_value, current_extensions)
            if acl_quirk is not None:
                self._merge_parsed_acl_extensions(
                    acl_quirk,
                    acl_value,
                    current_extensions,
                )

    def _restore_boolean_attribute_from_metadata(
        self,
        attr_name: str,
        conv_data: MutableMapping[str, MutableSequence[str] | str],
        restored_attrs: MutableMapping[str, MutableSequence[str]],
    ) -> bool:
        """Restore single boolean attribute from conversion metadata."""
        mk = c.Ldif
        converted_val = conv_data.get(mk.CONVERSION_CONVERTED_VALUE)
        converted_val_list: MutableSequence[str]
        if isinstance(converted_val, str):
            converted_val_list = [converted_val]
        elif isinstance(converted_val, list):
            converted_val_list = [str(item) for item in converted_val]
        else:
            converted_val_list = []
        if not converted_val_list:
            return False
        rfc_value = converted_val_list[0] if converted_val_list else ""
        oid_value = FlextLdifServersOidConstants.RFC_TO_OID.get(rfc_value, rfc_value)
        restored_attrs[attr_name] = [oid_value]
        logger.debug(
            "Restored OID boolean format from metadata",
            attribute_name=attr_name,
            rfc_value=rfc_value,
            oid_value=oid_value,
            operation="_restore_boolean_values_to_oid",
        )
        return True

    def _restore_boolean_values_to_oid(self, entry_data: m.Ldif.Entry) -> m.Ldif.Entry:
        """Restore OID boolean format from RFC format (RFC → OID: TRUE/FALSE → 0/1)."""
        if not entry_data.attributes:
            return entry_data
        boolean_conversions = self._extract_boolean_conversions_from_metadata(
            entry_data,
        )
        boolean_attr_names = {
            attr.lower() for attr in FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES
        }
        restored_attrs = dict(entry_data.attributes.attributes)
        for attr_name in list(restored_attrs.keys()):
            if attr_name.lower() not in boolean_attr_names:
                continue
            conv_data = boolean_conversions.get(attr_name, {})
            if core_u.is_type(conv_data, dict) and conv_data:
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
        entry_metadata: FlextLdifModelsMetadata.EntryMetadata | None = None
        if entry_data.attributes and entry_data.attributes.metadata:
            entry_metadata = entry_data.attributes.metadata
        return entry_data.model_copy(
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

    def _restore_entry_from_metadata(self, entry_data: m.Ldif.Entry) -> m.Ldif.Entry:
        """Restore OID-specific formats from metadata (RFC → OID denormalization)."""
        return self._restore_boolean_values_to_oid(entry_data)

    def _restore_single_attribute(
        self,
        attr_name: str,
        attr_values: MutableSequence[str],
        original_attrs: MutableMapping[str, MutableSequence[str]] | None,
    ) -> tuple[str, MutableSequence[str]]:
        """Restore attribute from metadata or apply denormalization."""
        if original_attrs:
            for orig_name, orig_values in original_attrs.items():
                if self._normalize_attribute_name(str(orig_name)) == attr_name:
                    restored_values = [str(v) for v in orig_values]
                    return (str(orig_name), restored_values)
        denorm_name = (
            FlextLdifServersOidConstants.ORCLACI
            if attr_name.lower()
            == FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME.lower()
            else attr_name
        )
        return (denorm_name, attr_values)

    def _should_skip_original_line(
        self,
        original_line: str,
        current_attrs: set[str],
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None,
        *,
        write_empty_values: bool,
    ) -> bool:
        """Check if original line should be skipped during restoration."""
        _ = write_empty_values
        if original_line.lower().startswith("dn:"):
            return True
        if original_line.strip().startswith("#"):
            include_comments = write_options and getattr(
                write_options,
                "write_metadata_as_comments",
                False,
            )
            if not include_comments:
                return True
        if ":" in original_line:
            attr_name_part = original_line.split(":", 1)[0].strip().lower()
            attr_name_part = attr_name_part.removesuffix(":").removeprefix("<")
            if current_attrs and attr_name_part not in current_attrs:
                return True
        return False

    def _write_original_attr_lines(
        self,
        ldif_lines: MutableSequence[str],
        entry_data: m.Ldif.Entry,
        original_attr_lines_complete: MutableSequence[str],
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None,
    ) -> set[str]:
        """Write original attribute lines preserving exact formatting."""
        written_attrs: set[str] = set()
        current_attrs = self._get_current_attrs_with_acl_equivalence(entry_data)
        for original_line in original_attr_lines_complete:
            if self._should_skip_original_line(
                original_line,
                current_attrs,
                write_options,
                write_empty_values=True,
            ):
                continue
            if ":" in original_line:
                original_attr_name = original_line.split(":", 1)[0].strip().lower()
                written_attrs.add(original_attr_name)
                if original_attr_name == "aci":
                    written_attrs.add("orclaci")
                elif original_attr_name == "orclaci":
                    written_attrs.add("aci")
            line_to_write = self._convert_line_boolean_to_oid(original_line)
            line_to_write = self._convert_line_acl_to_oid(line_to_write)
            ldif_lines.append(line_to_write)
        logger.debug(
            "Restored original attribute lines from metadata",
            entry_dn=entry_data.dn.value[:50] if entry_data.dn else "",
            original_lines_count=len(original_attr_lines_complete),
            written_attrs=", ".join(sorted(written_attrs)),
        )
        return written_attrs
