"""Oracle Internet Directory (OID) Quirks."""

from __future__ import annotations

import json
from functools import reduce

from flext_core import FlextLogger, FlextResult

from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t
from flext_ldif.utilities import u

logger = FlextLogger(__name__)


class FlextLdifServersOidEntry(FlextLdifServersRfc.Entry):
    """Oracle Internet Directory (OID) Entry implementation."""

    def _hook_transform_entry_raw(
        self,
        dn: str,
        attrs: dict[str, list[str | bytes]],
    ) -> FlextResult[tuple[str, dict[str, list[str | bytes]]]]:
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

        return FlextResult.ok((normalized_dn, attrs))

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

    def _convert_boolean_attributes_to_rfc(
        self,
        entry_attributes: dict[str, list[str]],
    ) -> tuple[
        dict[str, list[str]],
        set[str],
        dict[str, dict[str, str | list[str]]],
    ]:
        """Convert OID boolean attribute values to RFC format."""
        boolean_attributes = FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES
        boolean_attr_names = {attr.lower() for attr in boolean_attributes}

        converted_attrs_for_util: dict[str, list[str]] = dict(
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
        boolean_conversions: dict[str, dict[str, str | list[str]]] = {}

        for attr_name, attr_values in u.mapper().to_dict(entry_attributes).items():
            if attr_name.lower() in boolean_attr_names:
                original_values: list[str] = list(attr_values)

                converted_values: list[str] = converted_attributes.get(
                    attr_name, original_values
                )

                if converted_values != original_values:
                    converted_attrs.add(attr_name)

                    original_format_str = f"{FlextLdifServersOidConstants.ONE_OID}/{FlextLdifServersOidConstants.ZERO_OID}"
                    converted_format_str = f"{c.Ldif.BooleanFormats.TRUE_RFC}/{c.Ldif.BooleanFormats.FALSE_RFC}"

                    conversion_dict: dict[str, str | list[str]] = {}
                    original_key: str = c.Ldif.MetadataKeys.CONVERSION_ORIGINAL_VALUE
                    converted_key: str = c.Ldif.MetadataKeys.CONVERSION_CONVERTED_VALUE
                    format_key: str = c.Ldif.MetadataKeys.ORIGINAL_FORMAT
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

        return converted_attributes, converted_attrs, boolean_conversions

    def _detect_entry_acl_transformations(
        self,
        entry_attrs: dict[str, list[str]],
        converted_attributes: dict[str, list[str]],
    ) -> dict[str, m.Ldif.AttributeTransformation]:
        """Detect ACL attribute transformations (orclaci→aci)."""
        original_attr_names: dict[str, str] = {
            normalized.lower(): str(raw_attr_name)
            for raw_attr_name in entry_attrs
            if (
                normalized := self._normalize_attribute_name(str(raw_attr_name))
            ).lower()
            != str(raw_attr_name).lower()
        }

        acl_transformations: dict[str, m.Ldif.AttributeTransformation] = {
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
        converted_attributes: dict[str, list[str]],
    ) -> tuple[list[str], list[dict[str, str | list[str]]]]:
        """Detect RFC compliance violations in entry."""
        object_classes_raw = u.mapper().get(
            converted_attributes,
            "objectClass",
            default=[],
        )

        if isinstance(object_classes_raw, list):
            object_classes: list[str] = [str(oc) for oc in object_classes_raw]
        else:
            object_classes = []
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
        rfc_violations: list[str] = (
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
        attribute_conflicts: list[dict[str, str | list[str]]] = [
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

        return rfc_violations, attribute_conflicts

    def normalize_schema_strings_inline(
        self,
        entry: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
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

        new_attributes: dict[str, list[str]] = {
            attr_name: (
                [
                    reduce(
                        lambda val, pair: val.replace(pair[0], pair[1]),
                        replacements.items(),
                        value,
                    )
                    for value in attr_values
                ]
                if attr_name.lower() in schema_attrs
                else attr_values
            )
            for attr_name, attr_values in u
            .mapper()
            .to_dict(entry.attributes.attributes)
            .items()
        }

        if new_attributes == entry.attributes.attributes:
            return entry

        update_dict: dict[str, t.GeneralValueType] = {
            "attributes": m.Ldif.Attributes(attributes=new_attributes),
        }
        return entry.model_copy(update=update_dict)

    def _restore_single_attribute(
        self,
        attr_name: str,
        attr_values: list[str],
        original_attrs: dict[str, list[str]] | None,
    ) -> tuple[str, list[str]]:
        """Restore attribute from metadata or apply denormalization."""
        if original_attrs and isinstance(original_attrs, dict):
            for orig_name, orig_values in u.mapper().to_dict(original_attrs).items():
                if self._normalize_attribute_name(str(orig_name)) == attr_name:
                    if isinstance(orig_values, (list, tuple)):
                        restored_values = [str(v) for v in orig_values]
                    else:
                        restored_values = [str(orig_values)]
                    return str(orig_name), restored_values

        denorm_name = (
            FlextLdifServersOidConstants.ORCLACI
            if attr_name.lower()
            == FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME.lower()
            else attr_name
        )
        return denorm_name, attr_values

    def _denormalize_oid_attributes_for_output(
        self,
        attrs: dict[str, list[str]],
        metadata: m.Ldif.QuirkMetadata | None,
    ) -> dict[str, list[str]]:
        """Denormalize RFC attributes to OID format."""
        mk = c.Ldif.MetadataKeys
        original_attrs_raw = (
            metadata.extensions.get(mk.ORIGINAL_ATTRIBUTES_COMPLETE)
            if metadata and metadata.extensions
            else None
        )

        original_attrs: dict[str, list[str]] | None = None
        if original_attrs_raw is not None and isinstance(original_attrs_raw, dict):
            result_attrs: dict[str, list[str]] = {}
            for k, v in u.mapper().to_dict(original_attrs_raw).items():
                if isinstance(k, str):
                    if isinstance(v, list):
                        result_attrs[k] = [str(item) for item in v]
                    else:
                        result_attrs[k] = [str(v)]
            original_attrs = result_attrs
        denormalized: dict[str, list[str]] = {}
        for attr_name, attr_values in u.mapper().to_dict(attrs).items():
            restored_name, restored_values = self._restore_single_attribute(
                attr_name,
                attr_values,
                original_attrs,
            )
            denormalized[restored_name] = restored_values
        return denormalized

    def _extract_boolean_conversions_from_metadata(
        self,
        entry_data: m.Ldif.Entry,
    ) -> dict[str, dict[str, str | list[str]]]:
        """Extract boolean conversions from entry metadata."""
        mk = c.Ldif.MetadataKeys
        boolean_conversions: dict[str, dict[str, str | list[str]]] = {}

        if not (entry_data.metadata and entry_data.metadata.extensions):
            return boolean_conversions

        converted_attrs_data = (
            entry_data.metadata.extensions.get(mk.CONVERTED_ATTRIBUTES)
            if entry_data.metadata and entry_data.metadata.extensions
            else None
        )

        if isinstance(converted_attrs_data, dict):
            boolean_conversions_obj = u.mapper().get(
                converted_attrs_data,
                mk.CONVERSION_BOOLEAN_CONVERSIONS,
                default={},
            )

            if isinstance(boolean_conversions_obj, dict):
                for key, value in u.mapper().to_dict(boolean_conversions_obj).items():
                    if isinstance(key, str) and isinstance(value, dict):
                        typed_dict: dict[str, str | list[str]] = {}
                        for k, v in value.items():
                            if isinstance(k, str):
                                if isinstance(v, str):
                                    typed_dict[k] = v
                                elif isinstance(v, list):
                                    typed_dict[k] = [str(item) for item in v]
                        boolean_conversions[key] = typed_dict

        return boolean_conversions

    def _restore_boolean_attribute_from_metadata(
        self,
        attr_name: str,
        conv_data: dict[str, list[str] | str],
        restored_attrs: dict[str, list[str]],
    ) -> bool:
        """Restore single boolean attribute from conversion metadata."""
        mk = c.Ldif.MetadataKeys

        converted_val_list = conv_data.get(mk.CONVERSION_CONVERTED_VALUE, [])
        if not converted_val_list:
            return False

        rfc_value = converted_val_list[0] if converted_val_list else ""
        oid_value = FlextLdifServersOidConstants.RFC_TO_OID.get(
            rfc_value,
            rfc_value,
        )
        restored_attrs[attr_name] = [oid_value]
        logger.debug(
            "Restored OID boolean format from metadata",
            attribute_name=attr_name,
            rfc_value=rfc_value,
            oid_value=oid_value,
            operation="_restore_boolean_values_to_oid",
        )
        return True

    def _convert_rfc_boolean_to_oid(self, value: str) -> tuple[str, bool]:
        """Convert single RFC boolean value to OID format."""
        if value == "TRUE":
            return FlextLdifServersOidConstants.ONE_OID, True
        if value == "FALSE":
            return FlextLdifServersOidConstants.ZERO_OID, True
        return value, False

    def _convert_boolean_values_to_oid(
        self,
        attr_name: str,
        current_values: list[str],
        restored_attrs: dict[str, list[str]],
    ) -> None:
        """Convert RFC boolean values to OID format for an attribute."""
        new_values: list[str] = []
        changed = False
        for val in current_values:
            converted, was_converted = self._convert_rfc_boolean_to_oid(str(val))
            new_values.append(converted)
            if was_converted:
                changed = True
        if changed:
            restored_attrs[attr_name] = new_values

    def _restore_boolean_values_to_oid(
        self,
        entry_data: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
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
            if isinstance(conv_data, dict) and conv_data:
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

        update_dict: dict[str, t.GeneralValueType] = {
            "attributes": m.Ldif.Attributes(
                attributes=restored_attrs,
                attribute_metadata=(
                    entry_data.attributes.attribute_metadata
                    if entry_data.attributes
                    else {}
                ),
                metadata=entry_metadata,
            ),
        }
        return entry_data.model_copy(update=update_dict)

    def _restore_entry_from_metadata(
        self,
        entry_data: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Restore OID-specific formats from metadata (RFC → OID denormalization)."""
        return self._restore_boolean_values_to_oid(entry_data)

    def _extract_original_extensions(
        self,
        original_entry: m.Ldif.Entry,
    ) -> dict[str, str | int | bool | list[str]]:
        """Extract compatible extensions from original entry metadata."""
        original_extensions: dict[str, str | int | bool | list[str]] = {}
        if not (original_entry.metadata and original_entry.metadata.extensions):
            return original_extensions
        ext = original_entry.metadata.extensions
        if not hasattr(ext, "items"):
            return original_extensions
        for k, v in ext.items():
            if isinstance(v, (str, int, bool)):
                original_extensions[k] = v
            elif isinstance(v, list):
                if all(isinstance(item, str) for item in v):
                    original_extensions[k] = [str(item) for item in v]
                elif all(
                    isinstance(item, (str, int, float, bool, type(None))) for item in v
                ):
                    original_extensions[k] = [
                        str(item) for item in v if item is not None
                    ]
        return original_extensions

    def _build_json_serialized_metadata(
        self,
        rfc_violations: list[str],
        attribute_conflicts: list[dict[str, str]],
        boolean_conversions: dict[str, dict[str, str | list[str]]],
        converted_attributes: dict[str, list[str]],
        original_entry: m.Ldif.Entry,
    ) -> tuple[str | None, str | None, str | None, str | None, str | None]:
        """Serialize complex metadata to JSON strings for MetadataAttributeValue."""
        rfc_violations_str = json.dumps(rfc_violations) if rfc_violations else None
        attribute_conflicts_str = (
            json.dumps(attribute_conflicts) if attribute_conflicts else None
        )
        boolean_conversions_str = (
            json.dumps(boolean_conversions) if boolean_conversions else None
        )
        converted_attributes_str = (
            json.dumps(converted_attributes) if converted_attributes else None
        )
        original_entry_str = (
            json.dumps(original_entry.model_dump()) if original_entry else None
        )
        return (
            rfc_violations_str,
            attribute_conflicts_str,
            boolean_conversions_str,
            converted_attributes_str,
            original_entry_str,
        )

    def _create_entry_result_with_metadata(
        self,
        _entry: m.Ldif.Entry,
        cleaned_dn: str,
        original_dn: str,
        _dn_stats: m.Ldif.DNStatistics,
        converted_attrs: set[str],
        boolean_conversions: dict[str, dict[str, str | list[str]]],
        acl_transformations: dict[str, m.Ldif.AttributeTransformation],
        rfc_violations: list[str],
        attribute_conflicts: list[dict[str, str]],
        converted_attributes: dict[str, list[str]],
        original_entry: m.Ldif.Entry,
    ) -> FlextResult[m.Ldif.Entry]:
        """Create entry result with complete metadata."""
        original_attrs = (
            original_entry.attributes.attributes if original_entry.attributes else {}
        )

        mk = c.Ldif.MetadataKeys
        conversion_metadata: dict[str, t.MetadataAttributeValue] = (
            {mk.CONVERSION_CONVERTED_ATTRIBUTE_NAMES: list(converted_attrs)}
            if converted_attrs
            else {}
        )

        mk = c.Ldif.MetadataKeys
        dn_metadata: dict[str, t.MetadataAttributeValue] = (
            {
                mk.ORIGINAL_DN_COMPLETE: original_dn,
                mk.ORIGINAL_DN_LINE_COMPLETE: cleaned_dn,
                mk.HAS_DIFFERENCES: True,
            }
            if original_dn != cleaned_dn
            else {}
        )

        (
            rfc_violations_str,
            attribute_conflicts_str,
            boolean_conversions_str,
            converted_attributes_str,
            original_entry_str,
        ) = self._build_json_serialized_metadata(
            rfc_violations,
            attribute_conflicts,
            boolean_conversions,
            converted_attributes,
            original_entry,
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
            json.dumps(original_attrs) if original_attrs else None
        )
        processed_attributes_str: str | None = (
            json.dumps(converted_attributes) if converted_attributes else None
        )

        metadata_keys_dict = {
            k: v
            for k, v in c.Ldif.MetadataKeys.__dict__.items()
            if not k.startswith("_") and isinstance(v, str)
        }
        metadata_keys_str: str | None = (
            json.dumps(metadata_keys_dict) if metadata_keys_dict else None
        )
        operational_attributes_str: str | None = (
            json.dumps(list(FlextLdifServersOidConstants.OPERATIONAL_ATTRIBUTES))
            if FlextLdifServersOidConstants.OPERATIONAL_ATTRIBUTES
            else None
        )
        generic_metadata = FlextLdifUtilitiesMetadata.build_entry_metadata_extensions(
            "oid",
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

        mk = c.Ldif.MetadataKeys

        attr_name_conversions: dict[str, str] = (
            {
                FlextLdifServersOidConstants.ORCLACI: FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME,
            }
            if (
                FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME in converted_attributes
                and FlextLdifServersOidConstants.ORCLACI in original_attrs
            )
            else {}
        )
        converted_attrs_data: dict[
            str,
            dict[str, dict[str, str | list[str]]] | dict[str, str],
        ] = {
            c.Ldif.MetadataKeys.CONVERSION_BOOLEAN_CONVERSIONS: boolean_conversions,
            c.Ldif.MetadataKeys.CONVERSION_ATTRIBUTE_NAME_CONVERSIONS: attr_name_conversions,
        }

        converted_attrs_data_str: str = json.dumps(converted_attrs_data)
        generic_metadata[mk.CONVERTED_ATTRIBUTES] = converted_attrs_data_str
        generic_metadata[c.Ldif.MetadataKeys.ENTRY_TARGET_DN_CASE] = cleaned_dn
        generic_metadata[c.Ldif.MetadataKeys.ENTRY_ORIGINAL_FORMAT] = (
            f"OID Entry with {len(converted_attrs)} boolean conversions"
        )

        original_extensions = self._extract_original_extensions(original_entry)

        extensions_data: dict[str, t.MetadataAttributeValue] = {
            **conversion_metadata,
            **dn_metadata,
            **generic_metadata,
        }

        for key, val in rfc_compliance_metadata.items():
            if isinstance(val, list):
                widened_list: t.MetadataAttributeValue = list(val)
                extensions_data[key] = widened_list
            elif isinstance(val, dict):
                nested_dict: dict[str, t.ScalarValue | list[t.ScalarValue]] = {}
                for nk, nv in val.items():
                    if isinstance(nv, list):
                        nested_dict[nk] = list(nv)
                    else:
                        nested_dict[nk] = nv
                widened_dict: t.MetadataAttributeValue = nested_dict
                extensions_data[key] = widened_dict
            else:
                extensions_data[key] = val

        for ext_key, ext_val in original_extensions.items():
            if isinstance(ext_val, list):
                widened_ext: t.MetadataAttributeValue = list(ext_val)
                extensions_data[ext_key] = widened_ext
            elif isinstance(ext_val, (str, bool, int)):
                widened_scalar: t.MetadataAttributeValue = ext_val
                extensions_data[ext_key] = widened_scalar
        extensions_data[c.Ldif.MetadataKeys.ORIGINAL_DN_COMPLETE] = str(
            original_entry.dn,
        )

        metadata = m.Ldif.QuirkMetadata.create_for(
            self._get_server_type(),
            extensions=m.Ldif.DynamicMetadata.from_dict(extensions_data),
        )

        for attr_name, conv_data in boolean_conversions.items():
            original_vals = conv_data.get(mk.CONVERSION_ORIGINAL_VALUE, [])
            converted_vals = conv_data.get(mk.CONVERSION_CONVERTED_VALUE, [])
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
        orig_attr_lines: list[str] = []
        if original_entry.metadata and original_entry.metadata.original_format_details:
            format_details = original_entry.metadata.original_format_details
            raw_dn_line = getattr(format_details, "original_dn_line", None)
            orig_dn_line = str(raw_dn_line) if raw_dn_line is not None else None
            raw_lines = getattr(format_details, "original_attr_lines", [])
            if isinstance(raw_lines, (list, tuple)):
                orig_attr_lines = [str(line) for line in list(raw_lines)]

        converted_attrs_format_str: str | None = (
            json.dumps(list(converted_attrs)) if converted_attrs else None
        )
        boolean_conversions_format_str: str | None = (
            json.dumps(boolean_conversions) if boolean_conversions else None
        )
        converted_attributes_format_str: str | None = (
            json.dumps(converted_attributes) if converted_attributes else None
        )
        original_attributes_format_str: str | None = (
            json.dumps(original_attrs) if original_attrs else None
        )
        original_attr_lines_str: str | None = (
            json.dumps(orig_attr_lines) if orig_attr_lines else None
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
                original_dn_line=orig_dn_line,
                original_attr_lines=original_attr_lines_str,
            )
        )

        if (
            original_dn != cleaned_dn
            and original_dn.lower()
            == FlextLdifServersOidConstants.SCHEMA_DN_QUIRK.lower()
        ):
            if "schema_transformations" not in metadata.extensions:
                metadata.extensions["schema_transformations"] = []

            schema_transformations = metadata.extensions.get("schema_transformations")
            if isinstance(schema_transformations, list):
                schema_transformations.append("schema_dn_normalization")
            else:
                metadata.extensions["schema_transformations"] = [
                    "schema_dn_normalization",
                ]

        if acl_transformations:
            metadata.attribute_transformations.update(acl_transformations)

        ldif_attrs = m.Ldif.Attributes(attributes=converted_attributes)
        return FlextResult[m.Ldif.Entry].ok(
            m.Ldif.Entry(
                dn=m.Ldif.DN(value=cleaned_dn),
                attributes=ldif_attrs,
                metadata=metadata,
            ),
        )

    def _hook_post_parse_entry(
        self,
        entry: m.Ldif.Entry,
    ) -> FlextResult[m.Ldif.Entry]:
        """Hook: Transform parsed entry using OID-specific enhancements."""
        try:
            if not entry.attributes or not entry.dn:
                return FlextResult.ok(entry)

            logger.debug(
                "_hook_post_parse_entry attributes",
                attributes=",".join(entry.attributes.attributes.keys()),
            )
            converted_attributes, converted_attrs, boolean_conversions = (
                self._convert_boolean_attributes_to_rfc(entry.attributes.attributes)
            )
            logger.debug("converted_attrs", attrs=",".join(converted_attrs))
            logger.debug("boolean_conversions", count=len(boolean_conversions))

            normalized_attributes: dict[str, list[str]] = {}
            for attr_name, attr_values in converted_attributes.items():
                normalized_name = self._normalize_attribute_name(attr_name)
                normalized_attributes[normalized_name] = attr_values

            entry.attributes.attributes = normalized_attributes

            mk = c.Ldif.MetadataKeys
            if entry.metadata:
                if not entry.metadata.extensions:
                    entry.metadata.extensions = (
                        FlextLdifModelsMetadata.DynamicMetadata()
                    )

                converted_attrs_list: list[str] = list(converted_attrs)
                if boolean_conversions:
                    conv_data: dict[
                        str,
                        dict[str, dict[str, str | list[str]]] | list[str],
                    ] = {
                        mk.CONVERSION_CONVERTED_ATTRIBUTE_NAMES: converted_attrs_list,
                        mk.CONVERSION_BOOLEAN_CONVERSIONS: boolean_conversions,
                    }

                    conv_data_str: str = json.dumps(conv_data)
                    entry.metadata.extensions[mk.CONVERTED_ATTRIBUTES] = conv_data_str
                else:
                    entry.metadata.extensions[mk.CONVERTED_ATTRIBUTES] = (
                        converted_attrs_list
                    )

            return FlextResult.ok(entry)
        except Exception as e:
            logger.exception("OID post-parse entry hook failed")
            return FlextResult.fail(f"OID post-parse entry hook failed: {e}")

    def _extract_acl_metadata_from_string(
        self,
        acl_value: str,
        current_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Extract OID-specific ACL metadata from ACL string."""
        bindmode = FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_BINDMODE_PATTERN,
            group=1,
        )
        if bindmode:
            current_extensions[c.Ldif.MetadataKeys.ACL_BINDMODE] = bindmode

        if FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_DENY_GROUP_OVERRIDE_PATTERN,
        ):
            current_extensions[c.Ldif.MetadataKeys.ACL_DENY_GROUP_OVERRIDE] = True

        if FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_APPEND_TO_ALL_PATTERN,
        ):
            current_extensions[c.Ldif.MetadataKeys.ACL_APPEND_TO_ALL] = True

        bind_ip_filter = FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_BIND_IP_FILTER_PATTERN,
            group=1,
        )
        if bind_ip_filter:
            current_extensions[c.Ldif.MetadataKeys.ACL_BIND_IP_FILTER] = bind_ip_filter

        constrain_to_added = FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_CONSTRAIN_TO_ADDED_PATTERN,
            group=1,
        )
        if constrain_to_added:
            current_extensions[c.Ldif.MetadataKeys.ACL_CONSTRAIN_TO_ADDED_OBJECT] = (
                constrain_to_added
            )

    def _merge_parsed_acl_extensions(
        self,
        acl_quirk: object,
        acl_value: str,
        current_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Parse ACL and merge additional extensions from parsed model."""
        if not hasattr(acl_quirk, "parse"):
            return
        try:
            parse_method = getattr(acl_quirk, "parse", None)
            if parse_method is None or not callable(parse_method):
                return
            acl_result_raw = parse_method(acl_value)

            if not isinstance(acl_result_raw, FlextResult):
                return
            acl_result = acl_result_raw
            if not acl_result.is_success:
                return
            acl_model = acl_result.value
            if not (acl_model.metadata and acl_model.metadata.extensions):
                return
            acl_extensions = (
                acl_model.metadata.extensions.model_dump()
                if hasattr(acl_model.metadata.extensions, "model_dump")
                else dict(acl_model.metadata.extensions)
            )

            key_mapping = {
                "bindmode": c.Ldif.MetadataKeys.ACL_BINDMODE,
                "deny_group_override": c.Ldif.MetadataKeys.ACL_DENY_GROUP_OVERRIDE,
            }
            for key, value in acl_extensions.items():
                mapped_key = key_mapping.get(key)
                if mapped_key and not current_extensions.get(mapped_key):
                    current_extensions[mapped_key] = value
        except Exception:
            logger.debug("Failed to parse ACL extension metadata", exc_info=True)

    def _process_orclaci_values(
        self,
        orclaci_values: list[str] | str | None,
        current_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Process orclaci values and extract ACL metadata."""
        if not orclaci_values:
            return

        parent = self._get_parent_quirk_safe()
        acl_quirk = getattr(parent, "_acl_quirk", None) if parent is not None else None

        acl_list = (
            list(orclaci_values)
            if isinstance(orclaci_values, (list, tuple))
            else [str(orclaci_values)]
        )

        for acl_value in acl_list:
            if not isinstance(acl_value, str):
                continue
            self._extract_acl_metadata_from_string(acl_value, current_extensions)
            if acl_quirk is not None:
                self._merge_parsed_acl_extensions(
                    acl_quirk,
                    acl_value,
                    current_extensions,
                )

    def _hook_finalize_entry_parse(
        self,
        entry: m.Ldif.Entry,
        original_dn: str,
        original_attrs: dict[str, list[str]],
    ) -> FlextResult[m.Ldif.Entry]:
        """Finalize OID entry with ACL and RFC violation metadata."""
        _ = original_dn

        if not entry.attributes:
            return FlextResult.ok(entry)

        normalized_attrs = entry.attributes.attributes

        if not entry.metadata:
            entry.metadata = m.Ldif.QuirkMetadata.create_for(
                "oid",
                extensions=FlextLdifModelsMetadata.DynamicMetadata(),
            )
        elif entry.metadata.quirk_type != "oid":
            entry.metadata = entry.metadata.model_copy(
                update={"quirk_type": "oid"},
            )

        current_extensions: dict[str, t.MetadataAttributeValue] = (
            dict(entry.metadata.extensions) if entry.metadata.extensions else {}
        )
        mk = c.Ldif.MetadataKeys
        current_extensions[mk.ORIGINAL_DN_COMPLETE] = str(original_dn)

        orclaci_raw = original_attrs.get("orclaci") if original_attrs else None
        if not orclaci_raw:
            orclaci_raw = normalized_attrs.get("orclaci") if normalized_attrs else None

        orclaci_values: list[str] | str | None = None
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
            current_extensions["acl_transformations"] = json.dumps(
                acl_transformations_dict,
            )
        if rfc_violations:
            current_extensions["rfc_violations"] = json.dumps(rfc_violations)
        if attribute_conflicts:
            current_extensions["attribute_conflicts"] = json.dumps(attribute_conflicts)

        if current_extensions != (entry.metadata.extensions if entry.metadata else {}):
            update_dict: dict[str, t.GeneralValueType] = {
                "extensions": FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                    current_extensions,
                )
                if current_extensions
                else FlextLdifModelsMetadata.DynamicMetadata(),
            }
            entry.metadata = entry.metadata.model_copy(update=update_dict)

            logger.debug(
                "OID finalize: Added server-specific metadata",
                acl_count=len(acl_transformations),
                violations_count=len(rfc_violations),
                conflicts_count=len(attribute_conflicts),
            )

        return FlextResult.ok(entry)

    def _parse_entry_from_lines(self, lines: list[str]) -> FlextResult[m.Ldif.Entry]:
        """Parse entry from LDIF lines and finalize with OID metadata (original_dn_complete)."""
        result = super()._parse_entry_from_lines(lines)
        if result.is_failure:
            return result
        entry = result.value
        original_dn = entry.dn.value if entry.dn else ""
        original_attrs = dict(entry.attributes.attributes) if entry.attributes else {}
        return self._hook_finalize_entry_parse(entry, original_dn, original_attrs)

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

    def _write_original_attr_lines(
        self,
        ldif_lines: list[str],
        entry_data: m.Ldif.Entry,
        original_attr_lines_complete: list[str],
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
            entry_dn=entry_data.dn.value[:50] if entry_data.dn else None,
            original_lines_count=len(original_attr_lines_complete),
            written_attrs=list(written_attrs),
        )
        return written_attrs
