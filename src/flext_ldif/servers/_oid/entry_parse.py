"""Oracle Internet Directory (OID) entry server — parse hook helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidEntryParseMixin(FlextLdifServersRfc.Entry):
    """OID entry parse hook helpers."""

    def _detect_entry_acl_transformations(
        self,
        entry_attrs: t.MutableStrSequenceMapping,
        converted_attributes: t.MutableStrSequenceMapping,
    ) -> MutableMapping[str, m.Ldif.AttributeTransformation]:
        """Detect ACL attribute transformations (orclaci→aci).

        Returns:
            The resulting ``MutableMapping[str, m.Ldif.AttributeTransformation]``.
        """
        original_attr_names: t.MutableStrMapping = {
            normalized.lower(): raw_attr_name
            for raw_attr_name in entry_attrs
            if (normalized := self._normalize_attribute_name(raw_attr_name)).lower()
            != raw_attr_name.lower()
        }
        acl_transformations: MutableMapping[str, m.Ldif.AttributeTransformation] = {
            original_name: m.Ldif.AttributeTransformation.model_validate({
                "original_name": original_name,
                "target_name": attr_name,
                "original_values": attr_values,
                "target_values": attr_values,
                "transformation_type": c.Ldif.TransformationType.ATTRIBUTE_RENAMED,
                "reason": f"OID ACL ({original_name}) → RFC 2256 (aci)",
            })
            for attr_name, attr_values in converted_attributes.items()
            if attr_name.lower() in original_attr_names
            and (original_name := original_attr_names[attr_name.lower()]).lower()
            in {"orclaci", "orclentrylevelaci"}
        }
        return acl_transformations
    @staticmethod
    def _detect_rfc_violations(
        converted_attributes: t.MutableStrSequenceMapping,
    ) -> tuple[
        t.MutableSequenceOf[str],
        t.MutableSequenceOf[t.MutableAttributeMapping],
    ]:
        """Detect RFC compliance violations in entry.

        Returns:
            The resulting ``tuple[t.MutableSequenceOf[str],
                t.MutableSequenceOf[t.MutableAttributeMapping]]``.
        """
        object_classes_raw = converted_attributes.get("objectClass", [])
        object_classes: t.MutableSequenceOf[str] = list(object_classes_raw)
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
        rfc_violations: t.MutableSequenceOf[str] = (
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
        attribute_conflicts: t.MutableSequenceOf[t.MutableAttributeMapping] = [
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
    @staticmethod
    def _get_current_attrs_with_acl_equivalence(
        entry_data: m.Ldif.Entry,
    ) -> set[str]:
        """Get current attribute names with OID ACL equivalence.

        Returns:
            The resulting ``set[str]``.
        """
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
        original_attrs: t.MutableStrSequenceMapping,
    ) -> p.Result[m.Ldif.Entry]:
        """Preserve typed OID metadata for serialization and phase-aware ACL writes.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        _ = original_dn
        if not entry.attributes:
            return r[m.Ldif.Entry].ok(entry)
        normalized_attrs = entry.attributes.attributes
        metadata_values = dict(entry.metadata) if entry.metadata is not None else {}
        entry.metadata = m.Ldif.ServerMetadata.model_validate({
            **metadata_values,
            "server_type": c.Ldif.ServerTypes.OID,
        })
        current_extensions: t.Ldif.MutableMetadataMapping = (
            dict(entry.metadata.extensions) if entry.metadata.extensions else {}
        )
        mk = c.Ldif
        current_extensions[mk.ORIGINAL_DN_COMPLETE] = original_dn
        orclaci_raw = original_attrs.get("orclaci") if original_attrs else None
        if not orclaci_raw:
            orclaci_raw = normalized_attrs.get("orclaci") if normalized_attrs else None
        orclaci_values: t.MutableSequenceOf[str] | str | None = None
        if isinstance(orclaci_raw, list):
            orclaci_values = list(orclaci_raw)
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
            current_extensions["acl_transformations"] = u.Ldif.dump_dynamic_metadata(
                acl_transformations_dict,
            )
        if rfc_violations:
            current_extensions["rfc_violations"] = u.Ldif.dump_json_payload(
                list(rfc_violations),
            )
        if attribute_conflicts:
            attribute_conflicts_json: t.JsonValue = (
                t.Cli.JSON_VALUE_ADAPTER.validate_python([
                    {
                        key: (value if isinstance(value, str) else list(value))
                        for key, value in conflict.items()
                    }
                    for conflict in attribute_conflicts
                ])
            )
            current_extensions["attribute_conflicts"] = u.Ldif.dump_json_payload(
                attribute_conflicts_json,
            )
        # mro-wgwh.5 (agent: kimi-coder) — DynamicMetadata removed: assign the plain
        # mapping built above (already JSON-normalized).
        entry.metadata.extensions = current_extensions
        return r[m.Ldif.Entry].ok(entry)
    @override
    def _hook_post_parse_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Transform parsed entry using OID-specific enhancements.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        try:
            return self._post_parse_oid_entry(entry)
        except c.Ldif.EXC_LDIF_PARSE as e:
            FlextLdifServersOidEntryParseMixin._module_logger.exception(
                "OID post-parse entry hook failed",
            )
            return r[m.Ldif.Entry].fail_op("OID post-parse entry hook", e)
    def _post_parse_oid_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Normalize OID entry attributes after RFC parsing.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        if not entry.attributes or not entry.dn:
            return r[m.Ldif.Entry].ok(entry)
        converted_attributes, converted_attrs, boolean_conversions = (
            self._convert_boolean_attributes_to_rfc(entry.attributes.attributes)
        )
        normalized_attributes: t.MutableStrSequenceMapping = {}
        name_renames: t.MutableStrMapping = {}
        for attr_name, attr_values in converted_attributes.items():
            normalized_name = self._normalize_attribute_name(attr_name)
            normalized_attributes[normalized_name] = attr_values
            if normalized_name != attr_name:
                name_renames[normalized_name] = attr_name
        self._normalize_schema_values(normalized_attributes)
        entry.attributes.attributes = normalized_attributes
        mk = c.Ldif
        if entry.metadata:
            if not entry.metadata.extensions:
                entry.metadata.extensions = {}
            converted_attrs_list: t.MutableSequenceOf[t.JsonValue] = list(
                converted_attrs,
            )
            converted_attrs_json: t.JsonValueList = list(
                t.Cli.JSON_LIST_ADAPTER.validate_python(converted_attrs_list),
            )
            if boolean_conversions:
                boolean_conversions_dict: MutableMapping[str, t.JsonValue] = {
                    attr_name: {
                        conversion_key: t.Cli.JSON_VALUE_ADAPTER.validate_python(
                            conversion_value,
                        )
                        for conversion_key, conversion_value in conversion_data.items()
                    }
                    for attr_name, conversion_data in boolean_conversions.items()
                }
                boolean_conversions_json: t.JsonMapping = (
                    t.Cli.JSON_MAPPING_ADAPTER.validate_python({
                        attr_name: u.normalize_to_json_value(conversion_data)
                        for attr_name, conversion_data in (
                            boolean_conversions_dict.items()
                        )
                    })
                )
                conv_data = u.normalize_to_json_value({
                    mk.CONVERSION_CONVERTED_ATTRIBUTE_NAMES: converted_attrs_json,
                    mk.CONVERSION_BOOLEAN_CONVERSIONS: boolean_conversions_json,
                })
                # mro-wgwh.5 (agent: kimi-coder) — extensions is a plain mapping now:
                # subscript assignment instead of DynamicMetadata setattr.
                entry.metadata.extensions[mk.CONVERTED_ATTRIBUTES] = conv_data
            else:
                entry.metadata.extensions[mk.CONVERTED_ATTRIBUTES] = (
                    converted_attrs_json
                )
            if name_renames:
                rename_metadata: t.JsonDict = dict(name_renames)
                entry.metadata.extensions["attribute_name_renames"] = rename_metadata
        return r[m.Ldif.Entry].ok(entry)
    @staticmethod
    def _hook_transform_entry_raw(
        dn: str,
        attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
    ) -> p.Result[tuple[str, MutableMapping[str, t.MutableSequenceOf[str | bytes]]]]:
        """Transform OID-specific DN and attributes before RFC parsing.

        Returns:
            The resulting ``p.Result[tuple[str, MutableMapping[str,
                t.MutableSequenceOf[str | bytes]]]]``.
        """
        cleaned_dn, _ = u.Ldif.clean_dn_with_statistics(dn)
        normalized_dn = cleaned_dn
        if cleaned_dn.lower() == FlextLdifServersOidConstants.SCHEMA_DN_SERVER.lower():
            normalized_dn = FlextLdifServersRfc.Constants.SCHEMA_DN
            FlextLdifServersOidEntryParseMixin._module_logger.debug(
                "OID→RFC transform: Normalizing schema DN",
                original_dn=cleaned_dn,
                normalized_dn=normalized_dn,
            )
        return r[tuple[str, MutableMapping[str, t.MutableSequenceOf[str | bytes]]]].ok((
            normalized_dn,
            attrs,
        ))
    def _merge_parsed_acl_extensions(
        self,
        acl_server: p.Ldif.AclServer,
        acl_value: str,
        current_extensions: t.Ldif.MutableMetadataMapping,
    ) -> None:
        """Parse ACL and merge additional extensions from parsed model."""
        try:
            self._merge_parsed_acl_extensions_core(
                acl_server,
                acl_value,
                current_extensions,
            )
        except c.Ldif.EXC_LDIF_PARSE:
            FlextLdifServersOidEntryParseMixin._module_logger.debug(
                "Failed to parse ACL extension metadata",
                exc_info=True,
            )
    @staticmethod
    def _merge_parsed_acl_extensions_core(
        acl_server: p.Ldif.AclServer,
        acl_value: str,
        current_extensions: t.Ldif.MutableMetadataMapping,
    ) -> None:
        """Merge parsed ACL extension metadata into the current extension mapping."""
        acl_result = acl_server.parse_server(acl_value)
        acl_model = m.Ldif.Acl.model_validate(acl_result.value)
        if not (acl_model.metadata and acl_model.metadata.extensions):
            return
        # mro-wgwh.5 (agent: kimi-coder) — extensions is a plain mapping;
        # isinstance(dict)
        # replaces the hasattr(model_dump) dispatch.
        extensions_value = acl_model.metadata.extensions
        acl_extensions: t.MutableJsonMapping = (
            extensions_value
            if isinstance(extensions_value, dict)
            else dict(extensions_value)
        )
        key_mapping = {
            "bindmode": c.Ldif.ACL_BINDMODE,
            "deny_group_override": c.Ldif.ACL_DENY_GROUP_OVERRIDE,
        }
        for key, value in acl_extensions.items():
            mapped_key = key_mapping.get(key)
            if mapped_key and (not current_extensions.get(mapped_key)):
                current_extensions[mapped_key] = value
        return


__all__: list[str] = ["FlextLdifServersOidEntryParseMixin"]
