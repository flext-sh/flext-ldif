"""Oracle Internet Directory (OID) Servers."""

from __future__ import annotations

from collections.abc import (
    Mapping,
    MutableMapping,
)
from typing import override

from flext_ldif import (
    FlextLdifServersOidConstants,
    FlextLdifServersRfc,
    c,
    m,
    p,
    r,
    t,
    u,
)

logger = u.fetch_logger(__name__)


class FlextLdifServersOidEntry(FlextLdifServersRfc.Entry):
    """Oracle Internet Directory (OID) Entry implementation."""

    def _convert_boolean_attributes_to_rfc(
        self,
        entry_attributes: t.MutableStrSequenceMapping,
    ) -> tuple[
        t.MutableStrSequenceMapping,
        set[str],
        MutableMapping[str, t.MutableAttributeMapping],
    ]:
        """Convert OID boolean attribute values to RFC format."""
        boolean_attributes = FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES
        boolean_attr_names = {attr.lower() for attr in boolean_attributes}
        converted_attrs_for_util: t.MutableStrSequenceMapping = dict(
            entry_attributes.items(),
        )
        source_format = f"{FlextLdifServersOidConstants.ZERO_OID}/{FlextLdifServersOidConstants.ONE_OID}"
        target_format = "TRUE/FALSE"
        converted_attributes = u.Ldif.convert_boolean_attributes(
            converted_attrs_for_util,
            boolean_attr_names,
            source_format=source_format,
            target_format=target_format,
        )
        converted_attrs: set[str] = set()
        boolean_conversions: MutableMapping[
            str,
            t.MutableAttributeMapping,
        ] = {}
        for attr_name, attr_values in entry_attributes.items():
            if attr_name.lower() in boolean_attr_names:
                original_values: t.MutableSequenceOf[str] = list(attr_values)
                converted_values: t.MutableSequenceOf[str] = converted_attributes.get(
                    attr_name,
                    original_values,
                )
                if converted_values != original_values:
                    converted_attrs.add(attr_name)
                    original_format_str = f"{FlextLdifServersOidConstants.ONE_OID}/{FlextLdifServersOidConstants.ZERO_OID}"
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
                    logger.debug(
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

    def _denormalize_oid_attributes_for_output(
        self,
        attrs: t.MutableStrSequenceMapping,
        metadata: m.Ldif.ServerMetadata | None,
    ) -> t.MutableStrSequenceMapping:
        """Denormalize RFC attributes to OID format."""
        mk = c.Ldif
        original_attrs_raw = (
            metadata.extensions.get(mk.ORIGINAL_ATTRIBUTES_COMPLETE)
            if metadata and metadata.extensions
            else None
        )
        original_attrs_value: t.JsonPayload | None = original_attrs_raw
        original_attrs: t.MutableStrSequenceMapping | None = None
        if isinstance(original_attrs_value, Mapping):
            result_attrs: t.MutableStrSequenceMapping = {}
            for k, v in original_attrs_value.items():
                if isinstance(v, list):
                    result_attrs[k] = [str(item) for item in v]
                else:
                    result_attrs[k] = [str(v)]
            original_attrs = result_attrs
        denormalized: t.MutableStrSequenceMapping = {}
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
        entry_attrs: t.MutableStrSequenceMapping,
        converted_attributes: t.MutableStrSequenceMapping,
    ) -> MutableMapping[str, m.Ldif.AttributeTransformation]:
        """Detect ACL attribute transformations (orclaci→aci)."""
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

    def _detect_rfc_violations(
        self,
        converted_attributes: t.MutableStrSequenceMapping,
    ) -> tuple[
        t.MutableSequenceOf[str],
        t.MutableSequenceOf[t.MutableAttributeMapping],
    ]:
        """Detect RFC compliance violations in entry."""
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

    def extract_acl_metadata_from_string(
        self,
        acl_value: str,
        current_extensions: t.Ldif.MutableMetadataMapping,
    ) -> None:
        """Extract OID-specific ACL metadata from ACL string."""
        bindmode = u.Ldif.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_BINDMODE_PATTERN,
            group=1,
        )
        if bindmode:
            current_extensions[c.Ldif.ACL_BINDMODE] = bindmode
        if u.Ldif.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_DENY_GROUP_OVERRIDE_PATTERN,
        ):
            current_extensions[c.Ldif.ACL_DENY_GROUP_OVERRIDE] = True
        if u.Ldif.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_APPEND_TO_ALL_PATTERN,
        ):
            current_extensions[c.Ldif.ACL_APPEND_TO_ALL] = True
        bind_ip_filter = u.Ldif.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_BIND_IP_FILTER_PATTERN,
            group=1,
        )
        if bind_ip_filter:
            current_extensions[c.Ldif.ACL_BIND_IP_FILTER] = bind_ip_filter
        constrain_to_added = u.Ldif.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_CONSTRAIN_TO_ADDED_PATTERN,
            group=1,
        )
        if constrain_to_added:
            current_extensions[c.Ldif.ACL_CONSTRAIN_TO_ADDED_OBJECT] = (
                constrain_to_added
            )

    def _parse_metadata_boolean_flags(
        self,
        entry_data: m.Ldif.Entry,
    ) -> MutableMapping[str, t.MutableAttributeMapping]:
        """Extract boolean conversions from entry metadata."""
        mk = c.Ldif
        boolean_conversions: MutableMapping[
            str,
            t.MutableAttributeMapping,
        ] = {}
        if not (entry_data.metadata and entry_data.metadata.extensions):
            return boolean_conversions
        converted_attrs_data = (
            entry_data.metadata.extensions.get(mk.CONVERTED_ATTRIBUTES)
            if entry_data.metadata and entry_data.metadata.extensions
            else None
        )
        converted_attrs_value: t.JsonPayload | None = converted_attrs_data
        if isinstance(converted_attrs_value, Mapping):
            boolean_conversions_obj: t.JsonPayload | None = converted_attrs_value.get(
                mk.CONVERSION_BOOLEAN_CONVERSIONS,
                {},
            )
            if isinstance(boolean_conversions_obj, Mapping):
                for key, value in boolean_conversions_obj.items():
                    if isinstance(value, Mapping):
                        value_metadata = m.Ldif.DynamicMetadata.model_validate(value)
                        typed_dict: t.MutableAttributeMapping = {}
                        for key_str, raw_value in value_metadata.items():
                            if isinstance(raw_value, str):
                                typed_dict[key_str] = raw_value
                            elif isinstance(raw_value, list):
                                typed_items: t.MutableSequenceOf[str] = [
                                    str(item) for item in raw_value if u.primitive(item)
                                ]
                                typed_dict[key_str] = typed_items
                        boolean_conversions[key] = typed_dict
        return boolean_conversions

    def _extract_original_extensions(
        self,
        original_entry: m.Ldif.Entry,
    ) -> t.Ldif.MutableMetadataMapping:
        """Extract compatible extensions from original entry metadata."""
        original_extensions: t.Ldif.MutableMetadataMapping = {}
        if not (original_entry.metadata and original_entry.metadata.extensions):
            return original_extensions
        ext = original_entry.metadata.extensions
        for k, v in ext.items():
            extension_value: t.JsonPayload | None = v
            if isinstance(extension_value, (str, int, bool)):
                original_extensions[k] = extension_value
            elif isinstance(extension_value, list) and (
                all(isinstance(item, str) for item in extension_value)
                or all(u.primitive(item) for item in extension_value)
            ):
                original_extensions[k] = [str(item) for item in extension_value]
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
        original_attrs: t.MutableStrSequenceMapping,
    ) -> p.Result[m.Ldif.Entry]:
        """Finalize OID entry with ACL and RFC violation metadata."""
        _ = original_dn
        if not entry.attributes:
            return r[m.Ldif.Entry].ok(entry)
        normalized_attrs = entry.attributes.attributes
        if not entry.metadata:
            entry.metadata = m.Ldif.ServerMetadata.create_for(
                "oid",
                extensions=m.Ldif.DynamicMetadata(),
            )
        elif entry.metadata.server_type != "oid":
            entry.metadata = entry.metadata.model_copy(update={"server_type": "oid"})
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
                t.Cli.JSON_VALUE_ADAPTER.validate_python(
                    [
                        {
                            key: (value if isinstance(value, str) else list(value))
                            for key, value in conflict.items()
                        }
                        for conflict in attribute_conflicts
                    ],
                )
            )
            current_extensions["attribute_conflicts"] = u.Ldif.dump_json_payload(
                attribute_conflicts_json,
            )
        entry.metadata.extensions = m.Ldif.DynamicMetadata.from_dict(
            current_extensions,
        )
        return r[m.Ldif.Entry].ok(entry)

    @override
    def _hook_post_parse_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Hook: Transform parsed entry using OID-specific enhancements."""
        try:
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
                    entry.metadata.extensions = m.Ldif.DynamicMetadata()
                converted_attrs_list: t.MutableSequenceOf[t.JsonValue] = list(
                    converted_attrs,
                )
                converted_attrs_json: t.JsonList = (
                    t.Cli.JSON_LIST_ADAPTER.validate_python(
                        converted_attrs_list,
                    )
                )
                if boolean_conversions:
                    boolean_conversions_dict: MutableMapping[
                        str,
                        t.JsonValue,
                    ] = {
                        attr_name: {
                            conversion_key: t.Cli.JSON_VALUE_ADAPTER.validate_python(
                                conversion_value,
                            )
                            for conversion_key, conversion_value in conversion_data.items()
                        }
                        for attr_name, conversion_data in boolean_conversions.items()
                    }
                    boolean_conversions_json: t.JsonMapping = t.Cli.JSON_MAPPING_ADAPTER.validate_python(
                        {
                            attr_name: u.normalize_to_json_value(conversion_data)
                            for attr_name, conversion_data in boolean_conversions_dict.items()
                        },
                    )
                    conv_data = u.normalize_to_json_value({
                        mk.CONVERSION_CONVERTED_ATTRIBUTE_NAMES: converted_attrs_json,
                        mk.CONVERSION_BOOLEAN_CONVERSIONS: boolean_conversions_json,
                    })
                    setattr(
                        entry.metadata.extensions,
                        mk.CONVERTED_ATTRIBUTES,
                        conv_data,
                    )
                else:
                    setattr(
                        entry.metadata.extensions,
                        mk.CONVERTED_ATTRIBUTES,
                        converted_attrs_json,
                    )
                if name_renames:
                    rename_metadata: t.JsonDict = dict(name_renames)
                    entry.metadata.extensions["attribute_name_renames"] = (
                        rename_metadata
                    )
            return r[m.Ldif.Entry].ok(entry)
        except c.Ldif.EXC_LDIF_PARSE as e:
            logger.exception("OID post-parse entry hook failed")
            return r[m.Ldif.Entry].fail_op("OID post-parse entry hook", e)

    def _hook_transform_entry_raw(
        self,
        dn: str,
        attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
    ) -> p.Result[tuple[str, MutableMapping[str, t.MutableSequenceOf[str | bytes]]]]:
        """Transform OID-specific DN and attributes before RFC parsing."""
        cleaned_dn, _ = u.Ldif.clean_dn_with_statistics(dn)
        normalized_dn = cleaned_dn
        if cleaned_dn.lower() == FlextLdifServersOidConstants.SCHEMA_DN_SERVER.lower():
            normalized_dn = FlextLdifServersRfc.Constants.SCHEMA_DN
            logger.debug(
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
            acl_result = acl_server.parse_server(acl_value)
            if not acl_result.success:
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
        except c.Ldif.EXC_LDIF_PARSE:
            logger.debug("Failed to parse ACL extension metadata", exc_info=True)

    @staticmethod
    def _normalize_schema_values(
        attrs: t.MutableStrSequenceMapping,
    ) -> None:
        """Normalize OID matching rules and syntax OIDs in schema definition strings.

        Applies MATCHING_RULE_TO_RFC and SYNTAX_OID_TO_RFC conversions to the raw
        attributeTypes/objectClasses/matchingRules value strings. Handles context-aware
        replacement: ``caseIgnoreSubStringsMatch`` in EQUALITY context is replaced with
        ``caseIgnoreMatch`` (not a substring matching rule), while in SUBSTR context it
        becomes ``caseIgnoreSubstringsMatch`` (lowercase 's').
        """
        equality_map: dict[str, str] = {
            "caseIgnoreSubStringsMatch": "caseIgnoreMatch",
            "caseIgnoreSubstringsMatch": "caseIgnoreMatch",
        }
        substr_map = FlextLdifServersOidConstants.MATCHING_RULE_TO_RFC
        syntax_map = FlextLdifServersOidConstants.SYNTAX_OID_TO_RFC
        schema_fields = {"attributetypes", "objectclasses", "matchingrules"}
        for attr_name in list(attrs):
            if attr_name.lower() not in schema_fields:
                continue
            values = attrs[attr_name]
            updated: list[str] = []
            changed = False
            for value in values:
                new_value = value
                for oid_rule, rfc_rule in equality_map.items():
                    eq_token = f"EQUALITY {oid_rule}"
                    if eq_token in new_value:
                        new_value = new_value.replace(eq_token, f"EQUALITY {rfc_rule}")
                        changed = True
                for oid_rule, rfc_rule in substr_map.items():
                    substr_token = f"SUBSTR {oid_rule}"
                    if substr_token in new_value:
                        new_value = new_value.replace(
                            substr_token,
                            f"SUBSTR {rfc_rule}",
                        )
                        changed = True
                for oid_syntax, rfc_syntax in syntax_map.items():
                    token = f"'{oid_syntax}'"
                    replacement = f"'{rfc_syntax}'"
                    if token in new_value:
                        new_value = new_value.replace(token, replacement)
                        changed = True
                    elif f" {oid_syntax} " in new_value:
                        new_value = new_value.replace(
                            f" {oid_syntax} ",
                            f" {rfc_syntax} ",
                        )
                        changed = True
                if attr_name.lower() in {"objectclasses", "attributetypes"}:
                    sup_quoted = c.Ldif.sub_pattern(
                        r"SUP\s+'([^']+)'", r"SUP \1", new_value
                    )
                    if sup_quoted != new_value:
                        new_value = sup_quoted
                        changed = True
                updated.append(new_value)
            if changed:
                attrs[attr_name] = updated

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
    def _parse_entry_from_lines(
        self,
        lines: t.MutableSequenceOf[str],
    ) -> p.Result[m.Ldif.Entry]:
        """Parse entry from LDIF lines, apply OID→RFC normalization, finalize metadata."""
        result = super()._parse_entry_from_lines(lines)
        if result.failure:
            return result
        entry = result.value
        if entry.dn and str(entry.dn):
            original_dn = str(entry.dn)
            cleaned_dn, _ = u.Ldif.clean_dn_with_statistics(original_dn)
            if cleaned_dn != original_dn:
                entry.dn = m.Ldif.DN.model_validate({"value": cleaned_dn})
        original_dn = str(entry.dn) if entry.dn else ""
        original_attrs = entry.attributes.attributes if entry.attributes else {}
        finalize_result = self._hook_finalize_entry_parse(
            entry,
            original_dn,
            original_attrs,
        )
        if finalize_result.failure:
            return finalize_result
        return self._hook_post_parse_entry(finalize_result.value)

    def _process_orclaci_values(
        self,
        orclaci_values: t.MutableSequenceOf[str] | str | None,
        current_extensions: t.Ldif.MutableMetadataMapping,
    ) -> None:
        """Process orclaci values and extract ACL metadata."""
        if not orclaci_values:
            return
        parent = self._get_parent_server_safe()
        acl_server = parent.acl_server if parent is not None else None
        acl_list = (
            list(orclaci_values)
            if u.matches_type(orclaci_values, (list, tuple))
            else [str(orclaci_values)]
        )
        for acl_value in acl_list:
            if not u.matches_type(acl_value, str):
                continue
            self.extract_acl_metadata_from_string(acl_value, current_extensions)
            if acl_server is not None:
                self._merge_parsed_acl_extensions(
                    acl_server,
                    acl_value,
                    current_extensions,
                )

    def _restore_boolean_attribute_from_metadata(
        self,
        attr_name: str,
        conv_data: t.MutableAttributeMapping,
        restored_attrs: t.MutableStrSequenceMapping,
    ) -> bool:
        """Restore single boolean attribute from conversion metadata."""
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
        boolean_conversions = self._parse_metadata_boolean_flags(
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
        entry_metadata: m.Ldif.EntryMetadata | None = None
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

    def restore_entry_from_metadata(self, entry_data: m.Ldif.Entry) -> m.Ldif.Entry:
        """Restore OID-specific formats from metadata (RFC → OID denormalization)."""
        restored_entry = self._restore_boolean_values_to_oid(entry_data)
        metadata = restored_entry.metadata
        attributes = restored_entry.attributes
        if metadata is None or attributes is None:
            return restored_entry
        rename_map_raw = metadata.extensions.get("attribute_name_renames")
        rename_map: t.JsonPayload | None = rename_map_raw
        if not isinstance(rename_map, Mapping) or not rename_map:
            return restored_entry
        restored_attrs = dict(attributes.attributes)
        changed = False
        for current_name, original_name in rename_map.items():
            if not isinstance(original_name, str):
                continue
            current_values = restored_attrs.pop(current_name, None)
            if current_values is None or original_name in restored_attrs:
                continue
            restored_attrs[original_name] = list(current_values)
            changed = True
        if not changed:
            return restored_entry
        restored_copy: m.Ldif.Entry = restored_entry.model_copy(
            update={
                "attributes": m.Ldif.Attributes.model_validate({
                    "attributes": restored_attrs,
                    "attribute_metadata": attributes.attribute_metadata,
                    "metadata": attributes.metadata,
                }),
            },
        )
        return restored_copy

    @override
    def _write_entry(self, entry_data: m.Ldif.Entry) -> p.Result[str]:
        """Write OID entry preserving OID-specific denormalized attribute names."""
        entry_to_write = self.restore_entry_from_metadata(entry_data)
        return super()._write_entry(entry_to_write)

    def _restore_single_attribute(
        self,
        attr_name: str,
        attr_values: t.MutableSequenceOf[str],
        original_attrs: t.MutableStrSequenceMapping | None,
    ) -> tuple[str, t.MutableSequenceOf[str]]:
        """Restore attribute from metadata or apply denormalization."""
        if original_attrs:
            for orig_name, orig_values in original_attrs.items():
                if self._normalize_attribute_name(orig_name) == attr_name:
                    restored_values = list(orig_values)
                    return (orig_name, restored_values)
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
        write_options: m.Ldif.WriteFormatOptions | None,
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
        ldif_lines: t.MutableSequenceOf[str],
        entry_data: m.Ldif.Entry,
        original_attr_lines_complete: t.MutableSequenceOf[str],
        write_options: m.Ldif.WriteFormatOptions | None,
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
