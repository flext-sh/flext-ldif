"""OUD entry — AclExtract helpers.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudHelpersMixin``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping

from flext_ldif import (
    c,
    m,
    t,
    u,
)


class FlextLdifServersOudAclExtractMixin:
    """OUD AclExtract helpers."""

    @staticmethod
    def comment_acl_attributes(
        entry_data: p.Ldif.Entry,
        acl_attribute_names: t.MutableSequenceOf[str],
    ) -> p.Ldif.Entry:
        """Comment out ACL attributes by removing them from attributes dict and storing in metadata."""
        if not entry_data.attributes or not acl_attribute_names:
            return entry_data
        existing_metadata = entry_data.metadata
        if not existing_metadata:
            existing_metadata = u.Ldif.server_metadata_for("oud")
        else:
            existing_metadata = m.Ldif.ServerMetadata.model_validate(
                existing_metadata.model_dump(),
            )
        new_attributes_dict, commented_acl_values, hidden_attrs = (
            FlextLdifServersOudAclExtractMixin.extract_and_remove_acl_attributes(
                entry_data.attributes.attributes,
                acl_attribute_names,
            )
        )
        updated_metadata = (
            FlextLdifServersOudAclExtractMixin.update_metadata_with_commented_acls(
                existing_metadata,
                acl_attribute_names,
                commented_acl_values,
                hidden_attrs,
                entry_data.attributes.attributes,
            )
        )
        copy_result: p.Ldif.Entry = entry_data.model_copy(
            update={
                "attributes": m.Ldif.Attributes.model_validate({
                    "attributes": {**new_attributes_dict},
                    "attribute_metadata": entry_data.attributes.attribute_metadata,
                    "metadata": entry_data.attributes.metadata,
                }),
                "metadata": updated_metadata,
            },
        )
        return copy_result

    @staticmethod
    def normalize_acl_values(
        acl_values_raw: t.Ldif.ValueType | t.Ldif.MetadataInputMapping,
    ) -> t.MutableSequenceOf[str] | str:
        """Normalize ACL values to expected type for comment generation."""
        if isinstance(acl_values_raw, list):
            return [u.to_str(item) for item in acl_values_raw]
        return u.to_str(acl_values_raw)

    @staticmethod
    def parse_commented_values(
        commented_raw: t.JsonValue | None,
    ) -> t.Ldif.MutableMetadataMapping | None:
        """Parse commented ACL values from raw storage format."""
        if isinstance(commented_raw, str):
            parsed_items = t.json_dict_adapter().validate_json(commented_raw).items()
        elif u.matches_type(commented_raw, dict):
            parsed_items = t.json_dict_adapter().validate_python(commented_raw).items()
        else:
            return None
        normalized: t.Ldif.MutableMetadataMapping = {}
        for raw_key, raw_value in parsed_items:
            normalized[raw_key] = u.normalize_to_metadata(raw_value)
        return normalized

    @staticmethod
    def extract_and_remove_acl_attributes(
        attributes_dict: t.MutableStrSequenceMapping,
        acl_attribute_names: t.MutableSequenceOf[str],
    ) -> tuple[
        t.MutableStrSequenceMapping,
        t.MutableStrSequenceMapping,
        set[str],
    ]:
        """Extract ACL attributes and remove from active dict."""
        new_attrs: t.MutableStrSequenceMapping = dict(attributes_dict)
        commented_vals: t.MutableStrSequenceMapping = {}
        hidden_attrs: set[str] = set()
        for acl_attr in acl_attribute_names:
            if acl_attr in new_attrs:
                acl_values = new_attrs[acl_attr]
                if u.matches_type(acl_values, list):
                    commented_vals[acl_attr] = list(acl_values)
                else:
                    commented_vals[acl_attr] = [str(acl_values)]
                del new_attrs[acl_attr]
                hidden_attrs.add(acl_attr.lower())
        return (new_attrs, commented_vals, hidden_attrs)

    @staticmethod
    def update_metadata_with_commented_acls(
        metadata: m.Ldif.ServerMetadata,
        acl_attribute_names: t.MutableSequenceOf[str],
        commented_acl_values: t.MutableStrSequenceMapping,
        hidden_attrs: set[str],
        entry_attributes_dict: t.MutableStrSequenceMapping,
    ) -> p.Ldif.ServerMetadata:
        """Update metadata with commented ACL information."""
        metadata_typed: m.Ldif.ServerMetadata = metadata
        current_extensions: t.Ldif.MutableMetadataInputMapping = (
            dict(metadata_typed.extensions) if metadata_typed.extensions else {}
        )
        hidden_attribute_names: set[str] = set()
        hidden_attrs_raw = current_extensions.get(c.Ldif.HIDDEN_ATTRIBUTES, [])
        if isinstance(hidden_attrs_raw, (list, tuple, frozenset, set)):
            hidden_attribute_names = {str(item).lower() for item in hidden_attrs_raw}
        if metadata_typed.write_options is not None:
            legacy_hidden_attrs = getattr(
                metadata_typed.write_options,
                "hidden_attrs",
                [],
            )
            if isinstance(legacy_hidden_attrs, (list, tuple, frozenset, set)):
                hidden_attribute_names.update(
                    str(item).lower() for item in legacy_hidden_attrs
                )
            base_dn_value = getattr(metadata_typed.write_options, "base_dn", None)
            if isinstance(base_dn_value, str):
                current_extensions.setdefault(c.Ldif.BASE_DN, base_dn_value)
        hidden_attribute_names.update(attr.lower() for attr in hidden_attrs)
        if hidden_attribute_names:
            current_extensions[c.Ldif.HIDDEN_ATTRIBUTES] = (
                t.Cli.JSON_VALUE_ADAPTER.validate_python(
                    sorted(hidden_attribute_names),
                )
            )
        if commented_acl_values:
            converted_attrs_list: t.MutableSequenceOf[str] = list(
                commented_acl_values.keys(),
            )
            current_extensions[c.Ldif.CONVERTED_ATTRIBUTES] = (
                t.Cli.JSON_VALUE_ADAPTER.validate_python(converted_attrs_list)
            )
            current_extensions[c.Ldif.COMMENTED_ATTRIBUTE_VALUES] = (
                u.Ldif.dump_json_payload({
                    comment_key: t.Cli.JSON_VALUE_ADAPTER.validate_python(
                        comment_value,
                    )
                    for comment_key, comment_value in commented_acl_values.items()
                })
            )
        commented_attrs_raw = current_extensions.get(
            c.Ldif.ACL_COMMENTED_ATTRIBUTES,
            [],
        )
        commented_attrs: t.MutableSequenceOf[str] = (
            [str(x) for x in commented_attrs_raw]
            if isinstance(commented_attrs_raw, list)
            else []
        )
        for acl_attr in acl_attribute_names:
            if acl_attr in entry_attributes_dict and acl_attr not in commented_attrs:
                commented_attrs.append(acl_attr)
        if commented_attrs:
            current_extensions[c.Ldif.ACL_COMMENTED_ATTRIBUTES] = (
                t.Cli.JSON_VALUE_ADAPTER.validate_python(commented_attrs)
            )
        update_dict_final: MutableMapping[str, t.Ldif.MutableMetadataInputMapping] = {
            "extensions": current_extensions,
        }
        copy_result: m.Ldif.ServerMetadata = metadata_typed.model_copy(
            update=update_dict_final,
        )
        return copy_result


__all__: list[str] = ["FlextLdifServersOudAclExtractMixin"]
