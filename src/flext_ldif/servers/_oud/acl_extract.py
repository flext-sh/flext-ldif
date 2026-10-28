"""OUD entry — AclExtract helpers.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudHelpers``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import MutableSequence

from flext_ldif import c, m, t, u


class FlextLdifServersOudAclExtract:
    """OUD AclExtract helpers."""

    @staticmethod
    def comment_acl_attributes(
        entry_data: m.Ldif.Entry,
        acl_attribute_names: t.Ldif.AclAttributeNames,
    ) -> m.Ldif.Entry:
        """Comment out ACL attributes by removing them from attributes dict and.

        # storing in metadata.

        Returns:
            The resulting ``m.Ldif.Entry``.

        """
        if not entry_data.attributes or not acl_attribute_names:
            return entry_data
        new_attributes_dict, commented_acl_values, hidden_attrs = (
            FlextLdifServersOudAclExtract.extract_and_remove_acl_attributes(
                entry_data.attributes.attributes,
                acl_attribute_names,
            )
        )
        if not commented_acl_values:
            return entry_data
        existing_metadata = entry_data.metadata
        if existing_metadata is None:
            existing_metadata = m.Ldif.ServerMetadata(
                server_type=c.Ldif.ServerTypes.OUD,
            )
        updated_metadata = (
            FlextLdifServersOudAclExtract.update_metadata_with_commented_acls(
                existing_metadata,
                acl_attribute_names,
                commented_acl_values,
                hidden_attrs,
                entry_data.attributes.attributes,
            )
        )
        return entry_data.model_copy(
            update={
                "attributes": entry_data.attributes.model_copy(
                    update={"attributes": new_attributes_dict},
                ),
                "metadata": updated_metadata,
            },
        )

    @staticmethod
    def normalize_acl_values(
        acl_values_raw: t.Ldif.ValueType | t.Ldif.MetadataInputMapping,
    ) -> MutableSequence[str] | str:
        """Normalize ACL values to expected type for comment generation.

        Returns:
            The resulting ``MutableSequence[str] | str``.

        """
        if isinstance(acl_values_raw, list):
            return [u.to_str(item) for item in acl_values_raw]
        return u.to_str(acl_values_raw)

    @staticmethod
    def parse_commented_values(
        commented_raw: t.JsonValue | None,
    ) -> t.Ldif.MutableMetadataMapping | None:
        """Parse commented ACL values from raw storage format.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping | None``.

        """
        if isinstance(commented_raw, str):
            parsed_items = u.json_dict_adapter().validate_json(commented_raw).items()
        elif u.matches_type(commented_raw, dict):
            parsed_items = u.json_dict_adapter().validate_python(commented_raw).items()
        else:
            return None
        normalized: t.Ldif.MutableMetadataMapping = {}
        for raw_key, raw_value in parsed_items:
            normalized[raw_key] = u.normalize_to_json_value(raw_value)
        return normalized

    @staticmethod
    def extract_and_remove_acl_attributes(
        attributes_dict: t.MutableStrSequenceMapping,
        acl_attribute_names: t.Ldif.AclAttributeNames,
    ) -> tuple[t.MutableStrSequenceMapping, t.MutableStrSequenceMapping, set[str]]:
        """Extract ACL attributes and remove from active dict.

        Returns:
            The resulting ``tuple[t.MutableStrSequenceMapping,
                t.MutableStrSequenceMapping, set[str]]``.

        """
        new_attrs: t.MutableStrSequenceMapping = dict(attributes_dict)
        commented_vals: t.MutableStrSequenceMapping = {}
        hidden_attrs: set[str] = set()
        for acl_attr in acl_attribute_names:
            if acl_attr in new_attrs:
                commented_vals[acl_attr] = new_attrs.pop(acl_attr)
                hidden_attrs.add(acl_attr.lower())
        return (new_attrs, commented_vals, hidden_attrs)

    @staticmethod
    def update_metadata_with_commented_acls(
        metadata: m.Ldif.ServerMetadata,
        acl_attribute_names: t.Ldif.AclAttributeNames,
        commented_acl_values: t.MutableStrSequenceMapping,
        hidden_attrs: set[str],
        entry_attributes_dict: t.MutableStrSequenceMapping,
    ) -> m.Ldif.ServerMetadata:
        """Update metadata with commented ACL information.

        Returns:
            The resulting ``m.Ldif.ServerMetadata``.

        """
        metadata_typed: m.Ldif.ServerMetadata = metadata
        current_extensions: t.Ldif.MutableMetadataInputMapping = (
            dict(metadata_typed.extensions) if metadata_typed.extensions else {}
        )
        hidden_attribute_names: set[str] = set()
        hidden_attrs_raw = current_extensions.get(c.Ldif.HIDDEN_ATTRIBUTES, [])
        if isinstance(hidden_attrs_raw, (list, tuple, frozenset, set)):
            hidden_attribute_names = {str(item).lower() for item in hidden_attrs_raw}
        if metadata_typed.write_options is not None:
            hidden_attribute_names.update(
                attr.lower() for attr in metadata_typed.write_options.hidden_attrs
            )
            if metadata_typed.write_options.base_dn is not None:
                current_extensions.setdefault(
                    c.Ldif.BASE_DN,
                    metadata_typed.write_options.base_dn,
                )
        hidden_attribute_names.update(attr.lower() for attr in hidden_attrs)
        if hidden_attribute_names:
            current_extensions[c.Ldif.HIDDEN_ATTRIBUTES] = (
                u.Cli.JSON_VALUE_ADAPTER.validate_python(sorted(hidden_attribute_names))
            )
        if commented_acl_values:
            converted_attrs_list: MutableSequence[str] = list(
                commented_acl_values.keys(),
            )
            current_extensions[c.Ldif.CONVERTED_ATTRIBUTES] = (
                u.Cli.JSON_VALUE_ADAPTER.validate_python(converted_attrs_list)
            )
            current_extensions[c.Ldif.COMMENTED_ATTRIBUTE_VALUES] = (
                u.Ldif.dump_json_payload({
                    comment_key: u.Cli.JSON_VALUE_ADAPTER.validate_python(comment_value)
                    for comment_key, comment_value in commented_acl_values.items()
                })
            )
        commented_attrs_raw = current_extensions.get(
            c.Ldif.ACL_COMMENTED_ATTRIBUTES,
            [],
        )
        commented_attrs: MutableSequence[str] = (
            [str(x) for x in commented_attrs_raw]
            if isinstance(commented_attrs_raw, list)
            else []
        )
        for acl_attr in acl_attribute_names:
            if acl_attr in entry_attributes_dict and acl_attr not in commented_attrs:
                commented_attrs.append(acl_attr)
        if commented_attrs:
            current_extensions[c.Ldif.ACL_COMMENTED_ATTRIBUTES] = (
                u.Cli.JSON_VALUE_ADAPTER.validate_python(commented_attrs)
            )
        return metadata_typed.model_copy(update={"extensions": current_extensions})


__all__: list[str] = ["FlextLdifServersOudAclExtract"]
