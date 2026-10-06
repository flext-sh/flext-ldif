"""Oracle Internet Directory (OID) entry server — metadata extraction helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidEntryMetadataMixin(FlextLdifServersRfc.Entry):
    """OID entry metadata extraction helpers."""

    @staticmethod
    def extract_acl_metadata_from_string(
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
    @staticmethod
    def _parse_metadata_boolean_flags(
        entry_data: m.Ldif.Entry,
    ) -> MutableMapping[str, t.MutableAttributeMapping]:
        """Extract boolean conversions from entry metadata.

        Returns:
            The resulting ``MutableMapping[str, t.MutableAttributeMapping]``.
        """
        mk = c.Ldif
        boolean_conversions: MutableMapping[str, t.MutableAttributeMapping] = {}
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
                        value_metadata: t.MutableJsonMapping = (
                            t.json_dict_adapter().validate_python(value)
                        )
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
    @staticmethod
    def _extract_original_extensions(
        original_entry: m.Ldif.Entry,
    ) -> t.Ldif.MutableMetadataMapping:
        """Extract compatible extensions from original entry metadata.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping``.
        """
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


__all__: list[str] = ["FlextLdifServersOidEntryMetadataMixin"]
