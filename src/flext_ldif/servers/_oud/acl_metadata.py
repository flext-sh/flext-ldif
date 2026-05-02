"""OUD entry — AclMetadata helpers.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudHelpersMixin``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from types import MappingProxyType

from flext_ldif import (
    c,
    m,
    t,
    u,
)

logger = u.fetch_logger(__name__)


class FlextLdifServersOudAclMetadataMixin:
    """OUD AclMetadata helpers."""

    _ACL_METADATA_KEY_MAPPING_CACHE: t.MappingKV[str, str] | None = None

    @classmethod
    def _acl_metadata_key_mapping(cls) -> t.MappingKV[str, str]:
        """Lazy frozen mapping: ACL extension key → canonical metadata key."""
        cached_raw = cls.__dict__.get("_ACL_METADATA_KEY_MAPPING_CACHE")
        if isinstance(cached_raw, Mapping):
            return cached_raw
        mk = c.Ldif
        cached: t.MappingKV[str, str] = MappingProxyType({
            "extop": mk.ACL_EXTOP,
            "ip": mk.ACL_BIND_IP_FILTER,
            "bind_ip": mk.ACL_BIND_IP_FILTER,
            "dns": mk.ACL_BIND_DNS,
            "bind_dns": mk.ACL_BIND_DNS,
            "dayofweek": mk.ACL_BIND_DAYOFWEEK,
            "bind_dayofweek": mk.ACL_BIND_DAYOFWEEK,
            "timeofday": mk.ACL_BIND_TIMEOFDAY,
            "bind_timeofday": mk.ACL_BIND_TIMEOFDAY,
            "authmethod": mk.ACL_AUTHMETHOD,
            "ssf": mk.ACL_SSF,
            "targetcontrol": "targetcontrol",
            "targetscope": "targetscope",
            "targattrfilters": mk.ACL_TARGETATTR_FILTERS,
        })
        cls._ACL_METADATA_KEY_MAPPING_CACHE = cached
        return cached

    @staticmethod
    def _extract_acl_metadata(
        entry_data: m.Ldif.Entry,
    ) -> tuple[str | None, m.Ldif.DnRegistry | None]:
        """Extract base_dn and dn_registry from entry metadata for ACL processing."""
        base_dn: str | None = None
        dn_registry: m.Ldif.DnRegistry | None = None
        metadata = entry_data.metadata
        extensions = metadata.extensions if metadata is not None else None
        if extensions is not None:
            extensions_dict = extensions.to_dict()
            base_dn_raw = extensions_dict.get(c.Ldif.BASE_DN)
            base_dn = u.to_str(base_dn_raw) or base_dn
            dn_registry_raw = extensions_dict.get(c.Ldif.DN_REGISTRY)
            dn_registry = (
                m.Ldif.DnRegistry.model_validate(dn_registry_raw)
                if dn_registry_raw is not None
                else None
            )
        if (
            (base_dn is None or dn_registry is None)
            and entry_data.metadata
            and entry_data.metadata.write_options
        ):
            base_dn_value = getattr(entry_data.metadata.write_options, "base_dn", None)
            if base_dn is None and isinstance(base_dn_value, str):
                base_dn = base_dn_value
            dn_registry_value = getattr(
                entry_data.metadata.write_options,
                "dn_registry",
                None,
            )
            if dn_registry is None and isinstance(dn_registry_value, m.Ldif.DnRegistry):
                dn_registry = dn_registry_value
        return (base_dn, dn_registry)

    @staticmethod
    def _extract_acl_metadata_from_dict(
        acl_extensions: t.Ldif.MetadataInputMapping,
        acl_metadata_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> None:
        """Extract ACL metadata from dict extensions."""
        for (
            src_key,
            dest_key,
        ) in FlextLdifServersOudAclMetadataMixin._acl_metadata_key_mapping().items():
            value_raw = acl_extensions.get(src_key)
            if value_raw is not None:
                acl_metadata_extensions[dest_key] = u.normalize_to_metadata(value_raw)

    @staticmethod
    def _extract_acl_metadata_from_dynamic(
        acl_extensions: m.Ldif.DynamicMetadata,
        acl_metadata_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> None:
        """Extract ACL metadata from DynamicMetadata extensions."""
        extensions_dict = acl_extensions.to_dict()
        for (
            src_key,
            dest_key,
        ) in FlextLdifServersOudAclMetadataMixin._acl_metadata_key_mapping().items():
            if src_key not in extensions_dict:
                continue
            value_raw = extensions_dict[src_key]
            acl_metadata_extensions[dest_key] = u.normalize_to_metadata(value_raw)

    @staticmethod
    def _get_original_acl_attr(entry: m.Ldif.Entry) -> str:
        """Get original ACL attribute name (orclaci) from transformations or metadata."""
        if entry.metadata and entry.metadata.attribute_transformations:
            for (
                attr_name,
                transformation,
            ) in entry.metadata.attribute_transformations.items():
                if (
                    attr_name.lower() in {"aci", "orclaci"}
                    and transformation.target_name
                    and (transformation.target_name.lower() == "aci")
                ):
                    return attr_name
        if entry.metadata and entry.metadata.extensions:
            acl_original_format = u.to_str(
                entry.metadata.extensions.get("original_format"),
            )
            if "orclaci:" in acl_original_format:
                return "orclaci"
        return "orclaci"

    @staticmethod
    def _merge_acl_metadata_to_entry(
        entry: m.Ldif.Entry,
        acl_metadata_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> m.Ldif.Entry:
        """Merge ACL metadata extensions into entry metadata."""
        if not acl_metadata_extensions:
            return entry
        if entry.metadata:
            current_extensions: t.Ldif.MutableMetadataInputMapping = (
                dict(entry.metadata.extensions.to_dict())
                if entry.metadata.extensions
                else {}
            )
            current_extensions.update(acl_metadata_extensions)
            merged_extensions = m.Ldif.DynamicMetadata.from_dict(
                current_extensions,
            )
            merged_entry: m.Ldif.Entry = entry.model_copy(
                update={
                    "metadata": entry.metadata.model_copy(
                        update={"extensions": merged_extensions},
                        deep=True,
                    ),
                },
                deep=True,
            )
            return merged_entry
        entry_metadata = m.Ldif.ServerMetadata.create_for(
            "oud",
            extensions=m.Ldif.DynamicMetadata.from_dict(
                acl_metadata_extensions,
            ),
        )
        copy_entry: m.Ldif.Entry = entry.model_copy(
            update={"metadata": entry_metadata},
            deep=True,
        )
        return copy_entry

    @staticmethod
    def _process_parsed_acl_extensions(
        acl_extensions: t.Ldif.MetadataInputMapping,
        current_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> None:
        """Process parsed ACL extensions and add to current extensions."""
        mk = c.Ldif
        key_mapping: t.MutableStrMapping = {
            "targattrfilters": mk.ACL_TARGETATTR_FILTERS,
            "targetcontrol": mk.ACL_TARGET_CONTROL,
            "extop": mk.ACL_EXTOP,
            "ip": mk.ACL_BIND_IP_FILTER,
            "dns": mk.ACL_TARGETSCOPE,
            "dayofweek": mk.ACL_NUMBERING,
            "timeofday": mk.ACL_BINDMODE,
            "authmethod": mk.ACL_SOURCE_PERMISSIONS,
            "ssf": mk.ACL_SSFS,
            mk.ACL_TARGETATTR_FILTERS: mk.ACL_TARGETATTR_FILTERS,
            mk.ACL_TARGET_CONTROL: mk.ACL_TARGET_CONTROL,
            mk.ACL_EXTOP: mk.ACL_EXTOP,
            mk.ACL_BIND_IP_FILTER: mk.ACL_BIND_IP_FILTER,
            mk.ACL_TARGETSCOPE: mk.ACL_TARGETSCOPE,
            mk.ACL_NUMBERING: mk.ACL_NUMBERING,
            mk.ACL_BINDMODE: mk.ACL_BINDMODE,
            mk.ACL_SOURCE_PERMISSIONS: mk.ACL_SOURCE_PERMISSIONS,
            mk.ACL_SSFS: mk.ACL_SSFS,
        }
        known_keys = {
            mk.ACL_TARGETATTR_FILTERS,
            mk.ACL_TARGET_CONTROL,
            mk.ACL_EXTOP,
            mk.ACL_BIND_IP_FILTER,
            mk.ACL_TARGETSCOPE,
            mk.ACL_NUMBERING,
            mk.ACL_BINDMODE,
            mk.ACL_SOURCE_PERMISSIONS,
            mk.ACL_SSFS,
        }
        for key, value in acl_extensions.items():
            key_lower = key.lower()
            mapped_key = key_mapping.get(key) or key_mapping.get(key_lower)
            if mapped_key is None and key in known_keys:
                mapped_key = key
            final_key = mapped_key or key
            if value is None or u.primitive(value):
                current_extensions[final_key] = value
            elif isinstance(value, (list, tuple)):
                current_extensions[final_key] = (
                    t.Cli.JSON_VALUE_ADAPTER.validate_python(
                        [
                            item if item is None or u.primitive(item) else str(item)
                            for item in value
                        ],
                    )
                )
            elif isinstance(value, Mapping):
                value_dict_inner: MutableMapping[str, t.JsonValue] = {}
                for k, v in value.items():
                    key = k
                    value_dict_inner[key] = (
                        v
                        if u.primitive(v)
                        else t.Cli.JSON_VALUE_ADAPTER.validate_python(v)
                    )
                current_extensions[final_key] = (
                    t.Cli.JSON_VALUE_ADAPTER.validate_python(
                        value_dict_inner,
                    )
                )
            else:
                current_extensions[final_key] = str(value)


__all__: list[str] = ["FlextLdifServersOudAclMetadataMixin"]
