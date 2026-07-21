"""OUD entry — AclMetadata helpers.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudHelpersMixin``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import ClassVar

from flext_ldif import c, m, p, t, u


class FlextLdifServersOudAclMetadataMixin:
    """OUD AclMetadata helpers."""

    ACL_KEY_MAP: ClassVar[t.MappingKV[str, str]] = MappingProxyType({
        "extop": c.Ldif.ACL_EXTOP,
        "ip": c.Ldif.ACL_BIND_IP_FILTER,
        "bind_ip": c.Ldif.ACL_BIND_IP_FILTER,
        "dns": c.Ldif.ACL_BIND_DNS,
        "bind_dns": c.Ldif.ACL_BIND_DNS,
        "dayofweek": c.Ldif.ACL_BIND_DAYOFWEEK,
        "bind_dayofweek": c.Ldif.ACL_BIND_DAYOFWEEK,
        "timeofday": c.Ldif.ACL_BIND_TIMEOFDAY,
        "bind_timeofday": c.Ldif.ACL_BIND_TIMEOFDAY,
        "authmethod": c.Ldif.ACL_AUTHMETHOD,
        "ssf": c.Ldif.ACL_SSF,
        "targetcontrol": "targetcontrol",
        "targetscope": "targetscope",
        "targattrfilters": c.Ldif.ACL_TARGETATTR_FILTERS,
    })
    "Mapping: OUD extension key → canonical c.Ldif.ACL_* metadata key."

    PARSED_ACL_KEY_MAP: ClassVar[t.MappingKV[str, str]] = MappingProxyType({
        "targattrfilters": c.Ldif.ACL_TARGETATTR_FILTERS,
        "targetcontrol": c.Ldif.ACL_TARGET_CONTROL,
        "extop": c.Ldif.ACL_EXTOP,
        "ip": c.Ldif.ACL_BIND_IP_FILTER,
        "dns": c.Ldif.ACL_TARGETSCOPE,
        "dayofweek": c.Ldif.ACL_NUMBERING,
        "timeofday": c.Ldif.ACL_BINDMODE,
        "authmethod": c.Ldif.ACL_SOURCE_PERMISSIONS,
        "ssf": c.Ldif.ACL_SSFS,
    })
    "Mapping for parsed-ACL extensions: short alias → canonical c.Ldif.ACL_* key."

    @staticmethod
    def extract_acl_metadata(
        # NOTE (multi-agent, mro-0ftd.3.7.2): behavior layer accepts protocol (§3.2).
        entry_data: p.Ldif.Entry,
    ) -> tuple[str | None, p.Ldif.DnRegistry | None]:
        """Extract base_dn and dn_registry from entry metadata for ACL processing."""
        base_dn: str | None = None
        dn_registry: p.Ldif.DnRegistry | None = None
        metadata = entry_data.metadata
        extensions = metadata.extensions if metadata is not None else None
        if extensions is not None:
            base_dn_raw = extensions.get(c.Ldif.BASE_DN)
            base_dn = u.to_str(base_dn_raw) or base_dn
            dn_registry_raw = extensions.get(c.Ldif.DN_REGISTRY)
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
    def extract_acl_metadata_from_dict(
        acl_extensions: t.Ldif.MetadataInputMapping,
        acl_metadata_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> None:
        """Extract ACL metadata from dict extensions."""
        for (
            src_key,
            dest_key,
        ) in FlextLdifServersOudAclMetadataMixin.ACL_KEY_MAP.items():
            value_raw = acl_extensions.get(src_key)
            if value_raw is not None:
                acl_metadata_extensions[dest_key] = u.normalize_to_metadata(value_raw)

    @staticmethod
    def get_original_acl_attr(entry: p.Ldif.Entry) -> str:
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
                    original_attr_name: str = attr_name
                    return original_attr_name
        if entry.metadata and entry.metadata.extensions:
            acl_original_format = u.to_str(
                entry.metadata.extensions.get("original_format"),
            )
            if "orclaci:" in acl_original_format:
                return "orclaci"
        return "orclaci"

    @staticmethod
    def merge_acl_metadata_to_entry(
        # NOTE (multi-agent, mro-0ftd.3.7.2): protocol payload (§3.2).
        entry: p.Ldif.Entry,
        acl_metadata_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> p.Ldif.Entry:
        """Merge ACL metadata extensions into entry metadata."""
        if not acl_metadata_extensions:
            return entry
        if entry.metadata is None:
            new_metadata_entry: p.Ldif.Entry = entry.model_copy(
                update={
                    "metadata": u.Ldif.server_metadata_for(
                        "oud",
                        extensions=acl_metadata_extensions,
                    ),
                },
                deep=True,
            )
            return new_metadata_entry
        # mro-wgwh.5 (agent: kimi-coder) — DynamicMetadata removed: merge plain mappings.
        current: t.MutableJsonMapping = (
            dict(entry.metadata.extensions) if entry.metadata.extensions else {}
        )
        current.update(acl_metadata_extensions)
        updated_entry: p.Ldif.Entry = entry.model_copy(
            update={
                "metadata": entry.metadata.model_copy(
                    update={"extensions": current},
                    deep=True,
                ),
            },
            deep=True,
        )
        return updated_entry

    @staticmethod
    def process_parsed_acl_extensions(
        acl_extensions: t.Ldif.MetadataInputMapping,
        current_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> None:
        """Process parsed ACL extensions and add to current extensions."""
        key_map = FlextLdifServersOudAclMetadataMixin.PARSED_ACL_KEY_MAP
        canonical_keys = frozenset(key_map.values())
        for key, value in acl_extensions.items():
            final_key = key_map.get(key) or key_map.get(key.lower()) or key
            if final_key not in canonical_keys and key not in canonical_keys:
                final_key = key
            if value is None or u.primitive(value):
                current_extensions[final_key] = value
            elif isinstance(value, t.SEQUENCE_PAIR_TYPES):
                current_extensions[final_key] = (
                    t.Cli.JSON_VALUE_ADAPTER.validate_python(
                        [
                            item if item is None or u.primitive(item) else str(item)
                            for item in value
                        ],
                    )
                )
            elif isinstance(value, Mapping):
                value_dict_inner: t.MutableJsonMapping = {}
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
