"""Oracle Unified Directory (OUD) Servers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific servers for schema, ACL, and entry processing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, ClassVar, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
from flext_ldif.servers._oud.helpers import FlextLdifServersOudHelpersMixin
from flext_ldif.servers.rfc import FlextLdifServersRfc

if TYPE_CHECKING:
    from flext_ldif.servers.base import FlextLdifServersBase


class FlextLdifServersOudEntry(FlextLdifServersRfc.Entry):
    """Oracle OUD Entry implementation extending RFC 2849.

    OUD-specific overrides: ``can_handle`` (DN/attribute pattern detection),
    ``parse_server`` / ``parse_entry`` / ``_hook_post_parse_entry``
    (OUD post-processing), ``_hook_pre_write_entry`` / ``_write_entry``
    (ACI normalization + comment generation). Stateless helpers come from
    ``FlextLdifServersOudHelpersMixin`` (composed Mixin facade).
    """

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    def __init__(
        self,
        entry_service: p.Ldif.EntryServer | None = None,
        _parent_server: FlextLdifServersBase | None = None,
    ) -> None:
        """Initialize OUD entry server."""
        FlextLdifServersBaseEntry.__init__(
            self,
            entry_service,
            _parent_server=None,
        )
        if _parent_server is not None:
            object.__setattr__(self, "_parent_server", _parent_server)

    @override
    def can_handle(
        self,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
    ) -> bool:
        """Match OUD-specific DN/attribute patterns or fall back on objectclass."""
        oud_constants = FlextLdifServersOudConstants
        patterns_config = m.Ldif.ServerPatternsConfig(
            dn_patterns=oud_constants.DN_DETECTION_PATTERNS,
            attr_prefixes=oud_constants.DETECTION_ATTRIBUTE_PREFIXES,
            attr_names=oud_constants.BOOLEAN_ATTRIBUTES,
            keyword_patterns=oud_constants.KEYWORD_PATTERNS,
        )
        return (
            u.Ldif.matches_entry_server_patterns(entry_dn, attributes, patterns_config)
            or "objectclass" in attributes
        )

    @override
    # NOTE (multi-agent, mro-0ftd.3.7.2): return Sequence to match the base SSOT
    # (servers/_base/entry.py parse_server -> p.Result[Sequence[p.Ldif.Entry]]).
    def parse_server(self, value: str) -> p.Result[Sequence[p.Ldif.Entry]]:
        """Parse LDIF content and apply OUD post-processing hooks."""
        parsed_result = super().parse_server(value)
        if parsed_result.failure:
            return parsed_result
        processed_entries: t.MutableSequenceOf[p.Ldif.Entry] = []
        for parsed_entry in parsed_result.value:
            post_parse_result = self._hook_post_parse_entry(parsed_entry)
            if post_parse_result.failure:
                return r[Sequence[p.Ldif.Entry]].fail(
                    post_parse_result.error or "OUD post-parse failed",
                )
            entry_after_post: p.Ldif.Entry = post_parse_result.value
            original_dn = entry_after_post.dn.value if entry_after_post.dn else ""
            original_attrs: t.MutableStrSequenceMapping = (
                entry_after_post.attributes.attributes
                if entry_after_post.attributes
                and entry_after_post.attributes.attributes
                else {}
            )
            finalize_result = self._hook_finalize_entry_parse(
                entry_after_post,
                original_dn,
                original_attrs,
            )
            if finalize_result.failure:
                return r[Sequence[p.Ldif.Entry]].fail(
                    finalize_result.error or "OUD finalize parse failed",
                )
            processed_entries.append(finalize_result.value)
        return r[Sequence[p.Ldif.Entry]].ok(processed_entries)

    @override
    def parse_entry(
        self,
        entry_dn: str,
        entry_attrs: t.MutableStrSequenceMapping | p.Ldif.Entry,
    ) -> p.Result[p.Ldif.Entry]:
        """Delegate RFC parse, then enrich entry metadata with OUD round-trip context."""
        entry_attrs_dict: t.MutableStrSequenceMapping = {}
        if isinstance(entry_attrs, Mapping):
            for key, values in entry_attrs.items():
                entry_attrs_dict[key] = list(values)
        elif entry_attrs.attributes and entry_attrs.attributes.attributes:
            entry_attrs_dict = {
                k: list(vs) for k, vs in entry_attrs.attributes.attributes.items()
            }
        result = super().parse_entry(entry_dn, entry_attrs_dict)
        if result.failure:
            return result
        entry = result.value
        original_attribute_case: t.MutableStrMapping = {}
        for attr_name in entry_attrs_dict:
            original_attribute_case[attr_name.lower()] = attr_name
        metadata_config = m.Ldif.EntryParseMetadataConfig.model_validate({
            "server_type": c.Ldif.ServerTypes.OUD,
            "original_entry_dn": entry_dn,
            "cleaned_dn": str(entry.dn) if entry.dn else entry_dn,
            "original_dn_line": f"dn: {entry_dn}",
            "original_attr_lines": [],
            "dn_was_base64": False,
            "original_attribute_case": original_attribute_case,
        })
        metadata = u.Ldif.build_entry_parse_metadata(
            metadata_config,
        )
        # NOTE (multi-agent, mro-0ftd.3.7.2): metadata is a read-only protocol
        # property; transition via model_copy (Pydantic-2 canon) instead of assigning.
        entry = entry.model_copy(update={"metadata": metadata})
        return r[p.Ldif.Entry].ok(entry)

    def _hook_finalize_entry_parse(
        self,
        entry: p.Ldif.Entry,
        original_dn: str,
        original_attrs: t.AttributeMapping,
    ) -> p.Result[p.Ldif.Entry]:
        """Process ACL attributes (aci) into entry.metadata.extensions."""
        _ = original_dn
        aci_values = FlextLdifServersOudHelpersMixin.find_aci_values(
            entry,
            original_attrs,
        )
        if not aci_values:
            return r[p.Ldif.Entry].ok(entry)
        parent = self._get_parent_server_safe()
        acl_server = parent.acl_server if parent is not None else None
        if acl_server is None:
            return r[p.Ldif.Entry].ok(entry)
        # NOTE (multi-agent, mro-0ftd.3.7.2): metadata is a read-only protocol
        # property; build the updated metadata locally and transition the entry once
        # via model_copy (Pydantic-2 frozen-transition canon).
        metadata = entry.metadata or u.Ldif.server_metadata_for("oud")
        existing: t.Ldif.MutableMetadataInputMapping = (
            dict(metadata.extensions) if metadata.extensions else {}
        )
        FlextLdifServersOudHelpersMixin.process_aci_list_for_finalize(
            aci_values,
            acl_server,
            existing,
        )
        if existing:
            metadata = metadata.model_copy(
                update={
                    "extensions": existing,
                },
            )
        entry = entry.model_copy(update={"metadata": metadata})
        return r[p.Ldif.Entry].ok(entry)

    @override
    def _hook_post_parse_entry(self, entry: p.Ldif.Entry) -> p.Result[p.Ldif.Entry]:
        """Validate OUD ACI macros and merge ACL metadata into the parsed entry."""
        attrs_dict: t.MutableStrSequenceMapping = (
            entry.attributes.attributes if entry.attributes is not None else {}
        )
        aci_attrs = attrs_dict.get("aci")
        if aci_attrs and u.matches_type(aci_attrs, (list, tuple)):
            has_macros = False
            acl_metadata_extensions: t.Ldif.MutableMetadataInputMapping = {}
            for aci_value in aci_attrs:
                if u.matches_type(aci_value, str):
                    process_result = (
                        FlextLdifServersOudHelpersMixin.process_single_aci_value(
                            aci_value,
                            acl_metadata_extensions,
                        )
                    )
                    if process_result.failure:
                        return r[p.Ldif.Entry].fail(
                            process_result.error or "ACI processing failed",
                        )
                    if process_result.value:
                        has_macros = True
            if has_macros:
                aci_list = (
                    list(aci_attrs)
                    if u.matches_type(aci_attrs, (list, tuple))
                    else [str(aci_attrs)]
                )
                FlextLdifServersOudEntry._module_logger.debug(
                    "Entry contains OUD ACI macros - preserved for runtime expansion",
                    entry_dn=str(entry.dn) if entry.dn else "",
                    aci_count=len(aci_list),
                )
            entry = FlextLdifServersOudHelpersMixin.merge_acl_metadata_to_entry(
                entry,
                acl_metadata_extensions,
            )
        return r[p.Ldif.Entry].ok(entry)

    @override
    def _hook_pre_write_entry(self, entry: p.Ldif.Entry) -> p.Result[p.Ldif.Entry]:
        """Pre-write hook — entry is already RFC-canonical, no transformation needed."""
        return r[p.Ldif.Entry].ok(entry)

    @override
    def _write_entry(self, entry_data: p.Ldif.Entry) -> p.Result[str]:
        """Write entry with OUD pre-write hook + phase-aware ACL handling + DN normalization."""
        hook_result = self._hook_pre_write_entry(entry_data)
        if hook_result.failure:
            return r[str].fail_op("Pre-write hook", hook_result.error)
        normalized_entry = hook_result.value
        entry_to_write = FlextLdifServersOudHelpersMixin.restore_entry_from_metadata(
            normalized_entry,
        )
        write_options = self._extract_write_format_options(entry_to_write.metadata)
        ldif_parts: t.MutableSequenceOf[str] = []
        ldif_parts.extend(
            FlextLdifServersOudHelpersMixin.add_original_entry_comments(
                entry_data,
                write_options,
            ),
        )
        entry_data = FlextLdifServersOudHelpersMixin.apply_phase_aware_acl_handling(
            entry_data,
            write_options,
        )
        if FlextLdifServersOudConstants.ACL_NORMALIZE_DNS_IN_VALUES:
            entry_data = FlextLdifServersOudHelpersMixin.normalize_acl_dns(entry_data)
        return (
            super()
            ._write_entry(entry_data)
            .map(lambda ldif_text: u.Ldif.finalize_ldif_text([*ldif_parts, ldif_text]))
        )
