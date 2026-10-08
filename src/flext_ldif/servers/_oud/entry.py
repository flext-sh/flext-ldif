"""Oracle Unified Directory (OUD) Servers.

Provides OUD-specific servers for schema, ACL, and entry processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, ClassVar, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._oud.entry_parse import FlextLdifServersOudEntryParseMixin
from flext_ldif.servers.rfc import FlextLdifServersRfc

if TYPE_CHECKING:
    from flext_ldif.servers.base import FlextLdifServersBase


class FlextLdifServersOudEntry(
    FlextLdifServersOudEntryParseMixin,
    FlextLdifServersRfc.Entry,
):
    """Oracle OUD Entry implementation extending RFC 2849.

    OUD-specific overrides: ``can_handle`` (DN/attribute pattern detection),
    ``parse_server`` / ``parse_entry`` / ``_hook_post_parse_entry``
    (OUD post-processing), ``_hook_pre_write_entry`` / ``_write_entry``
    (schema definition normalization + phase-aware ACL handling + comment
    generation). Stateless helpers come from
    ``FlextLdifServersOudHelpersMixin`` (composed Mixin facade); the parse
    loop and ACL finalize hook come from
    ``FlextLdifServersOudEntryParseMixin``.
    """

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    def __init__(
        self,
        entry_service: p.Ldif.EntryServer | None = None,
        _parent_server: FlextLdifServersBase | None = None,
    ) -> None:
        """Initialize OUD entry server."""
        from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry

        FlextLdifServersBaseEntry.__init__(self, entry_service, _parent_server=None)
        if _parent_server is not None:
            object.__setattr__(self, "_parent_server", _parent_server)

    @override
    def can_handle(
        self,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
    ) -> bool:
        """Match OUD-specific DN/attribute patterns or fall back on objectclass.

        Returns:
            The resulting ``bool``.
        """
        from flext_ldif.servers._oud.server_constants import (
            FlextLdifServersOudConstants,
        )

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
    def parse_entry(
        self,
        entry_dn: str,
        entry_attrs: t.MutableStrSequenceMapping | m.Ldif.Entry,
    ) -> p.Result[m.Ldif.Entry]:
        """Delegate RFC parse, then enrich entry metadata with OUD round-trip context.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
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
        metadata = u.Ldif.build_entry_parse_metadata(metadata_config)
        entry.metadata = metadata
        return r[m.Ldif.Entry].ok(entry)

    @override
    def _hook_post_parse_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Validate OUD ACI macros and merge ACL metadata into the parsed entry.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        from flext_ldif.servers._oud.helpers import FlextLdifServersOudHelpersMixin

        attrs_dict: t.MutableStrSequenceMapping = (
            entry.attributes.attributes if entry.attributes is not None else {}
        )
        aci_attrs = attrs_dict.get("aci")
        if not (aci_attrs and u.matches_type(aci_attrs, (list, tuple))):
            return r[m.Ldif.Entry].ok(entry)
        process_result = FlextLdifServersOudEntry._process_aci_attribute_values(
            aci_attrs,
        )
        if process_result.failure:
            return r[m.Ldif.Entry].from_failure(process_result)
        has_macros, acl_metadata_extensions = process_result.value
        if has_macros:
            FlextLdifServersOudEntry._log_aci_macros_preserved(entry, aci_attrs)
        return r[m.Ldif.Entry].ok(
            FlextLdifServersOudHelpersMixin.merge_acl_metadata_to_entry(
                entry,
                acl_metadata_extensions,
            ),
        )

    @staticmethod
    def _process_aci_attribute_values(
        aci_attrs: t.StrSequence,
    ) -> p.Result[t.Pair[bool, t.Ldif.MutableMetadataInputMapping]]:
        """Process each ACI value, accumulating metadata and the macro flag.

        Returns:
            The resulting ``p.Result[t.Pair[bool,
                t.Ldif.MutableMetadataInputMapping]]``.
        """
        from flext_ldif.servers._oud.helpers import FlextLdifServersOudHelpersMixin

        has_macros = False
        acl_metadata_extensions: t.Ldif.MutableMetadataInputMapping = {}
        for aci_value in aci_attrs:
            if not u.matches_type(aci_value, str):
                continue
            process_result = FlextLdifServersOudHelpersMixin.process_single_aci_value(
                aci_value,
                acl_metadata_extensions,
            )
            if process_result.failure:
                return r[t.Pair[bool, t.Ldif.MutableMetadataInputMapping]].from_failure(
                    process_result,
                )
            if process_result.value:
                has_macros = True
        return r[t.Pair[bool, t.Ldif.MutableMetadataInputMapping]].ok((
            has_macros,
            acl_metadata_extensions,
        ))

    @staticmethod
    def _log_aci_macros_preserved(
        entry: m.Ldif.Entry,
        aci_attrs: t.StrSequence,
    ) -> None:
        """Log that an entry carries OUD ACI macros preserved for runtime expansion."""
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

    @override
    def _hook_pre_write_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Normalize schema definitions for OUD (RFC 4512 SYNTAX OIDs) before write.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        from flext_ldif.servers._oud.helpers import FlextLdifServersOudHelpersMixin

        return FlextLdifServersOudHelpersMixin.normalize_schema_definitions_for_write(
            entry,
        )

    @override
    def _write_entry(self, entry_data: m.Ldif.Entry) -> p.Result[str]:
        """Write entry with OUD pre-write hook + phase-aware ACL handling + DN.

        # normalization.

        Returns:
            The resulting ``p.Result[str]``.
        """
        from flext_ldif.servers._oud.helpers import FlextLdifServersOudHelpersMixin
        from flext_ldif.servers._oud.server_constants import (
            FlextLdifServersOudConstants,
        )

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
            normalized_entry,
            write_options,
        )
        if FlextLdifServersOudConstants.ACL_NORMALIZE_DNS_IN_VALUES:
            entry_data = FlextLdifServersOudHelpersMixin.normalize_acl_dns(entry_data)
        return (
            super()
            ._write_entry(entry_data)
            .map(lambda ldif_text: u.Ldif.finalize_ldif_text([*ldif_parts, ldif_text]))
        )
