"""Oracle Internet Directory (OID) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, override

from flext_ldif import m, p, t, u
from flext_ldif.servers._oid.entry_boolean import FlextLdifServersOidEntryBooleanMixin
from flext_ldif.servers._oid.entry_metadata import FlextLdifServersOidEntryMetadataMixin
from flext_ldif.servers._oid.entry_normalize import (
    FlextLdifServersOidEntryNormalizeMixin,
)
from flext_ldif.servers._oid.entry_parse import FlextLdifServersOidEntryParseMixin
from flext_ldif.servers._oid.entry_restore import FlextLdifServersOidEntryRestoreMixin
from flext_ldif.servers._oid.entry_restore_lines import (
    FlextLdifServersOidEntryRestoreLinesMixin,
)
from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidEntry(
    FlextLdifServersOidEntryBooleanMixin,
    FlextLdifServersOidEntryMetadataMixin,
    FlextLdifServersOidEntryParseMixin,
    FlextLdifServersOidEntryRestoreLinesMixin,
    FlextLdifServersOidEntryRestoreMixin,
    FlextLdifServersOidEntryNormalizeMixin,
    FlextLdifServersRfc.Entry,
):
    """Oracle Internet Directory (OID) Entry implementation.

    OID-specific behavior is composed from focused mixins: boolean value
    conversion (``entry_boolean``), metadata extraction (``entry_metadata``),
    parse hooks (``entry_parse``), round-trip attribute restore
    (``entry_restore``), original-line restoration (``entry_restore_lines``),
    and schema value normalization (``entry_normalize``).
    """

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @override
    def _normalize_attribute_name(self, attr_name: str) -> str:
        """Normalize OID attribute names to RFC-canonical format.

        Returns:
            The resulting ``str``.
        """
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
        """Parse entry from LDIF lines, apply OID→RFC normalization, finalize metadata.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
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

    @override
    def _write_entry(self, entry_data: m.Ldif.Entry) -> p.Result[str]:
        """Write OID entry preserving OID-specific denormalized attribute names.

        Returns:
            The resulting ``p.Result[str]``.
        """
        entry_to_write = self.restore_entry_from_metadata(entry_data)
        return super()._write_entry(entry_to_write)
