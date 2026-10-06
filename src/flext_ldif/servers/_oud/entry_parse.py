"""OUD entry — parse orchestration helpers.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudEntry``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_ldif import m, p, r, t, u
from flext_ldif.servers._oud.helpers import FlextLdifServersOudHelpersMixin
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOudEntryParseMixin(FlextLdifServersRfc.Entry):
    """OUD entry parse orchestration (server parse loop + ACL finalize hook)."""

    @override
    def parse_server(
        self,
        value: str,
    ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Parse LDIF content and apply OUD post-processing hooks.

        Returns:
            The resulting ``p.Result[t.MutableSequenceOf[m.Ldif.Entry]]``.
        """
        parsed_result = super().parse_server(value)
        if parsed_result.failure:
            return parsed_result
        processed_entries: t.MutableSequenceOf[m.Ldif.Entry] = []
        for parsed_entry in parsed_result.value:
            post_parse_result = self._hook_post_parse_entry(parsed_entry)
            if post_parse_result.failure:
                return r[t.MutableSequenceOf[m.Ldif.Entry]].from_failure(
                    post_parse_result,
                )
            entry_after_post: m.Ldif.Entry = post_parse_result.value
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
                return r[t.MutableSequenceOf[m.Ldif.Entry]].from_failure(
                    finalize_result,
                )
            processed_entries.append(finalize_result.value)
        return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(processed_entries)

    def _hook_finalize_entry_parse(
        self,
        entry: m.Ldif.Entry,
        original_dn: str,
        original_attrs: t.AttributeMapping,
    ) -> p.Result[m.Ldif.Entry]:
        """Process ACL attributes (aci) into entry.metadata.extensions.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        _ = original_dn
        aci_values = FlextLdifServersOudHelpersMixin.find_aci_values(
            entry,
            original_attrs,
        )
        if not aci_values:
            return r[m.Ldif.Entry].ok(entry)
        parent = self._get_parent_server_safe()
        acl_server = parent.acl_server if parent is not None else None
        if acl_server is None:
            return r[m.Ldif.Entry].ok(entry)
        if entry.metadata is None:
            entry.metadata = u.Ldif.server_metadata_for("oud")
        existing: t.Ldif.MutableMetadataInputMapping = (
            dict(entry.metadata.extensions) if entry.metadata.extensions else {}
        )
        FlextLdifServersOudHelpersMixin.process_aci_list_for_finalize(
            aci_values,
            acl_server,
            existing,
        )
        if existing:
            entry.metadata = entry.metadata.model_copy(update={"extensions": existing})
        return r[m.Ldif.Entry].ok(entry)


__all__: list[str] = ["FlextLdifServersOudEntryParseMixin"]
