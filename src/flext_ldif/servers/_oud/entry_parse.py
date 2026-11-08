"""OUD entry — parse orchestration helpers.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudEntry``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import override

from flext_ldif import p, r, t, u
from flext_ldif.servers._oud import FlextLdifServersOudHelpers
from flext_ldif.servers._rfc import FlextLdifServersRfcEntry


class FlextLdifServersOudEntryParse(FlextLdifServersRfcEntry):
    """OUD entry parse orchestration (server parse loop + ACL finalize hook)."""

    @override
    def parse_server(
        self,
        value: str,
    ) -> p.Result[MutableSequence[p.Ldif.Entry]]:
        """Parse LDIF content and apply OUD post-processing hooks.

        Returns:
            The resulting ``p.Result[MutableSequence[p.Ldif.Entry]]``.

        """
        parsed_result = super().parse_server(value)
        if parsed_result.failure:
            return parsed_result
        processed_entries: MutableSequence[p.Ldif.Entry] = []
        for parsed_entry in parsed_result.value:
            post_parse_result = self._hook_post_parse_entry(parsed_entry)
            if post_parse_result.failure:
                return r[MutableSequence[p.Ldif.Entry]].from_failure(
                    post_parse_result,
                )
            entry_after_post: p.Ldif.Entry = post_parse_result.value
            original_attrs: t.MutableStrSequenceMapping = (
                entry_after_post.attributes.attributes
                if entry_after_post.attributes
                and entry_after_post.attributes.attributes
                else {}
            )
            finalize_result = self._hook_finalize_entry_parse(
                entry_after_post,
                original_attrs,
            )
            if finalize_result.failure:
                return r[MutableSequence[p.Ldif.Entry]].from_failure(
                    finalize_result,
                )
            processed_entries.append(finalize_result.value)
        return r[MutableSequence[p.Ldif.Entry]].ok(processed_entries)

    def _hook_finalize_entry_parse(
        self,
        entry: p.Ldif.Entry,
        original_attrs: t.AttributeMapping,
    ) -> p.Result[p.Ldif.Entry]:
        """Process ACL attributes (aci) into entry.metadata.extensions.

        Returns:
            The resulting ``p.Result[p.Ldif.Entry]``.

        """
        aci_values = FlextLdifServersOudHelpers.find_aci_values(
            entry,
            original_attrs,
        )
        if not aci_values:
            return r[p.Ldif.Entry].ok(entry)
        current_metadata = entry.metadata
        if current_metadata is None:
            current_metadata = u.Ldif.server_metadata_for("oud")
            entry = entry.model_copy(update={"metadata": current_metadata})
        existing_metadata = entry.metadata
        existing_extensions = (
            existing_metadata.extensions if existing_metadata is not None else None
        )
        existing: t.Ldif.MutableMetadataInputMapping = (
            dict(existing_extensions) if existing_extensions else {}
        )
        finalize_result = FlextLdifServersOudHelpers.process_aci_list_for_finalize(
            aci_values,
            self.acl_server,
            existing,
        )
        if finalize_result.failure:
            return r[p.Ldif.Entry].from_failure(finalize_result)
        if existing and existing_metadata is not None:
            updated_metadata = existing_metadata.model_copy(
                update={"extensions": existing},
            )
            entry = entry.model_copy(update={"metadata": updated_metadata})
        return r[p.Ldif.Entry].ok(entry)


__all__: list[str] = ["FlextLdifServersOudEntryParse"]
