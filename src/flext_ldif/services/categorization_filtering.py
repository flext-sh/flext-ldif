"""Categorization filtering concern: forbidden/OID/base-DN post-filters.

Holds the filtering half of the LDIF categorization service; composition and
rejection tracking live on ``FlextLdifCategorization``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping

from flext_ldif import c, m, p, s, t, u
from flext_ldif.services.filters import FlextLdifFilters


class FlextLdifCategorizationFiltering(FlextLdifCategorizationRules):
    """Forbidden-attribute, whitelist-OID, and base-DN filtering helpers."""

    def validate_entry(entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Validate and normalize entry DN.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        dn_str = str(entry.dn) if entry.dn else ""
        if not u.Ldif.validate_dn(dn_str):
            rejected_entry = u.Ldif.update_entry_statistics(
                entry,
                mark_rejected=(
                    c.Ldif.RejectionCategory.INVALID_DN.value,
                    f"DN validation failed (RFC 4514): {dn_str[:80]}",
                ),
            )
            self.rejection_tracker[
                c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514
            ].append(rejected_entry)
            self.logger.debug(
                "Entry DN failed RFC 4514 validation",
                entry_dn=dn_str,
            )
            return r[m.Ldif.Entry].fail_op("DN validation", dn_str[:80])
        norm_result = u.Ldif.norm(dn_str)
        normalized_dn = norm_result.map_or(None)
        if normalized_dn is None:
            rejected_entry = u.Ldif.update_entry_statistics(
                entry,
                mark_rejected=(
                    c.Ldif.RejectionCategory.INVALID_DN.value,
                    (
                        f"DN normalization "
                        f"failed: {norm_result.error or c.Ldif.ERR_UNKNOWN}"
                    ),
                ),
            )
            self.rejection_tracker[
                c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514
            ].append(rejected_entry)
            return r[m.Ldif.Entry].fail_op(
                "DN normalization",
                norm_result.error or c.Ldif.ERR_UNKNOWN,
            )
        dn_obj = m.Ldif.DN(value=normalized_dn)
        return r[m.Ldif.Entry].ok(entry.model_copy(update={"dn": dn_obj}))

    validated: t.MutableSequenceOf[m.Ldif.Entry] = [
        validation_result.value
        for entry in normalized_entries
        if (validation_result := validate_entry(entry)).success
    ]
    self.logger.info(
        "Validated entries",
        validated_count=len(validated),
        rejected_count=len(
            self.rejection_tracker[c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514],
        ),
        rejection_reason=c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514,
    )
    if self.rejection_tracker[c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514]:
        sample_rejected_dns = [
            entry.dn.value[: c.Ldif.DN_PREVIEW_LENGTH]
            if entry.dn and len(entry.dn.value) > c.Ldif.DN_PREVIEW_LENGTH


__all__: list[str] = ["FlextLdifCategorizationFiltering"]
