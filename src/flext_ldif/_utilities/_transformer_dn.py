"""DN normalization step for LDIF entry pipelines.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifModels, c, p, r, t
from flext_ldif._utilities import FlextLdifUtilitiesDN


class FlextLdifUtilitiesEntryDnNormalization:
    """Stateless DN normalization of one LDIF entry."""

    @staticmethod
    def validate_dn_components(dn_str: str) -> p.Result[bool]:
        """Validate DN components.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        components = FlextLdifUtilitiesDN.split(dn_str)
        all_errors: t.MutableSequenceOf[str] = []
        for comp in components:
            if "=" not in comp:
                all_errors.append(f"Invalid RDN (missing '='): {comp}")
                continue
            _, _, value = comp.partition("=")
            valid, errors = FlextLdifUtilitiesDN.valid_dn_string(value.strip())
            if not valid:
                all_errors.extend([f"RDN value '{value}': {e}" for e in errors])
        if all_errors:
            return r[bool].fail(f"Invalid DN: {', '.join(all_errors)}")
        return r[bool].ok(value=True)

    @staticmethod
    def normalize_entry_dn(
        item: FlextLdifModels.Ldif.Entry,
        *,
        case: c.Ldif.CaseFoldOption = c.Ldif.CaseFoldOption.LOWER,
        spaces: c.Ldif.SpaceHandlingOption = c.Ldif.SpaceHandlingOption.TRIM,
        validate: bool = True,
    ) -> p.Result[FlextLdifModels.Ldif.Entry]:
        """Normalize the DN of one entry (validation, case folding, spaces).

        Returns:
            The resulting ``p.Result[FlextLdifModels.Ldif.Entry]``.
        """
        if item.dn is None:
            return r[FlextLdifModels.Ldif.Entry].fail("Entry has no DN")
        entry_dn = item.dn
        dn_str = entry_dn.value

        def validate_dn(_: str) -> p.Result[str]:
            if not validate:
                return r[str].ok(dn_str)
            return (
                FlextLdifUtilitiesEntryDnNormalization
                .validate_dn_components(dn_str)
                .map_error(lambda error: error or "DN validation failed")
                .map(lambda __: dn_str)
            )

        def update_entry(normalized_dn: str) -> FlextLdifModels.Ldif.Entry:
            if case == c.Ldif.CaseFoldOption.LOWER:
                normalized_dn = normalized_dn.lower()
            elif case == c.Ldif.CaseFoldOption.UPPER:
                normalized_dn = normalized_dn.upper()
            if spaces == c.Ldif.SpaceHandlingOption.TRIM:
                normalized_dn = normalized_dn.strip()
            copied: FlextLdifModels.Ldif.Entry = item.model_copy(
                update={
                    "dn": entry_dn.model_copy(update={"value": normalized_dn}),
                },
            )
            return copied

        return (
            r[str]
            .ok(dn_str)
            .flat_map(validate_dn)
            .flat_map(FlextLdifUtilitiesDN.norm)
            .map(update_entry)
        )


__all__: list[str] = ["FlextLdifUtilitiesEntryDnNormalization"]
