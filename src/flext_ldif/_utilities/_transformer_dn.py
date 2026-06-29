"""DN normalization transformer."""

from __future__ import annotations

from typing import override

from flext_ldif import c, m, p, r, t
from flext_ldif._utilities._transformer_base import FlextLdifUtilitiesTransformer
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN as udn


class FlextLdifUtilitiesNormalizeDnTransformer(
    FlextLdifUtilitiesTransformer[m.Ldif.Entry],
):
    """Transformer for DN normalization."""

    __slots__ = ("_case", "_spaces", "_validate")

    def __init__(
        self,
        *,
        case: c.Ldif.CaseFoldOption = c.Ldif.CaseFoldOption.LOWER,
        spaces: c.Ldif.SpaceHandlingOption = c.Ldif.SpaceHandlingOption.TRIM,
        validate: bool = True,
    ) -> None:
        """Initialize DN normalization transformer."""
        super().__init__()
        self._case = case
        self._spaces = spaces
        self._validate = validate

    @staticmethod
    def validate_dn_components(dn_str: str) -> p.Result[bool]:
        """Helper: Validate DN components."""
        components = udn.split(dn_str)
        all_errors: t.MutableSequenceOf[str] = []
        for comp in components:
            if "=" not in comp:
                all_errors.append(f"Invalid RDN (missing '='): {comp}")
                continue
            _, _, value = comp.partition("=")
            valid, errors = udn.is_valid_dn_string(
                value.strip(),
            )
            if not valid:
                all_errors.extend([f"RDN value '{value}': {e}" for e in errors])
        if all_errors:
            return r[bool].fail(f"Invalid DN: {', '.join(all_errors)}")
        return r[bool].ok(value=True)

    @override
    def apply(self, item: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Apply DN normalization to an entry."""
        if item.dn is None:
            return r[m.Ldif.Entry].fail("Entry has no DN")
        dn_str = (
            item.dn.value
            if getattr(item.dn, "value", None) is not None
            else str(item.dn)
        )

        def validate_dn(_: str) -> p.Result[str]:
            if not self._validate:
                return r[str].ok(dn_str)
            return (
                FlextLdifUtilitiesNormalizeDnTransformer
                .validate_dn_components(
                    dn_str,
                )
                .map_error(
                    lambda error: error or "DN validation failed",
                )
                .map(
                    lambda __: dn_str,
                )
            )

        def update_entry(normalized_dn: str) -> m.Ldif.Entry:
            normalized_text = self._normalize_dn_case_and_spaces(normalized_dn)
            normalized_dn_value = (
                item.dn.model_copy(update={"value": normalized_text})
                if isinstance(item.dn, m.Ldif.DN)
                else m.Ldif.DN.model_validate({"value": normalized_text})
            )
            copied: m.Ldif.Entry = item.model_copy(
                update={"dn": normalized_dn_value},
            )
            return copied

        return (
            r[str]
            .ok(dn_str)
            .flat_map(
                validate_dn,
            )
            .flat_map(
                udn.norm,
            )
            .map(
                update_entry,
            )
        )

    def _normalize_dn_case_and_spaces(self, normalized_dn: str) -> str:
        """Helper: Apply case folding and space handling."""
        if self._case == "lower":
            normalized_dn = normalized_dn.lower()
        elif self._case == "upper":
            normalized_dn = normalized_dn.upper()
        if self._spaces == "trim":
            normalized_dn = normalized_dn.strip()
        return normalized_dn


__all__: list[str] = ["FlextLdifUtilitiesNormalizeDnTransformer"]
