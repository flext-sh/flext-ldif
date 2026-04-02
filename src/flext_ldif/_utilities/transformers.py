"""Power Method Transformers - Entry transformation classes for pipelines."""

from __future__ import annotations

from collections.abc import MutableMapping, MutableSequence, Sequence
from typing import ClassVar, override

from flext_core import r
from flext_ldif import FlextLdifUtilitiesDN, c, m, t


class FlextLdifUtilitiesTransformer[T]:
    """Base class for entry transformers."""

    __slots__: ClassVar[tuple[str, ...]] = ()

    def apply(self, item: T) -> r[T]:
        """Apply the transformation to an item."""
        raise NotImplementedError

    def apply_batch(self, items: MutableSequence[T]) -> r[Sequence[T]]:
        """Apply transformation to a batch of items."""
        return r.traverse(items, self.apply)


class FlextLdifUtilitiesTransformers:
    """Concrete transformer classes for LDIF entry pipelines."""

    class NormalizeDnTransformer(FlextLdifUtilitiesTransformer[m.Ldif.Entry]):
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
        def validate_dn_components(dn_str: str) -> r[bool]:
            """Helper: Validate DN components."""
            components = FlextLdifUtilitiesDN.split(dn_str)
            all_errors: MutableSequence[str] = []
            for comp in components:
                if "=" not in comp:
                    all_errors.append(f"Invalid RDN (missing '='): {comp}")
                    continue
                _, _, value = comp.partition("=")
                is_valid, errors = FlextLdifUtilitiesDN.is_valid_dn_string(
                    value.strip(),
                )
                if not is_valid:
                    all_errors.extend([f"RDN value '{value}': {e}" for e in errors])
            if all_errors:
                return r[bool].fail(f"Invalid DN: {', '.join(all_errors)}")
            return r[bool].ok(value=True)

        @override
        def apply(self, item: m.Ldif.Entry) -> r[m.Ldif.Entry]:
            """Apply DN normalization to an entry."""
            if item.dn is None:
                return r[m.Ldif.Entry].fail("Entry has no DN")
            dn_str = (
                item.dn.value
                if getattr(item.dn, "value", None) is not None
                else str(item.dn)
            )
            if self._validate:
                validation_result = FlextLdifUtilitiesTransformers.NormalizeDnTransformer.validate_dn_components(
                    dn_str,
                )
                if validation_result.is_failure:
                    error_msg = (
                        str(validation_result.error)
                        if validation_result.error
                        else "DN validation failed"
                    )
                    return r[m.Ldif.Entry].fail(error_msg)
            norm_result = FlextLdifUtilitiesDN.norm(dn_str)
            if norm_result.is_failure:
                return r[m.Ldif.Entry].fail(norm_result.error)
            normalized_dn = norm_result.value
            normalized_dn = self._normalize_dn_case_and_spaces(normalized_dn)
            update_dict: t.MutableContainerMapping = {"dn": normalized_dn}
            updated_entry = item.model_copy(update=update_dict)
            return r[m.Ldif.Entry].ok(updated_entry)

        def _normalize_dn_case_and_spaces(self, normalized_dn: str) -> str:
            """Helper: Apply case folding and space handling."""
            if self._case == "lower":
                normalized_dn = normalized_dn.lower()
            elif self._case == "upper":
                normalized_dn = normalized_dn.upper()
            if self._spaces == "trim":
                normalized_dn = normalized_dn.strip()
            elif self._spaces == "normalize":
                parts = normalized_dn.split(",")
                normalized_dn = ",".join(p.strip() for p in parts)
            return normalized_dn

    class NormalizeAttrsTransformer(FlextLdifUtilitiesTransformer[m.Ldif.Entry]):
        """Transformer for attribute normalization."""

        __slots__ = ("_case_fold_names", "_remove_empty", "_trim_values")

        def __init__(
            self,
            *,
            case_fold_names: bool = True,
            trim_values: bool = True,
            remove_empty: bool = False,
        ) -> None:
            """Initialize attribute normalization transformer."""
            super().__init__()
            self._case_fold_names = case_fold_names
            self._trim_values = trim_values
            self._remove_empty = remove_empty

        @override
        def apply(self, item: m.Ldif.Entry) -> r[m.Ldif.Entry]:
            """Apply attribute normalization to an entry."""
            if item.attributes is None:
                return r[m.Ldif.Entry].fail("Entry has no attributes")
            attrs: MutableMapping[str, MutableSequence[str]] = (
                item.attributes.attributes
                if getattr(item.attributes, "attributes", None) is not None
                else {}
            )
            if self._case_fold_names:
                attrs = {k.lower(): v for k, v in attrs.items()}

            def process_value_list(
                values: MutableSequence[str],
            ) -> MutableSequence[str]:
                """Process a single attribute's values."""
                processed: MutableSequence[str] = []
                for value_item in values:
                    trimmed_value = (
                        value_item.strip() if self._trim_values else value_item
                    )
                    if self._remove_empty and (not trimmed_value):
                        continue
                    processed.append(trimmed_value)
                return processed

            def map_process_value(
                _key: str,
                value: MutableSequence[str],
            ) -> MutableSequence[str]:
                """Process value list for attribute."""
                return process_value_list(value)

            new_attrs = {
                key: map_process_value(key, value) for key, value in attrs.items()
            }
            needs_update = (
                self._case_fold_names
                or self._trim_values
                or self._remove_empty
                or (new_attrs != attrs)
            )
            if needs_update:
                update_dict: MutableMapping[str, m.Ldif.Attributes] = {
                    "attributes": m.Ldif.Attributes.model_validate({
                        "attributes": new_attrs,
                    }),
                }
                item = item.model_copy(update=update_dict)
            return r[m.Ldif.Entry].ok(item)

    class Normalize:
        """Factory class for normalization transformers."""

        __slots__: ClassVar[tuple[str, ...]] = ()

        @staticmethod
        def attrs(
            *,
            case_fold_names: bool = True,
            trim_values: bool = True,
            remove_empty: bool = False,
        ) -> FlextLdifUtilitiesTransformers.NormalizeAttrsTransformer:
            """Create an attribute normalization transformer."""
            return FlextLdifUtilitiesTransformers.NormalizeAttrsTransformer(
                case_fold_names=case_fold_names,
                trim_values=trim_values,
                remove_empty=remove_empty,
            )

        @staticmethod
        def dn(
            *,
            case: c.Ldif.CaseFoldOption = c.Ldif.CaseFoldOption.LOWER,
            spaces: c.Ldif.SpaceHandlingOption = c.Ldif.SpaceHandlingOption.TRIM,
            validate: bool = True,
        ) -> FlextLdifUtilitiesTransformers.NormalizeDnTransformer:
            """Create a DN normalization transformer."""
            return FlextLdifUtilitiesTransformers.NormalizeDnTransformer(
                case=case,
                spaces=spaces,
                validate=validate,
            )


__all__ = [
    "FlextLdifUtilitiesTransformer",
    "FlextLdifUtilitiesTransformers",
]
