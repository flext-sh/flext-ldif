"""Power Method Transformers - Entry transformation classes for pipelines."""

from __future__ import annotations

from typing import ClassVar

from flext_ldif import c, t
from flext_ldif._utilities._transformer_attrs import (
    FlextLdifUtilitiesNormalizeAttrsTransformer,
)
from flext_ldif._utilities._transformer_base import FlextLdifUtilitiesTransformer
from flext_ldif._utilities._transformer_dn import (
    FlextLdifUtilitiesNormalizeDnTransformer,
)


class FlextLdifUtilitiesTransformers:
    """Concrete transformer classes for LDIF entry pipelines."""

    NormalizeDnTransformer: ClassVar[type[FlextLdifUtilitiesNormalizeDnTransformer]] = (
        FlextLdifUtilitiesNormalizeDnTransformer
    )
    NormalizeAttrsTransformer: ClassVar[
        type[FlextLdifUtilitiesNormalizeAttrsTransformer]
    ] = FlextLdifUtilitiesNormalizeAttrsTransformer

    class Normalize:
        """Factory class for normalization transformers."""

        __slots__: ClassVar[t.StrSequence] = ()

        @staticmethod
        def attrs(
            *,
            case_fold_names: bool = True,
            trim_values: bool = True,
            remove_empty: bool = False,
        ) -> FlextLdifUtilitiesNormalizeAttrsTransformer:
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
        ) -> FlextLdifUtilitiesNormalizeDnTransformer:
            """Create a DN normalization transformer."""
            return FlextLdifUtilitiesTransformers.NormalizeDnTransformer(
                case=case,
                spaces=spaces,
                validate=validate,
            )


__all__: list[str] = [
    "FlextLdifUtilitiesTransformer",
    "FlextLdifUtilitiesTransformers",
]
