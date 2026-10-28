"""Extracted facade class from FlextLdifUtilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from flext_ldif._utilities._dn import (
    FlextLdifUtilitiesDNChars,
    FlextLdifUtilitiesDNClean,
    FlextLdifUtilitiesDNEscape,
    FlextLdifUtilitiesDNHierarchy,
    FlextLdifUtilitiesDNNormalize,
    FlextLdifUtilitiesDNParse,
    FlextLdifUtilitiesDNRdn,
    FlextLdifUtilitiesDNRebase,
    FlextLdifUtilitiesDNTransform,
    FlextLdifUtilitiesDNValidate,
)


class FlextLdifUtilitiesDN(
    FlextLdifUtilitiesDNChars,
    FlextLdifUtilitiesDNClean,
    FlextLdifUtilitiesDNEscape,
    FlextLdifUtilitiesDNHierarchy,
    FlextLdifUtilitiesDNNormalize,
    FlextLdifUtilitiesDNParse,
    FlextLdifUtilitiesDNRdn,
    FlextLdifUtilitiesDNRebase,
    FlextLdifUtilitiesDNTransform,
    FlextLdifUtilitiesDNValidate,
):
    """Facade for dn utilities."""


__all__: list[str] = ["FlextLdifUtilitiesDN"]
