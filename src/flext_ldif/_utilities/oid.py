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

from flext_ldif._utilities._oid import FlextLdifUtilitiesOIDOperations


class FlextLdifUtilitiesOID(
    FlextLdifUtilitiesOIDOperations,
):
    """Facade for oid utilities."""


__all__: list[str] = ["FlextLdifUtilitiesOID"]
