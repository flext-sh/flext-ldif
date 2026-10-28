"""Base Constants for Server Servers.

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

from flext_ldif import FlextLdifConstants


class FlextLdifConstantsServersBase(
    FlextLdifConstants,
):
    """Thin inheritor: declarations live in _constants parts."""


__all__: list[str] = ["FlextLdifConstantsServersBase"]
