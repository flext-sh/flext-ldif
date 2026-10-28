"""Protocol definitions for flextldif.

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

from flext_ldif import FlextLdifProtocols


class ExamplesFlextLdifProtocols(FlextLdifProtocols):
    """Protocol definitions for flextldif."""


__all__: list[str] = ["ExamplesFlextLdifProtocols"]
