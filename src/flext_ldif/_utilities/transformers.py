"""Extracted facade class from FlextLdifUtilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities._transformers import (
    FlextLdifUtilitiesTransformersAttrs,
    FlextLdifUtilitiesTransformersDn,
)


class FlextLdifUtilitiesTransformers(
    FlextLdifUtilitiesTransformersAttrs,
    FlextLdifUtilitiesTransformersDn,
):
    """Facade for transformers utilities."""


__all__: list[str] = ["FlextLdifUtilitiesTransformers"]
