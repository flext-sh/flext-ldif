"""Entry normalization steps for LDIF pipelines.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities import (
    FlextLdifUtilitiesEntryAttrsNormalization,
    FlextLdifUtilitiesEntryDnNormalization,
)


class FlextLdifUtilitiesTransformers(
    FlextLdifUtilitiesEntryDnNormalization,
    FlextLdifUtilitiesEntryAttrsNormalization,
):
    """Stateless entry normalization steps composed into ``u.Ldif``."""


__all__: list[str] = ["FlextLdifUtilitiesTransformers"]
