"""Ldif namespace module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_models/_ldif_namespace
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import m


class _LdifNamespace(m.BaseModel):
    """Open, frozen namespace exposing every ``config/*.yaml`` domain model-less."""

    model_config = m.ConfigDict(extra="allow", frozen=True)
