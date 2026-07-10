"""FlextLdifConfig — frozen config singleton for flext-ldif (ADR-005 §7).

Model-less: business rules live in ``config/*.yaml`` under the ``Ldif:`` key and
are exposed through the open ``config.Ldif`` namespace (``extra="allow"``), with
no per-domain model. Access is ``config.Ldif.<domain>[<key>...]``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from flext_cli import FlextCliConfig


class _LdifNamespace(BaseModel):
    """Open, frozen namespace exposing every ``config/*.yaml`` domain model-less."""

    model_config = ConfigDict(extra="allow", frozen=True)


class FlextLdifConfig(FlextCliConfig):
    """Ldif config auto-loaded model-less from ``config/*.yaml``."""

    Ldif: _LdifNamespace = _LdifNamespace()


config: FlextLdifConfig = FlextLdifConfig.fetch_global()
"""Pre-instantiated frozen config singleton — ``from flext_ldif import config``."""

__all__: list[str] = ["FlextLdifConfig", "config"]
