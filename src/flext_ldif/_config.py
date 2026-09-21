"""FlextLdifConfig — frozen config singleton for flext-ldif (ADR-005 §7).

Model-less: business rules live in ``config/*.yaml`` under the ``Ldif:`` key and
are exposed through the open ``config.Ldif`` namespace (``extra="allow"``), with
no per-domain model. Access is ``config.Ldif.<domain>[<key>...]``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated

from flext_cli import FlextCliConfig, m

from flext_core import FlextSettings


class _LdifNamespace(m.BaseModel):
    """Open, frozen namespace exposing every ``config/*.yaml`` domain model-less."""

    model_config = m.ConfigDict(extra="allow", frozen=True)


class FlextLdifConfig(FlextSettings, FlextCliConfig):
    """Ldif config auto-loaded model-less from ``config/*.yaml``.

    MRO carries ``FlextSettings`` FIRST (ENFORCE-042); unlike never-instantiated
    namespace holders, this class IS instantiated by ``fetch_global``, so the
    instance-inert holder contract does not apply and pydantic settings
    construction machinery stays intact.
    """

    Ldif: Annotated[
        _LdifNamespace,
        m.Field(
            description="Open namespace exposing ``config/*.yaml`` under ``Ldif``."
        ),
    ] = _LdifNamespace()


config: FlextLdifConfig = FlextLdifConfig.fetch_global()
"""Pre-instantiated frozen config singleton — ``from flext_ldif import config``."""

__all__: list[str] = ["FlextLdifConfig", "config"]
