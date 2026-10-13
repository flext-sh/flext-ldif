"""FlextLdifConfig — frozen config singleton for flext-ldif (ADR-005 §7).

Model-less: business rules live in ``config/*.yaml`` under the ``Ldif:`` key and
are exposed through the open ``config.Ldif`` namespace (``extra="allow"``), with
no per-domain model. Access is ``config.Ldif.<domain>[<key>...]``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated

from flext_cli import FlextCliConfig, m

from flext_ldif._models.config import FlextLdifNamespace


class FlextLdifConfig(FlextCliConfig):
    """Ldif config auto-loaded model-less from ``config/*.yaml``.

    The fleet-converged config inherits only the declared profile capability
    base (``FlextCliConfig``, the frozen YAML lifecycle owner); runtime settings
    keep their separate lifecycle. This class IS instantiated by ``fetch_global``,
    so the instance-inert holder contract does not apply and pydantic settings
    construction machinery stays intact.
    """

    Ldif: Annotated[
        FlextLdifNamespace,
        m.Field(
            description="Open namespace exposing ``config/*.yaml`` under ``Ldif``.",
        ),
    ] = FlextLdifNamespace()


config: FlextLdifConfig = FlextLdifConfig.fetch_global()
"""Pre-instantiated frozen config singleton — ``from flext_ldif import config``."""

__all__: list[str] = ["FlextLdifConfig", "config"]
