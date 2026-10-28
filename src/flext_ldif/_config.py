"""FlextLdifConfig — frozen config singleton for flext-ldif (ADR-005 §7).

Business rules live in ``config/*.yaml`` under the ``Ldif:`` key. The namespace
schema is declared by this layer-zero owner, independently of the model facade.

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

from typing import Annotated, ClassVar

from flext_cli import FlextCliConfig, m


class FlextLdifConfig(FlextCliConfig):
    """Ldif config auto-loaded from ``config/*.yaml``.

    The fleet-converged config inherits only the declared profile capability
    base (``FlextCliConfig``, the frozen YAML lifecycle owner); runtime settings
    keep their separate lifecycle. This class IS instantiated by ``fetch_global``,
    so the instance-inert holder contract does not apply and pydantic settings
    construction machinery stays intact.
    """

    class ConfigNamespace(m.BaseModel):
        """Open, frozen namespace exposing every configured LDIF domain."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
            extra="allow",
            frozen=True,
        )

    Ldif: Annotated[
        ConfigNamespace,
        m.Field(
            description="Open namespace exposing ``config/*.yaml`` under ``Ldif``.",
        ),
    ] = ConfigNamespace()


config: FlextLdifConfig = FlextLdifConfig.fetch_global()
"""Pre-instantiated frozen config singleton — ``from flext_ldif import config``."""

__all__: list[str] = ["FlextLdifConfig", "config"]
