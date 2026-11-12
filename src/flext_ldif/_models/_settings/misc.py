"""LDIF settings mix-in: misc.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Annotated

from flext_core import m


class FlextLdifModelsSettingsMisc:
    """LDIF settings mix-in: misc."""

    class LogContextExtras(m.Value):
        """Extra context fields for structured event logging."""

        user_id: Annotated[str | None, m.Field(description="User identifier")] = None
        session_id: Annotated[str | None, m.Field(description="Session identifier")] = (
            None
        )
        request_id: Annotated[str | None, m.Field(description="Request identifier")] = (
            None
        )
        component: Annotated[str | None, m.Field(description="Component name")] = None
        correlation_id: Annotated[
            str | None,
            m.Field(description="Correlation identifier"),
        ] = None
        trace_id: Annotated[str | None, m.Field(description="Trace identifier")] = None


__all__: list[str] = ["FlextLdifModelsSettingsMisc"]
