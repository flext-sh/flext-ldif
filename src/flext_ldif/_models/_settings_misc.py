"""LDIF settings mix-in: misc.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Annotated

from flext_cli import m, u
from flext_ldif import t


class FlextLdifModelsSettingsMisc:
    """LDIF settings mix-in: misc."""

    class LogContextExtras(m.Value):
        """Extra context fields for structured event logging."""

        user_id: Annotated[str | None, u.Field(description="User identifier")] = None
        session_id: Annotated[
            str | None,
            u.Field(description="Session identifier"),
        ] = None
        request_id: Annotated[
            str | None,
            u.Field(description="Request identifier"),
        ] = None
        component: Annotated[
            str | None,
            u.Field(description="Component name"),
        ] = None
        correlation_id: Annotated[
            str | None,
            u.Field(description="Correlation identifier"),
        ] = None
        trace_id: Annotated[str | None, u.Field(description="Trace identifier")] = None

    class RdnProcessingConfig(m.ArbitraryTypesModel):
        """Mutable state for RDN character-by-character parsing."""

        current_attr: Annotated[str, u.Field(description="Current attribute name")] = ""
        current_val: Annotated[str, u.Field(description="Current value")] = ""
        in_value: Annotated[
            bool,
            u.Field(description="Whether parser is inside the value portion"),
        ] = False
        pairs: Annotated[
            t.MutableStrPairSequence,
            u.Field(description="Accumulated (attr, value) pairs"),
        ] = u.Field(default_factory=list)
