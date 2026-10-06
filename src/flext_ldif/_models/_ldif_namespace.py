from __future__ import annotations

from flext_ldif import m


class _LdifNamespace(m.BaseModel):
    """Open, frozen namespace exposing every ``config/*.yaml`` domain model-less."""

    model_config = m.ConfigDict(extra="allow", frozen=True)
