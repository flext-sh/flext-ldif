from __future__ import annotations

from collections.abc import Mapping

from flext_ldif import t

type DnRefData = Mapping[str, t.StrMapping | t.StrSequence | str]
