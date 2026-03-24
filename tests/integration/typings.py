from __future__ import annotations

from collections.abc import Mapping

type DnRefData = Mapping[str, t.StrMapping | t.StrSequence | str]
