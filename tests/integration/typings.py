from __future__ import annotations

from collections.abc import Mapping

from tests import t

type DnRefData = Mapping[str, t.StrMapping | t.StrSequence | str]
