from __future__ import annotations

from collections.abc import Sequence, Mapping

type DnRefData = Mapping[str, Mapping[str, str] | Sequence[str] | str]
