from __future__ import annotations

from collections.abc import Mapping, Sequence

type DnRefData = Mapping[str, Mapping[str, str] | Sequence[str] | str]
