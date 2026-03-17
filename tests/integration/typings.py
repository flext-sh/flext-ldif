from __future__ import annotations

from collections.abc import Mapping

type DnRefData = dict[str, Mapping[str, str] | list[str] | str]
