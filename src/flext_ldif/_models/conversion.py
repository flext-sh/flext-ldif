"""Centralized Pydantic v2 conversion models for type casting."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Annotated, ClassVar, Literal

from flext_core import FlextModels
from pydantic import ConfigDict, Field

from flext_ldif import t


class FlextLdifModelsConversions:
    """LDIF conversion models namespace."""

    class _FrozenConversion(FlextModels.ArbitraryTypesModel):
        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    class ConvertToStr(_FrozenConversion):
        target_type: Literal["str"] = "str"
        value: Annotated[t.Ldif.ConvertValue, Field(...)]
        default: t.Ldif.ConvertValue | None = None

        def convert(self) -> t.Ldif.ConvertValue | None:
            try:
                return str(self.value)
            except (TypeError, ValueError):
                return self.default

    class ConvertToInt(_FrozenConversion):
        target_type: Literal["int"] = "int"
        value: Annotated[t.Ldif.ConvertValue, Field(...)]
        default: t.Ldif.ConvertValue | None = None

        def convert(self) -> t.Ldif.ConvertValue | None:
            try:
                return int(str(self.value))
            except (TypeError, ValueError):
                return self.default

    class ConvertToFloat(_FrozenConversion):
        target_type: Literal["float"] = "float"
        value: Annotated[t.Ldif.ConvertValue, Field(...)]
        default: t.Ldif.ConvertValue | None = None

        def convert(self) -> t.Ldif.ConvertValue | None:
            try:
                return float(str(self.value))
            except (TypeError, ValueError):
                return self.default

    class ConvertToBool(_FrozenConversion):
        target_type: Literal["bool"] = "bool"
        value: Annotated[t.Ldif.ConvertValue, Field(...)]
        default: t.Ldif.ConvertValue | None = None

        def convert(self) -> t.Ldif.ConvertValue | None:
            val = self.value
            if isinstance(val, str):
                return val.lower() in t.Ldif.TRUE_STRINGS
            try:
                return bool(val)
            except (TypeError, ValueError):
                return self.default

    class ConvertToList(_FrozenConversion):
        target_type: Literal["list"] = "list"
        value: Annotated[t.Ldif.ConvertValue, Field(...)]
        default: t.Ldif.ConvertValue | None = None

        def convert(self) -> t.Ldif.ConvertValue | None:
            val = self.value
            if isinstance(val, Sequence) and not isinstance(
                val,
                (str, bytes, bytearray),
            ):
                return [
                    item if isinstance(item, t.Ldif.CONTAINER_TYPES) else str(item)
                    for item in val
                ]
            return [
                val
                if isinstance(val, (str, int, float, bool, datetime, Path))
                else str(val)
            ]

    class ConvertToTuple(_FrozenConversion):
        target_type: Literal["tuple"] = "tuple"
        value: Annotated[t.Ldif.ConvertValue, Field(...)]
        default: t.Ldif.ConvertValue | None = None

        def convert(self) -> t.Ldif.ConvertValue | None:
            val = self.value
            if isinstance(val, Sequence) and not isinstance(
                val,
                (str, bytes, bytearray),
            ):
                return [item for item in val]
            if isinstance(val, (str, int, float, bool, datetime, Path)):
                return [val]
            return [str(val)]

    class ConvertToDict(_FrozenConversion):
        target_type: Literal["dict"] = "dict"
        value: Annotated[t.Ldif.ConvertValue, Field(...)]
        default: t.Ldif.ConvertValue | None = None

        def convert(self) -> t.Ldif.ConvertValue | None:
            if isinstance(self.value, Mapping):
                return {
                    str(key): item
                    if isinstance(item, t.Ldif.CONTAINER_TYPES)
                    else str(item)
                    for key, item in self.value.items()
                }
            return self.default


__all__ = ["FlextLdifModelsConversions"]
