"""Auto-generated centralized models."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Annotated, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field

from flext_ldif import t

_TRUE_STRINGS: frozenset[str] = frozenset({"true", "1", "yes", "on"})
type _ConvertValue = t.Container | Sequence[t.Container] | Mapping[str, t.Container]
_CONTAINER_TYPES: tuple[type[t.Container], ...] = (
    str,
    int,
    float,
    bool,
    datetime,
    Path,
)


class ConvertToStr(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["str"] = "str"
    value: Annotated[_ConvertValue, Field(...)]
    default: _ConvertValue | None = None

    def convert(self) -> _ConvertValue | None:
        try:
            return str(self.value)
        except (TypeError, ValueError):
            return self.default


class ConvertToInt(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["int"] = "int"
    value: Annotated[_ConvertValue, Field(...)]
    default: _ConvertValue | None = None

    def convert(self) -> _ConvertValue | None:
        try:
            return int(str(self.value))
        except (TypeError, ValueError):
            return self.default


class ConvertToFloat(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["float"] = "float"
    value: Annotated[_ConvertValue, Field(...)]
    default: _ConvertValue | None = None

    def convert(self) -> _ConvertValue | None:
        try:
            return float(str(self.value))
        except (TypeError, ValueError):
            return self.default


class ConvertToBool(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["bool"] = "bool"
    value: Annotated[_ConvertValue, Field(...)]
    default: _ConvertValue | None = None

    def convert(self) -> _ConvertValue | None:
        val = self.value
        if isinstance(val, str):
            return val.lower() in _TRUE_STRINGS
        try:
            return bool(val)
        except (TypeError, ValueError):
            return self.default


class ConvertToList(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["list"] = "list"
    value: Annotated[_ConvertValue, Field(...)]
    default: _ConvertValue | None = None

    def convert(self) -> _ConvertValue | None:
        val = self.value
        if isinstance(val, Sequence) and not isinstance(val, (str, bytes, bytearray)):
            return [
                item if isinstance(item, _CONTAINER_TYPES) else str(item)
                for item in val
            ]
        return [val if isinstance(val, _CONTAINER_TYPES) else str(val)]


class ConvertToTuple(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["tuple"] = "tuple"
    value: Annotated[_ConvertValue, Field(...)]
    default: _ConvertValue | None = None

    def convert(self) -> _ConvertValue | None:
        val = self.value
        if isinstance(val, Sequence) and not isinstance(val, (str, bytes, bytearray)):
            return tuple(
                item if isinstance(item, _CONTAINER_TYPES) else str(item)
                for item in val
            )
        return (val if isinstance(val, _CONTAINER_TYPES) else str(val),)


class ConvertToDict(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["dict"] = "dict"
    value: Annotated[_ConvertValue, Field(...)]
    default: _ConvertValue | None = None

    def convert(self) -> _ConvertValue | None:
        if isinstance(self.value, Mapping):
            return {
                str(key): item if isinstance(item, _CONTAINER_TYPES) else str(item)
                for key, item in self.value.items()
            }
        return self.default
