"""Auto-generated centralized models."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

_TRUE_STRINGS: frozenset[str] = frozenset({"true", "1", "yes", "on"})


class ConvertToStr(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["str"] = "str"
    value: object = Field(...)
    default: object | None = None

    def convert(self) -> object | None:
        try:
            return str(self.value)
        except (TypeError, ValueError):
            return self.default


class ConvertToInt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["int"] = "int"
    value: object = Field(...)
    default: object | None = None

    def convert(self) -> object | None:
        try:
            return int(str(self.value))
        except (TypeError, ValueError):
            return self.default


class ConvertToFloat(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["float"] = "float"
    value: object = Field(...)
    default: object | None = None

    def convert(self) -> object | None:
        try:
            return float(str(self.value))
        except (TypeError, ValueError):
            return self.default


class ConvertToBool(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["bool"] = "bool"
    value: object = Field(...)
    default: object | None = None

    def convert(self) -> object | None:
        val = self.value
        if isinstance(val, str):
            return val.lower() in _TRUE_STRINGS
        try:
            return bool(val)
        except (TypeError, ValueError):
            return self.default


class ConvertToList(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["list"] = "list"
    value: object = Field(...)
    default: object | None = None

    def convert(self) -> object | None:
        val = self.value
        if isinstance(val, Sequence) and not isinstance(val, (str, bytes, bytearray)):
            seq_val: Sequence[object] = val
            return list(seq_val)
        return [val]


class ConvertToTuple(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["tuple"] = "tuple"
    value: object = Field(...)
    default: object | None = None

    def convert(self) -> object | None:
        val = self.value
        if isinstance(val, Sequence) and not isinstance(val, (str, bytes, bytearray)):
            seq_val: Sequence[object] = val
            return tuple(seq_val)
        return (val,)


class ConvertToDict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["dict"] = "dict"
    value: object = Field(...)
    default: object | None = None

    def convert(self) -> object | None:
        if isinstance(self.value, Mapping):
            return dict(self.value)
        return self.default
