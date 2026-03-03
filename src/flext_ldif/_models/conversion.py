"""Centralized Pydantic v2 conversion models for type casting."""

from __future__ import annotations

from typing import Literal

from flext_core import u
from pydantic import BaseModel, ConfigDict, Field

from flext_ldif import t

_TRUE_STRINGS: frozenset[str] = frozenset({"true", "1", "yes", "on"})

type ConversionTargetType = Literal[
    "str",
    "int",
    "float",
    "bool",
    "list",
    "tuple",
    "dict",
]


class ConvertToStr(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["str"] = "str"
    value: t.ContainerValue = Field(...)
    default: t.ContainerValue | None = None

    def convert(self) -> t.ContainerValue | None:
        try:
            return str(self.value)
        except (TypeError, ValueError):
            return self.default


class ConvertToInt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["int"] = "int"
    value: t.ContainerValue = Field(...)
    default: t.ContainerValue | None = None

    def convert(self) -> t.ContainerValue | None:
        try:
            return int(str(self.value))
        except (TypeError, ValueError):
            return self.default


class ConvertToFloat(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["float"] = "float"
    value: t.ContainerValue = Field(...)
    default: t.ContainerValue | None = None

    def convert(self) -> t.ContainerValue | None:
        try:
            return float(str(self.value))
        except (TypeError, ValueError):
            return self.default


class ConvertToBool(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["bool"] = "bool"
    value: t.ContainerValue = Field(...)
    default: t.ContainerValue | None = None

    def convert(self) -> t.ContainerValue | None:
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
    value: t.ContainerValue = Field(...)
    default: t.ContainerValue | None = None

    def convert(self) -> t.ContainerValue | None:
        val = self.value
        if isinstance(val, (list, tuple, set, frozenset)):
            return list(val)  # type: ignore[arg-type]
        return [val]


class ConvertToTuple(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["tuple"] = "tuple"
    value: t.ContainerValue = Field(...)
    default: t.ContainerValue | None = None

    def convert(self) -> t.ContainerValue | None:
        val = self.value
        if isinstance(val, (list, tuple, set, frozenset)):
            return tuple(val)  # type: ignore[arg-type]
        return (val,)


class ConvertToDict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["dict"] = "dict"
    value: t.ContainerValue = Field(...)
    default: t.ContainerValue | None = None

    def convert(self) -> t.ContainerValue | None:
        if u.is_dict_like(self.value):
            return self.value
        return self.default


ConversionRequest = (
    ConvertToStr
    | ConvertToInt
    | ConvertToFloat
    | ConvertToBool
    | ConvertToList
    | ConvertToTuple
    | ConvertToDict
)
"""Discriminated union of all conversion request types."""
