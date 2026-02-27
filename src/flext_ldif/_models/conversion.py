"""Centralized Pydantic v2 conversion models for type casting."""

from __future__ import annotations

from typing import Literal

from flext_core import u
from pydantic import BaseModel, ConfigDict, Field

from flext_ldif.typings import t

_TRUE_STRINGS: frozenset[str] = frozenset({"true", "1", "yes", "on"})

type ConversionTargetType = Literal[
    "str", "int", "float", "bool", "list", "tuple", "dict"
]


class ConvertToStr(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["str"] = "str"
    value: t.GeneralValueType = Field(...)
    default: t.GeneralValueType | None = None

    def convert(self) -> t.GeneralValueType | None:
        try:
            return str(self.value)
        except (TypeError, ValueError):
            return self.default


class ConvertToInt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["int"] = "int"
    value: t.GeneralValueType = Field(...)
    default: t.GeneralValueType | None = None

    def convert(self) -> t.GeneralValueType | None:
        try:
            return int(str(self.value))
        except (TypeError, ValueError):
            return self.default


class ConvertToFloat(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["float"] = "float"
    value: t.GeneralValueType = Field(...)
    default: t.GeneralValueType | None = None

    def convert(self) -> t.GeneralValueType | None:
        try:
            return float(str(self.value))
        except (TypeError, ValueError):
            return self.default


class ConvertToBool(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["bool"] = "bool"
    value: t.GeneralValueType = Field(...)
    default: t.GeneralValueType | None = None

    def convert(self) -> t.GeneralValueType | None:
        val = self.value
        if val.__class__ is str:
            return val.lower() in _TRUE_STRINGS
        try:
            return bool(val)
        except (TypeError, ValueError):
            return self.default


class ConvertToList(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["list"] = "list"
    value: t.GeneralValueType = Field(...)
    default: t.GeneralValueType | None = None

    def convert(self) -> t.GeneralValueType | None:
        val = self.value
        if val.__class__ in {list, tuple, set, frozenset}:
            return list(val)
        return [val]


class ConvertToTuple(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["tuple"] = "tuple"
    value: t.GeneralValueType = Field(...)
    default: t.GeneralValueType | None = None

    def convert(self) -> t.GeneralValueType | None:
        val = self.value
        if val.__class__ in {list, tuple, set, frozenset}:
            return tuple(val)
        return (val,)


class ConvertToDict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    target_type: Literal["dict"] = "dict"
    value: t.GeneralValueType = Field(...)
    default: t.GeneralValueType | None = None

    def convert(self) -> t.GeneralValueType | None:
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
