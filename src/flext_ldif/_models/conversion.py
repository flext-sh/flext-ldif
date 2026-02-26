"""Centralized Pydantic v2 conversion models for type casting.

This module provides discriminated union models for type conversions
to replace the polymorphic _convert_with_target function.
"""

from __future__ import annotations

from typing import Literal

from flext_core import u
from pydantic import BaseModel, ConfigDict, Field

from flext_ldif.typings import t


class ConvertToStr(BaseModel):
    """Convert value to string."""

    model_config = ConfigDict(
        frozen=True,
        validate_assignment=True,
        extra="forbid",
    )

    target_type: Literal["str"] = Field(
        default="str", description="Conversion target type"
    )
    value: t.GeneralValueType = Field(..., description="Value to convert")
    default: t.GeneralValueType | None = Field(
        default=None,
        description="Default value if conversion fails",
    )

    def convert(self) -> t.GeneralValueType | None:
        """Execute string conversion."""
        try:
            return str(self.value)
        except (TypeError, ValueError):
            return self.default


class ConvertToInt(BaseModel):
    """Convert value to integer."""

    model_config = ConfigDict(
        frozen=True,
        validate_assignment=True,
        extra="forbid",
    )

    target_type: Literal["int"] = Field(
        default="int", description="Conversion target type"
    )
    value: t.GeneralValueType = Field(..., description="Value to convert")
    default: t.GeneralValueType | None = Field(
        default=None,
        description="Default value if conversion fails",
    )

    def convert(self) -> t.GeneralValueType | None:
        """Execute integer conversion with type guards."""
        if isinstance(self.value, (str, bytes, bytearray, int, float)):
            try:
                return int(self.value)
            except (TypeError, ValueError):
                return self.default

        try:
            return int(str(self.value))
        except (TypeError, ValueError):
            return self.default


class ConvertToFloat(BaseModel):
    """Convert value to float."""

    model_config = ConfigDict(
        frozen=True,
        validate_assignment=True,
        extra="forbid",
    )

    target_type: Literal["float"] = Field(
        default="float", description="Conversion target type"
    )
    value: t.GeneralValueType = Field(..., description="Value to convert")
    default: t.GeneralValueType | None = Field(
        default=None,
        description="Default value if conversion fails",
    )

    def convert(self) -> t.GeneralValueType | None:
        """Execute float conversion with type guards."""
        if isinstance(self.value, (str, bytes, bytearray, int, float)):
            try:
                return float(self.value)
            except (TypeError, ValueError):
                return self.default

        try:
            return float(str(self.value))
        except (TypeError, ValueError):
            return self.default


class ConvertToBool(BaseModel):
    """Convert value to boolean."""

    model_config = ConfigDict(
        frozen=True,
        validate_assignment=True,
        extra="forbid",
    )

    target_type: Literal["bool"] = Field(
        default="bool", description="Conversion target type"
    )
    value: t.GeneralValueType = Field(..., description="Value to convert")
    default: t.GeneralValueType | None = Field(
        default=None,
        description="Default value if conversion fails",
    )

    def convert(self) -> t.GeneralValueType | None:
        """Execute boolean conversion with string special handling."""
        if isinstance(self.value, str):
            return self.value.lower() in {"true", "1", "yes", "on"}
        try:
            return bool(self.value)
        except (TypeError, ValueError):
            return self.default


class ConvertToList(BaseModel):
    """Convert value to list."""

    model_config = ConfigDict(
        frozen=True,
        validate_assignment=True,
        extra="forbid",
    )

    target_type: Literal["list"] = Field(
        default="list", description="Conversion target type"
    )
    value: t.GeneralValueType = Field(..., description="Value to convert")
    default: t.GeneralValueType | None = Field(
        default=None,
        description="Default value if conversion fails",
    )

    def convert(self) -> t.GeneralValueType | None:
        """Execute list conversion."""
        if isinstance(self.value, list):
            return list(self.value)
        if isinstance(self.value, tuple | set):
            converted: list[t.GeneralValueType] = []
            for item in self.value:
                converted.append(item)
            return converted
        try:
            return [self.value]
        except (TypeError, ValueError):
            return self.default


class ConvertToTuple(BaseModel):
    """Convert value to tuple."""

    model_config = ConfigDict(
        frozen=True,
        validate_assignment=True,
        extra="forbid",
    )

    target_type: Literal["tuple"] = Field(
        default="tuple", description="Conversion target type"
    )
    value: t.GeneralValueType = Field(..., description="Value to convert")
    default: t.GeneralValueType | None = Field(
        default=None,
        description="Default value if conversion fails",
    )

    def convert(self) -> t.GeneralValueType | None:
        """Execute tuple conversion."""
        if isinstance(self.value, list | tuple):
            converted: list[t.GeneralValueType] = []
            for item in self.value:
                converted.append(item)
            return tuple(converted)
        try:
            return (self.value,)
        except (TypeError, ValueError):
            return self.default


class ConvertToDict(BaseModel):
    """Convert value to dict."""

    model_config = ConfigDict(
        frozen=True,
        validate_assignment=True,
        extra="forbid",
    )

    target_type: Literal["dict"] = Field(
        default="dict", description="Conversion target type"
    )
    value: t.GeneralValueType = Field(..., description="Value to convert")
    default: t.GeneralValueType | None = Field(
        default=None,
        description="Default value if conversion fails",
    )

    def convert(self) -> t.GeneralValueType | None:
        """Execute dict conversion with type guards."""
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
