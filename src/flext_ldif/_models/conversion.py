"""Centralized Pydantic v2 conversion models for type casting."""

from __future__ import annotations

from ._models import (
    ConvertToBool,
    ConvertToDict,
    ConvertToFloat,
    ConvertToInt,
    ConvertToList,
    ConvertToStr,
    ConvertToTuple,
)

_TRUE_STRINGS: frozenset[str] = frozenset({"true", "1", "yes", "on"})
ConversionRequest = (
    ConvertToStr
    | ConvertToInt
    | ConvertToFloat
    | ConvertToBool
    | ConvertToList
    | ConvertToTuple
    | ConvertToDict
)
"Discriminated union of all conversion request types."


class FlextLdifModelsConversions:
    ConvertToStr = ConvertToStr
    ConvertToInt = ConvertToInt
    ConvertToFloat = ConvertToFloat
    ConvertToBool = ConvertToBool
    ConvertToList = ConvertToList
    ConvertToTuple = ConvertToTuple
    ConvertToDict = ConvertToDict
    ConversionRequest = ConversionRequest


__all__ = ["FlextLdifModelsConversions"]
