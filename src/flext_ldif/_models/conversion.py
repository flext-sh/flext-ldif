"""Centralized Pydantic v2 conversion models for type casting."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Annotated, ClassVar, Literal, TypeAlias

from flext_core import FlextModels
from pydantic import ConfigDict, Field

from flext_ldif import t


class FlextLdifModelsConversions:
    """LDIF conversion models namespace."""

    _TRUE_STRINGS: frozenset[str] = frozenset({"true", "1", "yes", "on"})
    _ConvertValue: TypeAlias = (
        t.Container | Sequence[t.Container] | Mapping[str, t.Container]
    )
    _CONTAINER_TYPES: tuple[type[t.Container], ...] = (
        str,
        int,
        float,
        bool,
        datetime,
        Path,
    )

    class ConvertToStr(FlextModels.ArbitraryTypesModel):
        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
        target_type: Literal["str"] = "str"
        value: Annotated[
            t.Container | Sequence[t.Container] | Mapping[str, t.Container],
            Field(...),
        ]
        default: (
            t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None
        ) = None

        def convert(
            self,
        ) -> t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None:
            try:
                return str(self.value)
            except (TypeError, ValueError):
                return self.default

    class ConvertToInt(FlextModels.ArbitraryTypesModel):
        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
        target_type: Literal["int"] = "int"
        value: Annotated[
            t.Container | Sequence[t.Container] | Mapping[str, t.Container],
            Field(...),
        ]
        default: (
            t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None
        ) = None

        def convert(
            self,
        ) -> t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None:
            try:
                return int(str(self.value))
            except (TypeError, ValueError):
                return self.default

    class ConvertToFloat(FlextModels.ArbitraryTypesModel):
        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
        target_type: Literal["float"] = "float"
        value: Annotated[
            t.Container | Sequence[t.Container] | Mapping[str, t.Container],
            Field(...),
        ]
        default: (
            t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None
        ) = None

        def convert(
            self,
        ) -> t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None:
            try:
                return float(str(self.value))
            except (TypeError, ValueError):
                return self.default

    class ConvertToBool(FlextModels.ArbitraryTypesModel):
        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
        target_type: Literal["bool"] = "bool"
        value: Annotated[
            t.Container | Sequence[t.Container] | Mapping[str, t.Container],
            Field(...),
        ]
        default: (
            t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None
        ) = None

        def convert(
            self,
        ) -> t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None:
            val = self.value
            if isinstance(val, str):
                return val.lower() in FlextLdifModelsConversions._TRUE_STRINGS
            try:
                return bool(val)
            except (TypeError, ValueError):
                return self.default

    class ConvertToList(FlextModels.ArbitraryTypesModel):
        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
        target_type: Literal["list"] = "list"
        value: Annotated[
            t.Container | Sequence[t.Container] | Mapping[str, t.Container],
            Field(...),
        ]
        default: (
            t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None
        ) = None

        def convert(
            self,
        ) -> t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None:
            val = self.value
            if isinstance(val, Sequence) and not isinstance(
                val, (str, bytes, bytearray)
            ):
                return [
                    item
                    if isinstance(item, FlextLdifModelsConversions._CONTAINER_TYPES)
                    else str(item)
                    for item in val
                ]
            return [
                val
                if isinstance(val, FlextLdifModelsConversions._CONTAINER_TYPES)
                else str(val)
            ]

    class ConvertToTuple(FlextModels.ArbitraryTypesModel):
        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
        target_type: Literal["tuple"] = "tuple"
        value: Annotated[
            t.Container | Sequence[t.Container] | Mapping[str, t.Container],
            Field(...),
        ]
        default: (
            t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None
        ) = None

        def convert(
            self,
        ) -> t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None:
            val = self.value
            if isinstance(val, Sequence) and not isinstance(
                val, (str, bytes, bytearray)
            ):
                return tuple(
                    item
                    if isinstance(item, FlextLdifModelsConversions._CONTAINER_TYPES)
                    else str(item)
                    for item in val
                )
            return (
                val
                if isinstance(val, FlextLdifModelsConversions._CONTAINER_TYPES)
                else str(val),
            )

    class ConvertToDict(FlextModels.ArbitraryTypesModel):
        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")
        target_type: Literal["dict"] = "dict"
        value: Annotated[
            t.Container | Sequence[t.Container] | Mapping[str, t.Container],
            Field(...),
        ]
        default: (
            t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None
        ) = None

        def convert(
            self,
        ) -> t.Container | Sequence[t.Container] | Mapping[str, t.Container] | None:
            if isinstance(self.value, Mapping):
                return {
                    str(key): item
                    if isinstance(item, FlextLdifModelsConversions._CONTAINER_TYPES)
                    else str(item)
                    for key, item in self.value.items()
                }
            return self.default

    ConversionRequest: TypeAlias = (
        ConvertToStr
        | ConvertToInt
        | ConvertToFloat
        | ConvertToBool
        | ConvertToList
        | ConvertToTuple
        | ConvertToDict
    )


__all__ = ["FlextLdifModelsConversions"]
