"""Metadata models for LDIF processing."""

from __future__ import annotations

from collections.abc import (
    ItemsView,
    KeysView,
    Mapping,
    ValuesView,
)
from typing import ClassVar, Self, override

from flext_core import FlextModels
from pydantic import ConfigDict, Field

from flext_ldif import t


class FlextLdifModelsMetadata:
    """LDIF metadata models container."""

    class DynamicMetadata(FlextModels.ArbitraryTypesModel):
        """Model with extra='allow' for dynamic field storage."""

        model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)
        transformations: list[t.Scalar] | None = Field(default=None)
        original_format: str | None = Field(default=None)
        schema_source_server: str | None = Field(default=None)
        server_type: str | None = Field(default=None)
        relaxed_mode: bool | None = Field(default=None)

        @override
        def __eq__(self, other: object) -> bool:
            if other.__class__ is dict:
                return dict(self.items()) == other
            if isinstance(other, type(self)):
                return dict(self.items()) == dict(other.items())
            return NotImplemented

        def __hash__(self) -> int:
            msg = "unhashable type: 'DynamicMetadata'"
            raise TypeError(msg)

        def __getitem__(self, key: str) -> t.MetadataValue:
            if key in type(self).model_fields:
                return getattr(self, key)
            return self._extra()[key]

        def __setitem__(self, key: str, value: t.MetadataValue) -> None:
            setattr(self, key, value)

        def __len__(self) -> int:
            return len(self._extra())

        def __contains__(self, key: str) -> bool:
            return key in self._extra()

        @classmethod
        def from_dict(cls, data: Mapping[str, t.MetadataValue] | None = None) -> Self:
            """Create DynamicMetadata from a dictionary."""
            if data is None:
                return cls()
            return cls.model_validate(dict(data))

        @staticmethod
        def coerce_metadata_value(value: t.MetadataValue) -> t.MetadataValue:
            """Identity coercion — value already typed by MetadataAttributeValue."""
            return value

        def clear(self) -> None:
            extra = self.__pydantic_extra__
            if extra is not None:
                extra.clear()

        def get(
            self, key: str, default: t.MetadataValue | None = None
        ) -> t.MetadataValue | None:
            """Get value by key, returning default if not found."""
            if key in type(self).model_fields:
                return getattr(self, key)
            return self._extra().get(key, default)

        def items(self) -> ItemsView[str, t.MetadataValue]:
            return self._extra().items()

        def keys(self) -> KeysView[str]:
            return self._extra().keys()

        def pop(
            self, key: str, default: t.MetadataValue | None = None
        ) -> t.MetadataValue | None:
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                return extra.pop(key)
            return default

        def to_dict(self) -> Mapping[str, t.MetadataValue]:
            return dict(self.items())

        def update(self, other: Mapping[str, t.MetadataValue]) -> None:
            for key, value in other.items():
                setattr(self, key, value)

        def values(self) -> ValuesView[t.MetadataValue]:
            return self._extra().values()

        def _extra(self) -> dict[str, t.MetadataValue]:
            return self.__pydantic_extra__ or {}

    class EntryMetadata(FlextModels.ArbitraryTypesModel):
        """Entry metadata for tracking processing details."""

        model_config = ConfigDict(
            frozen=True, extra="allow", use_enum_values=True, str_strip_whitespace=True
        )

        def __getitem__(self, key: str) -> t.MetadataValue:
            return self._extra()[key]

        def __contains__(self, key: str) -> bool:
            return key in self._extra()

        def get(
            self, key: str, default: t.MetadataValue | None = None
        ) -> t.MetadataValue | None:
            return self._extra().get(key, default)

        def _extra(self) -> dict[str, t.MetadataValue]:
            return self.__pydantic_extra__ or {}

    class TransformationInfo(FlextModels.ArbitraryTypesModel):
        """Transformation step information stored in metadata."""

        model_config = ConfigDict(extra="forbid", validate_assignment=True)
        step: str | None = None
        server: str | None = None
        changes: ClassVar[list[str]] = []


__all__ = ["FlextLdifModelsMetadata"]
